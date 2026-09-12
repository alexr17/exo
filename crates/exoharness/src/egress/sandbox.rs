use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail, ensure};
use async_trait::async_trait;
use tokio::sync::Mutex;

use super::{EgressCredentialResolver, EgressIdentity, EgressProxy};
use crate::{
    BoxSandboxTcpStream, ManagedSandboxBackend, ManagedSandboxHandle, SandboxAttachment,
    SandboxCommand, SandboxCommandOutput, SandboxNetworkPolicy, SandboxProcessParts,
    SandboxRequest, SandboxTerminalParts, SandboxTerminalSize, SnapshotFormat, SnapshotPayload,
};

#[async_trait]
pub trait FirecrackerEgressProvider: ManagedSandboxBackend {
    async fn egress_transport(
        &self,
        request: &SandboxRequest,
        allowed_hosts: &[String],
    ) -> Result<Arc<dyn super::EgressTransport>>;

    async fn acquire_egress(
        &self,
        request: SandboxRequest,
        endpoints: crate::SandboxEgressProxy,
    ) -> Result<(Arc<dyn ManagedSandboxHandle>, std::net::Ipv4Addr)>;
}

struct NoCredentials;

#[async_trait]
impl EgressCredentialResolver for NoCredentials {
    async fn resolve(
        &self,
        _identity: &EgressIdentity,
        _binding_name: &str,
        _destination: &super::EgressDestination,
    ) -> Result<String> {
        bail!("Firecracker credential resolver is not configured")
    }
}

type SandboxSlot = Arc<Mutex<Option<Arc<EgressSandboxHandle>>>>;

pub struct FirecrackerEgressBackend {
    backend: Arc<dyn FirecrackerEgressProvider>,
    resolver: Option<Arc<dyn EgressCredentialResolver>>,
    #[cfg(test)]
    pub(super) upstream: Option<super::tests::TestUpstream>,
    sandboxes: Mutex<HashMap<String, SandboxSlot>>,
}

impl FirecrackerEgressBackend {
    pub fn new(
        backend: Arc<dyn FirecrackerEgressProvider>,
        resolver: Option<Arc<dyn EgressCredentialResolver>>,
    ) -> Self {
        Self {
            backend,
            resolver,
            #[cfg(test)]
            upstream: None,
            sandboxes: Mutex::new(HashMap::new()),
        }
    }

    pub async fn shutdown(&self) {
        let slots = self
            .sandboxes
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for slot in slots {
            if let Some(handle) = slot.lock().await.as_ref() {
                handle.proxy.close();
            }
        }
    }

    async fn slot(&self, id: &str) -> SandboxSlot {
        self.sandboxes
            .lock()
            .await
            .entry(id.to_owned())
            .or_default()
            .clone()
    }

    async fn proxy(&self, request: &SandboxRequest) -> Result<EgressProxy> {
        let state = super::State::new(
            EgressIdentity {
                sandbox_id: request.sandbox_id.clone(),
                scope: request.scope.clone(),
            },
            request.spec.policy.clone(),
            match &self.resolver {
                Some(resolver) => resolver.clone(),
                None => {
                    ensure!(
                        request.spec.policy.credentials.is_empty(),
                        "Firecracker policy.credentials requires a credential resolver"
                    );
                    Arc::new(NoCredentials)
                }
            },
        )?;
        let transport = self
            .backend
            .egress_transport(request, &state.hosts.iter().cloned().collect::<Vec<_>>())
            .await?;
        #[cfg(test)]
        let state = super::State {
            upstream: self.upstream.clone(),
            ..state
        };
        EgressProxy::start_with_transport(transport, state).await
    }
}

#[async_trait]
impl ManagedSandboxBackend for FirecrackerEgressBackend {
    fn is_local(&self) -> bool {
        self.backend.is_local()
    }
    fn consumable_snapshot_formats(&self) -> &[SnapshotFormat] {
        self.backend.consumable_snapshot_formats()
    }
    async fn delete_snapshot(&self, payload: SnapshotPayload) -> Result<()> {
        self.backend.delete_snapshot(payload).await
    }
    async fn fork_sandbox(
        &self,
        source: SandboxRequest,
        target: SandboxRequest,
    ) -> Result<Arc<dyn ManagedSandboxHandle>> {
        source
            .spec
            .policy
            .validate_basic("Firecracker snapshot source")?;
        target
            .spec
            .policy
            .validate_basic("Firecracker snapshot target")?;
        self.backend.fork_sandbox(source, target).await
    }
    async fn resolve_image(&self, image: &str) -> Result<crate::ResolvedSandboxImage> {
        self.backend.resolve_image(image).await
    }

    async fn acquire(&self, request: SandboxRequest) -> Result<Arc<dyn ManagedSandboxHandle>> {
        if request.spec.policy.credentials.is_empty()
            && !matches!(
                request.spec.policy.networking,
                SandboxNetworkPolicy::Limited { .. }
            )
        {
            return self.backend.acquire(request).await;
        }
        ensure!(
            request.lifecycle.idle_ttl.is_some(),
            "proxy egress requires a managed sandbox lifecycle"
        );
        ensure!(
            request.spec.policy.networking != SandboxNetworkPolicy::Disabled,
            "proxy egress requires networking enabled"
        );
        let slot = self.slot(&request.sandbox_id).await;
        let mut slot = slot.lock().await;
        if let Some(handle) = slot.as_ref() {
            ensure!(
                handle.request.spec == request.spec && handle.request.scope == request.scope,
                "stop the protected sandbox before changing its configuration"
            );
            if !handle.proxy.cancel.is_cancelled()
                && handle.inner.is_running().await? != Some(false)
            {
                return Ok(handle.clone());
            }
            handle.proxy.close();
        }
        let proxy = self.proxy(&request).await?;
        let (inner, source) = self
            .backend
            .acquire_egress(request.clone(), proxy.endpoints())
            .await?;
        proxy.bind_source(source).await?;
        let ca_path = format!("/tmp/exo-egress-{}.pem", uuid::Uuid::new_v4().simple());
        let preparation = SandboxCommand {
            argv: vec!["/bin/sh".into(), "-c".into(),
                "set -eu; umask 077; cat /etc/ssl/certs/ca-certificates.crt > \"$EXO_EGRESS_CA_PATH\"; printf '\\n%s\\n' \"$EXO_EGRESS_CA_PEM\" >> \"$EXO_EGRESS_CA_PATH\"".into()],
            env: HashMap::from([("EXO_EGRESS_CA_PATH".into(), ca_path.clone()), ("EXO_EGRESS_CA_PEM".into(), proxy.ca_pem().into())]),
            display_argv: None, cwd: None, timeout: Some(Duration::from_secs(30)),
        };
        let prepared = inner.exec(&preparation).await?;
        ensure!(
            prepared.ok,
            "could not prepare sandbox TLS trust: {}",
            prepared.stderr
        );
        let handle = Arc::new(EgressSandboxHandle {
            inner,
            proxy,
            request,
            ca_path,
        });
        *slot = Some(handle.clone());
        Ok(handle)
    }

    async fn terminate(&self, request: SandboxRequest) -> Result<()> {
        let slot = self.slot(&request.sandbox_id).await;
        let mut slot = slot.lock().await;
        if let Some(handle) = slot.as_ref() {
            handle.proxy.close();
        }
        self.backend.terminate(request).await?;
        *slot = None;
        Ok(())
    }

    async fn attach(
        &self,
        request: SandboxRequest,
        attachment: SandboxAttachment,
    ) -> Result<Arc<dyn ManagedSandboxHandle>> {
        request
            .spec
            .policy
            .validate_basic("Firecracker external attachments")?;
        self.backend.attach(request, attachment).await
    }
    async fn acquire_from_snapshot(
        &self,
        request: SandboxRequest,
        payload: SnapshotPayload,
    ) -> Result<Arc<dyn ManagedSandboxHandle>> {
        request
            .spec
            .policy
            .validate_basic("Firecracker snapshot restore")?;
        self.backend.acquire_from_snapshot(request, payload).await
    }
}

struct EgressSandboxHandle {
    inner: Arc<dyn ManagedSandboxHandle>,
    proxy: EgressProxy,
    request: SandboxRequest,
    ca_path: String,
}

impl EgressSandboxHandle {
    fn command(&self, command: &SandboxCommand) -> Result<SandboxCommand> {
        ensure!(
            !self.proxy.cancel.is_cancelled(),
            "sandbox egress proxy is closed; acquire the sandbox again"
        );
        let mut command = command.clone();
        command.env.extend(self.proxy.environment().clone());
        for key in [
            "SSL_CERT_FILE",
            "REQUESTS_CA_BUNDLE",
            "NODE_EXTRA_CA_CERTS",
            "CURL_CA_BUNDLE",
            "GIT_SSL_CAINFO",
        ] {
            command.env.insert(key.into(), self.ca_path.clone());
        }
        Ok(command)
    }
}

#[async_trait]
impl ManagedSandboxHandle for EgressSandboxHandle {
    fn id(&self) -> &str {
        self.inner.id()
    }
    fn provider_state(&self) -> Option<serde_json::Value> {
        self.inner.provider_state()
    }
    fn effective_image(&self) -> Option<String> {
        self.inner.effective_image()
    }
    async fn is_running(&self) -> Result<Option<bool>> {
        self.inner.is_running().await
    }
    async fn exec(&self, command: &SandboxCommand) -> Result<SandboxCommandOutput> {
        self.inner.exec(&self.command(command)?).await
    }
    async fn start_process(&self, command: &SandboxCommand) -> Result<SandboxProcessParts> {
        self.inner.start_process(&self.command(command)?).await
    }
    async fn start_terminal(
        &self,
        command: &SandboxCommand,
        size: SandboxTerminalSize,
    ) -> Result<SandboxTerminalParts> {
        self.inner
            .start_terminal(&self.command(command)?, size)
            .await
    }
    fn supports_tcp(&self) -> bool {
        self.inner.supports_tcp()
    }
    async fn connect_tcp(&self, port: u16) -> Result<Option<BoxSandboxTcpStream>> {
        self.inner.connect_tcp(port).await
    }
    async fn stop(&self) -> Result<()> {
        self.proxy.close();
        self.inner.stop().await
    }
    async fn detach(&self) -> Result<SandboxAttachment> {
        bail!("proxy egress does not support detaching")
    }
    async fn snapshot(&self) -> Result<SnapshotPayload> {
        bail!("proxy egress snapshots require a fresh identity and trust binding")
    }
    async fn delete_snapshot(&self, payload: SnapshotPayload) -> Result<()> {
        self.inner.delete_snapshot(payload).await
    }
}
