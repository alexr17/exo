use std::collections::HashMap;
use std::future::Future;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use anyhow::{Result, ensure};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use tokio_util::sync::CancellationToken;

use super::{
    EgressCredentialResolver, EgressIdentity, EgressProxy, EgressTransport, State, UpstreamResolver,
};
use crate::{ManagedSandboxHandle, SandboxCommand, SandboxRequest};

const PREPARE_TRUST: &str = r#"set -eu
umask 077
cat /etc/ssl/certs/ca-certificates.crt > "$EXO_EGRESS_CA_PATH"
printf '\n%s\n' "$EXO_EGRESS_CA_PEM" >> "$EXO_EGRESS_CA_PATH"
"#;

pub(crate) struct SandboxEgress {
    proxy: EgressProxy,
    ca_path: String,
}

impl SandboxEgress {
    pub(crate) fn endpoints(&self) -> crate::SandboxEgressProxy {
        self.proxy.endpoints()
    }

    pub(crate) async fn initialize(
        &self,
        handle: &dyn ManagedSandboxHandle,
        source: Ipv4Addr,
    ) -> Result<()> {
        self.proxy.bind_source(source).await?;
        let prepared = handle
            .exec(&SandboxCommand {
                argv: vec!["/bin/sh".into(), "-c".into(), PREPARE_TRUST.into()],
                env: HashMap::from([
                    ("EXO_EGRESS_CA_PATH".into(), self.ca_path.clone()),
                    ("EXO_EGRESS_CA_PEM".into(), self.proxy.ca_pem().into()),
                ]),
                display_argv: None,
                cwd: None,
                timeout: Some(Duration::from_secs(30)),
            })
            .await?;
        ensure!(
            prepared.ok,
            "could not prepare sandbox TLS trust: {}",
            prepared.stderr
        );
        Ok(())
    }

    pub(crate) fn command(&self, command: &SandboxCommand) -> Result<SandboxCommand> {
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

    pub(crate) fn close(&self) {
        self.proxy.close();
    }
}

struct CachedSandbox<H> {
    request: SandboxRequest,
    handle: Option<Arc<H>>,
    egress: Arc<SandboxEgress>,
}

pub(crate) struct EgressRuntime<H> {
    resolver: Option<Arc<dyn EgressCredentialResolver>>,
    upstream: Arc<dyn UpstreamResolver>,
    locks: Mutex<HashMap<String, Weak<AsyncMutex<()>>>>,
    sandboxes: Mutex<HashMap<String, CachedSandbox<H>>>,
    closed: CancellationToken,
}

impl<H: ManagedSandboxHandle + 'static> EgressRuntime<H> {
    pub(crate) fn new(
        resolver: Option<Arc<dyn EgressCredentialResolver>>,
        upstream: Arc<dyn UpstreamResolver>,
    ) -> Self {
        Self {
            resolver,
            upstream,
            locks: Mutex::new(HashMap::new()),
            sandboxes: Mutex::new(HashMap::new()),
            closed: CancellationToken::new(),
        }
    }

    async fn lock(&self, id: &str) -> OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.locks.lock().expect("egress lock map poisoned");
            locks.retain(|_, lock| lock.strong_count() > 0);
            match locks.get(id).and_then(Weak::upgrade) {
                Some(lock) => lock,
                None => {
                    let lock = Arc::new(AsyncMutex::new(()));
                    locks.insert(id.to_owned(), Arc::downgrade(&lock));
                    lock
                }
            }
        };
        lock.lock_owned().await
    }

    pub(crate) async fn acquire<T, TF, B, BF>(
        &self,
        request: SandboxRequest,
        transport: T,
        build: B,
    ) -> Result<Arc<H>>
    where
        T: FnOnce(Vec<String>) -> TF,
        TF: Future<Output = Result<Arc<dyn EgressTransport>>>,
        B: FnOnce(Option<Arc<SandboxEgress>>) -> BF,
        BF: Future<Output = Result<H>>,
    {
        let _guard = self.lock(&request.sandbox_id).await;
        let cached = self
            .sandboxes
            .lock()
            .expect("egress sandbox map poisoned")
            .get(&request.sandbox_id)
            .map(|cached| {
                (
                    cached.request.clone(),
                    cached.handle.clone(),
                    cached.egress.clone(),
                )
            });
        if let Some((previous, handle, egress)) = cached {
            ensure!(
                previous.spec == request.spec && previous.scope == request.scope,
                "stop the protected sandbox before changing its configuration"
            );
            if let Some(handle) = handle
                && !egress.proxy.cancel.is_cancelled()
                && handle.is_running().await? != Some(false)
            {
                return Ok(handle);
            }
            self.remove(&request.sandbox_id);
        }
        if !request.spec.policy.requires_proxy() {
            return Ok(Arc::new(build(None).await?));
        }
        ensure!(
            !self.closed.is_cancelled(),
            "sandbox egress runtime is shut down"
        );
        ensure!(
            request.lifecycle.idle_ttl.is_some(),
            "proxy egress requires a managed sandbox lifecycle"
        );
        let state = State::new(
            EgressIdentity {
                sandbox_id: request.sandbox_id.clone(),
                scope: request.scope.clone(),
            },
            request.spec.policy.clone(),
            self.resolver.clone(),
            self.upstream.clone(),
        )?;
        let transport = transport(state.hosts.iter().cloned().collect()).await?;
        let egress = Arc::new(SandboxEgress {
            proxy: EgressProxy::start_with_transport(transport, state, self.closed.child_token())
                .await?,
            ca_path: format!("/tmp/exo-egress-{}.pem", uuid::Uuid::new_v4().simple()),
        });
        {
            let mut sandboxes = self.sandboxes.lock().expect("egress sandbox map poisoned");
            ensure!(
                !self.closed.is_cancelled(),
                "sandbox egress runtime shut down during acquisition"
            );
            sandboxes.insert(
                request.sandbox_id.clone(),
                CachedSandbox {
                    request: request.clone(),
                    handle: None,
                    egress: egress.clone(),
                },
            );
        }
        let handle = match build(Some(egress)).await {
            Ok(handle) => Arc::new(handle),
            Err(error) => {
                self.remove(&request.sandbox_id);
                return Err(error);
            }
        };
        let mut sandboxes = self.sandboxes.lock().expect("egress sandbox map poisoned");
        ensure!(
            !self.closed.is_cancelled(),
            "sandbox egress runtime shut down during acquisition"
        );
        sandboxes
            .get_mut(&request.sandbox_id)
            .expect("acquiring sandbox remains registered")
            .handle = Some(handle.clone());
        Ok(handle)
    }

    fn remove(&self, id: &str) {
        if let Some(cached) = self
            .sandboxes
            .lock()
            .expect("egress sandbox map poisoned")
            .remove(id)
        {
            cached.egress.close();
        }
    }

    pub(crate) async fn terminate<F: Future<Output = Result<()>>>(
        &self,
        id: &str,
        terminate: F,
    ) -> Result<()> {
        let _guard = self.lock(id).await;
        self.remove(id);
        terminate.await
    }

    pub(crate) fn shutdown(&self) {
        self.closed.cancel();
        let sandboxes =
            std::mem::take(&mut *self.sandboxes.lock().expect("egress sandbox map poisoned"));
        for cached in sandboxes.into_values() {
            cached.egress.close();
        }
    }
}

impl<H> Drop for EgressRuntime<H> {
    fn drop(&mut self) {
        self.closed.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::PublicUpstreamResolver;
    use crate::{SandboxLifecycleConfig, SandboxNetworkPolicy, SandboxSpec};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Handle;

    #[async_trait]
    impl ManagedSandboxHandle for Handle {
        fn id(&self) -> &str {
            "test"
        }
        async fn exec(&self, _command: &SandboxCommand) -> Result<crate::SandboxCommandOutput> {
            unreachable!()
        }
        async fn start_process(
            &self,
            _command: &SandboxCommand,
        ) -> Result<crate::SandboxProcessParts> {
            unreachable!()
        }
        async fn stop(&self) -> Result<()> {
            unreachable!()
        }
        async fn detach(&self) -> Result<crate::SandboxAttachment> {
            unreachable!()
        }
        async fn snapshot(&self) -> Result<crate::SnapshotPayload> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct Transport {
        closed: AtomicBool,
    }

    #[async_trait]
    impl EgressTransport for Transport {
        fn endpoints(&self) -> crate::SandboxEgressProxy {
            crate::SandboxEgressProxy {
                http: "192.0.2.1:80".parse().unwrap(),
                https: "192.0.2.1:443".parse().unwrap(),
                dns: "192.0.2.1:53".parse().unwrap(),
            }
        }
        async fn bind_source(&self, _source: Ipv4Addr) -> Result<()> {
            Ok(())
        }
        async fn accept(&self, _tls: bool) -> Result<crate::BoxSandboxTcpStream> {
            std::future::pending().await
        }
        fn close(&self) {
            self.closed.store(true, Ordering::SeqCst);
        }
    }

    fn request(id: &str) -> SandboxRequest {
        SandboxRequest {
            sandbox_id: id.into(),
            scope: None,
            provider_state: None,
            spec: SandboxSpec {
                image: "test".into(),
                resources: Default::default(),
                mounts: vec![],
                durable_file_systems: vec![],
                default_workdir: "/tmp".into(),
                policy: SandboxNetworkPolicy::Limited {
                    allowed_hosts: vec!["api.test".into()],
                }
                .into(),
            },
            lifecycle: SandboxLifecycleConfig {
                idle_ttl: Some(Duration::from_secs(60)),
            },
        }
    }

    #[tokio::test]
    async fn shutdown_closes_proxies_while_acquisition_is_pending() -> Result<()> {
        let runtime = EgressRuntime::<Handle>::new(None, Arc::new(PublicUpstreamResolver));
        let transport = Arc::new(Transport::default());
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let acquiring = runtime.acquire(
            request("one"),
            |_| async { Ok(transport.clone() as Arc<dyn EgressTransport>) },
            |_| async {
                started.send(()).unwrap();
                released.await?;
                Ok(Handle)
            },
        );
        let shutdown = async {
            ready.await.unwrap();
            runtime.shutdown();
            assert!(transport.closed.load(Ordering::SeqCst));
            assert!(runtime.sandboxes.lock().unwrap().is_empty());
            release.send(()).unwrap();
        };
        let (result, ()) = tokio::join!(acquiring, shutdown);
        assert!(result.err().unwrap().to_string().contains("shut down"));
        Ok(())
    }

    #[tokio::test]
    async fn shutdown_during_transport_creation_prevents_late_registration() -> Result<()> {
        let runtime = EgressRuntime::<Handle>::new(None, Arc::new(PublicUpstreamResolver));
        let transport = Arc::new(Transport::default());
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let acquiring = runtime.acquire(
            request("one"),
            |_| async {
                started.send(()).unwrap();
                released.await?;
                Ok(transport.clone() as Arc<dyn EgressTransport>)
            },
            |_| async { panic!("closed runtime must not start a sandbox") },
        );
        let shutdown = async {
            ready.await.unwrap();
            runtime.shutdown();
            release.send(()).unwrap();
        };
        let (result, ()) = tokio::join!(acquiring, shutdown);
        assert!(result.err().unwrap().to_string().contains("shut down"));
        assert!(transport.closed.load(Ordering::SeqCst));
        assert!(runtime.sandboxes.lock().unwrap().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn termination_waits_for_acquisition_and_removes_cached_state() -> Result<()> {
        let runtime = EgressRuntime::<Handle>::new(None, Arc::new(PublicUpstreamResolver));
        let transport = Arc::new(Transport::default());
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let acquiring = runtime.acquire(
            request("one"),
            |_| async { Ok(transport.clone() as Arc<dyn EgressTransport>) },
            |_| async {
                started.send(()).unwrap();
                released.await?;
                Ok(Handle)
            },
        );
        let terminating = async {
            ready.await?;
            let terminate = runtime.terminate("one", async { Ok(()) });
            tokio::pin!(terminate);
            assert!(futures::poll!(&mut terminate).is_pending());
            assert!(!transport.closed.load(Ordering::SeqCst));
            release.send(()).unwrap();
            terminate.await
        };
        let (handle, terminated) = tokio::join!(acquiring, terminating);
        handle?;
        terminated?;
        assert!(transport.closed.load(Ordering::SeqCst));
        assert!(runtime.sandboxes.lock().unwrap().is_empty());
        for i in 0..20 {
            runtime.terminate(&i.to_string(), async { Ok(()) }).await?;
        }
        assert_eq!(runtime.locks.lock().unwrap().len(), 1);
        Ok(())
    }
}
