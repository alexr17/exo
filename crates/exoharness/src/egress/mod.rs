use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use async_trait::async_trait;
use bytes::Bytes;
use futures::TryStreamExt;
use http_body_util::{BodyExt, Full, Limited, StreamBody, combinators::BoxBody};
use hyper::body::{Frame, Incoming};
use hyper::header::{CONNECTION, HOST, HeaderMap, HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{self, ServerConfig, pki_types::PrivatePkcs8KeyDer};
use tokio_util::sync::CancellationToken;

use crate::types::{canonical_egress_host as canonical_host, canonical_egress_hosts};

use crate::{
    CredentialNetworkPolicy, EgressCredentialBinding, EgressPolicy, SandboxEgressProxy,
    SandboxNetworkPolicy,
};

mod transport;
pub use transport::{EgressTransport, LocalEgressTransport};
mod sandbox;
pub(crate) use sandbox::{EgressRuntime, SandboxEgress};

const PLACEHOLDER_PREFIX: &str = "exo_egress_";
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REQUEST_BODY: usize = 8 * 1024 * 1024;
const HTTP_BUFFER_SIZE: usize = 32 * 1024;
const MAX_CONNECTIONS: usize = 128;

pub(crate) struct ResolvedUpstream {
    addresses: Vec<SocketAddr>,
    root_certificate: Option<reqwest::Certificate>,
}

#[async_trait]
pub(crate) trait UpstreamResolver: Send + Sync {
    async fn resolve(&self, host: &str, port: u16) -> Result<ResolvedUpstream>;
}

pub(crate) struct PublicUpstreamResolver;

#[async_trait]
impl UpstreamResolver for PublicUpstreamResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<ResolvedUpstream> {
        let addresses =
            tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::lookup_host((host, port)))
                .await??
                .filter(|address| public_ipv4(address.ip()))
                .collect::<Vec<_>>();
        ensure!(
            !addresses.is_empty(),
            "upstream has no permitted IPv4 address"
        );
        Ok(ResolvedUpstream {
            addresses,
            root_certificate: None,
        })
    }
}
type ProxyError = Box<dyn std::error::Error + Send + Sync>;
type ProxyBody = BoxBody<Bytes, ProxyError>;

#[derive(Debug, Clone)]
pub struct EgressIdentity {
    pub sandbox_id: String,
    pub scope: Option<crate::SandboxScope>,
}

#[derive(Debug)]
pub struct EgressDestination {
    pub host: String,
    pub port: u16,
    pub method: Method,
    pub path: String,
}

#[async_trait]
pub trait EgressCredentialResolver: Send + Sync {
    async fn resolve(
        &self,
        identity: &EgressIdentity,
        binding_name: &str,
        destination: &EgressDestination,
    ) -> Result<String>;
}

struct EgressProxy {
    endpoints: SandboxEgressProxy,
    transport: Arc<dyn EgressTransport>,
    ca_pem: String,
    environment: HashMap<String, String>,
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

struct Binding {
    config: EgressCredentialBinding,
    hosts: Option<HashSet<String>>,
    placeholder: String,
}

impl Binding {
    fn permits_header(&self, host: &str) -> bool {
        self.config.injection_location.header
            && self.hosts.as_ref().is_none_or(|hosts| hosts.contains(host))
    }
}

struct State {
    hosts: HashSet<String>,
    bindings: Vec<Binding>,
    identity: EgressIdentity,
    resolver: Option<Arc<dyn EgressCredentialResolver>>,
    upstream: Arc<dyn UpstreamResolver>,
}

impl EgressProxy {
    async fn start_with_transport(
        transport: Arc<dyn EgressTransport>,
        state: State,
        cancel: CancellationToken,
    ) -> Result<Self> {
        let endpoints = transport.endpoints();
        endpoints.validate()?;
        let (ca_pem, tls) = tls_configuration(state.hosts.iter().cloned().collect())?;
        let environment = state
            .bindings
            .iter()
            .map(|b| (b.config.environment_variable.clone(), b.placeholder.clone()))
            .collect();
        let state = Arc::new(state);
        let task = tokio::spawn(serve(transport.clone(), tls, state, cancel.clone()));
        Ok(Self {
            endpoints,
            transport,
            ca_pem,
            environment,
            cancel,
            task,
        })
    }

    pub async fn bind_source(&self, source_ip: Ipv4Addr) -> Result<()> {
        self.transport.bind_source(source_ip).await
    }

    pub fn endpoints(&self) -> SandboxEgressProxy {
        self.endpoints
    }
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }
    pub fn environment(&self) -> &HashMap<String, String> {
        &self.environment
    }

    fn close(&self) {
        self.cancel.cancel();
        self.transport.close();
    }
}

impl Drop for EgressProxy {
    fn drop(&mut self) {
        self.close();
        self.task.abort();
    }
}

impl State {
    fn new(
        identity: EgressIdentity,
        policy: EgressPolicy,
        resolver: Option<Arc<dyn EgressCredentialResolver>>,
        upstream: Arc<dyn UpstreamResolver>,
    ) -> Result<Self> {
        ensure!(
            !identity.sandbox_id.is_empty(),
            "egress identity is required"
        );
        let SandboxNetworkPolicy::Limited { allowed_hosts } = policy.networking else {
            return Err(anyhow!(
                "egress proxy currently requires limited networking; unrestricted passthrough is not implemented"
            ));
        };
        let hosts = canonical_egress_hosts(&allowed_hosts)?;
        ensure!(
            policy.credentials.is_empty() || resolver.is_some(),
            "credential substitution requires an egress credential resolver"
        );
        let mut variables = HashSet::new();
        let mut bindings = Vec::new();
        for config in policy.credentials {
            let hosts = match &config.networking {
                CredentialNetworkPolicy::Unrestricted => None,
                CredentialNetworkPolicy::Limited { allowed_hosts } => {
                    Some(canonical_egress_hosts(allowed_hosts)?)
                }
            };
            ensure!(
                !config.name.is_empty(),
                "credential binding name is required"
            );
            ensure!(
                !config.environment_variable.is_empty()
                    && config
                        .environment_variable
                        .bytes()
                        .enumerate()
                        .all(|(i, c)| c == b'_'
                            || c.is_ascii_alphabetic()
                            || (i > 0 && c.is_ascii_digit())),
                "invalid credential environment variable"
            );
            ensure!(
                variables.insert(config.environment_variable.clone()),
                "duplicate credential environment variable"
            );
            bindings.push(Binding {
                config,
                hosts,
                placeholder: format!("{PLACEHOLDER_PREFIX}{}", uuid::Uuid::new_v4().simple()),
            });
        }
        Ok(Self {
            hosts,
            bindings,
            identity,
            resolver,
            upstream,
        })
    }

    async fn forward(
        &self,
        request: Request<Incoming>,
        sni: Option<&str>,
    ) -> Result<Response<ProxyBody>> {
        let (destination, url) = self.destination(&request, sni)?;
        let mut headers = request.headers().clone();
        self.validate_credentials(&headers, &destination.host, sni.is_some())?;
        strip_hop_headers(&mut headers)?;
        let client = self.client(&destination.host, destination.port).await?;
        self.substitute_credentials(&mut headers, &destination)
            .await?;
        relay(request, headers, url, client).await
    }

    fn destination(
        &self,
        request: &Request<Incoming>,
        sni: Option<&str>,
    ) -> Result<(EgressDestination, reqwest::Url)> {
        ensure!(
            request.method() != Method::CONNECT,
            "CONNECT is not supported on the transparent listener"
        );
        ensure!(
            !request.headers().contains_key("upgrade"),
            "protocol upgrades are not supported"
        );
        ensure!(
            request.uri().scheme().is_none() && request.uri().authority().is_none(),
            "expected origin-form request"
        );
        ensure!(
            request.headers().get_all(HOST).iter().count() == 1,
            "exactly one Host header is required"
        );
        let authority: hyper::http::uri::Authority = request
            .headers()
            .get(HOST)
            .context("missing Host")?
            .to_str()?
            .parse()?;
        let host = canonical_host(authority.host())?;
        ensure!(self.hosts.contains(&host), "host is not allowed");
        let port = if sni.is_some() { 443 } else { 80 };
        ensure!(
            authority.port_u16().unwrap_or(port) == port,
            "only standard HTTP ports are supported"
        );
        if let Some(sni) = sni {
            ensure!(
                canonical_host(sni)? == host,
                "TLS SNI and HTTP Host must match"
            );
        }
        let path = request
            .uri()
            .path_and_query()
            .context("missing request path")?
            .as_str()
            .to_owned();
        ensure!(
            path.starts_with('/') && !path.starts_with("//"),
            "invalid request path"
        );
        let scheme = if sni.is_some() { "https" } else { "http" };
        let url = reqwest::Url::parse(&format!("{scheme}://{host}{path}"))?;
        ensure!(
            url.host_str() == Some(host.as_str()) && url.port_or_known_default() == Some(port),
            "request changed the upstream authority"
        );
        let path = match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_owned(),
        };
        let destination = EgressDestination {
            host: host.clone(),
            port,
            method: request.method().clone(),
            path,
        };
        Ok((destination, url))
    }

    fn validate_credentials(&self, headers: &HeaderMap, host: &str, tls: bool) -> Result<()> {
        for (header, value) in headers {
            if !contains_placeholder(value.as_bytes()) {
                continue;
            }
            ensure!(tls, "credential substitution requires HTTPS");
            ensure!(
                !hop_header(header) && header != HOST && header != "content-length",
                "credential cannot rewrite HTTP routing or framing"
            );
            ensure!(
                headers.get_all(header).iter().count() == 1,
                "duplicate credential header"
            );
            let mut unresolved = value.to_str()?.to_owned();
            for binding in &self.bindings {
                if binding.permits_header(host) {
                    unresolved = unresolved.replace(&binding.placeholder, "");
                }
            }
            ensure!(
                !unresolved.contains(PLACEHOLDER_PREFIX),
                "credential placeholder does not match this request"
            );
        }
        Ok(())
    }

    async fn substitute_credentials(
        &self,
        headers: &mut HeaderMap,
        destination: &EgressDestination,
    ) -> Result<()> {
        for (_, header_value) in headers.iter_mut() {
            if !contains_placeholder(header_value.as_bytes()) {
                continue;
            }
            let mut replacement = header_value.to_str()?.to_owned();
            for binding in &self.bindings {
                if !binding.permits_header(&destination.host)
                    || !replacement.contains(&binding.placeholder)
                {
                    continue;
                }
                let value = tokio::time::timeout(
                    IO_TIMEOUT,
                    self.resolver
                        .as_ref()
                        .context("credential resolver is unavailable")?
                        .resolve(&self.identity, &binding.config.name, destination),
                )
                .await?
                .map_err(|_| anyhow!("credential is unavailable or not authorized"))?;
                replacement = replacement.replace(&binding.placeholder, &value);
            }
            let mut value = HeaderValue::from_str(&replacement)
                .map_err(|_| anyhow!("credential cannot be used in an HTTP header"))?;
            value.set_sensitive(true);
            *header_value = value;
        }
        Ok(())
    }

    async fn client(&self, host: &str, port: u16) -> Result<reqwest::Client> {
        let upstream = self
            .upstream
            .resolve(host, port)
            .await
            .map_err(|_| anyhow!("upstream address resolution failed"))?;
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(IO_TIMEOUT)
            .resolve_to_addrs(host, &upstream.addresses);
        if let Some(certificate) = upstream.root_certificate {
            builder = builder.add_root_certificate(certificate);
        }
        Ok(builder.build()?)
    }
}

fn contains_placeholder(value: &[u8]) -> bool {
    value
        .windows(PLACEHOLDER_PREFIX.len())
        .any(|s| s == PLACEHOLDER_PREFIX.as_bytes())
}

async fn relay(
    mut request: Request<Incoming>,
    mut headers: HeaderMap,
    url: reqwest::Url,
    client: reqwest::Client,
) -> Result<Response<ProxyBody>> {
    headers.remove(HOST);
    headers.remove("content-length");
    let method = request.method().clone();
    let body = tokio::time::timeout(
        IO_TIMEOUT,
        Limited::new(request.body_mut(), MAX_REQUEST_BODY).collect(),
    )
    .await?
    .map_err(|_| anyhow!("invalid or oversized request body"))?
    .to_bytes();
    let response = client
        .request(method, url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|_| anyhow!("upstream request failed"))?;
    let status = response.status();
    let mut headers = response.headers().clone();
    strip_hop_headers(&mut headers)?;
    let stream = response
        .bytes_stream()
        .map_ok(Frame::data)
        .map_err(|_| -> ProxyError { "upstream response failed".into() });
    let mut result = Response::new(BodyExt::boxed(StreamBody::new(stream)));
    *result.status_mut() = status;
    *result.headers_mut() = headers;
    Ok(result)
}

fn public_ipv4(ip: IpAddr) -> bool {
    let IpAddr::V4(ip) = ip else {
        return false;
    };
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && c <= 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113))
}

fn hop_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn strip_hop_headers(headers: &mut HeaderMap) -> Result<()> {
    let mut remove = Vec::new();
    for value in headers.get_all(CONNECTION) {
        for name in value.to_str()?.split(',') {
            remove.push(HeaderName::from_bytes(name.trim().as_bytes())?);
        }
    }
    remove.extend(headers.keys().filter(|name| hop_header(name)).cloned());
    for name in remove {
        headers.remove(name);
    }
    Ok(())
}

fn tls_configuration(hosts: Vec<String>) -> Result<(String, TlsAcceptor)> {
    let mut ca = CertificateParams::new(Vec::<String>::new())?;
    ca.distinguished_name
        .push(DnType::CommonName, "Exo sandbox egress CA");
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    let key = KeyPair::generate()?;
    let certificate = ca.self_signed(&key)?;
    let issuer = Issuer::new(ca, key);
    let leaf_key = KeyPair::generate()?;
    let mut leaf = CertificateParams::new(hosts)?;
    leaf.distinguished_name
        .push(DnType::CommonName, "Exo sandbox egress");
    leaf.use_authority_key_identifier_extension = true;
    let leaf = leaf.signed_by(&leaf_key, &issuer)?;
    let mut tls =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
            )?;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok((certificate.pem(), TlsAcceptor::from(Arc::new(tls))))
}

async fn http_connection<T>(stream: T, state: Arc<State>, sni: Option<String>) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let service = service_fn(move |request| {
        let state = state.clone();
        let sni = sni.clone();
        async move {
            let response = match state.forward(request, sni.as_deref()).await {
                Ok(response) => response,
                Err(error) => {
                    tracing::debug!(%error, sandbox_id = %state.identity.sandbox_id, "egress request failed");
                    let body = Full::new(Bytes::from_static(
                        b"egress request denied or upstream unavailable\n",
                    ))
                    .map_err(|never| -> ProxyError { match never {} })
                    .boxed();
                    let mut response = Response::new(body);
                    *response.status_mut() = StatusCode::BAD_GATEWAY;
                    response
                }
            };
            Ok::<_, Infallible>(response)
        }
    });
    hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(IO_TIMEOUT)
        .max_buf_size(HTTP_BUFFER_SIZE)
        .serve_connection(TokioIo::new(stream), service)
        .await?;
    Ok(())
}

async fn serve(
    transport: Arc<dyn EgressTransport>,
    tls: TlsAcceptor,
    state: Arc<State>,
    cancel: CancellationToken,
) {
    let mut tasks = JoinSet::new();
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if !matches!(result, Ok(Ok(()))) {
                    tracing::debug!("egress connection closed with an error");
                }
            }
            incoming = transport.accept(false) => {
                let Ok(stream) = incoming else { break; };
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                let state = state.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    http_connection(stream, state, None).await
                });
            }
            incoming = transport.accept(true) => {
                let Ok(stream) = incoming else { break; };
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                let state = state.clone();
                let tls = tls.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let stream = tokio::time::timeout(IO_TIMEOUT, tls.accept(stream)).await??;
                    let sni = stream.get_ref().1.server_name().context("TLS SNI is required")?.to_owned();
                    http_connection(stream, state, Some(sni)).await
                });
            }
        }
    }
    cancel.cancel();
    transport.close();
    tasks.shutdown().await;
}

#[cfg(test)]
mod tests;
