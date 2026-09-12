use super::transport::dns_response;
use super::*;
use crate::CredentialInjectionLocation;
use anyhow::bail;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

#[derive(Clone)]
pub(super) struct TestUpstream {
    pub address: SocketAddr,
    pub ca_pem: String,
}

struct TestResolver {
    value: RwLock<Option<String>>,
    uses: RwLock<Vec<(String, String, String)>>,
}

impl TestResolver {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            value: RwLock::new(Some("canary-v1".to_string())),
            uses: RwLock::new(Vec::new()),
        })
    }
}

#[async_trait]
impl EgressCredentialResolver for TestResolver {
    async fn resolve(
        &self,
        identity: &EgressIdentity,
        binding_name: &str,
        destination: &EgressDestination,
    ) -> Result<String> {
        ensure!(
            binding_name == "test-credential" && destination.port == 443,
            "wrong credential use"
        );
        self.uses.write().await.push((
            identity.sandbox_id.clone(),
            match &identity.scope {
                Some(crate::SandboxScope::Thread { thread_id }) => thread_id.clone(),
                _ => bail!("expected thread identity"),
            },
            destination.host.clone(),
        ));
        self.value
            .read()
            .await
            .clone()
            .context("credential removed")
    }
}

struct Upstream {
    config: TestUpstream,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Upstream {
    async fn start() -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let (ca_pem, tls) = tls_configuration(vec!["api.test".into(), "public.test".into()])?;
        let config = TestUpstream {
            address: listener.local_addr()?,
            ca_pem,
        };
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    incoming = listener.accept() => {
                        let Ok((stream, _)) = incoming else { break; };
                        let tls = tls.clone();
                        connections.spawn(async move {
                            let stream = tls.accept(stream).await?;
                            let service = service_fn(|request: Request<Incoming>| async move {
                                let authorization = request.headers().get("authorization")
                                    .or_else(|| request.headers().get("x-api-key"))
                                    .and_then(|h| h.to_str().ok());
                                let message = match authorization {
                                    Some("Bearer canary-v1") => "authenticated-v1",
                                    Some("canary-v1") => "raw-v1",
                                    Some("Token canary-v1; scope=read") => "token-v1",
                                    Some("Bearer canary-v2") => "authenticated-v2",
                                    None => "anonymous",
                                    _ => "bad-auth",
                                };
                                let mut response = Response::new(Full::new(Bytes::from_static(message.as_bytes())));
                                if request.uri().path() == "/redirect" {
                                    *response.status_mut() = StatusCode::FOUND;
                                    response.headers_mut().insert("location", HeaderValue::from_static("https://public.test/auth"));
                                }
                                Ok::<_, Infallible>(response)
                            });
                            hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service).await?;
                            Ok::<_, anyhow::Error>(())
                        });
                    }
                    Some(result) = connections.join_next(), if !connections.is_empty() => {
                        if !matches!(result, Ok(Ok(()))) { eprintln!("test upstream connection closed"); }
                    }
                }
            }
        });
        Ok(Self { config, task })
    }

    async fn proxy(
        &self,
        host_ip: Ipv4Addr,
        sandbox_id: &str,
        resolver: Arc<dyn EgressCredentialResolver>,
    ) -> Result<EgressProxy> {
        self.proxy_with_policy(host_ip, sandbox_id, resolver, policy())
            .await
    }

    async fn proxy_with_policy(
        &self,
        host_ip: Ipv4Addr,
        sandbox_id: &str,
        resolver: Arc<dyn EgressCredentialResolver>,
        policy: EgressPolicy,
    ) -> Result<EgressProxy> {
        let mut state = State::new(identity(sandbox_id), policy, resolver)?;
        state.upstream = Some(TestUpstream {
            address: self.config.address,
            ca_pem: self.config.ca_pem.clone(),
        });
        EgressProxy::start(host_ip, state).await
    }
}

struct ThreadResolver {
    credentials: HashMap<String, Vec<(EgressCredentialBinding, String)>>,
}

impl ThreadResolver {
    fn for_identity(
        &self,
        identity: &EgressIdentity,
    ) -> Result<&[(EgressCredentialBinding, String)]> {
        let Some(crate::SandboxScope::Thread { thread_id }) = &identity.scope else {
            bail!("thread scope is required");
        };
        self.credentials
            .get(thread_id)
            .map(Vec::as_slice)
            .context("thread is not authorized")
    }
}

#[async_trait]
impl EgressCredentialResolver for ThreadResolver {
    async fn resolve(
        &self,
        identity: &EgressIdentity,
        binding_name: &str,
        _destination: &EgressDestination,
    ) -> Result<String> {
        self.for_identity(identity)?
            .iter()
            .find(|(binding, _)| binding.name == binding_name)
            .map(|(_, value)| value.clone())
            .context("binding is not selected for this thread")
    }
}

#[tokio::test]
async fn threads_select_different_bindings_and_resolve_the_same_name_independently() -> Result<()> {
    let binding = policy().credentials.remove(0);
    let extra = EgressCredentialBinding {
        name: "extra".into(),
        environment_variable: "EXTRA_API_KEY".into(),
        ..binding.clone()
    };
    let resolver = Arc::new(ThreadResolver {
        credentials: HashMap::from([
            (
                "thread-one".into(),
                vec![(binding.clone(), "canary-v1".into())],
            ),
            (
                "thread-two".into(),
                vec![(binding, "canary-v2".into()), (extra, "canary-v1".into())],
            ),
            ("thread-empty".into(), vec![]),
        ]),
    });
    let upstream = Upstream::start().await?;
    for (id, expected) in [("one", "authenticated-v1"), ("two", "authenticated-v2")] {
        let mut policy = policy();
        policy.credentials = resolver
            .for_identity(&identity(id))?
            .iter()
            .map(|(binding, _)| binding.clone())
            .collect();
        let proxy = upstream
            .proxy_with_policy(host_ip()?, id, resolver.clone(), policy)
            .await?;
        proxy.bind_source(host_ip()?).await?;
        assert_eq!(
            proxy.environment().contains_key("EXTRA_API_KEY"),
            id == "two"
        );
        let client = client(&proxy)?;
        assert_eq!(
            client
                .get("https://api.test/auth")
                .header(
                    "authorization",
                    format!("Bearer {}", proxy.environment()["TEST_API_KEY"])
                )
                .send()
                .await?
                .text()
                .await?,
            expected
        );
        if id == "two" {
            assert_eq!(
                client
                    .get("https://api.test/auth")
                    .header("x-api-key", &proxy.environment()["EXTRA_API_KEY"])
                    .send()
                    .await?
                    .text()
                    .await?,
                "raw-v1"
            );
        }
        proxy.shutdown().await?;
    }
    let mut empty_policy = policy();
    empty_policy.credentials.clear();
    let empty = upstream
        .proxy_with_policy(host_ip()?, "empty", resolver.clone(), empty_policy)
        .await?;
    assert!(empty.environment().is_empty());
    empty.shutdown().await?;
    let unauthorized = upstream.proxy(host_ip()?, "unknown", resolver).await?;
    unauthorized.bind_source(host_ip()?).await?;
    assert_eq!(
        client(&unauthorized)?
            .get("https://api.test/auth")
            .header(
                "authorization",
                format!("Bearer {}", unauthorized.environment()["TEST_API_KEY"])
            )
            .send()
            .await?
            .status(),
        StatusCode::BAD_GATEWAY
    );
    unauthorized.shutdown().await?;
    Ok(())
}

fn identity(sandbox_id: &str) -> EgressIdentity {
    EgressIdentity {
        sandbox_id: sandbox_id.into(),
        scope: Some(crate::SandboxScope::Thread {
            thread_id: format!("thread-{sandbox_id}"),
        }),
    }
}

fn policy() -> EgressPolicy {
    EgressPolicy {
        networking: SandboxNetworkPolicy::Limited {
            allowed_hosts: vec!["api.test".into(), "public.test".into()],
        },
        credentials: vec![EgressCredentialBinding {
            name: "test-credential".into(),
            environment_variable: "TEST_API_KEY".into(),
            networking: CredentialNetworkPolicy::Limited {
                allowed_hosts: vec!["api.test".into()],
            },
            injection_location: CredentialInjectionLocation {
                header: true,
                body: false,
            },
        }],
    }
}

fn host_ip() -> Result<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect((Ipv4Addr::new(192, 0, 2, 1), 80))?;
    match socket.local_addr()?.ip() {
        IpAddr::V4(ip) => Ok(ip),
        _ => Err(anyhow!("test requires a local IPv4 address")),
    }
}

fn client(proxy: &EgressProxy) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .add_root_certificate(reqwest::Certificate::from_pem(proxy.ca_pem().as_bytes())?)
        .resolve("api.test", proxy.endpoints().https.into())
        .resolve("public.test", proxy.endpoints().https.into())
        .timeout(Duration::from_secs(10))
        .build()?)
}

#[tokio::test]
async fn proxy_authenticates_rotates_revokes_and_isolates() -> Result<()> {
    let upstream = Upstream::start().await?;
    let resolver = TestResolver::new();
    let proxy = upstream.proxy(host_ip()?, "one", resolver.clone()).await?;
    let unbound_client = client(&proxy)?;
    assert!(
        unbound_client
            .get("https://api.test/auth")
            .send()
            .await
            .is_err()
    );
    proxy.bind_source(host_ip()?).await?;
    assert!(proxy.bind_source(host_ip()?).await.is_err());
    let client = client(&proxy)?;
    let bearer = format!("Bearer {}", proxy.environment()["TEST_API_KEY"]);
    let response = client
        .get("https://api.test/auth")
        .header("authorization", &bearer)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().await?, "authenticated-v1");
    assert_eq!(
        client
            .get("https://api.test/auth")
            .header("x-api-key", &proxy.environment()["TEST_API_KEY"])
            .send()
            .await?
            .text()
            .await?,
        "raw-v1"
    );
    for header in ["connection", "proxy-authorization"] {
        assert!(
            client
                .get("https://api.test/auth")
                .header(header, &bearer)
                .send()
                .await?
                .status()
                .is_server_error()
        );
    }
    assert_eq!(
        client
            .get("https://api.test/auth")
            .header("authorization", &proxy.environment()["TEST_API_KEY"])
            .send()
            .await?
            .text()
            .await?,
        "raw-v1"
    );
    assert_eq!(
        client
            .get("https://api.test/auth")
            .header(
                "authorization",
                format!("Token {}; scope=read", proxy.environment()["TEST_API_KEY"])
            )
            .send()
            .await?
            .text()
            .await?,
        "token-v1"
    );

    assert_eq!(
        client
            .get("https://public.test/auth")
            .send()
            .await?
            .text()
            .await?,
        "anonymous"
    );
    *resolver.value.write().await = Some("canary-v2".into());
    assert_eq!(
        client
            .get("https://api.test/auth")
            .header("authorization", &bearer)
            .send()
            .await?
            .text()
            .await?,
        "authenticated-v2"
    );
    let cleartext = reqwest::Client::builder()
        .no_proxy()
        .resolve("api.test", proxy.endpoints().http.into())
        .timeout(Duration::from_secs(5))
        .build()?;
    assert!(
        cleartext
            .get("http://api.test/auth")
            .header("authorization", &bearer)
            .send()
            .await?
            .status()
            .is_server_error()
    );
    assert!(
        client
            .get("https://public.test/auth")
            .header("authorization", &bearer)
            .send()
            .await?
            .status()
            .is_server_error()
    );
    assert!(
        client
            .get("https://api.test/auth")
            .header(HOST, "public.test")
            .header("authorization", &bearer)
            .send()
            .await?
            .status()
            .is_server_error()
    );
    let redirect = client
        .get("https://api.test/redirect")
        .header("authorization", &bearer)
        .send()
        .await?;
    assert_eq!(redirect.status(), StatusCode::FOUND);
    let other = upstream.proxy(host_ip()?, "two", resolver.clone()).await?;
    other.bind_source(host_ip()?).await?;
    assert!(
        self::client(&other)?
            .get("https://api.test/auth")
            .header("authorization", &bearer)
            .send()
            .await?
            .status()
            .is_server_error()
    );
    *resolver.value.write().await = None;
    assert!(
        client
            .get("https://api.test/auth")
            .header("authorization", &bearer)
            .send()
            .await?
            .status()
            .is_server_error()
    );
    assert!(
        resolver
            .uses
            .read()
            .await
            .iter()
            .all(|(sandbox, thread, host)| sandbox == "one"
                && thread == "thread-one"
                && host == "api.test")
    );
    proxy.shutdown().await?;
    assert!(client.get("https://api.test/auth").send().await.is_err());
    other.shutdown().await?;
    Ok(())
}

#[test]
fn rejects_unsafe_policy_and_addresses() {
    for host in [
        "*",
        "*.example.com",
        "127.0.0.1",
        "::1",
        "example.com:443",
        "example.com/",
        "a..com",
        "-a.com",
        "example.com.",
    ] {
        assert!(canonical_host(host).is_err(), "{host}");
    }
    for ip in [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "100.100.100.200",
        "192.168.5.15",
        "198.19.0.1",
        "224.0.0.1",
        "::1",
        "::ffff:8.8.8.8",
        "2001:4860:4860::8888",
    ] {
        assert!(!public_ipv4(ip.parse().unwrap()), "{ip}");
    }
    assert!(public_ipv4("8.8.8.8".parse().unwrap()));
    let mut config = policy();
    config.credentials[0].networking = CredentialNetworkPolicy::Limited {
        allowed_hosts: vec!["blocked.test".into()],
    };
    let state = State::new(identity("one"), config, TestResolver::new()).unwrap();
    assert!(!state.hosts.contains("blocked.test"));
    assert!(!state.bindings[0].permits_header("api.test"));
}

#[test]
fn credential_networking_is_independent_of_environment_networking() -> Result<()> {
    let mut config = policy();
    config.credentials[0].networking = CredentialNetworkPolicy::Unrestricted;
    let state = State::new(identity("one"), config.clone(), TestResolver::new())?;
    assert!(state.hosts.contains("public.test"));
    assert!(!state.hosts.contains("blocked.test"));
    assert!(state.bindings[0].permits_header("public.test"));
    config.credentials[0].injection_location.header = false;
    let state = State::new(identity("one"), config.clone(), TestResolver::new())?;
    assert!(!state.bindings[0].permits_header("api.test"));
    config.credentials[0].injection_location.body = true;
    assert!(State::new(identity("one"), config, TestResolver::new()).is_err());
    let mut config = policy();
    config.networking = SandboxNetworkPolicy::Unrestricted;
    assert!(State::new(identity("one"), config, TestResolver::new()).is_err());
    Ok(())
}

#[test]
fn dns_only_answers_exact_allowed_names() -> Result<()> {
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;
    let state = State::new(identity("one"), policy(), TestResolver::new())?;
    for (host, kind, allowed) in [
        ("api.test", RecordType::A, true),
        ("api.test", RecordType::AAAA, true),
        ("api.test", RecordType::TXT, false),
        ("leak.api.test", RecordType::A, false),
        ("blocked.test", RecordType::A, false),
    ] {
        let mut query = Message::new();
        query
            .set_id(123)
            .add_query(Query::query(Name::from_ascii(host)?, kind));
        let response = Message::from_vec(&dns_response(&state.hosts, &query.to_vec()?)?)?;
        assert_eq!(response.id(), 123);
        assert_eq!(
            response.response_code(),
            if allowed {
                ResponseCode::NoError
            } else {
                ResponseCode::Refused
            }
        );
        assert_eq!(
            response.answers().len(),
            usize::from(allowed && kind == RecordType::A)
        );
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "firecracker"))]
async fn guest(
    handle: &Arc<dyn crate::ManagedSandboxHandle>,
    proxy: &EgressProxy,
    script: &str,
) -> Result<String> {
    let mut env = proxy.environment().clone();
    env.insert("EGRESS_CA".into(), proxy.ca_pem().into());
    let output = handle
        .exec(&crate::SandboxCommand {
            argv: vec!["python3".into(), "-c".into(), script.into()],
            env,
            display_argv: None,
            cwd: None,
            timeout: Some(Duration::from_secs(45)),
        })
        .await?;
    ensure!(
        output.ok,
        "guest check failed: {} {}",
        output.stdout,
        output.stderr
    );
    Ok(output.stdout)
}

#[cfg(all(target_os = "linux", feature = "firecracker"))]
#[tokio::test]
#[ignore = "requires root, Linux/KVM, and the Exo Firecracker artifact bundle"]
async fn firecracker_transparent_egress_live() -> Result<()> {
    use crate::{
        FirecrackerConfig, FirecrackerSandboxBackend, ManagedSandboxBackend,
        SandboxLifecycleConfig, SandboxRequest, SandboxResourceShape, SandboxSpec,
    };
    let state_root = tempfile::Builder::new()
        .prefix("eg-")
        .tempdir_in("/var/lib/exo")?;
    let config = FirecrackerConfig {
        state_root: state_root.path().join("state"),
        allowed_egress_cidrs: vec!["0.0.0.0/0".parse()?],
        ..Default::default()
    };
    let backend = FirecrackerSandboxBackend::new(config).await?;
    let upstream = Upstream::start().await?;
    let resolver = TestResolver::new();
    let proxy = upstream
        .proxy(host_ip()?, "live-one", resolver.clone())
        .await?;
    let other = upstream
        .proxy(host_ip()?, "live-two", resolver.clone())
        .await?;
    let request = |id: &str| SandboxRequest {
        sandbox_id: id.into(),
        scope: None,
        provider_state: None,
        spec: SandboxSpec {
            image: crate::default_firecracker_image(),
            resources: SandboxResourceShape::new(1, 512).unwrap(),
            mounts: vec![],
            durable_file_systems: vec![],
            policy: policy(),
            default_workdir: "/home/exo/workspace".into(),
        },
        lifecycle: SandboxLifecycleConfig {
            idle_ttl: Some(Duration::from_secs(300)),
        },
    };
    let one_request = request("egress-live-one");
    let two_request = request("egress-live-two");
    let result: Result<()> = async {
        let (one, one_source) = backend.acquire_egress(one_request.clone(), proxy.endpoints()).await?;
        let (two, two_source) = backend.acquire_egress(two_request.clone(), other.endpoints()).await?;
        proxy.bind_source(one_source).await?;
        other.bind_source(two_source).await?;
        let setup = r#"
import os, ssl, urllib.request, urllib.error, socket
assert os.environ['TEST_API_KEY'].startswith('exo_egress_')
assert 'canary-v1' not in str(os.environ)
assert 'canary-v2' not in str(os.environ)
ctx = ssl.create_default_context(cadata=os.environ['EGRESS_CA'])
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
def get(host='api.test', token=True, header_host=None):
    headers = {'Authorization': 'Bearer ' + os.environ['TEST_API_KEY']} if token else {}
    if header_host: headers['Host'] = header_host
    try:
        with opener.open(urllib.request.Request('https://' + host + '/auth', headers=headers), timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
"#;
        let checks = format!("{setup}\n{}", r#"
assert get() == (200, 'authenticated-v1')
import subprocess, tempfile
with tempfile.NamedTemporaryFile(mode='w') as ca:
    ca.write(os.environ['EGRESS_CA'])
    ca.flush()
    result = subprocess.run(['curl', '--noproxy', '*', '--cacert', ca.name, '--max-time', '5', '-sS', '-H', 'Authorization: Bearer ' + os.environ['TEST_API_KEY'], 'https://api.test/auth'], check=True, capture_output=True, text=True)
    assert result.stdout == 'authenticated-v1'
assert get('public.test', False) == (200, 'anonymous')
assert get('public.test')[0] == 502
assert get(header_host='public.test')[0] == 502
try:
    socket.getaddrinfo('blocked.test', 443)
    raise AssertionError('blocked DNS resolved')
except socket.gaierror:
    pass
for address in [('1.1.1.1', 22), ('169.254.169.254', 22)]:
    try:
        socket.create_connection(address, timeout=2)
        raise AssertionError('direct egress succeeded')
    except OSError:
        pass
try:
    opener.open('https://1.1.1.1/', timeout=3)
    raise AssertionError('direct IP HTTPS succeeded')
except (urllib.error.URLError, OSError):
    pass
print('PASS transparent Python and curl HTTPS, anonymous host, wrong host/SNI, DNS, direct TCP/IP, no real credentials in guest')
"#);
        println!("{}", guest(&one, &proxy, &checks).await?);
        *resolver.value.write().await = Some("canary-v2".into());
        println!("{}", guest(&one, &proxy, &format!("{setup}\nassert get() == (200, 'authenticated-v2')\nprint('PASS rotation')")).await?);
        let stolen = proxy.environment()["TEST_API_KEY"].clone();
        let script = format!("{setup}\nos.environ['TEST_API_KEY'] = '{stolen}'\nassert get()[0] == 502\nprint('PASS cross-sandbox placeholder isolation')");
        println!("{}", guest(&two, &other, &script).await?);
        let attack = format!("{setup}\nimport socket\ntry:\n socket.create_connection(('{host}', {port}), timeout=2)\n raise AssertionError('another sandbox proxy is reachable')\nexcept OSError:\n pass\nprint('PASS cross-sandbox listener isolation')", host=proxy.endpoints().https.ip(), port=proxy.endpoints().https.port());
        println!("{}", guest(&two, &other, &attack).await?);
        *resolver.value.write().await = None;
        println!("{}", guest(&one, &proxy, &format!("{setup}\nassert get()[0] == 502\nprint('PASS removal')")).await?);
        proxy.cancel.cancel();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let stopped = format!("{setup}\ntry:\n get()\n raise AssertionError('stopped proxy still permits requests')\nexcept (urllib.error.URLError, OSError):\n pass\nprint('PASS proxy failure blocks egress')");
        println!("{}", guest(&one, &proxy, &stopped).await?);
        Ok(())
    }.await;
    let one_cleanup = backend.terminate(one_request).await;
    let two_cleanup = backend.terminate(two_request).await;
    proxy.shutdown().await?;
    other.shutdown().await?;
    one_cleanup?;
    two_cleanup?;
    result
}

#[cfg(all(any(target_os = "linux", target_os = "macos"), feature = "firecracker"))]
#[tokio::test]
#[ignore = "requires Firecracker artifacts; macOS also requires EXO_EGRESS_BRIDGE_BINARY in Lima"]
async fn managed_firecracker_egress_live() -> Result<()> {
    use crate::{
        ManagedSandboxBackend, SandboxCommand, SandboxLifecycleConfig, SandboxRequest,
        SandboxResourceShape, SandboxScope, SandboxSpec,
    };
    let mut config = crate::FirecrackerConfig::default();
    let state_root = format!(
        "/var/lib/exo/eg-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    config.state_root = (&state_root).into();
    config.allowed_egress_cidrs = vec!["0.0.0.0/0".parse()?];
    let lima = crate::FirecrackerLimaConfig::default();
    #[cfg(target_os = "macos")]
    let lima = crate::FirecrackerLimaConfig {
        instance: std::env::var("EXO_FIRECRACKER_LIMA_INSTANCE").unwrap_or(lima.instance),
        bridge_binary: Some(
            std::env::var("EXO_EGRESS_BRIDGE_BINARY")
                .context("set EXO_EGRESS_BRIDGE_BINARY to the isolated Linux bridge binary")?
                .into(),
        ),
        ..lima
    };
    #[cfg(target_os = "macos")]
    let instance = lima.instance.clone();
    let raw = crate::firecracker_egress_provider(config, lima).await?;
    let upstream = Upstream::start().await?;
    let resolver = TestResolver::new();
    let make_backend = || {
        let mut backend = FirecrackerEgressBackend::new(raw.clone(), Some(resolver.clone()));
        backend.upstream = Some(upstream.config.clone());
        backend
    };
    let backend = make_backend();
    let request = SandboxRequest {
        sandbox_id: "managed-egress-live".into(),
        scope: Some(SandboxScope::Thread {
            thread_id: "managed-live".into(),
        }),
        provider_state: None,
        spec: SandboxSpec {
            image: crate::default_firecracker_image(),
            resources: SandboxResourceShape::new(1, 512).unwrap(),
            mounts: vec![],
            durable_file_systems: vec![],
            policy: policy(),
            default_workdir: "/home/exo/workspace".into(),
        },
        lifecycle: SandboxLifecycleConfig {
            idle_ttl: Some(Duration::from_secs(300)),
        },
    };
    let command = |script: String| SandboxCommand {
        argv: vec!["python3".into(), "-c".into(), script],
        env: HashMap::from([("TEST_API_KEY".into(), "must-be-overridden".into())]),
        display_argv: None,
        cwd: None,
        timeout: Some(Duration::from_secs(30)),
    };
    let setup = r#"
import os, ssl, urllib.request, urllib.error, socket, pathlib, subprocess
assert os.environ['TEST_API_KEY'].startswith('exo_egress_')
assert 'canary-v1' not in str(os.environ)
assert 'canary-v2' not in str(os.environ)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def get(token=None):
    headers = {'Authorization': 'Bearer ' + (token or os.environ['TEST_API_KEY'])}
    try:
        with opener.open(urllib.request.Request('https://api.test/auth', headers=headers), timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
"#;
    let run = |extra: &str| command(format!("{setup}\n{extra}"));
    let result: Result<()> = async {
        let handle = backend.acquire(request.clone()).await?;
        let id = handle.id().to_owned();
        let check = handle.exec(&run(r#"
assert get() == (200, 'authenticated-v1')
result = subprocess.run(['curl', '--noproxy', '*', '--max-time', '5', '-sS', '-H', 'Authorization: Bearer ' + os.environ['TEST_API_KEY'], 'https://api.test/auth'], capture_output=True, text=True, check=True)
assert result.stdout == 'authenticated-v1'
pathlib.Path('egress-retained').write_text('keep this')
pathlib.Path('old-placeholder').write_text(os.environ['TEST_API_KEY'])
try:
    socket.getaddrinfo('blocked.test', 443)
    raise AssertionError('blocked DNS resolved')
except socket.gaierror:
    pass
try:
    socket.create_connection(('1.1.1.1', 22), timeout=2)
    raise AssertionError('direct egress succeeded')
except OSError:
    pass
print('PASS automatic placeholders, Python and curl trust, native transport, DNS and direct egress denial')
"#)).await?;
        ensure!(check.ok, "managed check failed: {}", check.stderr);
        println!("{}", check.stdout);
        *resolver.value.write().await = Some("canary-v2".into());
        let check = handle.exec(&run("assert get() == (200, 'authenticated-v2')\nprint('PASS rotation')")).await?;
        ensure!(check.ok, "rotation failed: {}", check.stderr);
        println!("{}", check.stdout);
        let reused = backend.acquire(request.clone()).await?;
        assert_eq!(reused.id(), id);
        let old_ca = handle.exec(&command("import os; print(os.environ['SSL_CERT_FILE'])".into())).await?.stdout;
        backend.shutdown().await;
        let replacement = make_backend();
        let new_handle = replacement.acquire(request.clone()).await?;
        assert_eq!(new_handle.id(), id);
        let check = new_handle.exec(&run(r#"
assert pathlib.Path('egress-retained').read_text() == 'keep this'
assert get() == (200, 'authenticated-v2')
assert get(pathlib.Path('old-placeholder').read_text())[0] == 502
print('PASS reconnect retains VM files and rejects the previous placeholder')
"#)).await?;
        ensure!(check.ok, "reconnect failed: {}", check.stderr);
        println!("{}", check.stdout);
        let new_ca = new_handle.exec(&command("import os; print(os.environ['SSL_CERT_FILE'])".into())).await?.stdout;
        assert_ne!(new_ca, old_ca);
        use tokio_util::compat::FuturesAsyncReadCompatExt;
        let process = new_handle.start_process(&run("assert get() == (200, 'authenticated-v2')\nprint('PASS managed process environment')")).await?;
        let mut stdout = process.stdout.compat();
        let mut stderr = process.stderr.compat();
        let mut out = String::new();
        let mut err = String::new();
        let (exit, stdout_result, stderr_result) = tokio::join!(process.wait, tokio::io::AsyncReadExt::read_to_string(&mut stdout, &mut out), tokio::io::AsyncReadExt::read_to_string(&mut stderr, &mut err));
        let exit = exit?; stdout_result?; stderr_result?;
        ensure!(exit == 0, "managed process failed: {err}");
        println!("{out}");
        *resolver.value.write().await = None;
        let check = new_handle.exec(&run("assert get()[0] == 502\nprint('PASS revocation')")).await?;
        ensure!(check.ok, "revocation failed: {}", check.stderr);
        println!("{}", check.stdout);
        replacement.terminate(request.clone()).await?;
        Ok(())
    }.await;
    let cleanup = backend.terminate(request).await;
    cleanup?;
    #[cfg(target_os = "linux")]
    tokio::fs::remove_dir_all(&state_root).await?;
    #[cfg(target_os = "macos")]
    {
        let status = tokio::process::Command::new("limactl")
            .args([
                "shell",
                &instance,
                "--",
                "sudo",
                "-n",
                "rm",
                "-rf",
                &state_root,
            ])
            .status()
            .await?;
        ensure!(status.success(), "test state cleanup failed: {state_root}");
    }
    result
}

#[tokio::test]
async fn configured_listener_advertises_a_separate_address_and_binds_source() {
    use super::transport::{EgressTransport, LocalEgressTransport};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let advertised_address = Ipv4Addr::new(192, 0, 2, 2);
    let transport = LocalEgressTransport::with_config(
        crate::EgressListenConfig {
            bind_address: Ipv4Addr::LOCALHOST,
            advertised_address,
            http_port: 0,
            https_port: 0,
            dns_port: 0,
        },
        &["api.example.com".into()],
    )
    .await
    .unwrap();
    let endpoints = transport.endpoints();
    for endpoint in [endpoints.http, endpoints.https, endpoints.dns] {
        assert_eq!(*endpoint.ip(), advertised_address);
        assert_ne!(endpoint.port(), 0);
    }
    transport.bind_source(Ipv4Addr::LOCALHOST).await.unwrap();
    assert!(transport.bind_source(Ipv4Addr::LOCALHOST).await.is_err());
    let mut client = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, endpoints.https.port()))
        .await
        .unwrap();
    let mut stream = transport.accept(true).await.unwrap();
    client.write_all(b"request").await.unwrap();
    let mut buffer = [0; 7];
    stream.read_exact(&mut buffer).await.unwrap();
    assert_eq!(&buffer, b"request");
    transport.close();
    assert!(transport.accept(true).await.is_err());
}
