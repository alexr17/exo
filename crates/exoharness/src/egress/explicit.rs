use super::*;
use base64::Engine;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

pub struct ExplicitProxy {
    pub environment: HashMap<String, String>,
    pub ca_pem: String,
    pub ca_path: String,
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl ExplicitProxy {
    pub async fn start(
        identity: EgressIdentity,
        policy: EgressPolicy,
        resolver: Option<Arc<dyn EgressCredentialResolver>>,
        listener: TcpListener,
        advertised_host: &str,
    ) -> Result<Self> {
        let state = State::new(identity, policy, resolver, Arc::new(PublicUpstreamResolver))?;
        Self::with_listener(state, listener, advertised_host).await
    }

    pub(super) async fn with_listener(
        state: State,
        listener: TcpListener,
        advertised_host: &str,
    ) -> Result<Self> {
        let password = uuid::Uuid::new_v4().simple().to_string();
        let authorization = HeaderValue::from_str(&format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("exo:{password}"))
        ))?;
        let proxy_url = format!(
            "http://exo:{password}@{advertised_host}:{}",
            listener.local_addr()?.port()
        );
        let (ca_pem, tls) = tls_configuration(state.hosts.iter().cloned().collect())?;
        let ca_path = format!("/tmp/exo-egress-{}.pem", uuid::Uuid::new_v4().simple());
        let mut environment: HashMap<_, _> = state
            .bindings
            .iter()
            .map(|binding| {
                (
                    binding.config.environment_variable.clone(),
                    binding.placeholder.clone(),
                )
            })
            .collect();
        for variable in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            environment.insert(variable.into(), proxy_url.clone());
        }
        for variable in ["NO_PROXY", "no_proxy"] {
            environment.insert(variable.into(), "localhost,127.0.0.1,::1".into());
        }
        environment.insert("NODE_USE_ENV_PROXY".into(), "1".into());
        for variable in [
            "SSL_CERT_FILE",
            "CODEX_CA_CERTIFICATE",
            "REQUESTS_CA_BUNDLE",
            "NODE_EXTRA_CA_CERTS",
            "CURL_CA_BUNDLE",
            "GIT_SSL_CAINFO",
        ] {
            environment.insert(variable.into(), ca_path.clone());
        }
        let cancel = CancellationToken::new();
        let task = tokio::spawn(serve_explicit(
            listener,
            Arc::new(state),
            tls,
            authorization,
            cancel.clone(),
        ));
        Ok(Self {
            environment,
            ca_pem,
            ca_path,
            cancel,
            task,
        })
    }

    pub fn command(&self, command: &crate::SandboxCommand) -> Result<crate::SandboxCommand> {
        ensure!(
            !self.is_closed(),
            "sandbox credential proxy is closed; acquire the sandbox again"
        );
        let mut command = command.clone();
        command.env.extend(self.environment.clone());
        Ok(command)
    }

    pub fn is_closed(&self) -> bool {
        self.cancel.is_cancelled()
    }

    pub fn close(&self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

impl Drop for ExplicitProxy {
    fn drop(&mut self) {
        self.close();
    }
}

async fn serve_explicit(
    listener: TcpListener,
    state: Arc<State>,
    tls: TlsAcceptor,
    authorization: HeaderValue,
    cancel: CancellationToken,
) {
    let mut tasks = JoinSet::new();
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if !matches!(result, Ok(Ok(()))) {
                    tracing::debug!("explicit egress connection closed with an error");
                }
            }
            incoming = listener.accept() => {
                let (stream, _) = match incoming {
                    Ok(incoming) => incoming,
                    Err(error) => {
                        tracing::debug!(%error, "explicit egress accept failed; retrying");
                        if !super::transport::retry_after_error(&cancel).await {
                            break;
                        }
                        continue;
                    }
                };
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                tasks.spawn(explicit_connection(stream, state.clone(), tls.clone(), authorization.clone(), cancel.clone(), Arc::new(permit)));
            }
        }
    }
    cancel.cancel();
    tasks.shutdown().await;
}

fn error_response(status: StatusCode) -> Response<ProxyBody> {
    let body = Full::new(Bytes::from_static(
        b"sandbox proxy request denied or upstream unavailable\n",
    ))
    .map_err(|never| -> ProxyError { match never {} })
    .boxed();
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
}

async fn explicit_connection(
    stream: TcpStream,
    state: Arc<State>,
    tls: TlsAcceptor,
    authorization: HeaderValue,
    cancel: CancellationToken,
    permit: Arc<tokio::sync::OwnedSemaphorePermit>,
) -> Result<()> {
    let connection_cancel = cancel.clone();
    let service = service_fn(move |mut request: Request<Incoming>| {
        let state = state.clone();
        let tls = tls.clone();
        let cancel = cancel.clone();
        let permit = permit.clone();
        let authorized = request
            .headers()
            .get_all("proxy-authorization")
            .iter()
            .count()
            == 1
            && request.headers().get("proxy-authorization") == Some(&authorization);
        async move {
            if !authorized {
                let mut response = error_response(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
                response.headers_mut().insert(
                    "proxy-authenticate",
                    HeaderValue::from_static("Basic realm=\"Exo\""),
                );
                return Ok::<_, Infallible>(response);
            }
            let result = if request.method() == Method::CONNECT {
                connect(&mut request, state, tls, cancel, permit).await
            } else {
                forward_http(request, state).await
            };
            Ok(match result {
                Ok(response) => response,
                Err(error) => {
                    tracing::debug!(%error, "explicit egress request failed");
                    error_response(StatusCode::BAD_GATEWAY)
                }
            })
        }
    });
    tokio::select! {
        _ = connection_cancel.cancelled() => Ok(()),
        result = hyper::server::conn::http1::Builder::new()
            .timer(TokioTimer::new()).header_read_timeout(IO_TIMEOUT).max_buf_size(HTTP_BUFFER_SIZE)
            .serve_connection(TokioIo::new(stream), service).with_upgrades() => {
                result?;
                Ok(())
            }
    }
}

async fn forward_http(
    mut request: Request<Incoming>,
    state: Arc<State>,
) -> Result<Response<ProxyBody>> {
    ensure!(
        request.uri().scheme_str() == Some("http"),
        "proxy requires an HTTP URL"
    );
    let authority = request
        .uri()
        .authority()
        .context("missing request authority")?;
    ensure!(
        request.headers().get_all(HOST).iter().count() == 1
            && request
                .headers()
                .get(HOST)
                .context("missing Host")?
                .to_str()?
                == authority.as_str(),
        "URL and Host must match"
    );
    *request.uri_mut() = request
        .uri()
        .path_and_query()
        .context("missing path")?
        .as_str()
        .parse()?;
    state.forward(request, None).await
}

async fn connect(
    request: &mut Request<Incoming>,
    state: Arc<State>,
    tls: TlsAcceptor,
    cancel: CancellationToken,
    permit: Arc<tokio::sync::OwnedSemaphorePermit>,
) -> Result<Response<ProxyBody>> {
    let host = state.connect_host(
        request
            .uri()
            .authority()
            .context("CONNECT requires an authority")?
            .as_str(),
    )?;
    let intercept = state.hosts.contains(&host);
    let upstream = if intercept {
        None
    } else {
        let addresses = state.upstream.resolve(&host, 443).await?.addresses;
        Some(
            tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addresses.as_slice()))
                .await??,
        )
    };
    let upgrade = hyper::upgrade::on(request);
    tokio::spawn(async move {
        let _permit = permit;
        let result: Result<()> = tokio::select! {
            _ = cancel.cancelled() => Ok(()),
            result = async {
                let mut stream = TokioIo::new(tokio::time::timeout(IO_TIMEOUT, upgrade).await??);
                if let Some(mut upstream) = upstream {
                    tokio::io::copy_bidirectional(&mut stream, &mut upstream).await?;
                } else {
                    https_connection(stream, tls, state, Some(&host)).await?;
                }
                Ok(())
            } => result,
        };
        if let Err(error) = result {
            tracing::debug!(%error, "explicit egress tunnel closed");
        }
    });
    Ok(Response::new(
        Full::new(Bytes::new())
            .map_err(|never| -> ProxyError { match never {} })
            .boxed(),
    ))
}
