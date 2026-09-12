use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Result, anyhow, ensure};
use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, RData, Record, RecordType, rdata::A};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use super::{IO_TIMEOUT, canonical_host};
use crate::{BoxSandboxTcpStream, SandboxEgressProxy};

const SYNTHETIC_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

#[async_trait]
pub trait EgressTransport: Send + Sync {
    fn endpoints(&self) -> SandboxEgressProxy;
    async fn bind_source(&self, source_ip: Ipv4Addr) -> Result<()>;
    async fn accept(&self, tls: bool) -> Result<BoxSandboxTcpStream>;
    fn close(&self);
}

pub struct LocalEgressTransport {
    endpoints: SandboxEgressProxy,
    http: TcpListener,
    https: TcpListener,
    source: Arc<AtomicU32>,
    cancel: CancellationToken,
}

impl LocalEgressTransport {
    pub async fn for_hosts(hosts: &[String]) -> Result<Self> {
        let probe = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
        probe.connect((SYNTHETIC_IP, 9)).await?;
        let IpAddr::V4(host_ip) = probe.local_addr()?.ip() else {
            return Err(anyhow!("egress requires host IPv4 routing"));
        };
        let hosts = hosts
            .iter()
            .map(|h| canonical_host(h))
            .collect::<Result<HashSet<_>>>()?;
        ensure!(hosts.len() <= 128, "too many allowed hosts");
        Self::bind(host_ip, &hosts).await
    }

    pub async fn with_config(config: crate::EgressListenConfig, hosts: &[String]) -> Result<Self> {
        let hosts = hosts
            .iter()
            .map(|h| canonical_host(h))
            .collect::<Result<HashSet<_>>>()?;
        ensure!(hosts.len() <= 128, "too many allowed hosts");
        Self::listen(config, &hosts).await
    }

    pub(super) async fn bind(host_ip: Ipv4Addr, hosts: &HashSet<String>) -> Result<Self> {
        Self::listen(
            crate::EgressListenConfig {
                bind_address: host_ip,
                advertised_address: host_ip,
                http_port: 0,
                https_port: 0,
                dns_port: 0,
            },
            hosts,
        )
        .await
    }

    async fn listen(config: crate::EgressListenConfig, hosts: &HashSet<String>) -> Result<Self> {
        let host_ip = config.advertised_address;
        let http = TcpListener::bind((config.bind_address, config.http_port)).await?;
        let https = TcpListener::bind((config.bind_address, config.https_port)).await?;
        let dns = UdpSocket::bind((config.bind_address, config.dns_port)).await?;
        let dns_tcp = TcpListener::bind(dns.local_addr()?).await?;
        let endpoints = SandboxEgressProxy {
            http: SocketAddrV4::new(host_ip, http.local_addr()?.port()),
            https: SocketAddrV4::new(host_ip, https.local_addr()?.port()),
            dns: SocketAddrV4::new(host_ip, dns.local_addr()?.port()),
        };
        endpoints.validate()?;
        let source = Arc::new(AtomicU32::new(0));
        let cancel = CancellationToken::new();
        tokio::spawn(serve_dns(
            dns,
            dns_tcp,
            hosts.clone(),
            source.clone(),
            cancel.clone(),
        ));
        Ok(Self {
            endpoints,
            http,
            https,
            source,
            cancel,
        })
    }
}

#[async_trait]
impl EgressTransport for LocalEgressTransport {
    fn endpoints(&self) -> SandboxEgressProxy {
        self.endpoints
    }

    async fn bind_source(&self, source_ip: Ipv4Addr) -> Result<()> {
        ensure!(
            !source_ip.is_unspecified() && !source_ip.is_multicast() && !source_ip.is_broadcast(),
            "invalid proxy source address"
        );
        self.source
            .compare_exchange(0, u32::from(source_ip), Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| anyhow!("proxy source identity is already bound"))?;
        Ok(())
    }

    async fn accept(&self, tls: bool) -> Result<BoxSandboxTcpStream> {
        let listener = if tls { &self.https } else { &self.http };
        loop {
            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => return Err(anyhow!("egress listener closed")),
                incoming = listener.accept() => {
                    let (stream, peer) = incoming?;
                    if accepts_peer(&self.source, peer) { return Ok(Box::pin(stream)); }
                }
            }
        }
    }

    fn close(&self) {
        self.cancel.cancel();
    }
}

impl Drop for LocalEgressTransport {
    fn drop(&mut self) {
        self.close();
    }
}

fn accepts_peer(source: &AtomicU32, peer: SocketAddr) -> bool {
    let IpAddr::V4(ip) = peer.ip() else {
        return false;
    };
    let source = source.load(Ordering::SeqCst);
    source != 0 && source == u32::from(ip)
}

async fn serve_dns(
    dns: UdpSocket,
    tcp: TcpListener,
    hosts: HashSet<String>,
    source: Arc<AtomicU32>,
    cancel: CancellationToken,
) {
    let hosts = Arc::new(hosts);
    let mut tasks = JoinSet::new();
    let mut buffer = [0u8; 4096];
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if !matches!(result, Ok(Ok(()))) { tracing::debug!("egress DNS connection failed"); }
            }
            incoming = dns.recv_from(&mut buffer) => {
                let Ok((size, peer)) = incoming else { break; };
                if !accepts_peer(&source, peer) { continue; }
                if let Ok(answer) = dns_response(&hosts, &buffer[..size])
                    && dns.send_to(&answer, peer).await.is_err() {
                    tracing::debug!("egress DNS response failed");
                }
            }
            incoming = tcp.accept() => {
                let Ok((mut stream, peer)) = incoming else { break; };
                if !accepts_peer(&source, peer) || tasks.len() >= 32 { continue; }
                let hosts = hosts.clone();
                tasks.spawn(async move {
                    tokio::time::timeout(IO_TIMEOUT, async {
                        let size = stream.read_u16().await?;
                        ensure!(size <= 4096, "DNS request too large");
                        let mut bytes = vec![0; size as usize];
                        stream.read_exact(&mut bytes).await?;
                        let answer = dns_response(&hosts, &bytes)?;
                        stream.write_u16(answer.len().try_into()?).await?;
                        stream.write_all(&answer).await?;
                        Ok::<_, anyhow::Error>(())
                    }).await?
                });
            }
        }
    }
    tasks.shutdown().await;
}
pub(super) fn dns_response(hosts: &HashSet<String>, bytes: &[u8]) -> Result<Vec<u8>> {
    let query = Message::from_vec(bytes)?;
    ensure!(
        query.message_type() == MessageType::Query
            && query.op_code() == OpCode::Query
            && query.queries().len() == 1,
        "unsupported DNS query"
    );
    let question = &query.queries()[0];
    let mut response = Message::new();
    response
        .set_id(query.id())
        .set_message_type(MessageType::Response)
        .set_recursion_desired(query.recursion_desired())
        .set_recursion_available(false)
        .add_query(question.clone());
    let host = question
        .name()
        .to_ascii()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if question.query_class() != DNSClass::IN || !hosts.contains(&host) {
        response.set_response_code(ResponseCode::Refused);
    } else if question.query_type() == RecordType::A {
        response.add_answer(Record::from_rdata(
            question.name().clone(),
            0,
            RData::A(A(SYNTHETIC_IP)),
        ));
    } else if question.query_type() != RecordType::AAAA {
        response.set_response_code(ResponseCode::Refused);
    }
    Ok(response.to_vec()?)
}
