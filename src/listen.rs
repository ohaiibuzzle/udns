// Network listeners: plain DNS (UDP + TCP), DoT, DoQ and DoH.
// Each one only moves bytes in and out; all DNS logic lives in handler.rs.
// Every serve_* function binds first (so bind errors are reported), then loops forever.

use crate::handler::{Proto, Server};
use base64::Engine;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use socket2::{Domain, Socket, Type};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

/// Idle TCP/TLS connections are closed after this, so they can't pile up.
const IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Prefixes a DNS message with its 2-byte length (TCP, DoT and DoQ framing).
fn framed(message: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(message.len() + 2);
    out.extend_from_slice(&(message.len() as u16).to_be_bytes());
    out.extend_from_slice(message);
    out
}

/// Binds a non-blocking socket. An IPv6 address only takes IPv6 traffic: by default
/// Linux lets "[::]:53" also claim IPv4, which then collides with "0.0.0.0:53".
fn bind_socket(addr: SocketAddr, kind: Type) -> std::io::Result<Socket> {
    let socket: Socket = Socket::new(Domain::for_address(addr), kind, None)?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    if kind == Type::STREAM {
        // Same as tokio's TcpListener::bind: restart without waiting for TIME_WAIT.
        socket.set_reuse_address(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    if kind == Type::STREAM {
        socket.listen(1024)?;
    }
    Ok(socket)
}

fn bind_tcp(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket: Socket = bind_socket(addr, Type::STREAM)?;
    TcpListener::from_std(socket.into())
}

// ---------- plain DNS over UDP ----------

pub async fn serve_udp(server: Arc<Server>, addr: SocketAddr) -> Result<(), String> {
    let socket = match bind_socket(addr, Type::DGRAM).and_then(|s| UdpSocket::from_std(s.into())) {
        Ok(socket) => Arc::new(socket),
        Err(e) => return Err(format!("udp bind {addr}: {e}")),
    };
    eprintln!("udns: dns/udp listening on {addr}");
    let mut buf: Vec<u8> = vec![0u8; 4096];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(result) => result,
            Err(_) => continue, // e.g. ICMP port unreachable reported on the socket
        };
        // Under flood, drop queries instead of growing memory without bound.
        let permit = match server.inflight.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => continue,
        };
        let request: Vec<u8> = buf[..len].to_vec();
        let server = server.clone();
        let socket = socket.clone();
        tokio::spawn(async move {
            if let Some(response) = server.handle(Proto::Udp, &request).await {
                let _ = socket.send_to(&response, peer).await;
            }
            drop(permit);
        });
    }
}

// ---------- plain DNS over TCP, and DoT (same framing inside TLS) ----------

pub async fn serve_tcp(
    server: Arc<Server>,
    addr: SocketAddr,
    tls: Option<TlsAcceptor>,
) -> Result<(), String> {
    let listener = match bind_tcp(addr) {
        Ok(listener) => listener,
        Err(e) => return Err(format!("tcp bind {addr}: {e}")),
    };
    let label: &str = if tls.is_some() { "dot" } else { "dns/tcp" };
    eprintln!("udns: {label} listening on {addr}");
    loop {
        let tcp: TcpStream = match accept(&listener).await {
            Some(tcp) => tcp,
            None => continue,
        };
        let permit = match server.inflight.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => continue, // too busy: dropping `tcp` closes the connection
        };
        let server = server.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            match tls {
                None => serve_stream(&server, Proto::Tcp, tcp).await,
                Some(acceptor) => {
                    if let Ok(Ok(tls_stream)) = timeout(IDLE_TIMEOUT, acceptor.accept(tcp)).await {
                        serve_stream(&server, Proto::Dot, tls_stream).await;
                    }
                }
            }
            drop(permit);
        });
    }
}

/// Accepts one connection. On errors like "too many open files", waits a moment
/// instead of spinning. Returns None on error.
async fn accept(listener: &TcpListener) -> Option<TcpStream> {
    match listener.accept().await {
        Ok((tcp, _peer)) => Some(tcp),
        Err(_) => {
            tokio::time::sleep(Duration::from_millis(100)).await;
            None
        }
    }
}

/// Reads length-prefixed queries and answers them in order until the client
/// closes the connection or goes idle.
// ponytail: queries on one connection are answered one at a time (no pipelining
// in parallel). Fine for stub clients; spawn per query if that ever matters.
async fn serve_stream<S: AsyncRead + AsyncWrite + Unpin>(
    server: &Server,
    proto: Proto,
    mut stream: S,
) {
    loop {
        let mut len_buf: [u8; 2] = [0; 2];
        match timeout(IDLE_TIMEOUT, stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            _ => return, // idle, closed or broken
        }
        let len: usize = usize::from(u16::from_be_bytes(len_buf));
        let mut request: Vec<u8> = vec![0u8; len];
        match timeout(IDLE_TIMEOUT, stream.read_exact(&mut request)).await {
            Ok(Ok(_)) => {}
            _ => return,
        }
        let response: Vec<u8> = match server.handle(proto, &request).await {
            Some(response) => response,
            None => return,
        };
        if stream.write_all(&framed(&response)).await.is_err() {
            return;
        }
    }
}

// ---------- DoQ (RFC 9250) ----------

pub async fn serve_doq(
    server: Arc<Server>,
    addr: SocketAddr,
    tls: Arc<rustls::ServerConfig>,
) -> Result<(), String> {
    let mut crypto: rustls::ServerConfig = (*tls).clone();
    crypto.alpn_protocols = vec![b"doq".to_vec()];
    let quic_crypto = match quinn::crypto::rustls::QuicServerConfig::try_from(crypto) {
        Ok(quic_crypto) => quic_crypto,
        Err(e) => return Err(format!("doq tls config: {e}")),
    };
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().expect("30s fits")));
    transport.max_concurrent_bidi_streams(64u32.into());
    transport.max_concurrent_uni_streams(0u32.into());
    config.transport_config(Arc::new(transport));

    let socket: std::net::UdpSocket = match bind_socket(addr, Type::DGRAM) {
        Ok(socket) => socket.into(),
        Err(e) => return Err(format!("doq bind {addr}: {e}")),
    };
    let runtime = Arc::new(quinn::TokioRuntime);
    let endpoint = match quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(config),
        socket,
        runtime,
    ) {
        Ok(endpoint) => endpoint,
        Err(e) => return Err(format!("doq bind {addr}: {e}")),
    };
    eprintln!("udns: doq listening on {addr}");
    loop {
        let incoming: quinn::Incoming = match endpoint.accept().await {
            Some(incoming) => incoming,
            None => return Err("doq endpoint closed".to_string()),
        };
        let permit = match server.inflight.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                incoming.refuse();
                continue;
            }
        };
        let server = server.clone();
        tokio::spawn(async move {
            let connection: quinn::Connection = match incoming.await {
                Ok(connection) => connection,
                Err(_) => return,
            };
            // Each query arrives on its own bidirectional stream.
            loop {
                let (send, recv) = match connection.accept_bi().await {
                    Ok(streams) => streams,
                    Err(_) => break, // connection closed or timed out
                };
                let server = server.clone();
                tokio::spawn(async move {
                    doq_stream(&server, send, recv).await;
                });
            }
            drop(permit);
        });
    }
}

async fn doq_stream(server: &Server, mut send: quinn::SendStream, mut recv: quinn::RecvStream) {
    // The client sends one length-prefixed query, then closes its side.
    let data: Vec<u8> = match recv.read_to_end(2 + 65535).await {
        Ok(data) => data,
        Err(_) => return,
    };
    if data.len() < 2 {
        return;
    }
    let len: usize = usize::from(u16::from_be_bytes([data[0], data[1]]));
    if data.len() != 2 + len {
        return;
    }
    let response: Vec<u8> = match server.handle(Proto::Doq, &data[2..]).await {
        Some(response) => response,
        None => return,
    };
    if send.write_all(&framed(&response)).await.is_ok() {
        let _ = send.finish();
    }
}

// ---------- DoH (RFC 8484), over plain HTTP or HTTPS ----------

pub struct DohPaths {
    pub query: String,
    pub stats: Option<String>,
}

pub async fn serve_doh(
    server: Arc<Server>,
    addr: SocketAddr,
    paths: Arc<DohPaths>,
    tls: Option<TlsAcceptor>,
) -> Result<(), String> {
    let listener = match bind_tcp(addr) {
        Ok(listener) => listener,
        Err(e) => return Err(format!("doh bind {addr}: {e}")),
    };
    let scheme: &str = if tls.is_some() { "https" } else { "http" };
    eprintln!("udns: doh listening on {scheme}://{addr}{}", paths.query);
    loop {
        let tcp: TcpStream = match accept(&listener).await {
            Some(tcp) => tcp,
            None => continue,
        };
        let permit = match server.inflight.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => continue,
        };
        let server = server.clone();
        let paths = paths.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                doh_request(server.clone(), paths.clone(), request)
            });
            // `auto` speaks HTTP/1.1 and HTTP/2 (including h2c for reverse proxies).
            let http = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            match tls {
                None => {
                    let _ = http.serve_connection(TokioIo::new(tcp), service).await;
                }
                Some(acceptor) => {
                    if let Ok(Ok(tls_stream)) = timeout(IDLE_TIMEOUT, acceptor.accept(tcp)).await {
                        let _ = http
                            .serve_connection(TokioIo::new(tls_stream), service)
                            .await;
                    }
                }
            }
            drop(permit);
        });
    }
}

fn http_response(status: StatusCode, content_type: &str, body: Vec<u8>) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    if let Ok(value) = content_type.parse() {
        response
            .headers_mut()
            .insert(hyper::header::CONTENT_TYPE, value);
    }
    response
}

fn http_error(status: StatusCode) -> Response<Full<Bytes>> {
    http_response(status, "text/plain", Vec::new())
}

/// Extracts the base64url `dns=` parameter of a DoH GET request.
fn decode_get_query(uri_query: &str) -> Option<Vec<u8>> {
    for pair in uri_query.split('&') {
        if let Some(value) = pair.strip_prefix("dns=") {
            // Clients should not pad, but tolerate it.
            let unpadded: &str = value.trim_end_matches('=');
            return base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(unpadded)
                .ok();
        }
    }
    None
}

async fn doh_request(
    server: Arc<Server>,
    paths: Arc<DohPaths>,
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path: &str = request.uri().path();

    if let Some(stats_path) = &paths.stats {
        if path == stats_path && request.method() == Method::GET {
            return Ok(http_response(
                StatusCode::OK,
                "application/json",
                server.stats_json().into_bytes(),
            ));
        }
    }
    // Health check for load balancers / container orchestrators.
    if path == "/" && path != paths.query {
        return Ok(http_response(
            StatusCode::OK,
            "text/plain",
            b"ok\n".to_vec(),
        ));
    }
    if path != paths.query {
        return Ok(http_error(StatusCode::NOT_FOUND));
    }

    let query: Vec<u8> = if request.method() == Method::GET {
        match request.uri().query().and_then(decode_get_query) {
            Some(query) => query,
            None => return Ok(http_error(StatusCode::BAD_REQUEST)),
        }
    } else if request.method() == Method::POST {
        // Cap the body at the maximum DNS message size.
        match Limited::new(request.into_body(), 65535).collect().await {
            Ok(body) => body.to_bytes().to_vec(),
            Err(_) => return Ok(http_error(StatusCode::PAYLOAD_TOO_LARGE)),
        }
    } else {
        return Ok(http_error(StatusCode::METHOD_NOT_ALLOWED));
    };

    match server.handle(Proto::Doh, &query).await {
        Some(response) => Ok(http_response(
            StatusCode::OK,
            "application/dns-message",
            response,
        )),
        None => Ok(http_error(StatusCode::BAD_REQUEST)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doh_get_decoding() {
        // RFC 8484 section 4.1 example: www.example.com A query.
        let expected: Vec<u8> = vec![
            0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
            0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
            0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let query = "dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB";
        assert_eq!(decode_get_query(query), Some(expected.clone()));
        assert_eq!(decode_get_query(&format!("ct=x&{query}==")), Some(expected));
        assert_eq!(decode_get_query("other=1"), None);
        assert_eq!(decode_get_query("dns=!!!"), None);
    }
}
