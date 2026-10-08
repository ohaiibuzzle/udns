// udns: a small ad-blocking DNS forwarder serving plain DNS, DoT, DoQ and DoH.
//
// Startup: read config -> build upstream resolver -> start the enabled listeners
// -> load the blocklist in the background (after the listeners, so the download
// works even when this machine resolves through udns itself).

// Nested `if`s are kept on purpose: easier to read than `if let ... && ...` chains.
#![allow(clippy::collapsible_if)]

mod blocklist;
mod config;
mod handler;
mod listen;
#[cfg(all(target_arch = "arm", target_abi = "eabi"))]
mod softfloat;

use crate::blocklist::Blocklist;
use crate::config::{BlocklistConfig, Config, TlsFiles, UpstreamProtocol};
use crate::handler::Server;
use crate::listen::DohPaths;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolveHosts, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver, TokioResolver};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

fn main() {
    let config_path: String = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/udns.toml".to_string());
    let config: Config = match config::load(&config_path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("udns: {e}");
            std::process::exit(1);
        }
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("cannot start tokio runtime");
    if let Err(e) = runtime.block_on(run(config)) {
        eprintln!("udns: {e}");
        std::process::exit(1);
    }
}

async fn run(config: Config) -> Result<(), String> {
    // Only the ring backend is compiled in; make it the process default.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let resolver: TokioResolver = build_resolver(&config)?;
    let server = Arc::new(Server::new(resolver));

    let tls_config: Option<Arc<rustls::ServerConfig>> = match &config.tls {
        Some(files) if config.needs_tls() => Some(load_tls(files)?),
        _ => None,
    };

    // Every listener runs forever; if one returns, it failed (e.g. bind error).
    let mut listeners: JoinSet<Result<(), String>> = JoinSet::new();

    if config.dns.enabled {
        for addr in &config.dns.listen {
            listeners.spawn(listen::serve_udp(server.clone(), *addr));
            listeners.spawn(listen::serve_tcp(server.clone(), *addr, None));
        }
    }
    if config.dot.enabled {
        let mut dot_tls: rustls::ServerConfig =
            (*tls_config.clone().expect("validated in config::load")).clone();
        dot_tls.alpn_protocols = vec![b"dot".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(dot_tls));
        for addr in &config.dot.listen {
            listeners.spawn(listen::serve_tcp(
                server.clone(),
                *addr,
                Some(acceptor.clone()),
            ));
        }
    }
    if config.doq.enabled {
        let doq_tls: Arc<rustls::ServerConfig> =
            tls_config.clone().expect("validated in config::load");
        for addr in &config.doq.listen {
            listeners.spawn(listen::serve_doq(server.clone(), *addr, doq_tls.clone()));
        }
    }
    if config.doh.enabled {
        let acceptor: Option<TlsAcceptor> = if config.doh.tls {
            let mut doh_tls: rustls::ServerConfig =
                (*tls_config.clone().expect("validated in config::load")).clone();
            doh_tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            Some(TlsAcceptor::from(Arc::new(doh_tls)))
        } else {
            None
        };
        let paths = Arc::new(DohPaths {
            query: config.doh.path.clone(),
            stats: config.doh.stats_path.clone(),
        });
        for addr in &config.doh.listen {
            listeners.spawn(listen::serve_doh(
                server.clone(),
                *addr,
                paths.clone(),
                acceptor.clone(),
            ));
        }
    }

    match config.blocklist {
        Some(blocklist_config) => {
            tokio::spawn(blocklist_task(server.clone(), blocklist_config));
        }
        None => eprintln!("udns: no [blocklist] configured, nothing will be blocked"),
    }

    // Wait for the first listener to stop; that is always an error.
    match listeners.join_next().await {
        Some(Ok(Err(e))) => Err(e),
        Some(Ok(Ok(()))) => Err("a listener stopped unexpectedly".to_string()),
        Some(Err(e)) => Err(format!("listener task failed: {e}")),
        None => Err("no listeners running".to_string()),
    }
}

fn build_resolver(config: &Config) -> Result<TokioResolver, String> {
    let mut name_servers: Vec<NameServerConfig> = Vec::new();
    for upstream in &config.upstream.servers {
        let server_name: Arc<str> = Arc::from(upstream.server_name.clone().unwrap_or_default());
        let mut connections: Vec<ConnectionConfig> = match upstream.protocol {
            // TCP is the fallback for answers too large for UDP.
            UpstreamProtocol::Udp => vec![ConnectionConfig::udp(), ConnectionConfig::tcp()],
            UpstreamProtocol::Tls => vec![ConnectionConfig::tls(server_name)],
            UpstreamProtocol::Https => vec![ConnectionConfig::https(
                server_name,
                upstream.path.clone().map(Arc::from),
            )],
        };
        for connection in &mut connections {
            connection.port = upstream.addr.port();
        }
        name_servers.push(NameServerConfig::new(upstream.addr.ip(), true, connections));
    }

    // No servers configured: use this machine's DNS servers instead.
    if name_servers.is_empty() {
        let path: &str = &config.upstream.resolv_conf;
        let text: String = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) => {
                return Err(format!(
                    "no [upstream] servers set and cannot read {path}: {e}"
                ));
            }
        };
        let own_listeners: &[SocketAddr] = if config.dns.enabled {
            &config.dns.listen
        } else {
            &[]
        };
        let ips: Vec<IpAddr> = system_name_servers(path, &text, own_listeners)?;
        eprintln!("udns: using upstreams from {path}: {ips:?}");
        for ip in ips {
            name_servers.push(NameServerConfig::udp_and_tcp(ip));
        }
    }

    let resolver_config = ResolverConfig::from_parts(None, Vec::new(), name_servers);
    let mut builder =
        Resolver::builder_with_config(resolver_config, TokioRuntimeProvider::default());
    let options = builder.options_mut();
    options.cache_size = config.upstream.cache_size;
    options.use_hosts_file = ResolveHosts::Never; // pure forwarder: don't answer from /etc/hosts
    options.preserve_intermediates = true; // keep CNAME chains in answers
    builder
        .build()
        .map_err(|e| format!("cannot build upstream resolver: {e}"))
}

/// Returns the nameservers listed in resolv.conf `text`. Skips any that point back
/// at one of our own plain-DNS listeners, because forwarding to ourselves would loop.
// ponytail: only catches loops via loopback or the exact listen address. A
// nameserver that is this machine's LAN IP is not detected.
// ponytail: read once at startup; restart udns to pick up resolv.conf changes.
fn system_name_servers(
    path: &str,
    text: &str,
    own_listeners: &[SocketAddr],
) -> Result<Vec<IpAddr>, String> {
    let parsed = match resolv_conf::Config::parse(text) {
        Ok(parsed) => parsed,
        Err(e) => return Err(format!("cannot parse {path}: {e}")),
    };
    let mut ips: Vec<IpAddr> = Vec::new();
    for scoped_ip in &parsed.nameservers {
        let ip: IpAddr = IpAddr::from(scoped_ip);
        if is_own_listener(ip, own_listeners) {
            eprintln!("udns: skipping nameserver {ip} from {path}: that is udns itself");
            continue;
        }
        ips.push(ip);
    }
    if ips.is_empty() {
        return Err(format!(
            "no usable nameserver in {path}. Set [upstream] servers, or resolv_conf \
             (on OpenWRT: /tmp/resolv.conf.d/resolv.conf.auto)"
        ));
    }
    Ok(ips)
}

/// resolv.conf nameservers always use port 53.
fn is_own_listener(ip: IpAddr, own_listeners: &[SocketAddr]) -> bool {
    for listen in own_listeners {
        if listen.port() != 53 {
            continue;
        }
        if listen.ip() == ip || (listen.ip().is_unspecified() && ip.is_loopback()) {
            return true;
        }
    }
    false
}

fn load_tls(files: &TlsFiles) -> Result<Arc<rustls::ServerConfig>, String> {
    let mut certs: Vec<CertificateDer<'static>> = Vec::new();
    let cert_iter = match CertificateDer::pem_file_iter(&files.cert) {
        Ok(iter) => iter,
        Err(e) => return Err(format!("tls cert {}: {e}", files.cert)),
    };
    for cert in cert_iter {
        match cert {
            Ok(cert) => certs.push(cert),
            Err(e) => return Err(format!("tls cert {}: {e}", files.cert)),
        }
    }
    let key: PrivateKeyDer<'static> = match PrivateKeyDer::from_pem_file(&files.key) {
        Ok(key) => key,
        Err(e) => return Err(format!("tls key {}: {e}", files.key)),
    };
    match rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
    {
        Ok(config) => Ok(Arc::new(config)),
        Err(e) => Err(format!("tls cert/key: {e}")),
    }
}

/// Loads the cached list (if any), then downloads the list and refreshes it periodically.
async fn blocklist_task(server: Arc<Server>, config: BlocklistConfig) {
    if let Some(cache_file) = config.cache_file.clone() {
        let allow: Vec<String> = config.allow.clone();
        let parsed = tokio::task::spawn_blocking(move || {
            blocklist::fetch(&cache_file).map(|text| Blocklist::parse(&text, &allow))
        })
        .await;
        if let Ok(Ok(list)) = parsed {
            eprintln!("udns: blocklist loaded from cache: {} entries", list.len());
            server.set_blocklist(list);
        }
    }

    loop {
        let sources: Vec<String> = config.sources.clone();
        let cache_file: Option<String> = config.cache_file.clone();
        let allow: Vec<String> = config.allow.clone();
        // Download and parse off the async thread so queries keep flowing.
        let result = tokio::task::spawn_blocking(move || -> Result<Blocklist, String> {
            // Any failed source keeps the old list, so a dead URL can't silently shrink it.
            let mut text = String::new();
            for source in &sources {
                text.push_str(&blocklist::fetch(source)?);
                text.push('\n');
            }
            let list = Blocklist::parse(&text, &allow);
            if list.len() == 0 {
                return Err("no entries found in any source, keeping the old list".to_string());
            }
            if let Some(path) = cache_file {
                if !sources.contains(&path) {
                    if let Err(e) = std::fs::write(&path, &text) {
                        eprintln!("udns: cannot write blocklist cache {path}: {e}");
                    }
                }
            }
            Ok(list)
        })
        .await;

        let wait: Duration = match result {
            Ok(Ok(list)) => {
                eprintln!("udns: blocklist updated: {} entries", list.len());
                server.set_blocklist(list);
                Duration::from_secs(config.refresh_hours.max(1) * 3600)
            }
            Ok(Err(e)) => {
                eprintln!("udns: blocklist update failed: {e}");
                Duration::from_secs(60) // network may not be up yet after boot
            }
            Err(e) => {
                eprintln!("udns: blocklist task failed: {e}");
                Duration::from_secs(60)
            }
        };
        tokio::time::sleep(wait).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolv_conf_skips_loops() {
        let text = "# generated\nnameserver 127.0.0.1\nnameserver 192.168.1.1\nnameserver ::1\n";
        let own: Vec<SocketAddr> = vec!["0.0.0.0:53".parse().unwrap()];
        let ips = system_name_servers("test", text, &own).unwrap();
        assert_eq!(ips, vec!["192.168.1.1".parse::<IpAddr>().unwrap()]);

        // Listening on another port: 127.0.0.1:53 is someone else (e.g. dnsmasq).
        let own: Vec<SocketAddr> = vec!["127.0.0.1:5354".parse().unwrap()];
        assert_eq!(system_name_servers("test", text, &own).unwrap().len(), 3);

        // Only loops left: error instead of silently forwarding to ourselves.
        let own: Vec<SocketAddr> = vec!["127.0.0.1:53".parse().unwrap()];
        assert!(system_name_servers("test", "nameserver 127.0.0.1\n", &own).is_err());
    }
}
