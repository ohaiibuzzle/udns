// Config file: TOML, loaded and validated once at startup.
// See config.example.toml for a commented example.

use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub upstream: Upstream,
    pub blocklist: Option<BlocklistConfig>,
    pub tls: Option<TlsFiles>,
    #[serde(default)]
    pub dns: Listener,
    #[serde(default)]
    pub dot: Listener,
    #[serde(default)]
    pub doq: Listener,
    #[serde(default)]
    pub doh: DohListener,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    #[serde(default = "default_cache_size")]
    pub cache_size: u64,
    /// When empty, the nameservers from `resolv_conf` are used instead.
    #[serde(default)]
    pub servers: Vec<UpstreamServer>,
    #[serde(default = "default_resolv_conf")]
    pub resolv_conf: String,
}

impl Default for Upstream {
    fn default() -> Self {
        Upstream {
            cache_size: default_cache_size(),
            servers: Vec::new(),
            resolv_conf: default_resolv_conf(),
        }
    }
}

#[derive(Deserialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamProtocol {
    Udp,
    Tls,
    Https,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamServer {
    pub protocol: UpstreamProtocol,
    pub addr: SocketAddr,
    /// TLS certificate name of the upstream. Required for tls and https.
    pub server_name: Option<String>,
    /// URL path for https upstreams. Defaults to /dns-query.
    pub path: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlocklistConfig {
    /// http(s):// URLs or local file paths. All lists are merged.
    pub sources: Vec<String>,
    /// Where to keep the last downloaded copy, so blocking works right after a reboot.
    pub cache_file: Option<String>,
    /// Domains (and their subdomains) that are never blocked.
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default = "default_refresh_hours")]
    pub refresh_hours: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsFiles {
    pub cert: String,
    pub key: String,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Listener {
    pub enabled: bool,
    pub listen: Vec<SocketAddr>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DohListener {
    pub enabled: bool,
    pub listen: Vec<SocketAddr>,
    /// false = plain HTTP (for use behind a reverse proxy), true = HTTPS using [tls].
    pub tls: bool,
    pub path: String,
    /// If set, GET on this path returns statistics as JSON.
    pub stats_path: Option<String>,
}

impl Default for DohListener {
    fn default() -> Self {
        DohListener {
            enabled: false,
            listen: Vec::new(),
            tls: false,
            path: "/dns-query".to_string(),
            stats_path: None,
        }
    }
}

fn default_cache_size() -> u64 {
    1024
}

fn default_resolv_conf() -> String {
    "/etc/resolv.conf".to_string()
}

fn default_refresh_hours() -> u64 {
    24
}

impl Config {
    /// True if any enabled listener needs the [tls] certificate.
    pub fn needs_tls(&self) -> bool {
        self.dot.enabled || self.doq.enabled || (self.doh.enabled && self.doh.tls)
    }
}

pub fn load(path: &str) -> Result<Config, String> {
    let text: String = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) => return Err(format!("cannot read config {path}: {e}")),
    };
    let config: Config = match toml::from_str(&text) {
        Ok(config) => config,
        Err(e) => return Err(format!("invalid config {path}: {e}")),
    };

    for server in &config.upstream.servers {
        if server.protocol != UpstreamProtocol::Udp && server.server_name.is_none() {
            return Err(format!(
                "config: upstream {} needs server_name for tls/https",
                server.addr
            ));
        }
    }
    if config.needs_tls() && config.tls.is_none() {
        return Err(
            "config: DoT, DoQ or DoH-over-TLS is enabled but [tls] cert/key is missing".to_string(),
        );
    }
    let listeners: [(&str, bool, usize); 4] = [
        ("dns", config.dns.enabled, config.dns.listen.len()),
        ("dot", config.dot.enabled, config.dot.listen.len()),
        ("doq", config.doq.enabled, config.doq.listen.len()),
        ("doh", config.doh.enabled, config.doh.listen.len()),
    ];
    let mut any_enabled = false;
    for (name, enabled, count) in listeners {
        if enabled && count == 0 {
            return Err(format!(
                "config: [{name}] is enabled but has no listen addresses"
            ));
        }
        any_enabled = any_enabled || enabled;
    }
    if !any_enabled {
        return Err("config: no listener is enabled".to_string());
    }
    Ok(config)
}
