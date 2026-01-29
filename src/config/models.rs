pub use pingora::server::configuration::ServerConf;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct RootConfig {
    pub whoosh: WhooshConfig,
    pub pingora: Option<ServerConf>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct WhooshConfig {
    pub http_listen: String,
    pub https_listen: Option<String>,
    pub ssl: Option<SslSettings>,
    pub acme: Option<AcmeSettings>,
    pub metrics_listen: Option<String>,
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    #[serde(default)]
    pub services: Vec<Service>,

    // Allow for extra configuration that might not be strictly defined
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct PeerOptions {
    pub read_timeout: Option<u64>,
    pub idle_timeout: Option<u64>,
    pub write_timeout: Option<u64>,
    pub verify_cert: Option<bool>,
    pub verify_hostname: Option<bool>,
    pub tcp_recv_buf: Option<usize>,
    pub curves: Option<String>, // simplified
    pub tcp_fast_open: Option<bool>,
    pub cacert: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub sni: Option<String>,
    // Allow overrides or extra fields
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SslSettings {
    pub cacert: Option<String>,
    pub server_cert: Option<String>,
    pub server_key: Option<String>,
    pub sans: Option<Vec<String>>,
    pub ssl_min_version: Option<String>,
    pub ssl_max_version: Option<String>,
    pub cipher_suites: Option<CipherSuites>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct CipherSuites {
    pub tls12: Option<Vec<String>>,
    pub tls13: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub enum AcmeChallengeType {
    #[serde(rename = "http-01")]
    #[default]
    Http01,
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AcmeSettings {
    pub ca_server: String,
    pub email: String,
    pub storage: String,
    #[serde(default)]
    pub challenge: AcmeChallengeType,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Upstream {
    pub name: String,
    pub peer_options: Option<PeerOptions>,
    #[serde(default)]
    pub servers: Vec<UpstreamServer>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct UpstreamServer {
    pub host: String,
    pub weight: Option<u32>,
    pub peer_options: Option<PeerOptions>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub enum ServiceProtocol {
    #[serde(rename = "http")]
    Http,
    #[serde(rename = "https")]
    Https,
    #[serde(rename = "ws")]
    Ws,
    #[serde(rename = "wss")]
    Wss,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Service {
    pub name: String,
    pub host: String,
    pub protocols: Vec<ServiceProtocol>,
    #[serde(default)]
    pub routes: Vec<Route>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Route {
    pub name: String,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Rule {
    pub rule: String,
    pub priority: Option<i32>,
    pub request_transformer: Option<String>,
    pub response_transformer: Option<String>,
}
