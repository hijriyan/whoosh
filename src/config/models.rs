pub use pingora::server::configuration::ServerConf;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize)]
pub struct RootConfig {
    pub whoosh: WhooshConfig,
    pub pingora: Option<ServerConf>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct WhooshConfig {
    pub http_listen: String,
    pub https_listen: Option<String>,
    pub api: Option<ApiSettings>,
    pub ssl: Option<SslSettings>,
    pub acme: Option<AcmeSettings>,
    pub metrics_listen: Option<String>,
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    #[serde(default)]
    pub services: Vec<Arc<Service>>,
    #[serde(default)]
    pub dns: Option<DnsSettings>,

    // Allow for extra configuration that might not be strictly defined
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ApiSettings {
    pub listen: Option<String>,
    pub basic_auth: Option<BasicAuth>,
    pub rate_limit: Option<RateLimit>,
    pub openapi: Option<OpenApiSettings>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct BasicAuth {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct RateLimit {
    pub requests_per_second: u32,
    pub burst: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DnsSettings {
    pub nameservers: Option<Vec<String>>,
    pub timeout: Option<u64>,
    pub attempts: Option<usize>,
    pub strategy: Option<String>,
    pub cache_size: Option<usize>,
    #[serde(default = "default_true")]
    pub use_hosts_file: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, ToSchema)]
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

fn default_openapi_title() -> String {
    "Whoosh API".to_string()
}

fn default_openapi_description() -> String {
    "Whoosh Management API".to_string()
}

fn default_openapi_root_path() -> String {
    "/docs".to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct OpenApiSettings {
    #[serde(default = "default_openapi_title")]
    pub title: String,
    #[serde(default = "default_openapi_description")]
    pub description: String,
    #[serde(default = "default_openapi_root_path")]
    pub root_path: String,
}

impl Default for OpenApiSettings {
    fn default() -> Self {
        Self {
            title: default_openapi_title(),
            description: default_openapi_description(),
            root_path: default_openapi_root_path(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, ToSchema)]
pub struct Upstream {
    pub name: String,
    pub peer_options: Option<PeerOptions>,
    #[serde(default)]
    pub servers: Vec<UpstreamServer>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, ToSchema)]
pub struct UpstreamServer {
    pub host: String,
    pub weight: Option<u32>,
    pub peer_options: Option<PeerOptions>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash, ToSchema)]
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

#[derive(Debug, Serialize, Deserialize, Clone, Default, ToSchema)]
pub struct Service {
    pub name: String,
    pub host: String,
    pub protocols: Vec<ServiceProtocol>,
    #[serde(default)]
    pub routes: Vec<Route>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, ToSchema)]
pub struct Route {
    pub name: String,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, ToSchema)]
pub struct Rule {
    pub rule: String,
    pub priority: Option<i32>,
    pub request_transformer: Option<String>,
    pub response_transformer: Option<String>,
}
