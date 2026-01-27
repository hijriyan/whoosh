use crate::config::models::WhooshConfig;
use crate::error::WhooshError;

use crate::server::context::AppCtx;
use crate::server::extension::WhooshExtension;
use async_trait::async_trait;
use pingora::Error;
use pingora::http::ResponseHeader;
use pingora::proxy::{ProxyHttp, Session, http_proxy_service};
use pingora::server::Server;
use pingora::upstreams::peer::HttpPeer;
use prometheus::{
    Encoder, GaugeVec, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder,
};
use std::sync::Arc;

// Metric Names
pub const METRIC_HEARTBEAT: &str = "whoosh_heartbeat";
pub const METRIC_ACTIVE_CONNECTIONS: &str = "whoosh_active_connections";
pub const METRIC_ROUTER_DURATION: &str = "whoosh_router_duration_seconds";
pub const METRIC_TRANSFORMER_DURATION: &str = "whoosh_transformer_duration_seconds";
pub const METRIC_REQUESTS_TOTAL: &str = "whoosh_requests_total";
pub const METRIC_REQUEST_DURATION: &str = "whoosh_request_duration_seconds";
pub const METRIC_WS_EXTENSION_DURATION: &str = "whoosh_websocket_extension_duration_seconds";

pub struct MetricsExtension;

impl WhooshExtension for MetricsExtension {
    fn whoosh_init(&self, server: &mut Server, app_ctx: &mut AppCtx) -> Result<(), WhooshError> {
        let config = app_ctx
            .get::<WhooshConfig>()
            .ok_or_else(|| WhooshError::Config("WhooshConfig not found in AppCtx".to_string()))?;

        if let Some(listen_addr) = &config.metrics_listen {
            log::info!("Initializing Prometheus metrics backend on {}", listen_addr);
            let backend = PrometheusBackend::new();

            // Pre-initialize metrics
            backend
                .init_metrics()
                .map_err(|e| WhooshError::Other(format!("Failed to initialize metrics: {}", e)))?;

            app_ctx.insert(backend);
            let backend = app_ctx.get::<PrometheusBackend>().ok_or_else(|| {
                WhooshError::Other("Failed to retrieve PrometheusBackend from AppCtx".to_string())
            })?;

            // Create the service to expose metrics
            let proxy = PrometheusProxy {
                backend: backend.clone(),
            };
            let mut service = http_proxy_service(&server.configuration, proxy);
            service.add_tcp(listen_addr);
            server.add_service(service);

            // Register a heartbeat metric to ensure registry is not empty at startup
            backend.heartbeat.with_label_values(&[]).set(1.0);
            log::info!("Metrics service registered and heartbeat initialized");
        }

        Ok(())
    }
}

pub struct PrometheusBackend {
    registry: Registry,
    // Pre-defined metrics
    pub heartbeat: GaugeVec,
    pub active_connections: GaugeVec,
    pub router_duration: HistogramVec,
    pub transformer_duration: HistogramVec,
    pub requests_total: IntCounterVec,
    pub request_duration: HistogramVec,
    pub ws_extension_duration: HistogramVec,
}

impl PrometheusBackend {
    pub fn new() -> Self {
        let registry = Registry::new();

        // We use dummy metrics for now and replace them in init_metrics
        // Alternatively, we could use Option or once_cell, but this is simpler for now.
        // Actually, let's initialize them with the registry directly.

        let heartbeat = GaugeVec::new(Opts::new(METRIC_HEARTBEAT, METRIC_HEARTBEAT), &[]).unwrap();
        let active_connections = GaugeVec::new(
            Opts::new(METRIC_ACTIVE_CONNECTIONS, METRIC_ACTIVE_CONNECTIONS),
            &[],
        )
        .unwrap();
        let router_duration = HistogramVec::new(
            HistogramOpts::new(METRIC_ROUTER_DURATION, METRIC_ROUTER_DURATION),
            &[],
        )
        .unwrap();
        let transformer_duration = HistogramVec::new(
            HistogramOpts::new(METRIC_TRANSFORMER_DURATION, METRIC_TRANSFORMER_DURATION),
            &["type"],
        )
        .unwrap();
        let requests_total = IntCounterVec::new(
            Opts::new(METRIC_REQUESTS_TOTAL, METRIC_REQUESTS_TOTAL),
            &["status"],
        )
        .unwrap();
        let request_duration = HistogramVec::new(
            HistogramOpts::new(METRIC_REQUEST_DURATION, METRIC_REQUEST_DURATION),
            &["type"],
        )
        .unwrap();
        let ws_extension_duration = HistogramVec::new(
            HistogramOpts::new(METRIC_WS_EXTENSION_DURATION, METRIC_WS_EXTENSION_DURATION),
            &["direction"],
        )
        .unwrap();

        Self {
            registry,
            heartbeat,
            active_connections,
            router_duration,
            transformer_duration,
            requests_total,
            request_duration,
            ws_extension_duration,
        }
    }

    pub fn init_metrics(&self) -> Result<(), prometheus::Error> {
        self.registry.register(Box::new(self.heartbeat.clone()))?;
        self.registry
            .register(Box::new(self.active_connections.clone()))?;
        self.registry
            .register(Box::new(self.router_duration.clone()))?;
        self.registry
            .register(Box::new(self.transformer_duration.clone()))?;
        self.registry
            .register(Box::new(self.requests_total.clone()))?;
        self.registry
            .register(Box::new(self.request_duration.clone()))?;
        self.registry
            .register(Box::new(self.ws_extension_duration.clone()))?;
        Ok(())
    }

    pub fn encode(&self) -> String {
        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }

    // --- High Performance API (No string lookups for name) ---

    pub fn inc_active_connections(&self) {
        self.active_connections.with_label_values(&[]).inc();
    }

    pub fn dec_active_connections(&self) {
        self.active_connections.with_label_values(&[]).dec();
    }

    pub fn observe_router_duration(&self, duration: f64) {
        self.router_duration
            .with_label_values(&[])
            .observe(duration);
    }

    pub fn observe_transformer_duration(&self, duration: f64, r#type: &str) {
        self.transformer_duration
            .with_label_values(&[r#type])
            .observe(duration);
    }

    pub fn inc_requests_total(&self, status: &str) {
        self.requests_total.with_label_values(&[status]).inc();
    }

    pub fn observe_request_duration(&self, duration: f64, r#type: &str) {
        self.request_duration
            .with_label_values(&[r#type])
            .observe(duration);
    }

    pub fn observe_ws_extension_duration(&self, duration: f64, direction: &str) {
        self.ws_extension_duration
            .with_label_values(&[direction])
            .observe(duration);
    }
}

// Removed impl Metrics for PrometheusBackend

pub struct PrometheusProxy {
    backend: Arc<PrometheusBackend>,
}

#[async_trait]
impl ProxyHttp for PrometheusProxy {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<bool, Box<Error>> {
        let path = session.req_header().uri.path();
        if path == "/metrics" || path == "/" {
            log::info!("Handling metrics request for path: {}", path);
            let body = self.backend.encode();

            let mut header = ResponseHeader::build(200, None).unwrap();
            header
                .insert_header("Content-Type", "text/plain; version=0.0.4")
                .unwrap();
            header
                .insert_header("Content-Length", body.len().to_string())
                .unwrap();

            session
                .write_response_header(Box::new(header), false)
                .await?;
            session.write_response_body(Some(body.into()), true).await?;

            return Ok(true);
        }

        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>, Box<Error>> {
        // This should not be reached since request_filter handles the metrics request
        Err(Error::explain(
            pingora::ErrorType::HTTPStatus(404),
            "Not Found",
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::context::AppCtx;
    use pingora::server::Server;

    #[test]
    fn test_prometheus_backend_initialization() {
        let backend = PrometheusBackend::new();
        backend.init_metrics().unwrap();

        // Verify pre-initialized metrics can be reached
        backend.heartbeat.with_label_values(&[]).set(1.0);
        backend.inc_active_connections();
        backend.dec_active_connections();
        backend.observe_router_duration(0.1);
        backend.observe_transformer_duration(0.05, "request");
        backend.inc_requests_total("200");
        backend.observe_request_duration(0.2, "total");
        backend.observe_ws_extension_duration(0.01, "upstream");

        let encoded = backend.encode();
        assert!(encoded.contains(METRIC_HEARTBEAT));
        assert!(encoded.contains(METRIC_ACTIVE_CONNECTIONS));
        assert!(encoded.contains(METRIC_ROUTER_DURATION));
        assert!(encoded.contains(METRIC_TRANSFORMER_DURATION));
        assert!(encoded.contains(METRIC_REQUESTS_TOTAL));
        assert!(encoded.contains(METRIC_REQUEST_DURATION));
        assert!(encoded.contains(METRIC_WS_EXTENSION_DURATION));
        assert!(encoded.contains("status=\"200\""));
        assert!(encoded.contains("type=\"request\""));
        assert!(encoded.contains("type=\"total\""));
        assert!(encoded.contains("direction=\"upstream\""));
    }

    #[test]
    fn test_metrics_extension_init() {
        let mut server = Server::new(None).unwrap();
        let mut app_ctx = AppCtx::new();

        let mut config = WhooshConfig::default();
        config.metrics_listen = Some("127.0.0.1:9091".to_string());
        app_ctx.insert(config);

        let extension = MetricsExtension;
        extension.whoosh_init(&mut server, &mut app_ctx).unwrap();

        let backend = app_ctx.get::<PrometheusBackend>().unwrap();
        let encoded = backend.encode();
        assert!(encoded.contains(METRIC_HEARTBEAT));
        // Check heartbeat value
        assert!(encoded.contains(&format!("{} 1", METRIC_HEARTBEAT)));
    }
}
