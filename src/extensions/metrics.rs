use crate::config::models::WhooshConfig;
use crate::error::WhooshError;

use crate::server::context::AppCtx;
use crate::server::extension::WhooshExtension;
use async_trait::async_trait;
use dashmap::DashMap;
use pingora::Error;
use pingora::http::ResponseHeader;
use pingora::proxy::{ProxyHttp, Session, http_proxy_service};
use pingora::server::Server;
use pingora::upstreams::peer::HttpPeer;
use prometheus::{
    Encoder, GaugeVec, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder,
};
use std::sync::Arc;

pub struct MetricsExtension;

impl WhooshExtension for MetricsExtension {
    fn whoosh_init(&self, server: &mut Server, app_ctx: &mut AppCtx) -> Result<(), WhooshError> {
        let config = app_ctx
            .get::<WhooshConfig>()
            .ok_or_else(|| WhooshError::Config("WhooshConfig not found in AppCtx".to_string()))?;

        if let Some(listen_addr) = &config.metrics_listen {
            log::info!("Initializing Prometheus metrics backend on {}", listen_addr);
            let backend = PrometheusBackend::new();
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
            backend.set_gauge("whoosh_heartbeat", 1.0, &[]);
            log::info!("Metrics service registered and heartbeat initialized");
        }

        Ok(())
    }
}

pub struct PrometheusBackend {
    registry: Registry,
    counters: DashMap<String, IntCounterVec>,
    gauges: DashMap<String, GaugeVec>,
    histograms: DashMap<String, HistogramVec>,
}

impl PrometheusBackend {
    pub fn new() -> Self {
        Self {
            registry: Registry::new(),
            counters: DashMap::new(),
            gauges: DashMap::new(),
            histograms: DashMap::new(),
        }
    }

    pub fn encode(&self) -> String {
        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }

    fn get_or_create_counter(&self, name: &str, label_keys: &[&str]) -> Option<IntCounterVec> {
        if let Some(counter) = self.counters.get(name) {
            return Some(counter.clone());
        }

        let opts = Opts::new(name, name);
        let counter = IntCounterVec::new(opts, label_keys).ok()?;
        self.registry.register(Box::new(counter.clone())).ok()?;
        self.counters.insert(name.to_string(), counter.clone());
        Some(counter)
    }

    fn get_or_create_gauge(&self, name: &str, label_keys: &[&str]) -> Option<GaugeVec> {
        if let Some(gauge) = self.gauges.get(name) {
            return Some(gauge.clone());
        }

        let opts = Opts::new(name, name);
        let gauge = GaugeVec::new(opts, label_keys).ok()?;
        self.registry.register(Box::new(gauge.clone())).ok()?;
        self.gauges.insert(name.to_string(), gauge.clone());
        Some(gauge)
    }

    fn get_or_create_histogram(&self, name: &str, label_keys: &[&str]) -> Option<HistogramVec> {
        if let Some(histogram) = self.histograms.get(name) {
            return Some(histogram.clone());
        }

        let opts = HistogramOpts::new(name, name);
        let histogram = HistogramVec::new(opts, label_keys).ok()?;
        self.registry.register(Box::new(histogram.clone())).ok()?;
        self.histograms.insert(name.to_string(), histogram.clone());
        Some(histogram)
    }
    pub fn increment_counter(&self, name: &str, labels: &[(&str, &str)]) {
        self.increment_counter_by(name, 1, labels);
    }

    pub fn increment_counter_by(&self, name: &str, value: u64, labels: &[(&str, &str)]) {
        let label_keys: Vec<&str> = labels.iter().map(|(k, _)| *k).collect();
        let label_values: Vec<&str> = labels.iter().map(|(_, v)| *v).collect();

        if let Some(counter) = self.get_or_create_counter(name, &label_keys) {
            if let Ok(m) = counter.get_metric_with_label_values(&label_values) {
                m.inc_by(value);
            }
        }
    }

    pub fn set_gauge(&self, name: &str, value: f64, labels: &[(&str, &str)]) {
        let label_keys: Vec<&str> = labels.iter().map(|(k, _)| *k).collect();
        let label_values: Vec<&str> = labels.iter().map(|(_, v)| *v).collect();

        if let Some(gauge) = self.get_or_create_gauge(name, &label_keys) {
            if let Ok(m) = gauge.get_metric_with_label_values(&label_values) {
                m.set(value);
            }
        }
    }

    pub fn increment_gauge(&self, name: &str, labels: &[(&str, &str)]) {
        let label_keys: Vec<&str> = labels.iter().map(|(k, _)| *k).collect();
        let label_values: Vec<&str> = labels.iter().map(|(_, v)| *v).collect();

        if let Some(gauge) = self.get_or_create_gauge(name, &label_keys) {
            if let Ok(m) = gauge.get_metric_with_label_values(&label_values) {
                m.inc();
            }
        }
    }

    pub fn decrement_gauge(&self, name: &str, labels: &[(&str, &str)]) {
        let label_keys: Vec<&str> = labels.iter().map(|(k, _)| *k).collect();
        let label_values: Vec<&str> = labels.iter().map(|(_, v)| *v).collect();

        if let Some(gauge) = self.get_or_create_gauge(name, &label_keys) {
            if let Ok(m) = gauge.get_metric_with_label_values(&label_values) {
                m.dec();
            }
        }
    }

    pub fn observe_histogram(&self, name: &str, value: f64, labels: &[(&str, &str)]) {
        let label_keys: Vec<&str> = labels.iter().map(|(k, _)| *k).collect();
        let label_values: Vec<&str> = labels.iter().map(|(_, v)| *v).collect();

        if let Some(histogram) = self.get_or_create_histogram(name, &label_keys) {
            if let Ok(m) = histogram.get_metric_with_label_values(&label_values) {
                m.observe(value);
            }
        }
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
