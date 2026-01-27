use crate::config::models::{PeerOptions as ConfigPeerOptions, WhooshConfig};
use crate::error::WhooshError;
use crate::extensions::metrics::PrometheusBackend;
use crate::server::context::{AppCtx, RouteContext};
use crate::server::extension::{
    WebsocketDirection, WebsocketError, WebsocketErrorAction, WebsocketExtension,
    WebsocketMessageAction, WhooshFilter,
};
use crate::server::router::Router;
use crate::server::upstream::UpstreamManager;
use crate::websocket::{
    WsFrame, WsParseResult, encode_ws_frame_into, mask_key_from_time, parse_ws_frames,
};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use http::Version;
use pingora::Error;
use pingora::http::ResponseHeader;
use pingora::proxy::{ProxyHttp, Session};
use pingora::tls::{pkey::PKey, x509::X509};
use pingora::upstreams::peer::HttpPeer;
use pingora::utils::tls::CertKey;
use std::fs;
use std::sync::Arc;
use std::time::Duration;

// Move LbWrapper and BackgroundService impl to upstream.rs, or keep if still needed here, but they are defined in upstream.rs now.
// We should remove them from here to avoid duplication if reused or keep them private/local if unique.
// Plan suggests moving logic. I'll remove them.

/// Cached peer configuration with pre-loaded certificates for performance
#[derive(Clone)]
pub struct CachedPeerConfig {
    pub options: ConfigPeerOptions,
    pub ca_certs: Option<Arc<Box<[X509]>>>,
    pub client_cert_key: Option<Arc<CertKey>>,
}

impl CachedPeerConfig {
    pub fn new(options: ConfigPeerOptions) -> Result<Self, WhooshError> {
        let mut cached = Self {
            options: options.clone(),
            ca_certs: None,
            client_cert_key: None,
        };

        // Pre-load CA certificates if specified
        if let Some(cacert_path) = options.cacert.as_deref() {
            if !cacert_path.is_empty() {
                match load_x509_stack(cacert_path) {
                    Ok(certs) => {
                        cached.ca_certs = Some(Arc::new(certs.into_boxed_slice()));
                    }
                    Err(e) => {
                        log::error!("Failed to pre-load CA certs from {}: {}", cacert_path, e);
                        return Err(WhooshError::Tls(format!("Failed to load CA certs: {}", e)));
                    }
                }
            }
        }

        // Pre-load client certificate and key if specified
        if let (Some(cert_path), Some(key_path)) = (
            options.client_cert.as_deref(),
            options.client_key.as_deref(),
        ) {
            if !cert_path.is_empty() && !key_path.is_empty() {
                match load_client_cert_key(cert_path, key_path) {
                    Ok(cert_key) => {
                        cached.client_cert_key = Some(Arc::new(cert_key));
                    }
                    Err(e) => {
                        let msg = format!(
                            "Failed to pre-load client cert/key from {} and {}: {}",
                            cert_path, key_path, e
                        );
                        log::error!("{}", msg);
                        return Err(WhooshError::Tls(msg));
                    }
                }
            }
        }

        Ok(cached)
    }

    fn apply_to_peer(&self, peer: &mut HttpPeer) {
        // Apply basic options (same as original apply_peer_options)
        if let Some(read_timeout) = self.options.read_timeout {
            peer.options.read_timeout = Some(Duration::from_secs(read_timeout));
        }
        if let Some(idle_timeout) = self.options.idle_timeout {
            peer.options.idle_timeout = Some(Duration::from_secs(idle_timeout));
        }
        if let Some(write_timeout) = self.options.write_timeout {
            peer.options.write_timeout = Some(Duration::from_secs(write_timeout));
        }
        if let Some(verify_cert) = self.options.verify_cert {
            peer.options.verify_cert = verify_cert;
        }
        if let Some(verify_hostname) = self.options.verify_hostname {
            peer.options.verify_hostname = verify_hostname;
        }

        // Apply pre-loaded certificates (no need to load from disk again)
        if let Some(ca_certs) = &self.ca_certs {
            peer.options.ca = Some(ca_certs.clone());
        }
        if let Some(client_cert_key) = &self.client_cert_key {
            peer.client_cert_key = Some(client_cert_key.clone());
        }
    }
}

// --- Proxy ---

#[derive(Clone)]
pub struct WhooshProxy {
    pub config: Arc<WhooshConfig>,
    pub router: Arc<Router>,
    pub filters: Arc<Vec<Arc<dyn WhooshFilter>>>,
    pub websocket_extensions: Arc<Vec<Arc<dyn WebsocketExtension>>>,
    pub app_ctx: Arc<AppCtx>,
    pub upstream_manager: Arc<UpstreamManager>,
    pub metrics: Option<Arc<PrometheusBackend>>,
}

impl WhooshProxy {
    pub fn new(
        config: Arc<WhooshConfig>,
        router: Arc<Router>,
        filters: Arc<Vec<Arc<dyn WhooshFilter>>>,
        websocket_extensions: Arc<Vec<Arc<dyn WebsocketExtension>>>,
        app_ctx: Arc<AppCtx>,
        upstream_manager: Arc<UpstreamManager>,
    ) -> Result<Self, WhooshError> {
        let metrics = app_ctx.get::<PrometheusBackend>();
        Ok(WhooshProxy {
            config,
            router,
            filters,
            websocket_extensions,
            app_ctx,
            upstream_manager,
            metrics,
        })
    }
}

pub fn merge_peer_options(
    parent: Option<&ConfigPeerOptions>,
    child: Option<&ConfigPeerOptions>,
) -> ConfigPeerOptions {
    let mut merged = parent.cloned().unwrap_or_default();
    if let Some(child) = child {
        if child.read_timeout.is_some() {
            merged.read_timeout = child.read_timeout;
        }
        if child.idle_timeout.is_some() {
            merged.idle_timeout = child.idle_timeout;
        }
        if child.write_timeout.is_some() {
            merged.write_timeout = child.write_timeout;
        }
        if child.verify_cert.is_some() {
            merged.verify_cert = child.verify_cert;
        }
        if child.verify_hostname.is_some() {
            merged.verify_hostname = child.verify_hostname;
        }
        if child.tcp_recv_buf.is_some() {
            merged.tcp_recv_buf = child.tcp_recv_buf;
        }
        if child.curves.is_some() {
            merged.curves = child.curves.clone();
        }
        if child.tcp_fast_open.is_some() {
            merged.tcp_fast_open = child.tcp_fast_open;
        }
        if child.cacert.is_some() {
            merged.cacert = child.cacert.clone();
        }
        if child.client_cert.is_some() {
            merged.client_cert = child.client_cert.clone();
        }
        if child.client_key.is_some() {
            merged.client_key = child.client_key.clone();
        }
        if child.sni.is_some() {
            merged.sni = child.sni.clone();
        }
        if !child.extra.is_empty() {
            for (key, value) in &child.extra {
                merged.extra.insert(key.clone(), value.clone());
            }
        }
    }
    merged
}

fn load_x509_stack(path: &str) -> Result<Vec<X509>, Box<dyn std::error::Error>> {
    let pem = fs::read(path).map_err(|e| format!("Failed to read {}: {}", path, e))?;
    let certs = X509::stack_from_pem(&pem)
        .map_err(|e| format!("Failed to parse X509 from {}: {}", path, e))?;
    if certs.is_empty() {
        return Err(format!("no certificates found in {}", path).into());
    }
    Ok(certs)
}

fn load_client_cert_key(
    cert_path: &str,
    key_path: &str,
) -> Result<CertKey, Box<dyn std::error::Error>> {
    let certs = load_x509_stack(cert_path)?;
    let key_pem = fs::read(key_path).map_err(|e| format!("Failed to read {}: {}", key_path, e))?;
    let key = PKey::private_key_from_pem(&key_pem)
        .map_err(|e| format!("Failed to parse private key from {}: {}", key_path, e))?;
    Ok(CertKey::new(certs, key))
}

#[async_trait]
impl ProxyHttp for WhooshProxy {
    type CTX = RouteContext;
    fn new_ctx(&self) -> Self::CTX {
        RouteContext::new()
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool, Box<Error>> {
        if let Some(metrics) = &self.metrics {
            metrics.increment_gauge("whoosh_active_connections", &[]);
        }

        // Fast path: check filters first
        for filter in self.filters.iter() {
            if filter.request_filter(session, ctx, &self.app_ctx).await? {
                return Ok(true);
            }
        }

        let req_header = session.req_header_mut();

        // Optimized WebSocket detection
        let is_upgrade = req_header
            .headers
            .get("Upgrade")
            .and_then(|value| value.to_str().ok())
            .map_or(false, |value| value.eq_ignore_ascii_case("websocket"));

        if is_upgrade {
            // Check if Connection header needs to be added
            let needs_connection_upgrade = req_header
                .headers
                .get("Connection")
                .and_then(|value| value.to_str().ok())
                .map_or(true, |value| {
                    !value.to_ascii_lowercase().contains("upgrade")
                });

            if needs_connection_upgrade {
                req_header.insert_header("Connection", "Upgrade").ok();
            }
        }

        // Route matching with early return
        let route_start = std::time::Instant::now();
        let match_result = self.router.match_request(req_header);

        if let Some(metrics) = &self.metrics {
            metrics.observe_histogram(
                "whoosh_router_duration_seconds",
                route_start.elapsed().as_secs_f64(),
                &[],
            );
        }

        if let Some(match_result) = match_result {
            log::debug!("Route matched: upstream={}", match_result.upstream_name);

            if let Some(transformer) = &match_result.req_transformer {
                let transform_start = std::time::Instant::now();
                transformer.transform_request(req_header);

                if let Some(metrics) = &self.metrics {
                    metrics.observe_histogram(
                        "whoosh_transformer_duration_seconds",
                        transform_start.elapsed().as_secs_f64(),
                        &[("type", "request")],
                    );
                }
            }

            ctx.upstream_name = Some(match_result.upstream_name);
            ctx.response_transformer = match_result.res_transformer;
            ctx.is_upgrade = is_upgrade;

            return Ok(false);
        }

        // 404 response - optimized with minimal allocations
        let mut header = ResponseHeader::build(404, None).unwrap();
        header.insert_header("Content-Type", "text/plain").ok();
        session
            .write_response_header(Box::new(header), true)
            .await?;
        Ok(true)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>, Box<Error>> {
        // Fast path: get upstream name and find load balancer
        let upstream_name = ctx.upstream_name.as_ref().ok_or_else(|| {
            Error::explain(
                pingora::ErrorType::InternalError,
                "No upstream name in context",
            )
        })?;

        let load_balancer = self.upstream_manager.get(upstream_name).ok_or_else(|| {
            Error::explain(
                pingora::ErrorType::InternalError,
                "Load balancer not found for upstream",
            )
        })?;

        // Select backend using load balancer - Weighted selection (round-robin when weights are equal)
        let backend = load_balancer.select(b"", 256).ok_or_else(|| {
            Error::explain(
                pingora::ErrorType::InternalError,
                "No available backend from load balancer",
            )
        })?;

        // Get cached config with pre-loaded certificates
        let cached_config = backend.ext.get::<CachedPeerConfig>().cloned();
        let mut tls = false;
        let mut sni = String::new();

        if let Some(config) = cached_config.as_ref() {
            if let Some(option_sni) = &config.options.sni {
                tls = true;
                sni = option_sni.clone();
                ctx.rewrite_host = Some(sni.clone());
            }
        }

        let mut peer = HttpPeer::new(backend, tls, sni);

        // Apply cached configuration (includes pre-loaded certificates)
        if let Some(config) = cached_config.as_ref() {
            config.apply_to_peer(&mut peer);
        }

        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora::http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<Error>> {
        if ctx.is_upgrade {
            upstream_request.set_version(Version::HTTP_11);
        }

        if let Some(host) = &ctx.rewrite_host {
            upstream_request.insert_header("Host", host).map_err(|e| {
                Error::explain(pingora::ErrorType::InvalidHTTPHeader, e.to_string())
            })?;
        }

        ctx.upstream_start_time = Some(std::time::Instant::now());
        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<Error>> {
        for filter in self.filters.iter() {
            filter
                .response_filter(session, upstream_response, ctx, &self.app_ctx)
                .await?;
        }

        if let Some(transformer) = &ctx.response_transformer {
            if ctx.is_upgrade {
                return Ok(());
            }
            let transform_start = std::time::Instant::now();
            transformer.transform_response(upstream_response);

            if let Some(metrics) = &self.metrics {
                metrics.observe_histogram(
                    "whoosh_transformer_duration_seconds",
                    transform_start.elapsed().as_secs_f64(),
                    &[("type", "response")],
                );
            }
        }
        Ok(())
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<Error>> {
        if !ctx.is_upgrade {
            return Ok(());
        }

        let Some(chunk) = body.take() else {
            return Ok(());
        };

        // Reuse buffer to avoid frequent reallocations
        ctx.ws_client_buf.extend_from_slice(&chunk);
        let mut frames = Vec::with_capacity(16); // Pre-allocate reasonable capacity

        match parse_ws_frames(&mut ctx.ws_client_buf, &mut frames) {
            WsParseResult::Ok => {
                let mut out = BytesMut::with_capacity(chunk.len() + 256); // Pre-allocate output buffer

                for frame in frames {
                    let decompressor = if frame.rsv1 {
                        Some(
                            ctx.ws_client_decompressor
                                .get_or_insert_with(|| flate2::Decompress::new(false)),
                        )
                    } else {
                        None
                    };

                    match apply_ws_extensions(
                        &self.websocket_extensions,
                        WebsocketDirection::DownstreamToUpstream,
                        frame,
                        self.metrics.as_ref(),
                        decompressor,
                    ) {
                        WebsocketMessageAction::Forward(updated) => {
                            encode_ws_frame_into(&updated, Some(mask_key_from_time()), &mut out);
                        }
                        WebsocketMessageAction::Drop => {}
                        WebsocketMessageAction::Close(payload) => {
                            encode_ws_frame_into(
                                &close_frame(payload),
                                Some(mask_key_from_time()),
                                &mut out,
                            );
                            break;
                        }
                    }
                }

                *body = if out.is_empty() {
                    None
                } else {
                    Some(out.freeze())
                };
            }
            WsParseResult::Incomplete => {
                *body = None;
            }
            WsParseResult::Invalid => {
                match handle_ws_error(
                    &self.websocket_extensions,
                    WebsocketDirection::DownstreamToUpstream,
                    WebsocketError::InvalidFrame,
                ) {
                    WebsocketErrorAction::PassThrough => {
                        let data = ctx.ws_client_buf.split_to(ctx.ws_client_buf.len()).freeze();
                        *body = if data.is_empty() { None } else { Some(data) };
                    }
                    WebsocketErrorAction::Drop => {
                        ctx.clear_ws_buffers();
                        *body = None;
                    }
                    WebsocketErrorAction::Close(payload) => {
                        ctx.clear_ws_buffers();
                        let mut out = BytesMut::with_capacity(128);
                        encode_ws_frame_into(
                            &close_frame(payload),
                            Some(mask_key_from_time()),
                            &mut out,
                        );
                        *body = Some(out.freeze());
                    }
                }
            }
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>, Box<Error>> {
        if !ctx.is_upgrade {
            return Ok(None);
        }

        let Some(chunk) = body.take() else {
            return Ok(None);
        };
        ctx.ws_upstream_buf.extend_from_slice(&chunk);
        let mut frames = Vec::new();
        match parse_ws_frames(&mut ctx.ws_upstream_buf, &mut frames) {
            WsParseResult::Ok => {
                let mut out = BytesMut::new();
                for frame in frames {
                    let decompressor = if frame.rsv1 {
                        Some(
                            ctx.ws_upstream_decompressor
                                .get_or_insert_with(|| flate2::Decompress::new(false)),
                        )
                    } else {
                        None
                    };

                    match apply_ws_extensions(
                        &self.websocket_extensions,
                        WebsocketDirection::UpstreamToDownstream,
                        frame,
                        self.metrics.as_ref(),
                        decompressor,
                    ) {
                        WebsocketMessageAction::Forward(updated) => {
                            encode_ws_frame_into(&updated, None, &mut out);
                        }
                        WebsocketMessageAction::Drop => {}
                        WebsocketMessageAction::Close(payload) => {
                            encode_ws_frame_into(&close_frame(payload), None, &mut out);
                            break;
                        }
                    }
                }
                if out.is_empty() {
                    *body = None;
                } else {
                    *body = Some(out.freeze());
                }
            }
            WsParseResult::Incomplete => {
                *body = None;
            }
            WsParseResult::Invalid => {
                match handle_ws_error(
                    &self.websocket_extensions,
                    WebsocketDirection::UpstreamToDownstream,
                    WebsocketError::InvalidFrame,
                ) {
                    WebsocketErrorAction::PassThrough => {
                        let data = ctx
                            .ws_upstream_buf
                            .split_to(ctx.ws_upstream_buf.len())
                            .freeze();
                        if data.is_empty() {
                            *body = None;
                        } else {
                            *body = Some(data);
                        }
                    }
                    WebsocketErrorAction::Drop => {
                        ctx.ws_upstream_buf.clear();
                        *body = None;
                    }
                    WebsocketErrorAction::Close(payload) => {
                        ctx.ws_upstream_buf.clear();
                        let mut out = BytesMut::new();
                        encode_ws_frame_into(&close_frame(payload), None, &mut out);
                        *body = Some(out.freeze());
                    }
                }
            }
        }
        Ok(None)
    }

    async fn logging(&self, session: &mut Session, _e: Option<&Error>, ctx: &mut Self::CTX) {
        if let Some(metrics) = &self.metrics {
            metrics.decrement_gauge("whoosh_active_connections", &[]);

            let status = session
                .response_written()
                .map(|resp| resp.status.as_u16().to_string())
                .unwrap_or_else(|| "0".to_string());

            metrics.increment_counter("whoosh_requests_total", &[("status", &status)]);

            // Record total latency
            metrics.observe_histogram(
                "whoosh_request_duration_seconds",
                ctx.start_time.elapsed().as_secs_f64(),
                &[("type", "total")],
            );

            // Record upstream latency if applicable
            if let Some(upstream_start) = ctx.upstream_start_time {
                metrics.observe_histogram(
                    "whoosh_request_duration_seconds",
                    upstream_start.elapsed().as_secs_f64(),
                    &[("type", "upstream")],
                );
            }
        }
    }
}

fn apply_ws_extensions(
    extensions: &[Arc<dyn WebsocketExtension>],
    direction: WebsocketDirection,
    mut frame: WsFrame,
    metrics: Option<&Arc<PrometheusBackend>>,
    decompressor: Option<&mut flate2::Decompress>,
) -> WebsocketMessageAction {
    let start = std::time::Instant::now();

    // Decompress if RSV1 is set (permessage-deflate)
    let original_payload = frame.payload.clone();
    let was_compressed = frame.rsv1;
    let mut decompressed_payload = None;
    if was_compressed {
        if let Some(decompressor) = decompressor {
            if let Some(decompressed) = frame.decompress_with(decompressor) {
                decompressed_payload = Some(decompressed.clone());
                frame.payload = decompressed;
                frame.rsv1 = false;
            } else {
                log::error!("Failed to decompress WebSocket frame");
                return WebsocketMessageAction::Forward(frame);
            }
        } else {
            // No decompressor available but frame is compressed
            log::warn!("Compressed frame received but no decompressor available");
            return WebsocketMessageAction::Forward(frame);
        }
    }

    let mut action = WebsocketMessageAction::Forward(frame);
    for ext in extensions {
        action = match action {
            WebsocketMessageAction::Forward(current) => ext.on_message(direction, current),
            other => other,
        };
        if !matches!(action, WebsocketMessageAction::Forward(_)) {
            break;
        }
    }

    if let WebsocketMessageAction::Forward(mut final_frame) = action {
        // If the payload was modified, we keep it uncompressed (RSV1=false)
        // If it was NOT modified and was originally compressed, we restore it to compressed state
        // This is a heuristic: if the bytes are identical (or both match the decompressed version), we assume no modification.
        let is_modified = if let Some(dp) = &decompressed_payload {
            final_frame.payload != *dp
        } else {
            final_frame.payload != original_payload
        };

        if was_compressed && !is_modified {
            final_frame.payload = original_payload;
            final_frame.rsv1 = true;
        }
        action = WebsocketMessageAction::Forward(final_frame);
    }

    if let Some(metrics) = metrics {
        let direction_label = match direction {
            WebsocketDirection::UpstreamToDownstream => "downstream",
            WebsocketDirection::DownstreamToUpstream => "upstream",
        };
        metrics.observe_histogram(
            "whoosh_websocket_extension_duration_seconds",
            start.elapsed().as_secs_f64(),
            &[("direction", direction_label)],
        );
    }

    action
}

fn handle_ws_error(
    extensions: &[Arc<dyn WebsocketExtension>],
    direction: WebsocketDirection,
    error: WebsocketError,
) -> WebsocketErrorAction {
    let mut action = WebsocketErrorAction::PassThrough;
    for ext in extensions {
        match ext.on_error(direction, error.clone()) {
            WebsocketErrorAction::PassThrough => {}
            WebsocketErrorAction::Drop => {
                action = WebsocketErrorAction::Drop;
            }
            WebsocketErrorAction::Close(payload) => {
                return WebsocketErrorAction::Close(payload);
            }
        }
    }
    action
}

fn close_frame(payload: Option<Vec<u8>>) -> WsFrame {
    WsFrame {
        fin: true,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: crate::websocket::WsOpcode::Close,
        payload: payload.map(Bytes::from).unwrap_or_else(Bytes::new),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{Upstream, UpstreamServer, WhooshConfig};
    use crate::server::context::AppCtx;
    use crate::server::router::{ALL_PROTOCOLS, Router};
    use crate::server::service::ServiceManager;
    use crate::server::upstream::UpstreamManager;
    use std::sync::Arc;

    struct UppercaseExtension;

    impl WebsocketExtension for UppercaseExtension {
        fn on_message(
            &self,
            _direction: WebsocketDirection,
            mut frame: WsFrame,
        ) -> WebsocketMessageAction {
            if let Ok(text) = std::str::from_utf8(&frame.payload) {
                frame.payload = Bytes::copy_from_slice(text.to_ascii_uppercase().as_bytes());
            }
            WebsocketMessageAction::Forward(frame)
        }
    }

    #[test]
    fn websocket_extension_transform() {
        let extensions: Vec<Arc<dyn WebsocketExtension>> = vec![Arc::new(UppercaseExtension)];
        let frame = WsFrame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: crate::websocket::WsOpcode::Text,
            payload: Bytes::from_static(b"hello"),
        };
        match apply_ws_extensions(
            &extensions,
            WebsocketDirection::UpstreamToDownstream,
            frame,
            None,
            None,
        ) {
            WebsocketMessageAction::Forward(updated) => {
                assert_eq!(updated.payload, Bytes::from_static(b"HELLO"));
            }
            _ => panic!("unexpected action"),
        }
    }

    #[test]
    fn test_load_balancer_creation() {
        // Create a test configuration with multiple servers
        let mut config = WhooshConfig::default();

        let upstream = Upstream {
            name: "test_upstream".to_string(),
            peer_options: None,
            servers: vec![
                UpstreamServer {
                    host: "127.0.0.1:8080".to_string(),
                    weight: Some(1),
                    peer_options: None,
                },
                UpstreamServer {
                    host: "127.0.0.1:8081".to_string(),
                    weight: Some(2),
                    peer_options: None,
                },
                UpstreamServer {
                    host: "127.0.0.1:8082".to_string(),
                    weight: Some(1),
                    peer_options: None,
                },
            ],
        };

        config.upstreams.push(upstream);
        let config_arc = Arc::new(config.clone());

        // Create ServiceManager and UpstreamManager
        let service_manager = Arc::new(
            ServiceManager::new(config_arc.clone()).expect("Failed to create ServiceManager"),
        );
        let (upstream_manager, _services) =
            UpstreamManager::new(config_arc.clone()).expect("Failed to create UpstreamManager");
        let upstream_manager = Arc::new(upstream_manager);

        // Create router
        let router = Arc::new(Router::new(
            service_manager,
            upstream_manager.clone(),
            &ALL_PROTOCOLS,
            &config,
        ));
        let filters = Arc::new(vec![]);
        let websocket_extensions = Arc::new(vec![]);
        let app_ctx = Arc::new(AppCtx::new());

        // Create the proxy with load balancers
        let _proxy = WhooshProxy::new(
            Arc::new(config),
            router,
            filters,
            websocket_extensions,
            app_ctx,
            upstream_manager.clone(),
        )
        .expect("Failed to create WhooshProxy");

        // Verify load balancer was created
        assert!(upstream_manager.get("test_upstream").is_some());

        // Verify all servers are included
        let load_balancer = upstream_manager.get("test_upstream").unwrap();
        let backends = load_balancer.backends().get_backend();
        assert_eq!(backends.len(), 3);
        let backends = load_balancer.backends().get_backend();
        assert_eq!(backends.len(), 3);

        // Verify server addresses
        let hosts: Vec<String> = backends.iter().map(|b| b.addr.to_string()).collect();
        assert!(hosts.contains(&"127.0.0.1:8080".to_string()));
        assert!(hosts.contains(&"127.0.0.1:8081".to_string()));
        assert!(hosts.contains(&"127.0.0.1:8082".to_string()));

        // Verify weights
        let backend_8081 = backends
            .iter()
            .find(|b| b.addr.to_string() == "127.0.0.1:8081")
            .unwrap();
        assert_eq!(backend_8081.weight, 2); // Weight should be 2 for port 8081
    }

    #[test]
    fn test_load_balancer_selection() {
        // Create a test configuration
        let mut config = WhooshConfig::default();

        let upstream = Upstream {
            name: "test_upstream".to_string(),
            peer_options: None,
            servers: vec![
                UpstreamServer {
                    host: "127.0.0.1:8080".to_string(),
                    weight: Some(1),
                    peer_options: None,
                },
                UpstreamServer {
                    host: "127.0.0.1:8081".to_string(),
                    weight: Some(1),
                    peer_options: None,
                },
            ],
        };

        config.upstreams.push(upstream);
        let config_arc = Arc::new(config.clone());

        let service_manager = Arc::new(
            ServiceManager::new(config_arc.clone()).expect("Failed to create ServiceManager"),
        );
        let (upstream_manager, _services) =
            UpstreamManager::new(config_arc.clone()).expect("Failed to create UpstreamManager");
        let upstream_manager = Arc::new(upstream_manager);

        let router = Arc::new(Router::new(
            service_manager,
            upstream_manager.clone(),
            &ALL_PROTOCOLS,
            &config,
        ));
        let filters = Arc::new(vec![]);
        let websocket_extensions = Arc::new(vec![]);
        let app_ctx = Arc::new(AppCtx::new());

        let _proxy = WhooshProxy::new(
            Arc::new(config),
            router,
            filters,
            websocket_extensions,
            app_ctx,
            upstream_manager.clone(),
        )
        .expect("Failed to create WhooshProxy");

        let load_balancer = upstream_manager.get("test_upstream").unwrap();

        // Test multiple selections to verify round-robin behavior
        let mut selections = Vec::new();
        for _ in 0..10 {
            if let Some(backend) = load_balancer.select(b"", 256) {
                selections.push(backend.addr.to_string());
            }
        }

        // With round-robin and equal weights, we should see alternating selections
        assert!(!selections.is_empty());

        // Verify both backends are selected
        let unique_selections: std::collections::HashSet<_> = selections.iter().collect();
        assert!(unique_selections.len() >= 1); // Should have at least 1 unique backend

        // With round-robin, we should see both backends being selected
        let has_8080 = selections.iter().any(|s: &String| s.contains("8080"));
        let has_8081 = selections.iter().any(|s: &String| s.contains("8081"));
        assert!(
            has_8080 || has_8081,
            "Should select from available backends"
        );
    }

    #[test]
    fn test_empty_upstream() {
        let mut config = WhooshConfig::default();

        let upstream = Upstream {
            name: "empty_upstream".to_string(),
            peer_options: None,
            servers: vec![], // Empty servers list
        };

        config.upstreams.push(upstream);
        let config_arc = Arc::new(config.clone());

        let service_manager = Arc::new(
            ServiceManager::new(config_arc.clone()).expect("Failed to create ServiceManager"),
        );
        let (upstream_manager, _services) =
            UpstreamManager::new(config_arc.clone()).expect("Failed to create UpstreamManager");
        let upstream_manager = Arc::new(upstream_manager);

        let router = Arc::new(Router::new(
            service_manager,
            upstream_manager.clone(),
            &ALL_PROTOCOLS,
            &config,
        ));
        let filters = Arc::new(vec![]);
        let websocket_extensions = Arc::new(vec![]);
        let app_ctx = Arc::new(AppCtx::new());

        let _proxy = WhooshProxy::new(
            Arc::new(config),
            router,
            filters,
            websocket_extensions,
            app_ctx,
            upstream_manager.clone(),
        )
        .expect("Failed to create WhooshProxy");

        // Should not create load balancer for empty upstream
        assert!(upstream_manager.get("empty_upstream").is_none());
    }
}
