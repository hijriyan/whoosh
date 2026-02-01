use crate::config::models::ServiceProtocol;

use crate::server::service::ServiceManager;
use crate::server::upstream::UpstreamManager;
use crate::transformer::{RequestTransformer, ResponseTransformer};
use arc_swap::ArcSwap;
use pingora::http::RequestHeader;
use std::sync::Arc;

// Re-export protocol constants from service module
pub use crate::server::service::{ALL_PROTOCOLS, HTTP_PROTOCOLS, HTTPS_PROTOCOLS};

pub struct RouteMatch {
    pub upstream_name: Arc<str>,
    pub req_transformer: Option<Arc<dyn RequestTransformer>>,
    pub res_transformer: Option<Arc<dyn ResponseTransformer>>,
}

/// Router evaluates rules and transformers for request matching.
/// Requires ServiceManager and UpstreamManager for initialization.
pub struct Router {
    service_manager: Arc<ServiceManager>,
    upstream_manager: Arc<UpstreamManager>,
    /// Indices of services from ServiceManager that match the allowed protocols
    service_indices: ArcSwap<Vec<usize>>,
    /// Protocols this router handles (needed for refresh)
    protocols: Vec<ServiceProtocol>,
}

impl Router {
    pub fn new(
        service_manager: Arc<ServiceManager>,
        upstream_manager: Arc<UpstreamManager>,
        protocols: &[ServiceProtocol],
        // _config: &crate::config::models::WhooshConfig,
    ) -> Arc<Self> {
        let service_indices = service_manager.get_indices_for_protocols(protocols);

        let router = Arc::new(Router {
            service_manager: service_manager.clone(),
            upstream_manager,
            service_indices: ArcSwap::from_pointee(service_indices),
            protocols: protocols.to_vec(),
        });

        // Register callback to refresh indices when services change
        let router_weak = Arc::downgrade(&router);
        service_manager.add_services_changed_callback(move || {
            if let Some(r) = router_weak.upgrade() {
                r.refresh_indices();
            }
        });

        router
    }

    /// Refresh service indices based on current services and protocols
    pub fn refresh_indices(&self) {
        let new_indices = self
            .service_manager
            .get_indices_for_protocols(&self.protocols);
        self.service_indices.store(Arc::new(new_indices));
        log::debug!("Router indices refreshed");
    }

    pub fn match_request(&self, req_header: &RequestHeader) -> Option<RouteMatch> {
        let all_services = self.service_manager.get_all();
        let service_indices = self.service_indices.load();

        // Only iterate over services that match our protocols
        for &idx in service_indices.iter() {
            let service = &all_services[idx];
            for route in &service.routes {
                if route.matcher.matches(req_header) {
                    return Some(RouteMatch {
                        upstream_name: service.host.clone(),
                        req_transformer: route.req_transformer.clone(),
                        res_transformer: route.res_transformer.clone(),
                    });
                }
            }
        }
        None
    }

    pub fn upstream_manager(&self) -> &Arc<UpstreamManager> {
        &self.upstream_manager
    }

    pub fn service_manager(&self) -> &Arc<ServiceManager> {
        &self.service_manager
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{Route, Rule, Service, ServiceProtocol, WhooshConfig};
    use crate::extensions::dns::DnsResolver;
    use crate::server::context::AppCtx;

    fn create_test_config() -> WhooshConfig {
        let mut config = WhooshConfig::default();

        config.services = vec![
            Service {
                name: "http_only".to_string(),
                host: "http_backend".to_string(),
                protocols: vec![ServiceProtocol::Http],
                routes: vec![Route {
                    name: "http_route".to_string(),
                    rules: vec![Rule {
                        rule: "Host(`example.com`)".to_string(),
                        priority: None,
                        request_transformer: None,
                        response_transformer: None,
                    }],
                }],
            },
            Service {
                name: "https_only".to_string(),
                host: "https_backend".to_string(),
                protocols: vec![ServiceProtocol::Https],
                routes: vec![Route {
                    name: "https_route".to_string(),
                    rules: vec![Rule {
                        rule: "Host(`secure.example.com`)".to_string(),
                        priority: None,
                        request_transformer: None,
                        response_transformer: None,
                    }],
                }],
            },
            Service {
                name: "dual_protocol".to_string(),
                host: "dual_backend".to_string(),
                protocols: vec![ServiceProtocol::Http, ServiceProtocol::Https],
                routes: vec![Route {
                    name: "dual_route".to_string(),
                    rules: vec![Rule {
                        rule: "Host(`dual.example.com`)".to_string(),
                        priority: None,
                        request_transformer: None,
                        response_transformer: None,
                    }],
                }],
            },
            Service {
                name: "no_protocol".to_string(),
                host: "default_backend".to_string(),
                protocols: vec![],
                routes: vec![Route {
                    name: "default_route".to_string(),
                    rules: vec![Rule {
                        rule: "Host(`default.example.com`)".to_string(),
                        priority: None,
                        request_transformer: None,
                        response_transformer: None,
                    }],
                }],
            },
        ]
        .into_iter()
        .map(Arc::new)
        .collect();

        config
    }

    #[test]
    fn test_protocol_restriction() {
        let config = create_test_config();
        let config_arc = Arc::new(config.clone());

        let service_manager = Arc::new(
            ServiceManager::new(config_arc.clone()).expect("Failed to create ServiceManager"),
        );

        let app_ctx = AppCtx::new();
        app_ctx.insert(config.clone());
        app_ctx.insert(DnsResolver::new(&config));

        let (upstream_manager, _) =
            UpstreamManager::new(&app_ctx).expect("Failed to create UpstreamManager");
        let upstream_manager = Arc::new(upstream_manager);

        // Test HTTP router (should only include HTTP-compatible services)
        let http_router = Router::new(
            service_manager.clone(),
            upstream_manager.clone(),
            &HTTP_PROTOCOLS,
            // &config,
        );
        assert_eq!(http_router.service_indices.load().len(), 3);

        // Test HTTPS router (should only include HTTPS-compatible services)
        let https_router = Router::new(
            service_manager.clone(),
            upstream_manager.clone(),
            &HTTPS_PROTOCOLS,
            // &config,
        );
        assert_eq!(https_router.service_indices.load().len(), 3);

        // Test with all protocols (should include all services)
        let all_router = Router::new(
            service_manager.clone(),
            upstream_manager.clone(),
            &ALL_PROTOCOLS,
            // &config,
        );
        assert_eq!(all_router.service_indices.load().len(), 4);
    }

    #[test]
    fn test_router_refresh_on_service_changes() {
        let config = create_test_config();
        let config_arc = Arc::new(config.clone());

        let service_manager = Arc::new(
            ServiceManager::new(config_arc.clone()).expect("Failed to create ServiceManager"),
        );

        let app_ctx = AppCtx::new();
        app_ctx.insert(config.clone());
        app_ctx.insert(DnsResolver::new(&config));

        let (upstream_manager, _) =
            UpstreamManager::new(&app_ctx).expect("Failed to create UpstreamManager");
        let upstream_manager = Arc::new(upstream_manager);

        // Create router with HTTP protocols
        let http_router = Router::new(
            service_manager.clone(),
            upstream_manager.clone(),
            &HTTP_PROTOCOLS,
            // &config,
        );

        // Initial state: 3 HTTP-compatible services
        assert_eq!(http_router.service_indices.load().len(), 3);

        // Add a new HTTP service
        let new_service = Service {
            name: "new_http_service".to_string(),
            host: "new_backend".to_string(),
            protocols: vec![ServiceProtocol::Http],
            routes: vec![Route {
                name: "new_route".to_string(),
                rules: vec![Rule {
                    rule: "Host(`new.example.com`)".to_string(),
                    priority: None,
                    request_transformer: None,
                    response_transformer: None,
                }],
            }],
        };

        service_manager
            .add_service(new_service)
            .expect("Failed to add service");

        // Router should automatically refresh and now have 4 services
        assert_eq!(http_router.service_indices.load().len(), 4);

        // Remove a service
        service_manager
            .remove_service("http_only")
            .expect("Failed to remove service");

        // Router should automatically refresh and now have 3 services
        assert_eq!(http_router.service_indices.load().len(), 3);
    }
}
