use crate::config::models::ServiceProtocol;
use crate::server::service::ServiceManager;
use crate::server::upstream::UpstreamManager;
use crate::transformer::{RequestTransformer, ResponseTransformer};
use pingora::http::RequestHeader;
use std::sync::Arc;

// Re-export protocol constants from service module
pub use crate::server::service::{ALL_PROTOCOLS, HTTP_PROTOCOLS, HTTPS_PROTOCOLS};

pub struct RouteMatch {
    pub upstream_name: String,
    pub req_transformer: Option<Arc<dyn RequestTransformer>>,
    pub res_transformer: Option<Arc<dyn ResponseTransformer>>,
}

/// Router evaluates rules and transformers for request matching.
/// Requires ServiceManager and UpstreamManager for initialization.
pub struct Router {
    service_manager: Arc<ServiceManager>,
    upstream_manager: Arc<UpstreamManager>,
    /// Indices of services from ServiceManager that match the allowed protocols
    service_indices: Vec<usize>,
}

impl Router {
    pub fn new(
        service_manager: Arc<ServiceManager>,
        upstream_manager: Arc<UpstreamManager>,
        protocols: &[ServiceProtocol],
        _config: &crate::config::models::WhooshConfig,
    ) -> Self {
        let service_indices = service_manager.get_indices_for_protocols(protocols);

        Router {
            service_manager,
            upstream_manager,
            service_indices,
        }
    }

    pub fn match_request(&self, req_header: &RequestHeader) -> Option<RouteMatch> {
        let all_services = self.service_manager.get_all();

        // Only iterate over services that match our protocols
        for &idx in &self.service_indices {
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
        ];

        config
    }

    #[test]
    fn test_protocol_restriction() {
        let config = create_test_config();
        let config_arc = Arc::new(config.clone());

        let service_manager = Arc::new(
            ServiceManager::new(config_arc.clone()).expect("Failed to create ServiceManager"),
        );
        let (upstream_manager, _) =
            UpstreamManager::new(config_arc.clone()).expect("Failed to create UpstreamManager");
        let upstream_manager = Arc::new(upstream_manager);

        // Test HTTP router (should only include HTTP-compatible services)
        let http_router = Router::new(
            service_manager.clone(),
            upstream_manager.clone(),
            &HTTP_PROTOCOLS,
            &config,
        );
        assert_eq!(http_router.service_indices.len(), 3);

        // Test HTTPS router (should only include HTTPS-compatible services)
        let https_router = Router::new(
            service_manager.clone(),
            upstream_manager.clone(),
            &HTTPS_PROTOCOLS,
            &config,
        );
        assert_eq!(https_router.service_indices.len(), 3);

        // Test with all protocols (should include all services)
        let all_router = Router::new(
            service_manager.clone(),
            upstream_manager.clone(),
            &ALL_PROTOCOLS,
            &config,
        );
        assert_eq!(all_router.service_indices.len(), 4);
    }
}
