use arc_swap::ArcSwap;
use std::sync::Arc;

use crate::config::models::{ServiceProtocol, WhooshConfig};
use crate::router::parse_rule;
use crate::transformer::{
    RequestTransformer, ResponseTransformer, parse_response_transformers, parse_transformers,
};

/// Pre-computed protocol sets for faster lookups
pub const HTTP_PROTOCOLS: [ServiceProtocol; 2] = [ServiceProtocol::Http, ServiceProtocol::Ws];
pub const HTTPS_PROTOCOLS: [ServiceProtocol; 2] = [ServiceProtocol::Https, ServiceProtocol::Wss];
pub const ALL_PROTOCOLS: [ServiceProtocol; 4] = [
    ServiceProtocol::Http,
    ServiceProtocol::Https,
    ServiceProtocol::Ws,
    ServiceProtocol::Wss,
];

use crate::router::Matcher;

pub struct RuntimeRoute {
    pub matcher: Box<dyn Matcher>,
    pub priority: i32,
    pub req_transformer: Option<Arc<dyn RequestTransformer>>,
    pub res_transformer: Option<Arc<dyn ResponseTransformer>>,
}

pub struct RuntimeService {
    pub name: String,
    pub host: String, // Upstream name
    pub protocols: Vec<ServiceProtocol>,
    pub routes: Vec<RuntimeRoute>,
}

/// ServiceManager compiles services and rules from config and stores them grouped by protocol.
pub struct ServiceManager {
    /// All compiled services
    services: ArcSwap<Vec<RuntimeService>>,
}

use crate::error::WhooshError;

impl ServiceManager {
    pub fn new(config: Arc<WhooshConfig>) -> Result<Self, WhooshError> {
        let services = Self::compile_services(&config);
        Ok(Self {
            services: ArcSwap::from_pointee(services),
        })
    }

    fn compile_services(config: &WhooshConfig) -> Vec<RuntimeService> {
        use crate::router::registry::register_hosts;

        // Sequential service compilation
        let services: Vec<RuntimeService> = config
            .services
            .iter()
            .map(|svc_config| {
                let mut routes = Vec::new();

                for route_config in &svc_config.routes {
                    for rule_config in &route_config.rules {
                        // Parse Matcher
                        let matcher = match parse_rule(&rule_config.rule) {
                            Ok(m) => m,
                            Err(e) => {
                                log::error!(
                                    "Rule parse error [service={}, route={}, rule={}]: {}",
                                    svc_config.name,
                                    route_config.name,
                                    rule_config.rule,
                                    e
                                );
                                continue;
                            }
                        };

                        // Parse Request Transformer
                        let req_transformer = rule_config.request_transformer.as_ref().and_then(
                            |t_str| match parse_transformers(t_str) {
                                Ok(t) => Some(Arc::from(t)),
                                Err(e) => {
                                    log::error!(
                                    "Request transformer parse error [service={}, route={}, transformer={}]: {}",
                                    svc_config.name,
                                    route_config.name,
                                    t_str,
                                    e
                                );
                                    None
                                }
                            },
                        );

                        // Parse Response Transformer
                        let res_transformer = rule_config.response_transformer.as_ref().and_then(
                            |t_str| match parse_response_transformers(t_str) {
                                Ok(t) => Some(Arc::from(t)),
                                Err(e) => {
                                    log::error!(
                                    "Response transformer parse error [service={}, route={}, transformer={}]: {}",
                                    svc_config.name,
                                    route_config.name,
                                    t_str,
                                    e
                                );
                                    None
                                }
                            },
                        );

                        routes.push(RuntimeRoute {
                            matcher,
                            priority: rule_config.priority.unwrap_or(0),
                            req_transformer,
                            res_transformer,
                        });
                    }
                }

                // Sort routes by priority (descending)
                routes.sort_by(|a, b| b.priority.cmp(&a.priority));

                RuntimeService {
                    name: svc_config.name.clone(),
                    host: svc_config.host.clone(),
                    protocols: svc_config.protocols.clone(),
                    routes,
                }
            })
            .collect();

        // Batch register all hosts for ACME (performance optimization)
        let mut all_hosts = std::collections::HashSet::new();
        for svc in &services {
            for route in &svc.routes {
                for host in route.matcher.get_hosts() {
                    all_hosts.insert(host);
                }
            }
        }
        register_hosts(all_hosts);

        services
    }

    /// Get indices of services matching allowed protocols.
    /// Services with empty protocols are accessible through all protocols.
    pub fn get_indices_for_protocols(&self, allowed_protocols: &[ServiceProtocol]) -> Vec<usize> {
        let services = self.services.load();
        services
            .iter()
            .enumerate()
            .filter_map(|(idx, svc)| {
                if svc.protocols.is_empty() {
                    // Services with no protocols specified are accessible through all protocols
                    Some(idx)
                } else if svc.protocols.iter().any(|p| allowed_protocols.contains(p)) {
                    Some(idx)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get all compiled services
    pub fn get_all(&self) -> arc_swap::Guard<Arc<Vec<RuntimeService>>> {
        self.services.load()
    }

    /// Reload services from new config
    pub fn reload(&self, config: &WhooshConfig) {
        let services = Self::compile_services(config);
        self.services.store(Arc::new(services));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{Route, Rule, Service, WhooshConfig};

    #[test]
    fn test_protocol_filtering() {
        let mut config = WhooshConfig::default();

        config.services = vec![
            Service {
                name: "http_only".to_string(),
                host: "http_backend".to_string(),
                protocols: vec![ServiceProtocol::Http],
                routes: vec![],
            },
            Service {
                name: "https_only".to_string(),
                host: "https_backend".to_string(),
                protocols: vec![ServiceProtocol::Https],
                routes: vec![],
            },
            Service {
                name: "dual_protocol".to_string(),
                host: "dual_backend".to_string(),
                protocols: vec![ServiceProtocol::Http, ServiceProtocol::Https],
                routes: vec![],
            },
            Service {
                name: "no_protocol".to_string(),
                host: "default_backend".to_string(),
                protocols: vec![],
                routes: vec![],
            },
        ];

        let manager =
            ServiceManager::new(Arc::new(config)).expect("Failed to create ServiceManager");
        let all_services = manager.get_all();

        // Helper to get service names from indices
        let get_names = |indices: Vec<usize>| -> Vec<String> {
            indices
                .iter()
                .map(|&i| all_services[i].name.clone())
                .collect()
        };

        // Test HTTP protocols
        let http_indices = manager.get_indices_for_protocols(&HTTP_PROTOCOLS);
        let http_names = get_names(http_indices.clone());
        assert_eq!(http_indices.len(), 3); // http_only, dual_protocol, no_protocol
        assert!(http_names.contains(&"http_only".to_string()));
        assert!(http_names.contains(&"dual_protocol".to_string()));
        assert!(http_names.contains(&"no_protocol".to_string()));
        assert!(!http_names.contains(&"https_only".to_string()));

        // Test HTTPS protocols
        let https_indices = manager.get_indices_for_protocols(&HTTPS_PROTOCOLS);
        let https_names = get_names(https_indices.clone());
        assert_eq!(https_indices.len(), 3); // https_only, dual_protocol, no_protocol
        assert!(https_names.contains(&"https_only".to_string()));
        assert!(https_names.contains(&"dual_protocol".to_string()));
        assert!(https_names.contains(&"no_protocol".to_string()));
        assert!(!https_names.contains(&"http_only".to_string()));

        // Test all protocols
        let all_indices = manager.get_indices_for_protocols(&ALL_PROTOCOLS);
        assert_eq!(all_indices.len(), 4);
    }

    #[test]
    fn test_service_compilation() {
        let mut config = WhooshConfig::default();

        config.services = vec![Service {
            name: "test_service".to_string(),
            host: "test_backend".to_string(),
            protocols: vec![ServiceProtocol::Http],
            routes: vec![Route {
                name: "test_route".to_string(),
                rules: vec![
                    Rule {
                        rule: "Host(`example.com`)".to_string(),
                        priority: Some(10),
                        request_transformer: None,
                        response_transformer: None,
                    },
                    Rule {
                        rule: "Host(`api.example.com`)".to_string(),
                        priority: Some(5),
                        request_transformer: None,
                        response_transformer: None,
                    },
                ],
            }],
        }];

        let manager =
            ServiceManager::new(Arc::new(config)).expect("Failed to create ServiceManager");
        let services = manager.get_all();

        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name, "test_service");
        assert_eq!(services[0].routes.len(), 2);

        // Routes should be sorted by priority (descending)
        assert_eq!(services[0].routes[0].priority, 10);
        assert_eq!(services[0].routes[1].priority, 5);
    }
}
