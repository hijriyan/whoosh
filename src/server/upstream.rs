use crate::config::models::WhooshConfig;
use crate::error::WhooshError;
use crate::server::discovery::DnsDiscovery;
use crate::server::proxy::{CachedPeerConfig, merge_peer_options};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora::lb::Backends;
use pingora::lb::discovery::ServiceDiscovery;
use pingora::lb::{LoadBalancer, selection::weighted::Weighted};
use pingora::server::ShutdownWatch;
use pingora::services::background::{BackgroundService, GenBackgroundService};
use std::collections::HashMap;
use std::sync::Arc;

pub struct LbWrapper(pub Arc<LoadBalancer<Weighted>>);

#[async_trait]
impl BackgroundService for LbWrapper {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        self.0.start(shutdown.clone()).await;

        // If start() returns early (e.g. no background tasks like health checks enabled),
        // we wait for the actual shutdown signal to avoid triggering "service exited" logs.
        let _ = shutdown.changed().await;
    }
}

pub type LbBackgroundService = GenBackgroundService<LbWrapper>;

pub struct UpstreamManager {
    pub load_balancers: ArcSwap<HashMap<String, Arc<LoadBalancer<Weighted>>>>,
}

impl UpstreamManager {
    pub fn new(config: Arc<WhooshConfig>) -> Result<(Self, Vec<LbBackgroundService>), WhooshError> {
        let mut load_balancers = HashMap::new();
        let mut services: Vec<LbBackgroundService> = Vec::new();

        // Create load balancers for each upstream
        for upstream in &config.upstreams {
            if upstream.servers.is_empty() {
                log::warn!(
                    "Upstream {} has no servers, skipping load balancer creation",
                    upstream.name
                );
                continue;
            }

            // Create server config tuples
            let mut server_configs = Vec::new();
            for server in &upstream.servers {
                let mut merged_options = merge_peer_options(
                    upstream.peer_options.as_ref(),
                    server.peer_options.as_ref(),
                );

                // Smart SNI Fallback:
                // If SNI is not explicitly configured, and the host looks like a domain name
                // (not an IP address), use the host as the SNI.
                if merged_options.sni.is_none() {
                    let host_only = server.host.split(':').next().unwrap_or(&server.host);
                    // Simple check: if it parses as IP, it's an IP. Otherwise treat as domain.
                    // This avoids setting SNI for IP addresses which is generally invalid/useless.
                    if host_only.parse::<std::net::IpAddr>().is_err() {
                        merged_options.sni = Some(host_only.to_string());
                        log::debug!(
                            "Automatically setting SNI to '{}' for upstream {}",
                            host_only,
                            upstream.name
                        );
                    }
                }

                match CachedPeerConfig::new(merged_options) {
                    Ok(cached_config) => {
                        server_configs.push((server.clone(), cached_config));
                    }
                    Err(e) => {
                        log::error!(
                            "Failed to create cached peer config for {}: {}",
                            server.host,
                            e
                        );
                        // We continue here to try other servers, but could optionally fail hard
                    }
                }
            }

            if server_configs.is_empty() {
                log::warn!(
                    "No valid server configs for upstream {}, skipping",
                    upstream.name
                );
                continue;
            }

            // Use Box for discovery as required by Backends
            let discovery: Box<dyn ServiceDiscovery + Send + Sync> = Box::new(DnsDiscovery {
                servers: server_configs,
            });
            let backends = Backends::new(discovery);
            let load_balancer = LoadBalancer::from_backends(backends);
            // Wrap in Arc and LbWrapper
            let lb_arc = Arc::new(load_balancer);
            load_balancers.insert(upstream.name.clone(), lb_arc.clone());

            let background = GenBackgroundService::new(
                format!("lb_{}", upstream.name),
                Arc::new(LbWrapper(lb_arc)),
            );
            services.push(background);
        }

        Ok((
            UpstreamManager {
                load_balancers: ArcSwap::from_pointee(load_balancers),
            },
            services,
        ))
    }

    pub fn get(&self, name: &str) -> Option<Arc<LoadBalancer<Weighted>>> {
        self.load_balancers.load().get(name).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{PeerOptions, Upstream, UpstreamServer};

    #[test]
    fn test_sni_fallback() {
        // We'll simulate the logic inside UpstreamManager::new by extracting the relevant block
        // or just testing the result via creating a config.
        // Creating config is cleaner as it tests integration.

        let mut config = WhooshConfig::default();
        config.upstreams = vec![
            Upstream {
                name: "domain_upstream".to_string(),
                peer_options: None,
                servers: vec![UpstreamServer {
                    host: "example.com:443".to_string(), // Should get SNI
                    weight: None,
                    peer_options: None,
                }],
            },
            Upstream {
                name: "ip_upstream".to_string(),
                peer_options: None,
                servers: vec![UpstreamServer {
                    host: "127.0.0.1:8080".to_string(), // Should NOT get SNI
                    weight: None,
                    peer_options: None,
                }],
            },
            Upstream {
                name: "explicit_sni".to_string(),
                peer_options: None,
                servers: vec![UpstreamServer {
                    host: "example.org:443".to_string(),
                    weight: None,
                    peer_options: Some(PeerOptions {
                        sni: Some("custom.example.org".to_string()), // Should preserve custom SNI
                        ..Default::default()
                    }),
                }],
            },
        ];

        let (manager, _) =
            UpstreamManager::new(Arc::new(config)).expect("Failed to create manager");

        // To verify, we would ideally inspect the CachedPeerConfig in the LoadBalancer.
        // However, LoadBalancer internals are private.
        // We might need to rely on the fact that we can call get_backend() if we mock things, but that's hard.
        // Instead, let's verify via the logs (manual) or trust the logic if we could unit test the logic directly.
        // Or we can query the load balancer's backends and check extensions if accessible.

        let lb_domain = manager.get("domain_upstream").unwrap();
        let backends = lb_domain.backends().get_backend();
        let config_domain = backends
            .iter()
            .next()
            .unwrap()
            .ext
            .get::<CachedPeerConfig>()
            .unwrap();
        assert_eq!(config_domain.options.sni.as_deref(), Some("example.com"));

        let lb_ip = manager.get("ip_upstream").unwrap();
        let backends = lb_ip.backends().get_backend();
        let config_ip = backends
            .iter()
            .next()
            .unwrap()
            .ext
            .get::<CachedPeerConfig>()
            .unwrap();
        assert_eq!(config_ip.options.sni, None);

        let lb_explicit = manager.get("explicit_sni").unwrap();
        let backends = lb_explicit.backends().get_backend();
        let config_explicit = backends
            .iter()
            .next()
            .unwrap()
            .ext
            .get::<CachedPeerConfig>()
            .unwrap();
        assert_eq!(
            config_explicit.options.sni.as_deref(),
            Some("custom.example.org")
        );
    }
}
