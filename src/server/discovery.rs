use crate::config::models::UpstreamServer;
use crate::extensions::dns::DnsResolver;
use crate::server::proxy::CachedPeerConfig;
use async_trait::async_trait;
use pingora::Error;
use pingora::lb::Backend;
use pingora::lb::discovery::ServiceDiscovery;
use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;

pub struct WhooshUpstreamDiscovery {
    pub servers: Vec<(UpstreamServer, CachedPeerConfig)>,
    pub resolver: Arc<DnsResolver>,
}

impl WhooshUpstreamDiscovery {
    pub fn new(
        servers: Vec<(UpstreamServer, CachedPeerConfig)>,
        resolver: Arc<DnsResolver>,
    ) -> Self {
        Self { servers, resolver }
    }
}

#[async_trait]
impl ServiceDiscovery for WhooshUpstreamDiscovery {
    async fn discover(&self) -> Result<(BTreeSet<Backend>, HashMap<u64, bool>), Box<Error>> {
        let mut backends = BTreeSet::new();

        for (server, cached_config) in &self.servers {
            // Check if it's already an IP address
            if server.host.parse::<SocketAddr>().is_ok() {
                let weight = server.weight.unwrap_or(1) as usize;
                if let Ok(mut backend) = Backend::new_with_weight(&server.host, weight) {
                    backend.ext.insert(cached_config.clone());
                    backends.insert(backend);
                }
                continue;
            }

            // Split host and port
            let (host, port) = if let Some((h, p)) = server.host.rsplit_once(':') {
                (h, p.parse::<u16>().unwrap_or(80))
            } else {
                (server.host.as_str(), 80)
            };

            // Perform DNS resolution
            match self.resolver.lookup_ip(host).await {
                Ok(resolved) => {
                    let count = resolved.len();
                    if count > 0 {
                        let total_weight = server.weight.unwrap_or(1) as usize;
                        // Distribute weight among resolved addresses, ensuring at least 1 per address
                        let weight_per_addr = (total_weight / count).max(1);

                        for addr in resolved {
                            let socket_addr = SocketAddr::new(addr, port);
                            let addr_str = socket_addr.to_string();
                            log::trace!(
                                "Discovered backend for {}: {} with weight {} (total host weight {})",
                                server.host,
                                addr_str,
                                weight_per_addr,
                                total_weight
                            );
                            if let Ok(mut backend) =
                                Backend::new_with_weight(&addr_str, weight_per_addr)
                            {
                                backend.ext.insert(cached_config.clone());
                                backends.insert(backend);
                            }
                        }
                    } else {
                        log::warn!("No addresses resolved for host {}", server.host);
                    }
                }
                Err(e) => {
                    log::error!("Failed to resolve host {}: {}", server.host, e);
                }
            }
        }

        Ok((backends, HashMap::new()))
    }
}
