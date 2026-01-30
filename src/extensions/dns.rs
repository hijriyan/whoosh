use crate::config::models::WhooshConfig;
use crate::server::context::AppCtx;
use crate::server::extension::WhooshExtension;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{
    LookupIpStrategy, NameServerConfig, Protocol, ResolverConfig, ResolverOpts,
};
use pingora::server::Server;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

pub struct DnsResolver {
    pub resolver: Arc<TokioAsyncResolver>,
}

impl DnsResolver {
    pub fn new(config: &WhooshConfig) -> Self {
        let dns_settings = config.dns.as_ref();
        let mut opts = ResolverOpts::default();
        let resolver_config = if let Some(dns) = dns_settings {
            let mut conf = ResolverConfig::new();
            if let Some(nameservers) = &dns.nameservers {
                for ns in nameservers {
                    let socket = if let Ok(socket) = ns.parse::<SocketAddr>() {
                        socket
                    } else if let Ok(ip) = ns.parse::<IpAddr>() {
                        SocketAddr::new(ip, 53)
                    } else {
                        log::warn!("Invalid nameserver: {}", ns);
                        continue;
                    };
                    conf.add_name_server(NameServerConfig::new(socket, Protocol::Udp));
                    conf.add_name_server(NameServerConfig::new(socket, Protocol::Tcp));
                }
            } else {
                // Fallback to Google if dns settings present but empty nameservers (though usually implies just use defaults, but we'll stick to google for consistency with previous impl)
                conf = ResolverConfig::google();
            }

            if let Some(timeout) = dns.timeout {
                opts.timeout = Duration::from_secs(timeout);
            }
            if let Some(attempts) = dns.attempts {
                opts.attempts = attempts;
            }
            if let Some(strategy) = &dns.strategy {
                opts.ip_strategy = match strategy.as_str() {
                    "ipv4_only" => LookupIpStrategy::Ipv4Only,
                    "ipv6_only" => LookupIpStrategy::Ipv6Only,
                    "ipv4_then_ipv6" => LookupIpStrategy::Ipv4thenIpv6,
                    "ipv6_then_ipv4" => LookupIpStrategy::Ipv6thenIpv4,
                    _ => {
                        log::warn!(
                            "Invalid DNS strategy '{}', defaulting to Ipv4thenIpv6",
                            strategy
                        );
                        LookupIpStrategy::Ipv4thenIpv6
                    }
                };
            }
            if let Some(cache_size) = dns.cache_size {
                opts.cache_size = cache_size;
            }
            opts.use_hosts_file = dns.use_hosts_file;

            conf
        } else {
            // Default config (Google DNS)
            ResolverConfig::google()
        };

        let resolver = TokioAsyncResolver::tokio(resolver_config, opts);
        Self {
            resolver: Arc::new(resolver),
        }
    }

    pub async fn lookup_ip(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        match self.resolver.lookup_ip(host).await {
            Ok(lookup) => Ok(lookup.iter().collect()),
            Err(e) => Err(e.to_string()),
        }
    }
}

pub struct DnsExtension;

impl WhooshExtension for DnsExtension {
    fn whoosh_init(
        &self,
        _server: &mut Server,
        ctx: &mut AppCtx,
    ) -> Result<(), crate::error::WhooshError> {
        if let Some(config) = ctx.get::<WhooshConfig>() {
            let resolver = DnsResolver::new(&config);
            ctx.insert(resolver);
            log::info!("DNS Resolver initialized");
        } else {
            log::warn!("WhooshConfig not found in AppCtx during DnsExtension init");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::DnsSettings;

    #[test]
    fn test_dns_config_parsing() {
        let mut config = WhooshConfig::default();
        config.dns = Some(DnsSettings {
            nameservers: Some(vec!["1.1.1.1".to_string()]),
            timeout: Some(10),
            attempts: Some(3),
            strategy: Some("ipv6_only".to_string()),
            cache_size: Some(100),
            use_hosts_file: false,
        });

        // We can't easily inspect the internal state of ResolverOpts from the Arc<TokioAsyncResolver>
        // But we can ensure that new() runs without panic and creates a resolver.
        let _resolver = DnsResolver::new(&config);

        // Test invalid strategy fallback
        let mut config_invalid = WhooshConfig::default();
        config_invalid.dns = Some(DnsSettings {
            nameservers: None,
            timeout: None,
            attempts: None,
            strategy: Some("invalid_strategy".to_string()),
            cache_size: None,
            use_hosts_file: true,
        });
        let _resolver_invalid = DnsResolver::new(&config_invalid);
    }
}
