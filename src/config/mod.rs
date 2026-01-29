pub mod builder;
pub mod models;

pub use builder::ConfigBuilder;
pub use models::*;

#[cfg(test)]
mod tests {
    use super::ConfigBuilder;
    use serde::{Deserialize, Serialize};

    #[test]
    fn test_load_from_file() {
        // We need to ensure we are running from the root where whoosh.yml is
        // or provide the correct path. Cargo usually runs tests from the crate root.
        let builder = ConfigBuilder::new().from_file("whoosh.yml");

        assert!(builder.is_ok());
        let (config, _) = builder.unwrap().build();

        assert_eq!(config.http_listen, "[::]:2023");
        assert!(config.ssl.is_some());
        assert_eq!(config.upstreams.len(), 1);
        assert_eq!(config.upstreams[0].name, "ups_searchengine");
    }

    #[test]
    fn test_builder_fluent_api() {
        let (config, _) = ConfigBuilder::new()
            .configure(|cfg, _| {
                cfg.http_listen = "127.0.0.1:8080".to_string();
            })
            .build();

        assert_eq!(config.http_listen, "127.0.0.1:8080");
    }

    // Requirement 3: User wants to add new method "with_grpc(xxx)"
    // This demonstrates how a user would do that using Extension Trait pattern
    #[derive(Debug, Serialize, Deserialize)]
    struct GrpcSettings {
        enabled: bool,
        port: u16,
    }

    trait ConfigBuilderExt {
        fn with_grpc(self, settings: GrpcSettings) -> Self;
    }

    impl ConfigBuilderExt for ConfigBuilder {
        fn with_grpc(self, settings: GrpcSettings) -> Self {
            self.configure(|cfg, _| {
                let val = serde_yaml::to_value(settings).unwrap();
                cfg.extra.insert("grpc".to_string(), val);
            })
        }
    }

    #[test]
    fn test_custom_extension() {
        let grpc_settings = GrpcSettings {
            enabled: true,
            port: 50051,
        };

        let (config, _) = ConfigBuilder::new()
            .with_grpc(grpc_settings) // This method didn't exist in original builder
            .build();

        assert!(config.extra.contains_key("grpc"));
        let val = config.extra.get("grpc").unwrap();
        assert_eq!(val["port"], 50051);
    }

    #[test]
    fn test_configure_pingora() {
        let (_, server_conf) = ConfigBuilder::new()
            .configure(|_, sc| {
                sc.threads = 8;
            })
            .build();

        assert_eq!(server_conf.unwrap().threads, 8);
    }
}
