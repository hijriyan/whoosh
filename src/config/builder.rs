use super::models::{
    AcmeSettings, RootConfig, ServerConf, Service, SslSettings, Upstream, WhooshConfig,
};
use serde_yaml;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

pub struct ConfigBuilder {
    config: WhooshConfig,
    server_conf: Option<ServerConf>,
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigBuilder {
    pub fn new() -> Self {
        ConfigBuilder {
            config: WhooshConfig::default(),
            server_conf: Some(ServerConf::default()),
        }
    }

    /// Load configuration from a YAML file with optimized error handling.
    /// This will merge or overwrite existing configuration depending on implementation.
    /// Here we assume it loads the base config.
    pub fn from_file<P: AsRef<Path>>(
        mut self,
        path: P,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let path_ref = path.as_ref();

        // Pre-validate file exists for better error messages
        if !path_ref.exists() {
            return Err(format!("Configuration file not found: {}", path_ref.display()).into());
        }

        let file = File::open(path_ref)?;
        let reader = BufReader::new(file);

        // Parse with better error context
        let root: RootConfig = serde_yaml::from_reader(reader).map_err(|e| {
            format!(
                "Failed to parse YAML config from {}: {}",
                path_ref.display(),
                e
            )
        })?;

        self.config = root.whoosh;
        if root.pingora.is_some() {
            self.server_conf = root.pingora;
        }
        Ok(self)
    }

    pub fn with_ssl(mut self, ssl: SslSettings) -> Self {
        self.config.ssl = Some(ssl);
        self
    }

    pub fn with_acme(mut self, acme: AcmeSettings) -> Self {
        self.config.acme = Some(acme);
        self
    }

    pub fn with_metrics(mut self, listen: String) -> Self {
        self.config.metrics_listen = Some(listen);
        self
    }

    pub fn add_upstream(mut self, upstream: Upstream) -> Self {
        self.config.upstreams.push(upstream);
        self
    }

    pub fn add_service(mut self, service: Service) -> Self {
        self.config.services.push(std::sync::Arc::new(service));
        self
    }

    /// A generic extension point.
    /// Users can pass a closure to modify the internal config directly.
    /// This allows for arbitrary modifications without changing the Builder struct.
    ///
    /// Example:
    /// ```rust
    /// use whoosh::config::ConfigBuilder;
    ///
    /// let builder = ConfigBuilder::new();
    /// builder.configure(|cfg, _server_conf| {
    ///     cfg.http_listen = "0.0.0.0:8080".to_string();
    /// });
    /// ```
    pub fn configure<F>(mut self, func: F) -> Self
    where
        F: FnOnce(&mut WhooshConfig, &mut ServerConf),
    {
        if let Some(ref mut sc) = self.server_conf {
            func(&mut self.config, sc);
        }
        self
    }

    pub fn build(self) -> (WhooshConfig, Option<ServerConf>) {
        (self.config, self.server_conf)
    }
}

// Extensibility Example:
// To add a `with_grpc` method, the user (or another module) can define an Extension Trait.
//
// pub trait GrpcBuilderExt {
//     fn with_grpc(self, settings: GrpcSettings) -> Self;
// }
//
// impl GrpcBuilderExt for ConfigBuilder {
//     fn with_grpc(self, settings: GrpcSettings) -> Self {
//         self.configure(|cfg| {
//             // Assuming we store grpc settings in the `extra` map or a specific field if we added one.
//             // Since WhooshConfig has an `extra` field for dynamic config:
//             let val = serde_yaml::to_value(settings).unwrap();
//             cfg.extra.insert("grpc".to_string(), val);
//         })
//     }
// }
