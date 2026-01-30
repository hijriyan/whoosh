use crate::config::models::{ServerConf, WhooshConfig};
use crate::extensions::acme::{AcmeExtension, AcmeFilter};
use crate::extensions::dns::{DnsExtension, DnsResolver};
use crate::extensions::http::HttpExtension;
use crate::extensions::https::HttpsExtension;
use crate::server::context::AppCtx;
use crate::server::extension::{WebsocketExtension, WhooshExtension, WhooshFilter};
use crate::server::service::ServiceManager;
use crate::server::upstream::UpstreamManager;
use pingora::server::Server;
use std::sync::Arc;

pub struct App {
    pub config: WhooshConfig,
    pub server_conf: Option<ServerConf>,
    pub extensions: Vec<Box<dyn WhooshExtension>>,
    pub filters: Vec<Arc<dyn WhooshFilter>>,
    pub websocket_extensions: Vec<Arc<dyn WebsocketExtension>>,
    pub app_ctx: AppCtx,
}

impl App {
    pub fn new(
        config: WhooshConfig,
        server_conf: Option<ServerConf>,
        custom_extensions: Vec<Box<dyn WhooshExtension>>,
        custom_websocket_extensions: Vec<Arc<dyn WebsocketExtension>>,
    ) -> Self {
        let mut app = Self {
            config,
            server_conf,
            extensions: custom_extensions,
            filters: Vec::new(),
            websocket_extensions: custom_websocket_extensions,
            app_ctx: AppCtx::new(),
        };

        app.add_extension(crate::extensions::metrics::MetricsExtension);

        // Register ACME extension if configured
        // Must be added before HttpsExtension so HttpsExtension can find AcmeManager in AppCtx
        if let Some(acme_settings) = &app.config.acme {
            let acme_ext = AcmeExtension::new(acme_settings, Arc::new(app.config.clone()));
            let acme_filter = AcmeFilter {
                acme_manager: acme_ext.acme_manager.clone(),
            };
            app.add_extension(acme_ext.clone());
            app.add_filter(acme_filter);
        }

        app.add_extension(DnsExtension);
        app.add_extension(HttpExtension);
        app.add_extension(HttpsExtension);
        app
    }

    pub fn add_extension<E: WhooshExtension + 'static>(&mut self, extension: E) {
        self.extensions.push(Box::new(extension));
    }

    pub fn add_filter<F: WhooshFilter + 'static>(&mut self, filter: F) {
        self.filters.push(Arc::new(filter));
    }

    pub fn add_websocket_extension<E: WebsocketExtension + 'static>(&mut self, extension: E) {
        self.websocket_extensions.push(Arc::new(extension));
    }

    pub fn app_ctx(&self) -> &AppCtx {
        &self.app_ctx
    }

    pub fn run(self) -> Result<(), crate::error::WhooshError> {
        let mut server = Server::new_with_opt_and_conf(None, self.server_conf.unwrap_or_default());
        server.bootstrap();
        let mut app_ctx = self.app_ctx;

        let config_arc = Arc::new(self.config.clone());

        // Share resources via AppCtx for extensions to use (moved up)
        app_ctx.insert(self.config.clone());

        // Initialize DNS Resolver early
        // Initialize DNS Resolver early
        let dns_resolver = DnsResolver::new(&self.config);
        app_ctx.insert(dns_resolver);

        // Initialize UpstreamManager
        let (upstream_manager, lb_services) = UpstreamManager::new(&app_ctx)?;

        // Initialize ServiceManager
        let service_manager = ServiceManager::new(config_arc.clone())?;

        // Add LB background services
        for service in lb_services {
            server.add_service(service);
        }

        // Share global filters and websocket extensions

        // Share global filters and websocket extensions
        app_ctx.insert(self.filters);
        app_ctx.insert(self.websocket_extensions);

        // Share core managers for dependency injection within extensions
        app_ctx.insert(upstream_manager);
        app_ctx.insert(service_manager);

        for ext in &self.extensions {
            ext.whoosh_init(&mut server, &mut app_ctx)?;
        }

        server.run_forever();
    }
}
