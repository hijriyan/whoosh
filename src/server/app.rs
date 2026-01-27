use crate::config::models::WhooshConfig;
use crate::extensions::acme::{AcmeExtension, AcmeFilter};
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
    pub extensions: Vec<Box<dyn WhooshExtension>>,
    pub filters: Vec<Arc<dyn WhooshFilter>>,
    pub websocket_extensions: Vec<Arc<dyn WebsocketExtension>>,
    pub app_ctx: AppCtx,
}

impl App {
    pub fn new(
        config: WhooshConfig,
        custom_extensions: Vec<Box<dyn WhooshExtension>>,
        custom_websocket_extensions: Vec<Arc<dyn WebsocketExtension>>,
    ) -> Self {
        let mut app = Self {
            config,
            extensions: custom_extensions,
            filters: Vec::new(),
            websocket_extensions: custom_websocket_extensions,
            app_ctx: AppCtx::new(),
        };

        app.add_extension(crate::extensions::metrics::MetricsExtension);
        app.add_extension(HttpExtension);
        app.add_extension(HttpsExtension);
        // Register ACME extension if configured
        if let Some(acme_settings) = &app.config.acme {
            let acme_ext = AcmeExtension::new(acme_settings, Arc::new(app.config.clone()));
            let acme_filter = AcmeFilter {
                acme_manager: acme_ext.acme_manager.clone(),
            };
            app.add_extension(acme_ext.clone());
            app.add_filter(acme_filter);
        }
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
        let mut server =
            Server::new(None).map_err(|e| crate::error::WhooshError::Other(e.to_string()))?;
        server.bootstrap();
        let mut app_ctx = self.app_ctx;

        let config_arc = Arc::new(self.config.clone());

        // Initialize UpstreamManager
        let (upstream_manager, lb_services) = UpstreamManager::new(config_arc.clone())?;

        // Initialize ServiceManager
        let service_manager = ServiceManager::new(config_arc.clone())?;

        // Add LB background services
        for service in lb_services {
            server.add_service(service);
        }

        // Share resources via AppCtx for extensions to use
        app_ctx.insert(self.config.clone());

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
