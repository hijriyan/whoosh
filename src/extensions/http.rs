use crate::config::models::WhooshConfig;
use crate::server::context::AppCtx;
use crate::server::extension::WhooshExtension;
use crate::server::proxy::WhooshProxy;
use crate::server::router::{HTTP_PROTOCOLS, Router};
use crate::server::service::ServiceManager;
use crate::server::upstream::UpstreamManager;
use pingora::proxy::http_proxy_service;
use pingora::server::Server;
use std::sync::Arc;

pub struct HttpExtension;

use crate::error::WhooshError;

impl WhooshExtension for HttpExtension {
    fn whoosh_init(&self, server: &mut Server, app_ctx: &mut AppCtx) -> Result<(), WhooshError> {
        let config = app_ctx
            .get::<WhooshConfig>()
            .ok_or_else(|| WhooshError::Config("WhooshConfig not found in AppCtx".to_string()))?;

        let upstream_manager = app_ctx.get::<UpstreamManager>().ok_or_else(|| {
            WhooshError::Config("UpstreamManager not found in AppCtx".to_string())
        })?;
        let service_manager = app_ctx
            .get::<ServiceManager>()
            .ok_or_else(|| WhooshError::Config("ServiceManager not found in AppCtx".to_string()))?;

        let router = Router::new(
            service_manager,
            upstream_manager.clone(),
            &HTTP_PROTOCOLS,
            &config,
        );

        let proxy = WhooshProxy::new(router, Arc::new(app_ctx.clone()))?;

        let mut http_service = http_proxy_service(&server.configuration, proxy);
        http_service.add_tcp(&config.http_listen);
        server.add_service(http_service);
        log::info!("HTTP proxy listening on {}", config.http_listen);
        Ok(())
    }
}
