use crate::config::models::{ApiSettings, Service, ServiceProtocol, Upstream};
use crate::error::WhooshError;
use crate::extensions::dns::DnsResolver;
use crate::server::context::AppCtx;
use crate::server::extension::WhooshExtension;
use crate::server::service::{RuntimeService, ServiceManager};
use crate::server::upstream::UpstreamManager;
use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use pingora::server::Server;
use pingora::server::ShutdownWatch;
use pingora::services::background::{BackgroundService, GenBackgroundService};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

// API Models

// Upstream requests
#[derive(Debug, Deserialize, ToSchema)]
pub struct AddUpstreamRequest {
    pub upstream: Upstream,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUpstreamRequest {
    pub name: String,
    pub upstream: Upstream,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RemoveUpstreamRequest {
    pub name: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyUpstreamRequest {
    pub name: String,
}

// Service requests
#[derive(Debug, Deserialize, ToSchema)]
pub struct AddServiceRequest {
    pub service: Service,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateServiceRequest {
    pub name: String,
    pub service: Service,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RemoveServiceRequest {
    pub name: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyServiceRequest {
    pub name: String,
}

// Common responses
#[derive(Debug, Serialize, ToSchema)]
pub struct SuccessResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    pub success: bool,
    pub error: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UpstreamListResponse {
    pub upstreams: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ServiceListResponse {
    pub services: Vec<ServiceInfo>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ServiceInfo {
    pub name: String,
    pub host: String,
    pub protocols: Vec<ServiceProtocol>,
    pub routes: Vec<crate::config::models::Route>,
}

impl From<RuntimeService> for ServiceInfo {
    fn from(svc: RuntimeService) -> Self {
        ServiceInfo {
            name: svc.name,
            host: svc.host.to_string(),
            protocols: svc.protocols,
            routes: svc.config.routes.clone(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct VerifyResponse {
    pub exists: bool,
}

// API Extension

pub struct ApiExtension {
    settings: ApiSettings,
}

impl ApiExtension {
    pub fn new(settings: ApiSettings) -> Self {
        Self { settings }
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_upstreams,
        verify_upstream,
        add_upstream,
        update_upstream,
        remove_upstream,
        list_services,
        verify_service,
        add_service,
        update_service,
        remove_service
    ),
    components(
        schemas(
            AddUpstreamRequest, UpdateUpstreamRequest, RemoveUpstreamRequest, VerifyUpstreamRequest,
            AddServiceRequest, UpdateServiceRequest, RemoveServiceRequest, VerifyServiceRequest,
            SuccessResponse, ErrorResponse, UpstreamListResponse, ServiceListResponse, ServiceInfo, VerifyResponse,
            // Config models
            crate::config::models::Upstream,
            crate::config::models::UpstreamServer,
            crate::config::models::PeerOptions,
            crate::config::models::Service,
            crate::config::models::ServiceProtocol,
            crate::config::models::Route,
            crate::config::models::Rule
        )
    ),
    tags(
        (name = "upstreams", description = "Upstream management endpoints"),
        (name = "services", description = "Service management endpoints")
    ),
    modifiers(&SecurityAddon)
)]
struct ApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "basic_auth",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::HttpBuilder::new()
                        .scheme(utoipa::openapi::security::HttpAuthScheme::Basic)
                        .description(Some("Basic Auth"))
                        .build(),
                ),
            )
        }
    }
}

#[derive(Clone)]
struct ApiState {
    app_ctx: Arc<AppCtx>,
}

struct ApiService {
    settings: ApiSettings,
    app_ctx: Arc<AppCtx>,
}

#[async_trait]
impl BackgroundService for ApiService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let state = ApiState {
            app_ctx: self.app_ctx.clone(),
        };

        let mut protected_routes = Router::new()
            .route("/upstreams/list", get(list_upstreams))
            .route("/upstreams/verify", post(verify_upstream))
            .route("/upstreams/add", post(add_upstream))
            .route("/upstreams/update", post(update_upstream))
            .route("/upstreams/remove", post(remove_upstream))
            .route("/services/list", get(list_services))
            .route("/services/verify", post(verify_service))
            .route("/services/add", post(add_service))
            .route("/services/update", post(update_service))
            .route("/services/remove", post(remove_service))
            .with_state(state);

        // Apply basic auth if configured
        if let Some(ref auth) = self.settings.basic_auth {
            let username = auth.username.clone();
            let password = auth.password.clone();
            protected_routes = protected_routes.layer(middleware::from_fn(move |req, next| {
                basic_auth_middleware(req, next, username.clone(), password.clone())
            }));
            log::info!("API basic authentication enabled");
        }

        // Apply rate limiting if configured
        if let Some(ref rate_limit) = self.settings.rate_limit {
            let governor_conf = Arc::new(
                GovernorConfigBuilder::default()
                    .per_second(rate_limit.requests_per_second as u64)
                    .burst_size(rate_limit.burst)
                    .finish()
                    .unwrap(),
            );
            protected_routes = protected_routes.layer(GovernorLayer::new(governor_conf));
            log::info!(
                "API rate limiting enabled: {} req/s, burst {}",
                rate_limit.requests_per_second,
                rate_limit.burst
            );
        }

        // Configure OpenAPI
        let mut openapi = ApiDoc::openapi();
        let mut swagger_path = "/docs".to_string();
        let mut openapi_path = "/docs/openapi.json".to_string();

        if let Some(openapi_settings) = &self.settings.openapi {
            openapi.info.title = openapi_settings.title.clone();
            openapi.info.description = Some(openapi_settings.description.clone());

            swagger_path = openapi_settings.root_path.clone();
            // Clean up path for openapi.json relative to root
            let clean_root = openapi_settings.root_path.trim_end_matches('/');
            openapi_path = format!("{}/openapi.json", clean_root);
        }

        let app = Router::new()
            .merge(protected_routes)
            .merge(SwaggerUi::new(swagger_path).url(openapi_path, openapi))
            .layer(middleware::from_fn(no_cache_middleware));

        let listen_addr = self.settings.listen.as_ref().unwrap();
        match TcpListener::bind(listen_addr).await {
            Ok(listener) => {
                log::info!("API server listening on {}", listen_addr);
                let server = axum::serve(listener, app).with_graceful_shutdown(async move {
                    let _ = shutdown.changed().await;
                });

                if let Err(e) = server.await {
                    log::error!("API server error: {}", e);
                }
            }
            Err(e) => {
                log::error!("Failed to bind API server to {}: {}", listen_addr, e);
            }
        }
    }
}

impl WhooshExtension for ApiExtension {
    fn whoosh_init(&self, server: &mut Server, app_ctx: &mut AppCtx) -> Result<(), WhooshError> {
        let service = GenBackgroundService::new(
            "api_server".to_string(),
            Arc::new(ApiService {
                settings: self.settings.clone(),
                app_ctx: Arc::new(app_ctx.clone()),
            }),
        );
        server.add_service(service);

        log::info!(
            "API Extension initialized on {}",
            self.settings
                .listen
                .as_ref()
                .unwrap_or(&"unknown".to_string())
        );
        Ok(())
    }
}

// Middleware functions
async fn basic_auth_middleware(
    req: Request<axum::body::Body>,
    next: Next,
    username: String,
    password: String,
) -> Response {
    use axum::http::header::AUTHORIZATION;

    let auth_header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    if let Some(auth) = auth_header {
        if auth.starts_with("Basic ") {
            let encoded = &auth[6..];
            use base64::Engine;
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                if let Ok(credentials) = String::from_utf8(decoded) {
                    let parts: Vec<&str> = credentials.splitn(2, ':').collect();
                    if parts.len() == 2 && parts[0] == username && parts[1] == password {
                        return next.run(req).await;
                    }
                }
            }
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        [("WWW-Authenticate", "Basic realm=\"API\"")],
        "Unauthorized",
    )
        .into_response()
}

async fn no_cache_middleware(req: Request<axum::body::Body>, next: Next) -> Response {
    use axum::http::HeaderValue;
    use axum::http::header::{CACHE_CONTROL, EXPIRES, PRAGMA};

    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store, must-revalidate"),
    );
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(EXPIRES, HeaderValue::from_static("0"));

    response
}

// Upstream handlers
#[utoipa::path(
    get,
    path = "/upstreams/list",
    tag = "upstreams",
    security(("basic_auth" = [])),
    responses(
        (status = 200, description = "List all upstreams", body = UpstreamListResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn list_upstreams(
    State(state): State<ApiState>,
) -> Result<Json<UpstreamListResponse>, ApiError> {
    let upstream_manager = state
        .app_ctx
        .get::<UpstreamManager>()
        .ok_or_else(|| ApiError::Internal("UpstreamManager not found".into()))?;

    let upstreams = upstream_manager.list_upstreams();
    Ok(Json(UpstreamListResponse { upstreams }))
}

#[utoipa::path(
    post,
    path = "/upstreams/verify",
    tag = "upstreams",
    request_body = VerifyUpstreamRequest,
    security(("basic_auth" = [])),
    responses(
        (status = 200, description = "Verify upstream existence", body = VerifyResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn verify_upstream(
    State(state): State<ApiState>,
    Json(req): Json<VerifyUpstreamRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let upstream_manager = state
        .app_ctx
        .get::<UpstreamManager>()
        .ok_or_else(|| ApiError::Internal("UpstreamManager not found".into()))?;

    let exists = upstream_manager.verify_upstream(&req.name);
    Ok(Json(VerifyResponse { exists }))
}

#[utoipa::path(
    post,
    path = "/upstreams/add",
    tag = "upstreams",
    request_body = AddUpstreamRequest,
    security(("basic_auth" = [])),
    responses(
        (status = 200, description = "Add new upstream", body = SuccessResponse),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn add_upstream(
    State(state): State<ApiState>,
    Json(req): Json<AddUpstreamRequest>,
) -> Result<Json<SuccessResponse>, ApiError> {
    let upstream_manager = state
        .app_ctx
        .get::<UpstreamManager>()
        .ok_or_else(|| ApiError::Internal("UpstreamManager not found".into()))?;

    let dns_resolver = state
        .app_ctx
        .get::<DnsResolver>()
        .ok_or_else(|| ApiError::Internal("DnsResolver not found".into()))?;

    upstream_manager
        .add_upstream(req.upstream, dns_resolver)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    Ok(Json(SuccessResponse {
        success: true,
        message: "Upstream added successfully".into(),
    }))
}

#[utoipa::path(
    post,
    path = "/upstreams/update",
    tag = "upstreams",
    request_body = UpdateUpstreamRequest,
    security(("basic_auth" = [])),
    responses(
        (status = 200, description = "Update existing upstream", body = SuccessResponse),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn update_upstream(
    State(state): State<ApiState>,
    Json(req): Json<UpdateUpstreamRequest>,
) -> Result<Json<SuccessResponse>, ApiError> {
    let upstream_manager = state
        .app_ctx
        .get::<UpstreamManager>()
        .ok_or_else(|| ApiError::Internal("UpstreamManager not found".into()))?;

    let dns_resolver = state
        .app_ctx
        .get::<DnsResolver>()
        .ok_or_else(|| ApiError::Internal("DnsResolver not found".into()))?;

    upstream_manager
        .update_upstream(&req.name, req.upstream, dns_resolver)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    Ok(Json(SuccessResponse {
        success: true,
        message: "Upstream updated successfully".into(),
    }))
}

#[utoipa::path(
    post,
    path = "/upstreams/remove",
    tag = "upstreams",
    request_body = RemoveUpstreamRequest,
    security(("basic_auth" = [])),
    responses(
        (status = 200, description = "Remove upstream", body = SuccessResponse),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn remove_upstream(
    State(state): State<ApiState>,
    Json(req): Json<RemoveUpstreamRequest>,
) -> Result<Json<SuccessResponse>, ApiError> {
    let upstream_manager = state
        .app_ctx
        .get::<UpstreamManager>()
        .ok_or_else(|| ApiError::Internal("UpstreamManager not found".into()))?;

    upstream_manager
        .remove_upstream(&req.name)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    Ok(Json(SuccessResponse {
        success: true,
        message: "Upstream removed successfully".into(),
    }))
}

// Service handlers
#[utoipa::path(
    get,
    path = "/services/list",
    tag = "services",
    security(("basic_auth" = [])),
    responses(
        (status = 200, description = "List all services", body = ServiceListResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn list_services(
    State(state): State<ApiState>,
) -> Result<Json<ServiceListResponse>, ApiError> {
    let service_manager = state
        .app_ctx
        .get::<ServiceManager>()
        .ok_or_else(|| ApiError::Internal("ServiceManager not found".into()))?;

    let services = service_manager
        .list_services()
        .into_iter()
        .map(ServiceInfo::from)
        .collect();

    Ok(Json(ServiceListResponse { services }))
}

#[utoipa::path(
    post,
    path = "/services/verify",
    tag = "services",
    request_body = VerifyServiceRequest,
    security(("basic_auth" = [])),
    responses(
        (status = 200, description = "Verify service existence", body = VerifyResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn verify_service(
    State(state): State<ApiState>,
    Json(req): Json<VerifyServiceRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let service_manager = state
        .app_ctx
        .get::<ServiceManager>()
        .ok_or_else(|| ApiError::Internal("ServiceManager not found".into()))?;

    let exists = service_manager.verify_service(&req.name);
    Ok(Json(VerifyResponse { exists }))
}

#[utoipa::path(
    post,
    path = "/services/add",
    tag = "services",
    request_body = AddServiceRequest,
    security(("basic_auth" = [])),
    responses(
        (status = 200, description = "Add new service", body = SuccessResponse),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn add_service(
    State(state): State<ApiState>,
    Json(req): Json<AddServiceRequest>,
) -> Result<Json<SuccessResponse>, ApiError> {
    let service_manager = state
        .app_ctx
        .get::<ServiceManager>()
        .ok_or_else(|| ApiError::Internal("ServiceManager not found".into()))?;

    service_manager
        .add_service(req.service)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    Ok(Json(SuccessResponse {
        success: true,
        message: "Service added successfully".into(),
    }))
}

#[utoipa::path(
    post,
    path = "/services/update",
    tag = "services",
    request_body = UpdateServiceRequest,
    security(("basic_auth" = [])),
    responses(
        (status = 200, description = "Update existing service", body = SuccessResponse),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn update_service(
    State(state): State<ApiState>,
    Json(req): Json<UpdateServiceRequest>,
) -> Result<Json<SuccessResponse>, ApiError> {
    let service_manager = state
        .app_ctx
        .get::<ServiceManager>()
        .ok_or_else(|| ApiError::Internal("ServiceManager not found".into()))?;

    service_manager
        .update_service(&req.name, req.service)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    Ok(Json(SuccessResponse {
        success: true,
        message: "Service updated successfully".into(),
    }))
}

#[utoipa::path(
    post,
    path = "/services/remove",
    tag = "services",
    request_body = RemoveServiceRequest,
    security(("basic_auth" = [])),
    responses(
        (status = 200, description = "Remove service", body = SuccessResponse),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn remove_service(
    State(state): State<ApiState>,
    Json(req): Json<RemoveServiceRequest>,
) -> Result<Json<SuccessResponse>, ApiError> {
    let service_manager = state
        .app_ctx
        .get::<ServiceManager>()
        .ok_or_else(|| ApiError::Internal("ServiceManager not found".into()))?;

    service_manager
        .remove_service(&req.name)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    Ok(Json(SuccessResponse {
        success: true,
        message: "Service removed successfully".into(),
    }))
}

// Error handling
#[derive(Debug)]
enum ApiError {
    BadRequest(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        let body = Json(ErrorResponse {
            success: false,
            error: error_message,
        });

        (status, body).into_response()
    }
}
