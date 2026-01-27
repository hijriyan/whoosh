use crate::server::context::{AppCtx, RouteContext};
use crate::websocket::WsFrame;
use async_trait::async_trait;
use pingora::Error;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use pingora::server::Server;

#[async_trait]
pub trait WhooshFilter: Send + Sync {
    /// Called when the request is received, before routing.
    /// Returns Ok(true) if the request was handled and the proxy should stop processing.
    /// Returns Ok(false) to continue to the next filter/routing.
    async fn request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut RouteContext,
        _app_ctx: &AppCtx,
    ) -> Result<bool, Box<Error>> {
        Ok(false)
    }

    /// Called after the upstream response is received, before sending to client.
    async fn response_filter(
        &self,
        _session: &mut Session,
        _upstream_response: &mut ResponseHeader,
        _ctx: &mut RouteContext,
        _app_ctx: &AppCtx,
    ) -> Result<(), Box<Error>> {
        Ok(())
    }
}

use crate::error::WhooshError;

pub trait WhooshExtension: Send + Sync {
    /// Called during server bootstrap to add background services etc.
    fn whoosh_init(&self, _server: &mut Server, _app_ctx: &mut AppCtx) -> Result<(), WhooshError> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebsocketDirection {
    DownstreamToUpstream,
    UpstreamToDownstream,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebsocketError {
    InvalidFrame,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebsocketErrorAction {
    PassThrough,
    Drop,
    Close(Option<Vec<u8>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebsocketMessageAction {
    Forward(WsFrame),
    Drop,
    Close(Option<Vec<u8>>),
}

pub trait WebsocketExtension: Send + Sync {
    fn on_message(&self, _direction: WebsocketDirection, frame: WsFrame) -> WebsocketMessageAction {
        WebsocketMessageAction::Forward(frame)
    }

    fn on_error(
        &self,
        _direction: WebsocketDirection,
        _error: WebsocketError,
    ) -> WebsocketErrorAction {
        WebsocketErrorAction::PassThrough
    }
}
