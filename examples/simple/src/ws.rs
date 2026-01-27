use log;
use whoosh::server::extension::*;
use whoosh::websocket::WsFrame;

pub struct SimpleWebsocketExtension;

impl WebsocketExtension for SimpleWebsocketExtension {
    fn on_message(
        &self,
        direction: WebsocketDirection,
        mut frame: WsFrame,
    ) -> WebsocketMessageAction {
        if direction == WebsocketDirection::UpstreamToDownstream {
            if frame.is_text() {
                if let Some(text) = frame.text() {
                    log::info!("Received text: {}", text);
                    let merged = format!("simple: {}", text);
                    frame.set_text(&merged);
                }
            } else if frame.is_binary() {
                let old_payload = frame.payload.as_ref();
                log::info!("Received binary: {}", old_payload.len());
                let mut new_payload = Vec::with_capacity(8 + old_payload.len());
                new_payload.extend_from_slice(b"simple: ");
                new_payload.extend_from_slice(old_payload);
                frame.set_binary(new_payload);
            }
        }
        WebsocketMessageAction::Forward(frame)
    }
    fn on_error(
        &self,
        _direction: WebsocketDirection,
        error: WebsocketError,
    ) -> WebsocketErrorAction {
        log::error!("Websocket error: {:?}", error);
        WebsocketErrorAction::PassThrough
    }
}
