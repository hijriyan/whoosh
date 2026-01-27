use crate::config::ConfigBuilder;
use crate::server::app::App;
use crate::server::extension::{WebsocketExtension, WhooshExtension};
use std::env;
use std::sync::Arc;

pub fn whoosh_main(
    extensions: Vec<Box<dyn WhooshExtension>>,
    websocket_extensions: Vec<Arc<dyn WebsocketExtension>>,
) {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    let config_path = if args.len() > 1 {
        &args[1]
    } else {
        "whoosh.yml"
    };

    log::info!("Loading configuration from {}", config_path);

    let builder = match ConfigBuilder::new().from_file(config_path) {
        Ok(b) => b,
        Err(e) => {
            log::error!("Failed to load configuration file: {}", e);
            std::process::exit(1);
        }
    };

    let config = builder.build();
    let app = App::new(config.clone(), extensions, websocket_extensions);
    log::info!("Starting Whoosh server...");
    if let Err(e) = app.run() {
        log::error!("Fatal error: {}", e);
        std::process::exit(1);
    }
}
