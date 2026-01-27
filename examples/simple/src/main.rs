use std::sync::Arc;
use whoosh::cli::whoosh_main;
pub mod ws;

fn main() {
    whoosh_main(Vec::new(), vec![Arc::new(ws::SimpleWebsocketExtension)]);
}
