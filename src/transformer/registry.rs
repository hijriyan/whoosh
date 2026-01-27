use nom::IResult;
use crate::transformer::models::{RequestTransformer, ResponseTransformer};
use std::sync::{Arc, OnceLock};
use arc_swap::ArcSwap;

// Define the type for a transformer parser factory
pub type RequestTransformerParser = Arc<dyn Fn(&str) -> IResult<&str, Box<dyn RequestTransformer>> + Send + Sync>;
pub type ResponseTransformerParser = Arc<dyn Fn(&str) -> IResult<&str, Box<dyn ResponseTransformer>> + Send + Sync>;

// Global registries
static REQUEST_TRANSFORMER_REGISTRY: OnceLock<ArcSwap<Vec<RequestTransformerParser>>> = OnceLock::new();
static RESPONSE_TRANSFORMER_REGISTRY: OnceLock<ArcSwap<Vec<ResponseTransformerParser>>> = OnceLock::new();

fn get_request_registry() -> &'static ArcSwap<Vec<RequestTransformerParser>> {
    REQUEST_TRANSFORMER_REGISTRY.get_or_init(|| ArcSwap::from_pointee(Vec::new()))
}

fn get_response_registry() -> &'static ArcSwap<Vec<ResponseTransformerParser>> {
    RESPONSE_TRANSFORMER_REGISTRY.get_or_init(|| ArcSwap::from_pointee(Vec::new()))
}

/// Register a custom request transformer parser
pub fn register_request_transformer<F>(parser: F)
where
    F: Fn(&str) -> IResult<&str, Box<dyn RequestTransformer>> + Send + Sync + 'static,
{
    let registry = get_request_registry();
    let parser = Arc::new(parser);
    registry.rcu(move |old| {
        let mut new = (**old).clone();
        new.push(parser.clone());
        new
    });
}

/// Register a custom response transformer parser
pub fn register_response_transformer<F>(parser: F)
where
    F: Fn(&str) -> IResult<&str, Box<dyn ResponseTransformer>> + Send + Sync + 'static,
{
    let registry = get_response_registry();
    let parser = Arc::new(parser);
    registry.rcu(move |old| {
        let mut new = (**old).clone();
        new.push(parser.clone());
        new
    });
}

/// Try to parse input using registered custom request transformers
pub fn parse_custom_request_transformers(input: &str) -> IResult<&str, Box<dyn RequestTransformer>> {
    let registry = get_request_registry();
    let parsers = registry.load();
    
    for parser in parsers.iter() {
        if let Ok((remaining, transformer)) = parser(input) {
            return Ok((remaining, transformer));
        }
    }
    
    Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Tag)))
}

/// Try to parse input using registered custom response transformers
pub fn parse_custom_response_transformers(input: &str) -> IResult<&str, Box<dyn ResponseTransformer>> {
    let registry = get_response_registry();
    let parsers = registry.load();
    
    for parser in parsers.iter() {
        if let Ok((remaining, transformer)) = parser(input) {
            return Ok((remaining, transformer));
        }
    }
    
    Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Tag)))
}
