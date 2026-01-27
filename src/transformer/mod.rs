pub mod models;
pub mod parser;
pub mod registry;

pub use models::{RequestTransformer, ResponseTransformer};
pub use parser::{parse_transformers, parse_response_transformers};
pub use registry::{
    register_request_transformer, register_response_transformer,
    parse_custom_request_transformers, parse_custom_response_transformers
};

#[cfg(test)]
mod tests {
    use super::{parse_transformers, parse_response_transformers};
    use pingora::http::{RequestHeader, ResponseHeader};
    use crate::transformer::models::{RequestTransformer, ResponseTransformer};
    use crate::transformer::registry::{register_request_transformer, register_response_transformer};
    use nom::{
        bytes::complete::tag,
        character::complete::{char, multispace0},
        IResult,
    };

    #[test]
    fn test_request_transformer_parsing_and_execution() {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("X-Old", "remove-me").unwrap();
        req.insert_header("Host", "original").unwrap();

        // Test multiple transformers separated by semicolon
        let script = "ReplaceHeader(`Host`, `new-host`) ; DeleteHeader(`X-Old`) ; AppendHeader(`X-New`, `value`)";
        let (_, transformer) = parse_transformers(script).unwrap();

        transformer.transform_request(&mut req);

        assert_eq!(req.headers.get("Host").unwrap(), "new-host");
        assert!(req.headers.get("X-Old").is_none());
        assert_eq!(req.headers.get("X-New").unwrap(), "value");
    }

    #[test]
    fn test_response_transformer_parsing_and_execution() {
        let mut res = ResponseHeader::build(200, None).unwrap();
        res.insert_header("X-Old", "remove-me").unwrap();
        res.insert_header("Server", "original").unwrap();

        // Test multiple transformers separated by semicolon
        let script = "ReplaceHeader(`Server`, `new-server`) ; DeleteHeader(`X-Old`) ; AppendHeader(`X-New`, `value`)";
        let (_, transformer) = parse_response_transformers(script).unwrap();

        transformer.transform_response(&mut res);

        assert_eq!(res.headers.get("Server").unwrap(), "new-server");
        assert!(res.headers.get("X-Old").is_none());
        assert_eq!(res.headers.get("X-New").unwrap(), "value");
    }

    #[test]
    fn test_query_transformer() {
        // Initial request with query params
        let mut req = RequestHeader::build("GET", b"/path?foo=bar&baz=qux", None).unwrap();
        
        // Script to modify query params
        let script = "ReplaceQuery(`foo`, `updated`) ; DeleteQuery(`baz`) ; AppendQuery(`new`, `param`)";
        let (_, transformer) = parse_transformers(script).unwrap();

        transformer.transform_request(&mut req);

        let uri = req.uri.to_string();
        // Check that foo is updated
        assert!(uri.contains("foo=updated"));
        // Check that baz is removed
        assert!(!uri.contains("baz="));
        // Check that new param is appended
        assert!(uri.contains("new=param"));
    }

    #[derive(Debug)]
    struct CustomRequestTransformer;
    impl RequestTransformer for CustomRequestTransformer {
        fn transform_request(&self, req: &mut RequestHeader) {
            let _ = req.insert_header("X-Custom-Req", "true");
        }
    }

    #[derive(Debug)]
    struct CustomResponseTransformer;
    impl ResponseTransformer for CustomResponseTransformer {
        fn transform_response(&self, res: &mut ResponseHeader) {
            let _ = res.insert_header("X-Custom-Res", "true");
        }
    }

    #[test]
    fn test_custom_transformer_registry() {
        // Define custom parsers
        fn parse_my_req_transformer(input: &str) -> IResult<&str, Box<dyn RequestTransformer>> {
            let (input, _) = tag("MyReqTransformer")(input)?;
            let (input, _) = multispace0(input)?;
            let (input, _) = char('(')(input)?;
            let (input, _) = char(')')(input)?;
            Ok((input, Box::new(CustomRequestTransformer)))
        }

        fn parse_my_res_transformer(input: &str) -> IResult<&str, Box<dyn ResponseTransformer>> {
            let (input, _) = tag("MyResTransformer")(input)?;
            let (input, _) = multispace0(input)?;
            let (input, _) = char('(')(input)?;
            let (input, _) = char(')')(input)?;
            Ok((input, Box::new(CustomResponseTransformer)))
        }

        // Register them
        register_request_transformer(parse_my_req_transformer);
        register_response_transformer(parse_my_res_transformer);

        // Parse and test request transformer
        let script_req = "MyReqTransformer()";
        let (_, transformer_req) = parse_transformers(script_req).unwrap();
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        transformer_req.transform_request(&mut req);
        assert_eq!(req.headers.get("X-Custom-Req").unwrap(), "true");

        // Parse and test response transformer
        let script_res = "MyResTransformer()";
        let (_, transformer_res) = parse_response_transformers(script_res).unwrap();
        let mut res = ResponseHeader::build(200, None).unwrap();
        transformer_res.transform_response(&mut res);
        assert_eq!(res.headers.get("X-Custom-Res").unwrap(), "true");
    }
}
