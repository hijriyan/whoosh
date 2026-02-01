pub mod matcher;
pub mod parser;
pub mod registry;

pub use matcher::Matcher;
pub use parser::parse_rule;
pub use registry::{parse_custom_rules, register_router_rule};

#[cfg(test)]
mod tests {
    use super::parse_rule;
    use crate::router::matcher::Matcher;
    use crate::router::registry::register_router_rule;
    use pingora::http::RequestHeader;
    use winnow::ascii::multispace0;
    use winnow::token::literal as tag;
    use winnow::{Parser, Result};

    #[test]
    fn test_rule_parsing_and_matching() {
        // Create a dummy request
        let mut req = RequestHeader::build("GET", b"/api/v1/users", None).unwrap();
        req.insert_header("Host", "example.com").unwrap();

        // 1. Simple Host Match
        let rule = parse_rule("Host(`example.com`)").unwrap();
        assert!(rule.matches(&req));

        let rule = parse_rule("Host(`other.com`)").unwrap();
        assert!(!rule.matches(&req));

        // 2. Path Prefix Match
        let rule = parse_rule("PathPrefix(`/api`)").unwrap();
        assert!(rule.matches(&req));

        // 3. AND Logic
        let rule = parse_rule("Host(`example.com`) && PathPrefix(`/api`)").unwrap();
        assert!(rule.matches(&req));

        // 4. OR Logic
        let rule = parse_rule("Host(`other.com`) || PathPrefix(`/api`)").unwrap();
        assert!(rule.matches(&req));

        // 5. Nested Logic
        let rule =
            parse_rule("(Host(`example.com`) && Path(`/foo`)) || PathPrefix(`/api`)").unwrap();
        assert!(rule.matches(&req));
    }

    #[test]
    fn test_regex_and_not_matching() {
        let mut req = RequestHeader::build("GET", b"/api/v1/users", None).unwrap();
        req.insert_header("Host", "sub.example.com").unwrap();

        // 1. HostRegexp
        let rule = parse_rule("HostRegexp(`.*\\.example\\.com`)").unwrap();
        assert!(rule.matches(&req));

        let rule = parse_rule("HostRegexp(`^example\\.com$`)").unwrap();
        assert!(!rule.matches(&req));

        // 2. PathRegexp
        let rule = parse_rule("PathRegexp(`^/api/v\\d+/.*`)").unwrap();
        assert!(rule.matches(&req));

        // 3. Not Matcher
        let rule = parse_rule("!Host(`other.com`)").unwrap();
        assert!(rule.matches(&req));

        let rule = parse_rule("!Host(`sub.example.com`)").unwrap();
        assert!(!rule.matches(&req));

        // 4. Combined
        let rule = parse_rule("HostRegexp(`.*\\.example\\.com`) && !PathPrefix(`/admin`)").unwrap();
        assert!(rule.matches(&req));
    }

    #[derive(Debug)]
    struct CustomMatcher;
    impl Matcher for CustomMatcher {
        fn matches(&self, _req: &RequestHeader) -> bool {
            true
        }

        fn clone_box(&self) -> Box<dyn Matcher> {
            Box::new(CustomMatcher)
        }
    }

    #[test]
    fn test_custom_rule_registry() {
        // Define a custom parser
        fn parse_my_rule(input: &mut &str) -> Result<Box<dyn Matcher>> {
            (tag("MyRule"), multispace0, '(', ')')
                .map(|_| Box::new(CustomMatcher) as Box<dyn Matcher>)
                .parse_next(input)
        }

        // Register it
        register_router_rule(parse_my_rule);

        // Parse it
        let rule = parse_rule("MyRule()").unwrap();

        // Test it
        let req = RequestHeader::build("GET", b"/", None).unwrap();
        assert!(rule.matches(&req));
    }

    #[test]
    fn test_header_and_query_regexp() {
        // HeaderRegexp
        let rule = parse_rule("HeaderRegexp(`User-Agent`, `^Mozilla.*`)").unwrap();
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header(
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        )
        .unwrap();
        assert!(rule.matches(&req));

        req.insert_header("User-Agent", "Curl/7.64.1").unwrap();
        assert!(!rule.matches(&req));

        // QueryRegexp
        let rule = parse_rule("QueryRegexp(`id`, `^[0-9]+$`)").unwrap();
        let req_match = RequestHeader::build("GET", b"/path?id=123", None).unwrap();
        assert!(rule.matches(&req_match));

        let req_no_match = RequestHeader::build("GET", b"/path?id=abc", None).unwrap();
        assert!(!rule.matches(&req_no_match));
    }
}
