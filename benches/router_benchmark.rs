use criterion::{Criterion, criterion_group, criterion_main};
use pingora::http::RequestHeader;
use std::hint::black_box;
use whoosh::router::{Matcher, parse_rule, register_router_rule};
use winnow::Parser;
use winnow::ascii::multispace0;
use winnow::token::literal as tag;

// Custom matcher for benchmark
#[derive(Debug)]
struct BenchmarkMatcher;
impl Matcher for BenchmarkMatcher {
    fn matches(&self, _req: &RequestHeader) -> bool {
        true
    }

    fn clone_box(&self) -> Box<dyn Matcher> {
        Box::new(BenchmarkMatcher)
    }
}

fn parse_benchmark_rule(
    input: &mut &str,
) -> std::result::Result<Box<dyn Matcher>, winnow::error::ContextError> {
    (tag("BenchmarkRule"), multispace0, '(', ')')
        .map(|_| Box::new(BenchmarkMatcher) as Box<dyn Matcher>)
        .parse_next(input)
        .map_err(|e: winnow::error::ErrMode<winnow::error::ContextError>| {
            e.into_inner().unwrap_or_default()
        })
}

fn router_benchmark(c: &mut Criterion) {
    // Setup request
    let mut req = RequestHeader::build("GET", b"/api/v1/users?id=123", None).unwrap();
    req.insert_header("Host", "example.com").unwrap();
    req.insert_header("User-Agent", "Benchmark").unwrap();

    // 1. Benchmark Parsing
    c.bench_function("parse_simple_rule", |b| {
        b.iter(|| parse_rule(black_box("Host(`example.com`)")))
    });

    c.bench_function("parse_complex_rule", |b| {
        b.iter(|| {
            parse_rule(black_box(
                "(Host(`example.com`) && PathPrefix(`/api`)) || Method(`GET`)",
            ))
        })
    });

    // 2. Benchmark Matching
    let simple_rule = parse_rule("Host(`example.com`)").unwrap();
    c.bench_function("match_simple_rule", |b| {
        b.iter(|| simple_rule.matches(black_box(&req)))
    });

    let complex_rule =
        parse_rule("(Host(`example.com`) && PathPrefix(`/api`)) || Method(`POST`)").unwrap();
    c.bench_function("match_complex_rule", |b| {
        b.iter(|| complex_rule.matches(black_box(&req)))
    });

    // 3. Benchmark Custom Rule
    register_router_rule(parse_benchmark_rule);
    let custom_rule = parse_rule("BenchmarkRule()").unwrap();
    c.bench_function("match_custom_rule", |b| {
        b.iter(|| custom_rule.matches(black_box(&req)))
    });

    // 4. Benchmark Regex Rule
    c.bench_function("parse_regex_rule", |b| {
        b.iter(|| parse_rule(black_box("HostRegexp(`.*\\.example\\.com`)")))
    });

    let regex_rule = parse_rule("HostRegexp(`.*\\.example\\.com`)").unwrap();
    c.bench_function("match_regex_rule", |b| {
        b.iter(|| regex_rule.matches(black_box(&req)))
    });
}

criterion_group!(benches, router_benchmark);
criterion_main!(benches);
