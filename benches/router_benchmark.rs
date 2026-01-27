use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use pingora::http::RequestHeader;
use whoosh::router::{parse_rule, Matcher, register_router_rule};
use nom::{IResult, bytes::complete::tag, character::complete::{multispace0, char}};

// Custom matcher for benchmark
#[derive(Debug)]
struct BenchmarkMatcher;
impl Matcher for BenchmarkMatcher {
    fn matches(&self, _req: &RequestHeader) -> bool { true }
}

fn parse_benchmark_rule(input: &str) -> IResult<&str, Box<dyn Matcher>> {
    let (input, _) = tag("BenchmarkRule")(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char('(')(input)?;
    let (input, _) = char(')')(input)?;
    Ok((input, Box::new(BenchmarkMatcher)))
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
        b.iter(|| parse_rule(black_box("(Host(`example.com`) && PathPrefix(`/api`)) || Method(`GET`)")))
    });

    // 2. Benchmark Matching
    let simple_rule = parse_rule("Host(`example.com`)").unwrap();
    c.bench_function("match_simple_rule", |b| {
        b.iter(|| simple_rule.matches(black_box(&req)))
    });

    let complex_rule = parse_rule("(Host(`example.com`) && PathPrefix(`/api`)) || Method(`POST`)").unwrap();
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
