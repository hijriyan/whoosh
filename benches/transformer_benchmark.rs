use criterion::{Criterion, criterion_group, criterion_main};
use pingora::http::RequestHeader;
use std::hint::black_box;
use whoosh::transformer::{RequestTransformer, parse_transformers, register_request_transformer};
use winnow::Parser;
use winnow::ascii::multispace0;
use winnow::token::literal as tag;

// Custom transformer for benchmark
#[derive(Debug)]
struct BenchmarkTransformer;
impl RequestTransformer for BenchmarkTransformer {
    fn transform_request(&self, req: &mut RequestHeader) {
        let _ = req.insert_header("X-Benchmark", "true");
    }
}

fn parse_benchmark_transformer(
    input: &mut &str,
) -> std::result::Result<Box<dyn RequestTransformer>, winnow::error::ContextError> {
    (tag("BenchmarkTransformer"), multispace0, '(', ')')
        .map(|_| Box::new(BenchmarkTransformer) as Box<dyn RequestTransformer>)
        .parse_next(input)
        .map_err(|e: winnow::error::ErrMode<winnow::error::ContextError>| {
            e.into_inner().unwrap_or_default()
        })
}

fn transformer_benchmark(c: &mut Criterion) {
    // 1. Benchmark Parsing
    c.bench_function("parse_simple_transformer", |b| {
        b.iter(|| parse_transformers(black_box("ReplaceHeader(`Host`, `new.com`)")))
    });

    c.bench_function("parse_chain_transformer", |b| {
        b.iter(|| parse_transformers(black_box("ReplaceHeader(`Host`, `new.com`) ; DeleteHeader(`X-Old`) ; AppendQuery(`foo`, `bar`)")))
    });

    // 2. Benchmark Execution
    // Setup request for each iteration to simulate real world usage (cloning overhead included but necessary to keep state clean)
    // Actually for Criterion, we can modify the same request if the transformer is idempotent or we reset it.
    // But `AppendQuery` keeps adding. So we should clone.

    let req_template = RequestHeader::build("GET", b"/api/v1/users?id=123", None).unwrap();

    let simple_transformer = parse_transformers("ReplaceHeader(`Host`, `new.com`)").unwrap();
    c.bench_function("transform_header_replace", |b| {
        b.iter(|| {
            let mut req = req_template.clone();
            simple_transformer.transform_request(black_box(&mut req))
        })
    });

    let query_transformer = parse_transformers("ReplaceQuery(`id`, `456`)").unwrap();
    c.bench_function("transform_query_replace", |b| {
        b.iter(|| {
            let mut req = req_template.clone();
            query_transformer.transform_request(black_box(&mut req))
        })
    });

    // 3. Benchmark Custom Transformer
    register_request_transformer(parse_benchmark_transformer);
    let custom_transformer = parse_transformers("BenchmarkTransformer()").unwrap();
    c.bench_function("transform_custom", |b| {
        b.iter(|| {
            let mut req = req_template.clone();
            custom_transformer.transform_request(black_box(&mut req))
        })
    });
}

criterion_group!(benches, transformer_benchmark);
criterion_main!(benches);
