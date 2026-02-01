use whoosh::config::models::WhooshConfig;
use whoosh::extensions::dns::DnsResolver;

#[tokio::test]
async fn test_dns_lookup_ip() {
    let config = WhooshConfig::default();
    let resolver = DnsResolver::new(&config);

    // Resolve a known domain
    let result = resolver.lookup_ip("google.com").await;

    assert!(result.is_ok(), "DNS lookup failed: {:?}", result.err());
    let ips = result.unwrap();
    assert!(!ips.is_empty(), "Resolved IP list is empty");
    println!("Resolved IPs for google.com: {:?}", ips);

    // Resolve an invalid domain
    let result_invalid = resolver
        .lookup_ip("invalid.domain.that.does.not.exist.hopefully")
        .await;
    assert!(
        result_invalid.is_err(),
        "DNS lookup should fail for invalid domain"
    );
}
