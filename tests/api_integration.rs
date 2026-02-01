use reqwest::StatusCode;
use std::time::Duration;
use whoosh::config::models::{ApiSettings, BasicAuth, WhooshConfig};
use whoosh::server::app::App;

#[tokio::test]
async fn test_api_extension() {
    // Initialize logger for debug visibility
    let _ = env_logger::builder().is_test(true).try_init();

    // 1. Setup Configuration
    let api_port = 9099;
    let api_addr = format!("127.0.0.1:{}", api_port);

    let config = WhooshConfig {
        http_listen: "127.0.0.1:0".to_string(), // Use random port for main HTTP
        api: Some(ApiSettings {
            listen: Some(api_addr.clone()),
            ..Default::default()
        }),
        ..Default::default()
    };

    // 2. Start Server in Background Thread
    std::thread::spawn(move || {
        let app = App::new(config, None, vec![], vec![]);
        if let Err(e) = app.run() {
            eprintln!("Server exited with error: {}", e);
        }
    });

    // 3. Wait for Server to Start
    let client = reqwest::Client::new();
    let base_url = format!("http://{}", api_addr);

    // Poll until API is ready
    let mut ready = false;
    for _ in 0..20 {
        if client
            .get(format!("{}/upstreams/list", base_url))
            .send()
            .await
            .is_ok()
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    assert!(ready, "API server did not start in time");

    // =========================================================================
    // 4. Test Upstream API
    // =========================================================================

    let upstream_payload = serde_json::json!({
        "upstream": {
            "name": "test-upstream",
            "servers": [{ "host": "httpbingo.org:443" }]
        }
    });

    // A. Add Upstream
    let resp = client
        .post(format!("{}/upstreams/add", base_url))
        .json(&upstream_payload)
        .send()
        .await
        .expect("Failed add upstream");
    assert_eq!(resp.status(), StatusCode::OK);

    // B. Verify Upstream Added
    let resp = client
        .get(format!("{}/upstreams/list", base_url))
        .send()
        .await
        .unwrap();
    let list: serde_json::Value = resp.json().await.unwrap();
    let upstreams = list.get("upstreams").and_then(|v| v.as_array()).unwrap();
    assert_eq!(upstreams.len(), 1);
    assert_eq!(upstreams[0].as_str(), Some("test-upstream"));

    // C. Verify Exists via /verify
    let verify_body = serde_json::json!({ "name": "test-upstream" });
    let resp = client
        .post(format!("{}/upstreams/verify", base_url))
        .json(&verify_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v_resp: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v_resp.get("exists").and_then(|v| v.as_bool()), Some(true));

    // D. Add Duplicate Upstream -> Expect 400 Bad Request
    let resp = client
        .post(format!("{}/upstreams/add", base_url))
        .json(&upstream_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // E. Add Invalid Upstream (No servers) -> Expect 400 Bad Request
    let invalid_upstream = serde_json::json!({
        "upstream": {
            "name": "invalid-upstream",
            "servers": []
        }
    });
    let resp = client
        .post(format!("{}/upstreams/add", base_url))
        .json(&invalid_upstream)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // F. Update Upstream (Valid)
    // Changing weight implies complex update, here we just check request succeeds
    let update_payload = serde_json::json!({
        "name": "test-upstream", // Name in body for lookup
        "upstream": {
            "name": "test-upstream", // Name in upstream definition
            "servers": [{ "host": "httpbingo.org:443", "weight": 50 }]
        }
    });
    let resp = client
        .post(format!("{}/upstreams/update", base_url))
        .json(&update_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // G. Update Non-Existent Upstream -> Expect 400 Bad Request
    let update_missing = serde_json::json!({
        "name": "missing-upstream",
        "upstream": {
            "name": "missing-upstream",
            "servers": [{ "host": "httpbingo.org:443" }]
        }
    });
    let resp = client
        .post(format!("{}/upstreams/update", base_url))
        .json(&update_missing)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // H. Remove Upstream
    let remove_body = serde_json::json!({ "name": "test-upstream" });
    let resp = client
        .post(format!("{}/upstreams/remove", base_url))
        .json(&remove_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // I. Verify Removed
    let resp = client
        .get(format!("{}/upstreams/list", base_url))
        .send()
        .await
        .unwrap();
    let list: serde_json::Value = resp.json().await.unwrap();
    let upstreams = list.get("upstreams").and_then(|v| v.as_array()).unwrap();
    assert!(upstreams.is_empty());

    // J. Remove Non-Existent (Idempotent) -> Expect 200 OK
    let resp = client
        .post(format!("{}/upstreams/remove", base_url))
        .json(&remove_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // =========================================================================
    // 5. Test Service API
    // =========================================================================

    // Add upstream back for service
    client
        .post(format!("{}/upstreams/add", base_url))
        .json(&upstream_payload)
        .send()
        .await
        .unwrap();

    let service_payload = serde_json::json!({
        "service": {
            "name": "test-service",
            "host": "test-upstream",
            "protocols": ["http"],
            "routes": [{
                "name": "root",
                "rules": [{ "rule": "PathPrefix(`/`)" }]
            }]
        }
    });

    // A. Add Service
    let resp = client
        .post(format!("{}/services/add", base_url))
        .json(&service_payload)
        .send()
        .await
        .unwrap();
    if resp.status() != StatusCode::OK {
        // Debug
        let txt = resp.text().await.unwrap_or_default();
        panic!("Add service failed: {}", txt);
    }
    assert_eq!(resp.status(), StatusCode::OK);

    // A2. Add Duplicate Service -> Expect 400 Bad Request
    let resp = client
        .post(format!("{}/services/add", base_url))
        .json(&service_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // B. Verify Service List
    let resp = client
        .get(format!("{}/services/list", base_url))
        .send()
        .await
        .unwrap();
    let list: serde_json::Value = resp.json().await.unwrap();
    let services = list.get("services").and_then(|v| v.as_array()).unwrap();
    assert_eq!(services.len(), 1);
    assert_eq!(
        services[0].get("name").and_then(|v| v.as_str()),
        Some("test-service")
    );
    assert_eq!(
        services[0].get("host").and_then(|v| v.as_str()),
        Some("test-upstream")
    );

    // C. Update Service (Valid)
    let update_svc_payload = serde_json::json!({
        "name": "test-service",
        "service": {
            "name": "test-service",
            "host": "test-upstream",
            "protocols": ["http"],
            "routes": [{
                "name": "api",
                "rules": [{ "rule": "PathPrefix(`/api`)" }] // Changed rule
            }]
        }
    });
    let resp = client
        .post(format!("{}/services/update", base_url))
        .json(&update_svc_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // D. Update Non-Existent Service -> Expect 400 Bad Request
    let update_missing_svc = serde_json::json!({
        "name": "missing-service",
        "service": {
            "name": "missing-service",
            "host": "test-upstream",
            "protocols": ["http"],
            "routes": [{
                "name": "root",
                "rules": [{ "rule": "PathPrefix(`/`)" }]
            }]
        }
    });
    let resp = client
        .post(format!("{}/services/update", base_url))
        .json(&update_missing_svc)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // E. Remove Service
    let remove_svc_body = serde_json::json!({ "name": "test-service" });
    let resp = client
        .post(format!("{}/services/remove", base_url))
        .json(&remove_svc_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // F. Verify Removed
    let resp = client
        .get(format!("{}/services/list", base_url))
        .send()
        .await
        .unwrap();
    let list: serde_json::Value = resp.json().await.unwrap();
    let services = list.get("services").and_then(|v| v.as_array()).unwrap();
    assert!(services.is_empty());
}

#[tokio::test]
async fn test_api_basic_auth() {
    let _ = env_logger::builder().is_test(true).try_init();

    // Setup API with basic auth
    let api_port = 9100;
    let api_addr = format!("127.0.0.1:{}", api_port);

    let config = WhooshConfig {
        http_listen: "127.0.0.1:0".to_string(),
        api: Some(ApiSettings {
            listen: Some(api_addr.clone()),
            basic_auth: Some(BasicAuth {
                username: "admin".to_string(),
                password: "secret123".to_string(),
            }),
            ..Default::default()
        }),
        ..Default::default()
    };

    std::thread::spawn(move || {
        let app = App::new(config, None, vec![], vec![]);
        if let Err(e) = app.run() {
            eprintln!("Server exited with error: {}", e);
        }
    });

    let client = reqwest::Client::new();
    let base_url = format!("http://{}", api_addr);

    // Wait for server to start
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Test 1: Request without auth should return 401
    let resp = client
        .get(format!("{}/upstreams/list", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(resp.headers().contains_key("www-authenticate"));

    // Test 2: Request with wrong credentials should return 401
    let resp = client
        .get(format!("{}/upstreams/list", base_url))
        .basic_auth("admin", Some("wrongpassword"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Test 3: Request with correct credentials should succeed
    let resp = client
        .get(format!("{}/upstreams/list", base_url))
        .basic_auth("admin", Some("secret123"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Test 4: POST request with auth should work
    let upstream_payload = serde_json::json!({
        "upstream": {
            "name": "auth-test-upstream",
            "servers": [{ "host": "httpbingo.org:443" }]
        }
    });

    let resp = client
        .post(format!("{}/upstreams/add", base_url))
        .basic_auth("admin", Some("secret123"))
        .json(&upstream_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_control_upstream_services_from_config() {
    let _ = env_logger::builder().is_test(true).try_init();

    // 1. Setup Config with Pre-defined Upstream and Service
    let api_port = 9101;
    let api_addr = format!("127.0.0.1:{}", api_port);

    // We need to import Upstream, Service, UpstreamServer, Route, Rule...
    // They are available in whoosh::config::models
    use whoosh::config::models::{Route, Rule, Service, ServiceProtocol, Upstream, UpstreamServer};

    let config = WhooshConfig {
        http_listen: "127.0.0.1:9102".to_string(),
        api: Some(ApiSettings {
            listen: Some(api_addr.clone()),
            ..Default::default()
        }),
        upstreams: vec![Upstream {
            name: "config-upstream".to_string(),
            servers: vec![UpstreamServer {
                host: "httpbingo.org:443".to_string(),
                weight: Some(1),
                peer_options: None,
            }],
            peer_options: None,
        }],
        services: vec![Service {
            name: "config-service".to_string(),
            host: "config-upstream".to_string(),
            protocols: vec![ServiceProtocol::Http],
            routes: vec![Route {
                name: "config-route".to_string(),
                rules: vec![Rule {
                    rule: "PathPrefix(`/get`)".to_string(),
                    priority: None,
                    request_transformer: None,
                    response_transformer: None,
                }],
            }],
        }]
        .into_iter()
        .map(std::sync::Arc::new)
        .collect(),
        ..Default::default()
    };

    // 2. Start Server
    std::thread::spawn(move || {
        let app = App::new(config, None, vec![], vec![]);
        if let Err(e) = app.run() {
            eprintln!("Server exited with error: {}", e);
        }
    });

    let client = reqwest::Client::new();
    let base_url = format!("http://{}", api_addr);

    // Wait for server to start
    tokio::time::sleep(Duration::from_secs(1)).await;

    // 3. Verify Upstream Exists
    let resp = client
        .get(format!("{}/upstreams/list", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let list: serde_json::Value = resp.json().await.unwrap();
    let upstreams = list.get("upstreams").and_then(|v| v.as_array()).unwrap();
    assert!(
        upstreams
            .iter()
            .any(|u| u.as_str() == Some("config-upstream"))
    );

    // 4. Verify Service Exists
    let resp = client
        .get(format!("{}/services/list", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let list: serde_json::Value = resp.json().await.unwrap();
    let services = list.get("services").and_then(|v| v.as_array()).unwrap();
    let svc = services
        .iter()
        .find(|s| s["name"] == "config-service")
        .expect("Service from config not found");
    assert_eq!(svc["host"], "config-upstream");

    // 4.5 Verify Proxy Request
    let proxy_url = "http://127.0.0.1:9102/get";
    let resp = client
        .get(proxy_url)
        .header("User-Agent", "whoosh-test")
        .send()
        .await
        .expect("Failed to call proxy");
    assert_eq!(resp.status(), StatusCode::OK);
    // Optional: check body to confirm it's from httpbingo
    // let body: serde_json::Value = resp.json().await.unwrap();
    // assert!(body.get("url").is_some());

    // 5. Update Config-defined Upstream
    let update_upstream_payload = serde_json::json!({
        "name": "config-upstream",
        "upstream": {
            "name": "config-upstream",
            "servers": [{ "host": "httpbingo.org:443", "weight": 10 }]
        }
    });
    let resp = client
        .post(format!("{}/upstreams/update", base_url))
        .json(&update_upstream_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 5.5. Update Config-defined Service (Change Route)
    let update_svc_payload = serde_json::json!({
        "name": "config-service",
        "service": {
            "name": "config-service",
            "host": "config-upstream",
            "protocols": ["http"],
            "routes": [{
                "name": "config-route",
                "rules": [{ "rule": "PathPrefix(`/headers`)" }]
            }]
        }
    });
    let resp = client
        .post(format!("{}/services/update", base_url))
        .json(&update_svc_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify New Route (/headers) works
    let proxy_url_new = "http://127.0.0.1:9102/headers";
    let resp = client
        .get(proxy_url_new)
        .header("User-Agent", "whoosh-test")
        .send()
        .await
        .expect("Failed to call proxy on new route");
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify Old Route (/get) is 404
    let proxy_url_old = "http://127.0.0.1:9102/get";
    let resp = client
        .get(proxy_url_old)
        .header("User-Agent", "whoosh-test")
        .send()
        .await
        .expect("Failed to call proxy on old route");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // 6. Remove Config-defined Service
    let remove_svc_body = serde_json::json!({ "name": "config-service" });
    let resp = client
        .post(format!("{}/services/remove", base_url))
        .json(&remove_svc_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify removed
    let resp = client
        .get(format!("{}/services/list", base_url))
        .send()
        .await
        .unwrap();
    let list: serde_json::Value = resp.json().await.unwrap();
    let services = list.get("services").and_then(|v| v.as_array()).unwrap();
    assert!(!services.iter().any(|s| s["name"] == "config-service"));

    // 7. Remove Config-defined Upstream
    let remove_upstream_body = serde_json::json!({ "name": "config-upstream" });
    let resp = client
        .post(format!("{}/upstreams/remove", base_url))
        .json(&remove_upstream_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify removed
    let resp = client
        .get(format!("{}/upstreams/list", base_url))
        .send()
        .await
        .unwrap();
    let list: serde_json::Value = resp.json().await.unwrap();
    let upstreams = list.get("upstreams").and_then(|v| v.as_array()).unwrap();
    assert!(
        !upstreams
            .iter()
            .any(|u| u.as_str() == Some("config-upstream"))
    );
}
