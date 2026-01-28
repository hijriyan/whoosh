use crate::config::models::WhooshConfig;
use crate::error::WhooshError;
use crate::extensions::acme::AcmeManager;
use crate::server::context::AppCtx;
use crate::server::extension::{WebsocketExtension, WhooshExtension, WhooshFilter};
use crate::server::proxy::WhooshProxy;
use crate::server::router::{HTTPS_PROTOCOLS, Router};
use crate::server::service::ServiceManager;
use crate::server::upstream::UpstreamManager;
use openssl::pkey::PKey;
use openssl::ssl::{NameType, SslAcceptor, SslMethod, SslVerifyMode, SslVersion};
use openssl::x509::X509;
use pingora::listeners::tls::TlsSettings;
use pingora::proxy::http_proxy_service;
use pingora::server::Server;
use std::fs;
use std::path::Path;
use std::sync::Arc;

pub struct HttpsExtension;

impl HttpsExtension {
    fn load_pem_pair_from_files(
        cert_path: &str,
        key_path: &str,
    ) -> Result<(X509, PKey<openssl::pkey::Private>), Box<dyn std::error::Error>> {
        let cert_pem = fs::read(cert_path)?;
        let key_pem = fs::read(key_path)?;
        let cert = X509::from_pem(&cert_pem)?;
        let key = PKey::private_key_from_pem(&key_pem)?;
        Ok((cert, key))
    }

    fn self_signed_pair(
        ssl: &crate::config::models::SslSettings,
    ) -> Option<(X509, PKey<openssl::pkey::Private>)> {
        let subject_alt_names = ssl
            .sans
            .clone()
            .filter(|sans| !sans.is_empty())
            .unwrap_or_else(|| vec!["localhost".to_string(), "127.0.0.1".to_string()]);

        // Custom cert parameters for self-signed
        let mut params = rcgen::CertificateParams::new(subject_alt_names).ok()?;
        params.distinguished_name.remove(rcgen::DnType::CommonName);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Whoosh Gateway");

        let key_pair = rcgen::KeyPair::generate().ok()?;
        let cert = params.self_signed(&key_pair).ok()?;

        let priv_key_pem = key_pair.serialize_pem();
        let cert_pem = cert.pem();
        let key = PKey::private_key_from_pem(priv_key_pem.as_bytes()).ok()?;
        let cert = X509::from_pem(cert_pem.as_bytes()).ok()?;
        Some((cert, key))
    }
}

fn parse_ssl_version(version: &str) -> Option<SslVersion> {
    match version.to_uppercase().as_str() {
        "TLSV1" | "TLS1" => Some(SslVersion::TLS1),
        "TLSV1.1" | "TLS1.1" => Some(SslVersion::TLS1_1),
        "TLSV1.2" | "TLS1.2" => Some(SslVersion::TLS1_2),
        "TLSV1.3" | "TLS1.3" => Some(SslVersion::TLS1_3),
        _ => None,
    }
}

impl WhooshExtension for HttpsExtension {
    fn whoosh_init(&self, server: &mut Server, app_ctx: &mut AppCtx) -> Result<(), WhooshError> {
        let config = app_ctx
            .get::<WhooshConfig>()
            .ok_or_else(|| WhooshError::Config("WhooshConfig not found in AppCtx".to_string()))?;

        // Check if HTTPS is configured to listen
        if config.https_listen.is_none() {
            return Ok(());
        }

        let filters = app_ctx
            .get::<Vec<Arc<dyn WhooshFilter>>>()
            .unwrap_or_else(|| Arc::new(Vec::new()));
        let websocket_extensions = app_ctx
            .get::<Vec<Arc<dyn WebsocketExtension>>>()
            .unwrap_or_else(|| Arc::new(Vec::new()));
        let acme_manager = app_ctx.get::<AcmeManager>();
        let upstream_manager = app_ctx.get::<UpstreamManager>().ok_or_else(|| {
            WhooshError::Config("UpstreamManager not found in AppCtx".to_string())
        })?;
        let service_manager = app_ctx
            .get::<ServiceManager>()
            .ok_or_else(|| WhooshError::Config("ServiceManager not found in AppCtx".to_string()))?;

        let router = Arc::new(Router::new(
            service_manager,
            upstream_manager.clone(),
            &HTTPS_PROTOCOLS,
            &config,
        ));

        // WhooshProxy::new returns only proxy
        let proxy = WhooshProxy::new(
            config.clone(),
            router,
            filters,
            websocket_extensions,
            Arc::new(app_ctx.clone()),
            upstream_manager,
        )?;

        // Services are already added by App from UpstreamManager

        if let Some(ssl) = &config.ssl {
            let mut ssl_acceptor = match SslAcceptor::mozilla_intermediate(SslMethod::tls()) {
                Ok(acceptor) => acceptor,
                Err(e) => {
                    log::error!("Failed to create SSL acceptor: {}", e);
                    return Err(WhooshError::Tls(format!(
                        "Failed to create SSL acceptor: {}",
                        e
                    )));
                }
            };

            let cert_paths = match (&ssl.server_cert, &ssl.server_key) {
                (Some(cert), Some(key)) if Path::new(cert).exists() && Path::new(key).exists() => {
                    Some((cert, key))
                }
                _ => None,
            };

            let base_pair = if let Some((cert_path, key_path)) = cert_paths {
                match Self::load_pem_pair_from_files(cert_path, key_path) {
                    Ok(pair) => Some(pair),
                    Err(e) => {
                        log::error!("Failed to load TLS certs from config: {}", e);
                        None
                    }
                }
            } else {
                None
            };

            let fallback_pair = match base_pair.clone() {
                Some(pair) => Some(pair),
                None => {
                    let generated = Self::self_signed_pair(ssl);
                    if generated.is_some() {
                        log::debug!("Using self-signed certificate fallback");
                    }
                    generated
                }
            };

            // Set initial certificate on the acceptor
            if let Some((cert, key)) = fallback_pair.as_ref() {
                if let Err(e) = ssl_acceptor.set_private_key(key) {
                    log::error!("Failed to set base private key: {}", e);
                }
                if let Err(e) = ssl_acceptor.set_certificate(cert) {
                    log::error!("Failed to set base certificate: {}", e);
                }
            }

            let use_acme_tls_alpn = acme_manager.is_some()
                && config
                    .acme
                    .as_ref()
                    .map(|acme| {
                        matches!(
                            acme.challenge,
                            crate::config::models::AcmeChallengeType::TlsAlpn01
                        )
                    })
                    .unwrap_or(false);

            // Configure ALPN
            if use_acme_tls_alpn {
                let acme_manager_for_alpn = acme_manager.clone();
                ssl_acceptor.set_alpn_select_callback(move |ssl_ref, client_protos| {
                    // Check if client is requesting ACME TLS-ALPN-01 challenge
                    if client_protos.windows(10).any(|w| w == b"acme-tls/1") {
                        if let Some(name) = ssl_ref.servername(NameType::HOST_NAME) {
                            // Only accept acme-tls/1 if we have the challenge cert in cache
                            if let Some(am) = acme_manager_for_alpn.as_ref() {
                                if am.get_certificate_cached(name).is_some() {
                                    log::info!("ACME TLS-ALPN-01 challenge request for {}", name);
                                    return Ok(b"acme-tls/1");
                                } else {
                                    log::warn!(
                                        "ACME challenge requested for {} but no cert in cache",
                                        name
                                    );
                                }
                            }
                        }
                    }

                    // Fallback to standard protocols if offered
                    if client_protos.windows(2).any(|w| w == b"h2") {
                        Ok(b"h2")
                    } else if client_protos.windows(8).any(|w| w == b"http/1.1") {
                        Ok(b"http/1.1")
                    } else {
                        // If h2/http.1.1 not found and it was an acme request, it will fail ALPN negotiation correctly
                        // by returning the first protocol or NOACK.
                        if let Some(first_len) = client_protos.first().copied() {
                            let first_len = first_len as usize;
                            if first_len + 1 <= client_protos.len() {
                                return Ok(&client_protos[1..first_len + 1]);
                            }
                        }
                        Err(openssl::ssl::AlpnError::NOACK)
                    }
                });
            } else {
                ssl_acceptor.set_alpn_select_callback(|_, client_protos| {
                    if client_protos.windows(2).any(|w| w == b"h2") {
                        Ok(b"h2")
                    } else {
                        Ok(b"http/1.1")
                    }
                });
            }

            // Configure SNI callback (always if acme is enabled to handle SNI-based cert loading)
            let acme_manager_for_sni = acme_manager.clone();
            let fallback_pair_for_sni = fallback_pair.clone();

            ssl_acceptor.set_servername_callback(move |ssl_ref, _alert| {
                if let Some(name) = ssl_ref
                    .servername(NameType::HOST_NAME)
                    .map(|value| value.to_string())
                {
                    log::debug!("SNI callback for hostname: {}", name);
                    if let Some(am) = acme_manager_for_sni.as_ref() {
                        if let Some(cached) = am.get_certificate_cached(&name) {
                            log::debug!("Serving certificate from cache for {}", name);
                            if let Some(leaf) = cached.certificate_chain.first() {
                                if ssl_ref.set_certificate(leaf).is_ok()
                                    && ssl_ref.set_private_key(&cached.private_key).is_ok()
                                {
                                    for intermediate in cached.certificate_chain.iter().skip(1) {
                                        let _ = ssl_ref.add_chain_cert(intermediate.clone());
                                    }
                                    log::info!(
                                        "Successfully applied ACME certificate (cached) for {}",
                                        name
                                    );
                                    return Ok(());
                                }
                            }
                        }
                    }
                }

                // Fallback cert if SNI matched nothing
                if let Some((cert, key)) = fallback_pair_for_sni.as_ref() {
                    let _ = ssl_ref.set_certificate(cert);
                    let _ = ssl_ref.set_private_key(key);
                }
                Ok(())
            });

            if let Some(ver) = ssl.ssl_min_version.as_deref().and_then(parse_ssl_version) {
                if let Err(e) = ssl_acceptor.set_min_proto_version(Some(ver)) {
                    log::error!("Failed to set min TLS version: {}", e);
                    return Err(WhooshError::Tls(format!(
                        "Failed to set min TLS version: {}",
                        e
                    )));
                }
            }
            if let Some(ver) = ssl.ssl_max_version.as_deref().and_then(parse_ssl_version) {
                if let Err(e) = ssl_acceptor.set_max_proto_version(Some(ver)) {
                    log::error!("Failed to set max TLS version: {}", e);
                    return Err(WhooshError::Tls(format!(
                        "Failed to set max TLS version: {}",
                        e
                    )));
                }
            }

            if let Some(ciphers) = &ssl.cipher_suites {
                if let Some(tls12) = &ciphers.tls12 {
                    if let Err(e) = ssl_acceptor.set_cipher_list(&tls12.join(":")) {
                        log::error!("Failed to set TLS1.2 ciphers: {}", e);
                        return Err(WhooshError::Tls(format!(
                            "Failed to set TLS1.2 ciphers: {}",
                            e
                        )));
                    }
                }
                if let Some(tls13) = &ciphers.tls13 {
                    if let Err(e) = ssl_acceptor.set_ciphersuites(&tls13.join(":")) {
                        log::error!("Failed to set TLS1.3 ciphersuites: {}", e);
                        return Err(WhooshError::Tls(format!(
                            "Failed to set TLS1.3 ciphersuites: {}",
                            e
                        )));
                    }
                }
            }

            if let Some(cacert) = &ssl.cacert {
                if let Err(e) = ssl_acceptor.set_ca_file(cacert) {
                    log::error!("Failed to set CA file {}: {}", cacert, e);
                    return Err(WhooshError::Tls(format!(
                        "Failed to set CA file {}: {}",
                        cacert, e
                    )));
                }
                ssl_acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
            }

            let tls_settings = TlsSettings::from(ssl_acceptor);

            let mut https_service = http_proxy_service(&server.configuration, proxy.clone());
            https_service.add_tls_with_settings(
                config.https_listen.as_ref().unwrap(),
                None,
                tls_settings,
            );
            server.add_service(https_service);
            log::info!(
                "HTTPS proxy listening on {}",
                config.https_listen.as_ref().unwrap()
            );
        }
        Ok(())
    }
}
