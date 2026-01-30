use crate::config::models::WhooshConfig;
use crate::error::WhooshError;
use crate::extensions::acme::AcmeManager;
use crate::server::context::AppCtx;
use crate::server::extension::WhooshExtension;
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
        let proxy = WhooshProxy::new(router, Arc::new(app_ctx.clone()))?;

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
                (Some(cert), Some(key)) => {
                    if !Path::new(cert).exists() {
                        return Err(WhooshError::Tls(format!(
                            "Certificate file not found: {}",
                            cert
                        )));
                    }
                    if !Path::new(key).exists() {
                        return Err(WhooshError::Tls(format!(
                            "Private key file not found: {}",
                            key
                        )));
                    }
                    Some((cert, key))
                }
                (Some(_), None) | (None, Some(_)) => {
                    log::error!("Both server_cert and server_key must be specified together");
                    return Err(WhooshError::Tls(
                        "Both server_cert and server_key must be specified together".to_string(),
                    ));
                }
                _ => None,
            };

            let base_pair = if let Some((cert_path, key_path)) = cert_paths {
                match Self::load_pem_pair_from_files(cert_path, key_path) {
                    Ok(pair) => Some(pair),
                    Err(e) => {
                        log::error!("Failed to load TLS certs from config: {}", e);
                        return Err(WhooshError::Tls(format!(
                            "Failed to load TLS certs from config: {}",
                            e
                        )));
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
                    log::error!("Failed to set fallback private key: {}", e);
                    return Err(WhooshError::Tls(format!(
                        "Failed to set fallback private key: {}",
                        e
                    )));
                }
                if let Err(e) = ssl_acceptor.set_certificate(cert) {
                    log::error!("Failed to set fallback certificate: {}", e);
                    return Err(WhooshError::Tls(format!(
                        "Failed to set fallback certificate: {}",
                        e
                    )));
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
                    log::debug!("ALPN selection callback triggered (ACME mode)");

                    // Helper to parse OpenSSL ALPN wire format (len1, proto1, len2, proto2...)
                    let mut found_acme = false;
                    let mut found_h2 = false;

                    let mut pos = 0;
                    while pos < client_protos.len() {
                        let len = client_protos[pos] as usize;
                        pos += 1;
                        if pos + len > client_protos.len() {
                            break;
                        }
                        let proto = &client_protos[pos..pos + len];
                        if proto == b"acme-tls/1" {
                            found_acme = true;
                        } else if proto == b"h2" {
                            found_h2 = true;
                        }
                        pos += len;
                    }

                    if found_acme {
                        if let Some(name) = ssl_ref.servername(NameType::HOST_NAME) {
                            log::debug!("ACME TLS-ALPN-01 support requested for {}", name);
                            if let Some(am) = acme_manager_for_alpn.as_ref() {
                                if am.get_certificate_cached(name, true).is_some() {
                                    log::debug!("Selecting acme-tls/1 for {}", name);
                                    return Ok(b"acme-tls/1");
                                } else {
                                    log::warn!(
                                        "ACME challenge requested for {} but no cert in cache",
                                        name
                                    );
                                }
                            }
                        } else {
                            log::warn!("ACME challenge requested but no SNI hostname provided");
                        }
                    }

                    if found_h2 { Ok(b"h2") } else { Ok(b"http/1.1") }
                });
            } else {
                ssl_acceptor.set_alpn_select_callback(|_, client_protos| {
                    log::debug!("ALPN selection callback triggered (Standard mode)");
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
                        if let Some(cached) = am.get_certificate_cached(&name, use_acme_tls_alpn) {
                            log::debug!("Serving certificate from cache for {}", name);
                            if let Some(leaf) = cached.certificate_chain.first() {
                                if ssl_ref.set_certificate(leaf).is_ok()
                                    && ssl_ref.set_private_key(&cached.private_key).is_ok()
                                {
                                    for intermediate in cached.certificate_chain.iter().skip(1) {
                                        let _ = ssl_ref.add_chain_cert(intermediate.clone());
                                    }
                                    log::debug!(
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
                if !Path::new(cacert).exists() {
                    return Err(WhooshError::Tls(format!(
                        "CA certificate file not found: {}",
                        cacert
                    )));
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{AcmeChallengeType, AcmeSettings, WhooshConfig};

    #[test]
    fn test_use_acme_tls_alpn_logic() {
        let mut config = WhooshConfig::default();

        // Case 1: No acme manager, no acme config
        let acme_manager: Option<Arc<AcmeManager>> = None;
        let use_acme_tls_alpn = acme_manager.is_some()
            && config
                .acme
                .as_ref()
                .map(|acme| matches!(acme.challenge, AcmeChallengeType::TlsAlpn01))
                .unwrap_or(false);
        assert!(!use_acme_tls_alpn);

        // Case 2: Acme config present but not TlsAlpn01
        config.acme = Some(AcmeSettings {
            challenge: AcmeChallengeType::Http01,
            ..Default::default()
        });

        // We need a dummy AcmeSettings for AcmeManager
        let settings = AcmeSettings {
            storage: "/tmp/whoosh_test_storage.json".to_string(),
            challenge: AcmeChallengeType::Http01,
            ..Default::default()
        };
        let acme_manager = Some(Arc::new(AcmeManager::new(&settings)));
        let use_acme_tls_alpn = acme_manager.is_some()
            && config
                .acme
                .as_ref()
                .map(|acme| matches!(acme.challenge, AcmeChallengeType::TlsAlpn01))
                .unwrap_or(false);
        assert!(!use_acme_tls_alpn);

        // Case 3: Acme config present and TlsAlpn01
        config.acme = Some(AcmeSettings {
            challenge: AcmeChallengeType::TlsAlpn01,
            ..Default::default()
        });
        let use_acme_tls_alpn = acme_manager.is_some()
            && config
                .acme
                .as_ref()
                .map(|acme| matches!(acme.challenge, AcmeChallengeType::TlsAlpn01))
                .unwrap_or(false);
        assert!(use_acme_tls_alpn);
    }

    #[test]
    fn test_alpn_selection_logic() {
        // Mock the logic inside the callback
        let client_protos_with_acme = b"\x0aacme-tls/1\x02h2\x08http/1.1";
        let client_protos_without_acme = b"\x02h2\x08http/1.1";

        // Logic check for acme-tls/1
        // client_protos.windows(11).any(|w| w[0] == 0x0a && &w[1..] == b"acme-tls/1")
        let has_acme = |protos: &[u8]| {
            protos
                .windows(11)
                .any(|w| w[0] == 0x0a && &w[1..] == b"acme-tls/1")
        };

        assert!(has_acme(client_protos_with_acme));
        assert!(!has_acme(client_protos_without_acme));

        // Logic check for h2
        // client_protos.windows(2).any(|w| w == b"h2")
        let has_h2 = |protos: &[u8]| protos.windows(2).any(|w| w == b"h2");

        assert!(has_h2(client_protos_with_acme));
        assert!(has_h2(client_protos_without_acme));
    }
}
