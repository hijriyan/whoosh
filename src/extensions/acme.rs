use crate::config::models::{AcmeChallengeType, AcmeSettings};
use dashmap::DashMap;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use rcgen::CertificateParams;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Default, Clone)]
struct AcmeStorage {
    certificates: HashMap<String, CertificateEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    account: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CertificateEntry {
    pub certificate: String,
    pub private_key: String,
}

use std::sync::RwLock;

pub struct AcmeManager {
    settings: AcmeSettings,
    // Map of token -> key_authorization used for HTTP-01 challenge
    challenges: Arc<DashMap<String, String>>,
    // Map of domain -> (certificate, private_key) for TLS-ALPN-01 challenge
    tls_alpn_challenges: Arc<DashMap<String, (String, String)>>,
    // Cache of the persistent storage
    storage: Arc<RwLock<AcmeStorage>>,
}

impl AcmeManager {
    pub fn new(settings: &AcmeSettings) -> Self {
        let manager = Self {
            settings: settings.clone(),
            challenges: Arc::new(DashMap::new()),
            tls_alpn_challenges: Arc::new(DashMap::new()),
            storage: Arc::new(RwLock::new(AcmeStorage::default())),
        };
        // Load storage into cache
        let storage = manager.read_storage_from_disk();
        *manager.storage.write().unwrap() = storage;
        manager
    }

    /// Retrieve the key authorization for a given token.
    /// This should be called by the HTTP server when handling /.well-known/acme-challenge/<token>
    pub fn get_challenge(&self, token: &str) -> Option<String> {
        self.challenges.get(token).map(|v| v.value().clone())
    }

    /// Retrieve the TLS-ALPN challenge certificate for a given domain.
    /// This should be called by the SSL extension during TLS handshake
    pub fn get_tls_alpn_challenge(&self, domain: &str) -> Option<(String, String)> {
        self.tls_alpn_challenges
            .get(domain)
            .map(|v| v.value().clone())
    }

    fn read_storage_from_disk(&self) -> AcmeStorage {
        let path = Path::new(&self.settings.storage);
        if !path.exists() {
            return AcmeStorage::default();
        }

        match File::open(path) {
            Ok(file) => {
                let reader = BufReader::new(file);
                match serde_json::from_reader(reader) {
                    Ok(storage) => storage,
                    Err(e) => {
                        log::warn!(
                            "Failed to parse ACME storage from {}: {}. Using default.",
                            path.display(),
                            e
                        );
                        AcmeStorage::default()
                    }
                }
            }
            Err(e) => {
                log::warn!(
                    "Failed to open ACME storage at {}: {}. Using default.",
                    path.display(),
                    e
                );
                AcmeStorage::default()
            }
        }
    }

    fn load_storage(&self) -> AcmeStorage {
        (*self.storage.read().unwrap()).clone()
    }

    fn save_storage(&self, storage: &AcmeStorage) -> Result<(), Box<dyn std::error::Error>> {
        // Update cache
        *self.storage.write().unwrap() = storage.clone();

        // Write to disk
        let path = Path::new(&self.settings.storage);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                WhooshError::Acme(format!(
                    "Failed to create directory: {} (error {})",
                    parent.display(),
                    e
                ))
            })?;
        }
        let file = File::create(path).map_err(|e| {
            WhooshError::Acme(format!(
                "Failed to create file: {} (error {})",
                path.display(),
                e
            ))
        })?;
        serde_json::to_writer_pretty(file, storage).map_err(|e| {
            WhooshError::Acme(format!(
                "Failed to write to file: {} (error {})",
                path.display(),
                e
            ))
        })?;
        Ok(())
    }

    pub fn load_certificate(&self, domain: &str) -> Option<CertificateEntry> {
        let storage = self.load_storage();
        storage.certificates.get(domain).cloned()
    }

    pub fn list_certificates(&self) -> HashMap<String, CertificateEntry> {
        self.load_storage().certificates
    }

    fn save_certificate(
        &self,
        domain: String,
        cert: String,
        key: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut storage = self.load_storage();
        storage.certificates.insert(
            domain,
            CertificateEntry {
                certificate: cert,
                private_key: key,
            },
        );
        self.save_storage(&storage)
    }

    fn save_account(&self, credentials: String) -> Result<(), Box<dyn std::error::Error>> {
        let mut storage = self.load_storage();
        storage.account = Some(credentials);
        self.save_storage(&storage)
    }

    fn load_account(&self) -> Option<String> {
        self.load_storage().account
    }

    /// Request a certificate for the given domains.
    /// Returns (certificate_pem, private_key_pem)
    pub async fn request_certificate(
        &self,
        domains: Vec<String>,
    ) -> Result<(String, String), Box<dyn std::error::Error>> {
        if domains.is_empty() {
            return Err("No domains provided".into());
        }

        log::info!("Starting ACME order for domains: {:?}", domains);

        // 1. Get or Create ACME Account
        let account = if let Some(creds_json) = self.load_account() {
            log::info!("Loading existing ACME account");
            let creds: AccountCredentials = serde_json::from_str(&creds_json)?;
            Account::builder()?.from_credentials(creds).await?
        } else {
            log::info!("Creating new ACME account");
            let contact = format!("mailto:{}", self.settings.email);
            let new_account = NewAccount {
                contact: &[&contact],
                terms_of_service_agreed: true,
                only_return_existing: false,
            };

            let (account, credentials) = Account::builder()?
                .create(&new_account, self.settings.ca_server.clone(), None)
                .await?;

            let creds_json = serde_json::to_string(&credentials)?;
            self.save_account(creds_json)?;
            log::info!("ACME account created and saved");
            account
        };

        // 2. Create New Order
        let identifiers: Vec<Identifier> =
            domains.iter().map(|d| Identifier::Dns(d.clone())).collect();

        let new_order = NewOrder::new(&identifiers);

        let mut order = account.new_order(&new_order).await?;

        // 3. Handle Authorizations
        let mut auths = order.authorizations();
        let mut tokens_to_cleanup = Vec::new();
        let mut domains_to_cleanup = Vec::new();

        while let Some(auth) = auths.next().await {
            let mut auth = auth?;
            if auth.status == AuthorizationStatus::Valid {
                continue;
            }

            // Select challenge based on config
            let challenge_type = match self.settings.challenge {
                AcmeChallengeType::Http01 => ChallengeType::Http01,
                AcmeChallengeType::TlsAlpn01 => ChallengeType::TlsAlpn01,
            };

            let challenge_type_str = format!("{:?}", challenge_type);

            // Get domain identifier before creating challenge to avoid borrowing issues
            let domain = format!("{}", auth.identifier());

            let mut challenge = auth
                .challenge(challenge_type)
                .ok_or(format!("No {} challenge found", challenge_type_str))?;

            let token = challenge.token.clone();
            let key_auth = challenge.key_authorization();

            // Register challenge so our server can serve it
            if matches!(self.settings.challenge, AcmeChallengeType::Http01) {
                self.challenges
                    .insert(token.clone(), key_auth.as_str().to_string());
                tokens_to_cleanup.push(token.clone());
            } else if matches!(self.settings.challenge, AcmeChallengeType::TlsAlpn01) {
                // For TLS-ALPN-01, generate a special certificate with the key authorization
                let key_auth_str = key_auth.as_str().to_string();

                match self.generate_tls_alpn_certificate(&domain, &key_auth_str) {
                    Ok((cert_pem, key_pem)) => {
                        self.tls_alpn_challenges
                            .insert(domain.clone(), (cert_pem, key_pem));
                        domains_to_cleanup.push(domain.clone());
                        tokens_to_cleanup.push(token.clone());
                        log::info!("Generated TLS-ALPN certificate for domain: {}", domain);
                    }
                    Err(e) => {
                        log::error!(
                            "Failed to generate TLS-ALPN certificate for {}: {}",
                            domain,
                            e
                        );
                        return Err(e);
                    }
                }
            }

            log::info!("Prepared challenge for token: {}", token);

            // Signal to ACME server that we are ready
            challenge.set_ready().await?;
        }

        // Wait for order to be ready
        let state = order.poll_ready(&RetryPolicy::default()).await?;
        if state != OrderStatus::Ready {
            // Cleanup on failure
            for t in tokens_to_cleanup {
                self.challenges.remove(&t);
            }
            for domain in domains_to_cleanup {
                self.tls_alpn_challenges.remove(&domain);
            }
            return Err(format!("Order failed: {:?}", state).into());
        }

        // 4. Finalize Order
        // Generate CSR
        let mut params = CertificateParams::new(domains.clone())?;
        params.distinguished_name.remove(rcgen::DnType::CommonName);
        if let Some(first_domain) = domains.first() {
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, first_domain.clone());
        }
        // rcgen generates a key pair automatically
        let key_pair = rcgen::KeyPair::generate()?;
        let csr = params.serialize_request(&key_pair)?;
        let private_key_pem = key_pair.serialize_pem();

        log::info!("Finalizing order with CSR");
        order.finalize_csr(csr.der()).await?;

        // 5. Download Certificate
        let cert_pem = order.poll_certificate(&RetryPolicy::default()).await?;
        log::info!("Certificate received");

        // Save certificate
        if let Some(first_domain) = domains.first() {
            self.save_certificate(
                first_domain.clone(),
                cert_pem.clone(),
                private_key_pem.clone(),
            )
            .unwrap_or_else(|e| log::error!("Failed to save certificate: {}", e));
        }

        // Cleanup challenges
        for t in tokens_to_cleanup {
            self.challenges.remove(&t);
        }
        for domain in domains_to_cleanup {
            self.tls_alpn_challenges.remove(&domain);
        }

        Ok((cert_pem, private_key_pem))
    }

    /// Generate a TLS-ALPN-01 challenge certificate for the given domain and key authorization
    fn generate_tls_alpn_certificate(
        &self,
        domain: &str,
        key_auth: &str,
    ) -> Result<(String, String), Box<dyn std::error::Error>> {
        use openssl::sha::sha256;

        // Generate a key pair for the certificate
        let key_pair = rcgen::KeyPair::generate()?;

        // Create certificate parameters
        let mut params = rcgen::CertificateParams::new(vec![domain.to_string()])?;
        params.distinguished_name.remove(rcgen::DnType::CommonName);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, domain.to_string());

        // For TLS-ALPN-01, we need to add the ACME identifier extension
        // The extension contains a hash of the key authorization
        let key_auth_hash = sha256(key_auth.as_bytes());

        // Create the ACME identifier extension using rcgen's built-in method
        let acme_extension = rcgen::CustomExtension::new_acme_identifier(&key_auth_hash);
        params.custom_extensions.push(acme_extension);

        // Generate the certificate
        let cert = params.self_signed(&key_pair)?;

        // Convert to PEM format
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        Ok((cert_pem, key_pem))
    }
}

use crate::config::models::WhooshConfig;
use crate::router::registry::get_registered_hosts;
use crate::server::context::{AppCtx, RouteContext};
use crate::server::extension::{WhooshExtension, WhooshFilter};
use async_trait::async_trait;
use pingora::Error;
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use pingora::server::Server;
use pingora::server::ShutdownWatch;
use pingora::services::background::{BackgroundService, background_service};
use x509_parser::pem::Pem;

#[derive(Clone)]
pub struct AcmeExtension {
    pub acme_manager: Arc<AcmeManager>,
    pub config: Arc<WhooshConfig>,
}

impl AcmeExtension {
    pub fn new(settings: &AcmeSettings, config: Arc<WhooshConfig>) -> Self {
        Self {
            acme_manager: Arc::new(AcmeManager::new(settings)),
            config,
        }
    }
}

#[derive(Clone)]
pub struct AcmeFilter {
    pub acme_manager: Arc<AcmeManager>,
}

#[async_trait]
impl WhooshFilter for AcmeFilter {
    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut RouteContext,
        _app_ctx: &AppCtx,
    ) -> Result<bool, Box<Error>> {
        let path = session.req_header().uri.path();
        if path.starts_with("/.well-known/acme-challenge/") {
            let token = path.trim_start_matches("/.well-known/acme-challenge/");
            if let Some(key_auth) = self.acme_manager.get_challenge(token) {
                let mut header = ResponseHeader::build(200, Some(key_auth.len())).unwrap();
                header.insert_header("Content-Type", "text/plain").unwrap();

                session
                    .write_response_header(Box::new(header), false)
                    .await?;
                session
                    .write_response_body(Some(bytes::Bytes::from(key_auth)), true)
                    .await?;
                return Ok(true); // Handled
            }
        }
        Ok(false)
    }
}

use crate::error::WhooshError;

#[async_trait]
impl WhooshExtension for AcmeExtension {
    fn whoosh_init(&self, server: &mut Server, app_ctx: &mut AppCtx) -> Result<(), WhooshError> {
        let renewal_service = AcmeRenewalService {
            acme: self.acme_manager.clone(),
            config: self.config.clone(),
        };
        let bg_service = background_service("acme_renewal", renewal_service);
        server.add_service(bg_service);

        // Share AcmeManager with other extensions (e.g. HttpsExtension)
        app_ctx.insert(self.acme_manager.clone());
        Ok(())
    }
}

pub struct AcmeRenewalService {
    pub acme: Arc<AcmeManager>,
    pub config: Arc<WhooshConfig>,
}

#[async_trait]
impl BackgroundService for AcmeRenewalService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400)); // 24 hours

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.renew_certificates().await;
                }
                _ = shutdown.changed() => {
                    break;
                }
            }
        }
    }
}

impl AcmeRenewalService {
    async fn renew_certificates(&self) {
        log::info!("Checking for certificate renewals...");
        let certificates = self.acme.list_certificates();
        let registered_hosts = get_registered_hosts();
        for host in registered_hosts {
            if !certificates.contains_key(&host) {
                if let Err(e) = self.acme.request_certificate(vec![host.clone()]).await {
                    log::error!("Failed to request certificate for {}: {}", host, e);
                } else {
                    log::info!("Successfully requested certificate for {}", host);
                }
            }
        }

        for (domain, entry) in certificates {
            let Ok((cert, _bytes_read)) =
                Pem::read(std::io::Cursor::new(entry.certificate.as_bytes()))
            else {
                continue;
            };

            if let Ok((_, x509)) = x509_parser::parse_x509_certificate(&cert.contents) {
                let not_after = x509.validity().not_after;
                let now = x509_parser::time::ASN1Time::now();

                // Renew if expiring in less than 30 days
                let days_remaining = (not_after.timestamp() - now.timestamp()) / 86400;

                if days_remaining < 30 {
                    log::info!(
                        "Certificate for {} is expiring in {} days. Renewing...",
                        domain,
                        days_remaining
                    );
                    if let Err(e) = self.acme.request_certificate(vec![domain.clone()]).await {
                        log::error!("Failed to renew certificate for {}: {}", domain, e);
                    } else {
                        log::info!("Successfully renewed certificate for {}", domain);
                    }
                } else {
                    log::debug!(
                        "Certificate for {} is valid for {} days",
                        domain,
                        days_remaining
                    );
                }
            }
        }
    }
}
