use nullifierdb::NullifierDB;
use anonymous_credit_tokens::{PrivateKey, u32_to_scalar, Params};
use std::path::Path;
use std::sync::{Arc, Mutex};
use log::{info, warn, error, debug};
use rand_core::OsRng;
use actix_web::{App, HttpServer, post, HttpResponse};
use actix_web::web::Data;
use actix_web::error::{ErrorBadRequest, ErrorInternalServerError};
use bytes::Bytes;
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType};
use crate::leading_zeros;

// Import the API types from our library
use crate::{Request, Response};

type DB = Arc<Mutex<NullifierDB>>;

fn generate_self_signed_cert() -> Result<(String, String), Box<dyn std::error::Error>> {
    info!("Generating self-signed TLS certificate...");
    
    let cert_path = Path::new("cert.pem");
    let key_path = Path::new("key.pem");
    
    // Check if certificate files already exist
    if cert_path.exists() && key_path.exists() {
        info!("Found existing TLS certificate and key");
        let cert = std::fs::read_to_string(cert_path)?;
        let key = std::fs::read_to_string(key_path)?;
        return Ok((cert, key));
    }
    
    // Configure certificate parameters
    let mut params = CertificateParams::default();
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "localhost");
    params.distinguished_name = distinguished_name;
    
    // Generate self-signed certificate
    let cert = Certificate::from_params(params)?;
    let cert_pem = cert.serialize_pem()?;
    let key_pem = cert.serialize_private_key_pem();
    
    // Save certificate and key to files
    std::fs::write(cert_path, &cert_pem)?;
    std::fs::write(key_path, &key_pem)?;
    
    info!("Generated and saved self-signed TLS certificate");
    
    Ok((cert_pem, key_pem))
}

fn initialize_keys() -> PrivateKey {
    let key_path = Path::new("private_key");
    
    if key_path.exists() {
        // Try to read existing key from file
        match std::fs::read(key_path) {
            Ok(bytes) => match bincode::serde::decode_from_slice::<PrivateKey, _>(&bytes, bincode::config::standard()) {
                Ok((key, _)) => {
                    info!("Successfully loaded private key from file");
                    info!("Public key is available for verification");
                    return key
                },
                Err(e) => warn!("Failed to decode private key file: {}. Generating new key.", e)
            },
            Err(e) => warn!("Failed to read private key file: {}. Generating new key.", e)
        }
    } else {
        info!("No existing private key found. Generating new key.");
    }
    
    // Generate a new key since we couldn't read an existing one
    let new_key = PrivateKey::random(OsRng);
    info!("Generated new private key");
    
    // Save the new key to file
    if let Ok(bytes) = bincode::serde::encode_to_vec(&new_key, bincode::config::standard()) {
        match std::fs::write(key_path, bytes) {
            Ok(_) => {
                info!("Saved new private key to file");
                info!("Public key is available for verification");
            },
            Err(e) => warn!("Failed to save private key to file: {}", e)
        }
    } else {
        error!("Failed to encode private key");
    }
    
    new_key
}

fn load_rustls_config() -> std::io::Result<ServerConfig> {
    // Generate or load certificate and private key
    let (cert_pem, key_pem) = generate_self_signed_cert()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    
    // Load certificate
    let cert_chain = certs(&mut cert_pem.as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid certificate data"))?
        .iter()
        .map(|c| rustls::Certificate(c.clone()))
        .collect();
    
    // Load private key
    let mut keys = pkcs8_private_keys(&mut key_pem.as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid private key data"))?;
    
    if keys.is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "No private keys found"));
    }
    
    let private_key = rustls::PrivateKey(keys.remove(0));
    
    // Create TLS configuration
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    
    Ok(config)
}

// Handler for processing token requests
#[post("/token")]
async fn process_token(
    data: Bytes,
    db: Data<DB>,
    private_key: Data<Arc<PrivateKey>>,
) -> actix_web::Result<HttpResponse> {
    let params = Params::nothing_up_my_sleeve(b"innocence v0.1");
    let mut db = db.lock().expect("poisoning my ass");

    // Decode the request
    let request = match bincode::serde::decode_from_slice::<Request, _>(
        &data,
        bincode::config::standard()
    ) {
        Ok((req, _)) => req,
        Err(e) => {
            error!("Failed to decode request: {}", e);
            return Err(ErrorBadRequest("Invalid request format"));
        }
    };
    
    // Process based on request type
    let response = match request {
        Request::Spend(proof) => {
            debug!("Processing spend request");
            if let Some(refund) = private_key.refund(&params, &proof, OsRng) {
                if db.insert(proof.nullifier()).map_err(|_e| ErrorInternalServerError("internal error"))? {
                    Ok(Response::Refund(refund))
                } else {
                    Err(ErrorBadRequest("already seen nullifier"))
                }
            } else {
                Err(ErrorBadRequest("bad spend proof"))
            }

        },
        Request::Issue(issuance_request, proof_of_work) => {
            debug!("Processing issuance request");

            let hash = *blake3::hash(&proof_of_work).as_bytes();

            let leading_zeros = leading_zeros(&hash);
            debug!("leading_zeros = {}", leading_zeros);

            let c = if leading_zeros == 31 {
                u32_to_scalar(u32::MAX)
            } else {
                u32_to_scalar(2u32.pow(leading_zeros))
            };
            
            // Verify the issuance request
            if let Some(response) = private_key.issue(&params, &issuance_request, c, OsRng) {
                Ok(Response::Issue(response))
            } else {
                warn!("Incorrect issuance proofs");
                return Err(ErrorBadRequest("invalid issuance proof"));
            }
        },
        Request::GetPublicKey => {
            debug!("Processing public key request");
            let public_key = private_key.public().clone();
            Ok(Response::PublicKey(public_key))
        }
    }?;
    
    // Encode the response
    let response_bytes = match bincode::serde::encode_to_vec(
        &response,
        bincode::config::standard()
    ) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to encode response: {}", e);
            return Err(ErrorInternalServerError("Failed to encode response"));
        }
    };
    
    Ok(HttpResponse::Ok().body(response_bytes))
}

/// Run the server application with the specified configuration
pub async fn run_server() -> std::io::Result<()> {
    // Initialize the logger if not already initialized
    if std::env::var_os("RUST_LOG").is_none() {
        unsafe { std::env::set_var("RUST_LOG", "info"); }
    }
    
    info!("Starting anonymous credit server with HTTPS");
    let private_key = initialize_keys();
    
    let db = match NullifierDB::create(Path::new("./nullifiers.db")) {
        Ok(db) => {
            info!("Successfully created nullifier database");
            Arc::new(Mutex::new(db))
        },
        Err(e) => {
            error!("Failed to create nullifier database: {}", e);
            panic!("Failed to initialize nullifier database");
        }
    };
    
    // Load TLS configuration with self-signed certificate
    let rustls_config = match load_rustls_config() {
        Ok(config) => {
            info!("Successfully loaded TLS configuration");
            config
        },
        Err(e) => {
            error!("Failed to load TLS configuration: {}", e);
            panic!("Failed to initialize TLS");
        }
    };
    
    info!("Server initialized with private key, nullifier database, and TLS");
    
    // Start the HTTPS server
    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(db.clone()))
            .app_data(Data::new(Arc::new(private_key.clone())))
            .service(process_token)
    })
    .bind_rustls("0.0.0.0:8443", rustls_config)?
    .run()
    .await
}
