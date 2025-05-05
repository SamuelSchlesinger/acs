use nullifierdb::NullifierDB;
use anonymous_credit_tokens::{PrivateKey, scalar_to_u128, Params};
use std::path::Path;
use std::sync::{Arc, Mutex};
use log::{info, warn, error, debug};
use rand_core::OsRng;
use actix_web::{App, HttpServer, post, HttpResponse};
use actix_web::web::Data;
use actix_web::error::{ErrorBadRequest, ErrorInternalServerError};
use bytes::Bytes;
use rustls::ServerConfig;
use curve25519_dalek::Scalar;
use rustls_pemfile::{certs, pkcs8_private_keys};
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType};
use rusqlite::{Connection, params};
use crate::leading_zeros;

// Import the API types from our library
use crate::{Request, Response};

type DB = Arc<Mutex<NullifierDB>>;
type NonceDB = Arc<Mutex<Connection>>;

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
    nonce_db: Data<NonceDB>,
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

            // Check if this proof of work nonce has been used before
            match check_pow_nonce(&nonce_db, &proof_of_work) {
                Ok(true) => {
                    warn!("Attempted to reuse proof of work nonce");
                    return Err(ErrorBadRequest("proof of work nonce already used"));
                },
                Ok(false) => {
                    debug!("New proof of work nonce, proceeding with validation");
                    // Continue with validation
                },
                Err(e) => {
                    error!("Error checking proof of work nonce: {}", e);
                    return Err(ErrorInternalServerError("internal database error"));
                }
            }

            let mut hasher = blake3::Hasher::new();
            hasher.update(b"TODO make configurable");
            hasher.update(&proof_of_work);

            let hash = *hasher.finalize().as_bytes();

            let leading_zeros = leading_zeros(&hash);
            debug!("leading_zeros = {}", leading_zeros);

            let c = if leading_zeros == 128 {
                Scalar::from(u128::MAX)
            } else {
                Scalar::from(2u128.pow(leading_zeros))
            };
            
            // Verify the issuance request
            if let Some(response) = private_key.issue(&params, &issuance_request, c, OsRng) {
                // Store the nonce in the database to prevent reuse
                match store_pow_nonce(&nonce_db, &proof_of_work) {
                    Ok(_) => {
                        debug!("Successfully stored proof of work nonce");
                        Ok(Response::Issue(response))
                    },
                    Err(e) => {
                        error!("Failed to store proof of work nonce: {}", e);
                        // If this is a unique constraint violation, it means the nonce was already used
                        // (race condition where another request used the same nonce between our check and insert)
                        if let rusqlite::Error::SqliteFailure(error, _) = &e {
                            if error.code == rusqlite::ErrorCode::ConstraintViolation {
                                return Err(ErrorBadRequest("proof of work nonce already used"));
                            }
                        }
                        return Err(ErrorInternalServerError("internal database error"));
                    }
                }
            } else {
                warn!("Incorrect issuance proofs");
                return Err(ErrorBadRequest("invalid issuance proof"));
            }
        },
        Request::Combine(spend_proofs, issuance_request) => {
            debug!("Processing combine request with {} spend proofs", spend_proofs.len());
            if spend_proofs.is_empty() {
                return Err(ErrorBadRequest("no spend proofs provided"));
            }
            
            // Sum up the credits from each spend proof
            let mut total_credits = Scalar::ZERO;
            
            // Verify all spend proofs and make sure no nullifiers have been seen before
            for (i, proof) in spend_proofs.iter().enumerate() {
                debug!("Verifying spend proof {} of {}", i+1, spend_proofs.len());
                
                // Verify the spend proof is valid
                if let Some(_) = private_key.refund(&params, proof, OsRng) {
                    // Check if the nullifier has been seen before
                    if db.contains(&proof.nullifier()) {
                        warn!("Nullifier from spend proof {} has been seen before", i+1);
                        return Err(ErrorBadRequest("already seen nullifier"));
                    }
                    
                    // Add the credits from this proof to the total
                    total_credits = total_credits + proof.charge();
                } else {
                    warn!("Invalid spend proof at index {}", i);
                    return Err(ErrorBadRequest("invalid spend proof"));
                }
            }

            if scalar_to_u128(&total_credits).is_none() {
                warn!("Too many credits");
                return Err(ErrorBadRequest("too many credits"));
            }

            // TODO: charge a fee for combining, otherwise its a DOS vector.

            debug!("All spend proofs verified, issuing new token");
            
            // Now insert all nullifiers to prevent double-spending
            // NB: This is kinda fucked.
            for proof in &spend_proofs {
                if !db.insert(proof.nullifier()).map_err(|_e| ErrorInternalServerError("internal database error"))? {
                    error!("Race condition: nullifier was already inserted by another request");
                    return Err(ErrorInternalServerError("database consistency error"));
                }
            }
            
            // Issue a new token with the combined credits
            if let Some(response) = private_key.issue(&params, &issuance_request, total_credits, OsRng) {
                debug!("Successfully issued combined token");
                Ok(Response::Issue(response))
            } else {
                warn!("Failed to issue combined token");
                return Err(ErrorBadRequest("invalid issuance request"));
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

/// Initialize the nonce database for proof of work tracking
fn initialize_nonce_db() -> std::io::Result<NonceDB> {
    let db_path = Path::new("./pow_nonces.db");
    
    match Connection::open(db_path) {
        Ok(conn) => {
            // Create the nonces table if it doesn't exist
            match conn.execute(
                "CREATE TABLE IF NOT EXISTS pow_nonces (
                    id INTEGER PRIMARY KEY,
                    nonce BLOB NOT NULL UNIQUE,
                    used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )",
                [],
            ) {
                Ok(_) => {
                    // Create index for faster lookups
                    match conn.execute(
                        "CREATE INDEX IF NOT EXISTS idx_nonces_used_at ON pow_nonces(used_at)",
                        [],
                    ) {
                        Ok(_) => {
                            info!("Successfully initialized proof of work nonce database");
                            Ok(Arc::new(Mutex::new(conn)))
                        },
                        Err(e) => Err(std::io::Error::new(
                            std::io::ErrorKind::Other, 
                            format!("Failed to create index on nonce database: {}", e)
                        ))
                    }
                },
                Err(e) => Err(std::io::Error::new(
                    std::io::ErrorKind::Other, 
                    format!("Failed to create table in nonce database: {}", e)
                ))
            }
        },
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::Other, 
            format!("Failed to open nonce database: {}", e)
        ))
    }
}

/// Check if a proof of work nonce has been used before
fn check_pow_nonce(nonce_db: &NonceDB, nonce: &[u8; 32]) -> Result<bool, rusqlite::Error> {
    let conn = nonce_db.lock().expect("Failed to acquire lock on nonce database");
    
    let mut stmt = conn.prepare("SELECT 1 FROM pow_nonces WHERE nonce = ?")?;
    let exists = stmt.exists(params![nonce])?;
    
    debug!("Checking if PoW nonce exists: {}", exists);
    Ok(exists)
}

/// Store a proof of work nonce in the database
fn store_pow_nonce(nonce_db: &NonceDB, nonce: &[u8; 32]) -> Result<(), rusqlite::Error> {
    let conn = nonce_db.lock().expect("Failed to acquire lock on nonce database");
    
    conn.execute(
        "INSERT INTO pow_nonces (nonce) VALUES (?)",
        params![nonce],
    )?;
    
    debug!("Stored PoW nonce in database");
    Ok(())
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
    
    // Initialize the proof of work nonce database
    let nonce_db = match initialize_nonce_db() {
        Ok(nonce_db) => {
            info!("Successfully initialized proof of work nonce database");
            nonce_db
        },
        Err(e) => {
            error!("Failed to initialize proof of work nonce database: {}", e);
            panic!("Failed to initialize proof of work nonce database");
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
    
    info!("Server initialized with private key, nullifier database, proof of work nonce database, and TLS");
    
    // Start the HTTPS server
    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(db.clone()))
            .app_data(Data::new(nonce_db.clone()))
            .app_data(Data::new(Arc::new(private_key.clone())))
            .service(process_token)
    })
    .bind_rustls("0.0.0.0:8443", rustls_config)?
    .run()
    .await
}
