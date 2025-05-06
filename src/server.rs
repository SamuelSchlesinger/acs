use nullifierdb::NullifierDB;
use anonymous_credit_tokens::{PrivateKey, scalar_to_u128, Params};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::fs;
use std::fmt;
use log::{info, warn, error, debug};
use rand_core::OsRng;
use actix_web::{App, HttpServer, post, get, HttpResponse};
use actix_web::web::{self, Data};
use actix_web::error::{ErrorBadRequest, ErrorInternalServerError};
use actix_web::http::header::ContentType;
use bytes::Bytes;
use rustls::ServerConfig;
use curve25519_dalek::Scalar;
use rustls_pemfile::{certs, pkcs8_private_keys};
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType};
use rusqlite::{Connection, params};
use tempfile;
use crate::leading_zeros;

use crate::{Request, Response};

// Embedded HTML content for the index page
const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Anonymous Credit System (ACS)</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        pre {
            background-color: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }
        code {
            font-family: 'Courier New', Courier, monospace;
            background-color: #f5f5f5;
            padding: 2px 4px;
            border-radius: 3px;
        }
        .warning {
            background-color: #fff3cd;
            color: #856404;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        a {
            color: #3498db;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <h1>Anonymous Credit System (ACS)</h1>
    
    <div class="warning">
        <strong>⚠️ EXPERIMENTAL DISCLAIMER ⚠️</strong>
        <p>THIS CRYPTOGRAPHY IS EXPERIMENTAL AND UNAUDITED. DO NOT USE IN PRODUCTION ENVIRONMENTS.</p>
        <p>This system relies on experimental cryptographic techniques and has not undergone formal security auditing. It is intended solely for research, educational purposes, and experimentation.</p>
    </div>

    <h2>What is ACS?</h2>
    <p>
        The Anonymous Credit System (ACS) is a Rust implementation that enables privacy-preserving digital credits through proof-of-work. This system allows users to:
    </p>
    <ul>
        <li><strong>Issue tokens</strong> by performing computational work (proof-of-work)</li>
        <li><strong>Spend tokens</strong> anonymously without revealing their identity</li>
        <li><strong>Combine tokens</strong> to consolidate multiple tokens into a single one with their sum value</li>
        <li><strong>Split tokens</strong> into multiple smaller-value tokens</li>
        <li><strong>Manage tokens</strong> through a simple command-line interface</li>
    </ul>
    <p>The system maintains privacy through cryptographic techniques that ensure spending a token cannot be linked to its issuance.</p>

    <h2>Client Implementation</h2>
    <p>
        The ACS client is implemented as a command-line interface (CLI) and can be found in the same repository.
        The CLI provides a user-friendly way to interact with the ACS server.
    </p>
    <p>
        For more details on the client implementation, you can visit the repositories:
    </p>
    <ul>
        <li><a href="https://github.com/SamuelSchlesinger/anonymous-credit-tokens" target="_blank">anonymous-credit-tokens</a> - Core library implementing the cryptographic primitives</li>
        <li><a href="https://github.com/SamuelSchlesinger/anoncreds" target="_blank">anoncreds</a> - A proposal for anonymous API credit usage in the web platform</li>
        <li><a href="https://github.com/SamuelSchlesinger/acs" target="_blank">acs</a> - The server and client implementation</li>
    </ul>

    <h2>How to Use ACS</h2>
    <h3>Installation</h3>
    <pre><code>
# Clone the repository
git clone https://github.com/SamuelSchlesinger/acs.git
cd acs

# Build the project
cargo build --release

# Two binaries will be built:
# - The server: target/release/acs
# - The CLI client: target/release/acs-cli
    </code></pre>

    <h3>Running the Server</h3>
    <p>
        This server instance is already running and handling token issuance and validation. The server component uses an HTTPS connection with a self-signed certificate on port 443.
    </p>

    <h3>Using the CLI Client</h3>
    <p>When you first use the CLI, it will ask you to put in the URI. That will be https://anonymous-credit-tokens.info/</p>
    <p>Here are the main commands available in the CLI client:</p>

    <h4>Issue Tokens</h4>
    <pre><code>./target/release/acs-cli issue --bits 10</code></pre>
    <p>This will perform computational work to issue a token worth 2^10 (1024) credits.</p>

    <h4>List Available Tokens</h4>
    <pre><code>./target/release/acs-cli list</code></pre>

    <h4>Show Token Details</h4>
    <pre><code>./target/release/acs-cli show --id &lt;TOKEN_ID&gt;</code></pre>

    <h4>Spend Tokens</h4>
    <pre><code>./target/release/acs-cli spend --id &lt;TOKEN_ID&gt; --amount &lt;AMOUNT&gt;</code></pre>
    <p>This will spend the specified amount of credits while maintaining anonymity.</p>

    <h4>Combine Tokens</h4>
    <pre><code>./target/release/acs-cli combine --ids &lt;TOKEN_ID_1&gt;,&lt;TOKEN_ID_2&gt;,...</code></pre>
    <p>This will create a new token with the sum value of all the provided tokens. The original tokens will be spent in the process.</p>

    <h4>Split Token</h4>
    <pre><code>./target/release/acs-cli split --id &lt;TOKEN_ID&gt; --amounts &lt;AMOUNT_1&gt;,&lt;AMOUNT_2&gt;,...</code></pre>
    <p>This will divide a token into multiple new tokens with the specified values. The sum of the amounts must equal the original token's value. The original token will be spent in the process.</p>

    <h2>Technical Details</h2>
    <p>ACS consists of several components:</p>
    <ul>
        <li><strong>Server</strong>: An HTTPS server for token issuance, validation, and combining</li>
        <li><strong>Client Library</strong>: Core functionality for token operations</li>
        <li><strong>CLI</strong>: Command-line interface for user interactions</li>
        <li><strong>Storage</strong>: Database-based persistent token storage</li>
    </ul>
    <p>The system uses a nullifier database to prevent double-spending while maintaining anonymity.</p>

    <h3>API Endpoint</h3>
    <p>
        The server exposes a single API endpoint:
    </p>
    <ul>
        <li><code>POST /token</code> - Used for all token operations (issue, spend, combine, split)</li>
    </ul>
    <p>
        Communication occurs over HTTPS with a self-signed certificate. The requests and responses are binary encoded using bincode.
    </p>

    <h2>Security Considerations</h2>
    <ul>
        <li>Tokens are stored locally and should be backed up to prevent loss</li>
        <li>The system uses a sharded database to track spent tokens and prevent double-spending</li>
        <li>Communication with the server occurs over HTTPS with self-signed certificates</li>
        <li>Proof-of-work parameters can be adjusted to balance security and usability</li>
        <li>Combined tokens provide the same privacy guarantees as newly issued tokens</li>
    </ul>

    <h2>About the Project</h2>
    <p>
        This project is an implementation of an Anonymous Credit System that enables privacy-preserving digital transactions. It builds on concepts from anonymous credentials and zero-knowledge proofs.
    </p>
    <p>
        For more information on the cryptographic foundations, visit the <a href="https://github.com/SamuelSchlesinger/anonymous-credit-tokens" target="_blank">anonymous-credit-tokens</a> repository.
    </p>
    <p>
        For a broader perspective on anonymous credentials for API usage, check out the <a href="https://github.com/SamuelSchlesinger/anoncreds" target="_blank">anoncreds</a> project.
    </p>
</body>
</html>"#;

/// A sharded database for nullifiers and proof of work hashes.
/// Each shard is a separate NullifierDB, and the shard is determined by the first byte of the hash.
/// Using 256 shards provides optimal distribution and performance.
pub struct ShardedDB {
    /// 256 separate NullifierDBs for storing nullifiers
    nullifiers: Vec<Mutex<NullifierDB>>,
    /// 256 separate NullifierDBs for storing proof of work hashes
    pow_hashes: Vec<Mutex<NullifierDB>>,
}

impl ShardedDB {
    /// Create a new ShardedDB with 256 NullifierDBs for nullifiers and 256 NullifierDBs for proof of work hashes.
    /// 
    /// # Arguments
    /// 
    /// * `base_dir` - The base directory for storing the database files
    /// 
    /// # Returns
    /// 
    /// A Result containing a new ShardedDB on success, or an error on failure
    pub fn create<P: AsRef<Path>>(base_dir: P) -> std::io::Result<Self> {
        // Create the base directory if it doesn't exist
        let base_dir = base_dir.as_ref();
        fs::create_dir_all(base_dir)?;
        
        // Create subdirectories for nullifiers and pow hashes
        let nullifiers_dir = base_dir.join("nullifiers");
        let pow_dir = base_dir.join("pow");
        
        fs::create_dir_all(&nullifiers_dir)?;
        fs::create_dir_all(&pow_dir)?;
        
        // Create 256 NullifierDBs for nullifiers
        let nullifiers = Self::create_nullifier_dbs(&nullifiers_dir)?;
        
        // Create 256 NullifierDBs for proof of work hashes
        let pow_hashes = Self::create_nullifier_dbs(&pow_dir)?;
        
        Ok(Self {
            nullifiers,
            pow_hashes,
        })
    }
    
    /// Create 256 NullifierDBs in the specified directory, one for each possible first byte value.
    /// 
    /// # Arguments
    /// 
    /// * `dir` - The directory in which to create the NullifierDBs
    /// 
    /// # Returns
    /// 
    /// A Result containing a vector of 256 Mutex-wrapped NullifierDBs on success, or an error on failure
    fn create_nullifier_dbs<P: AsRef<Path>>(dir: P) -> std::io::Result<Vec<Mutex<NullifierDB>>> {
        // Use 256 shards for optimal distribution and performance
        let shard_count = 256;
        let mut db_vec = Vec::with_capacity(shard_count);
        
        // Create each database and add it to the Vec
        for i in 0..shard_count {
            let db_path = Self::get_db_path(dir.as_ref(), i);
            match NullifierDB::create(&db_path) {
                Ok(db) => {
                    db_vec.push(Mutex::new(db));
                },
                Err(e) => {
                    error!("Failed to create NullifierDB {}: {}", i, e);
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, 
                        format!("Failed to create NullifierDB {}: {}", i, e)));
                }
            }
        }
        
        Ok(db_vec)
    }
    
    /// Get the path to a database file for a specific shard
    /// 
    /// # Arguments
    /// 
    /// * `dir` - The directory containing the database files
    /// * `shard` - The shard index (0-255)
    /// 
    /// # Returns
    /// 
    /// A PathBuf pointing to the database file
    fn get_db_path<P: AsRef<Path>>(dir: P, shard: usize) -> PathBuf {
        dir.as_ref().join(format!("{:02x}.db", shard))
    }
    
    /// Get the shard index for a hash
    /// 
    /// # Arguments
    /// 
    /// * `hash` - The hash to get the shard index for
    /// 
    /// # Returns
    /// 
    /// The shard index (0-255)
    fn get_shard(hash: &[u8]) -> usize {
        // Use the first byte directly as the shard index
        // This gives us perfect distribution across all 256 shards
        hash[0] as usize
    }
}

impl ShardedDB {
    /// Insert a nullifier into the appropriate shard
    /// 
    /// # Arguments
    /// 
    /// * `nullifier` - The nullifier to insert
    /// 
    /// # Returns
    /// 
    /// A Result containing a boolean indicating whether the nullifier was newly inserted (true)
    /// or already present (false), or an error on failure
    pub fn insert_nullifier(&self, nullifier: [u8; 32]) -> std::io::Result<bool> {
        let shard = Self::get_shard(&nullifier);
        let mut db = self.nullifiers[shard].lock().expect("Failed to acquire lock on nullifier DB");
        db.insert(nullifier).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
    }
    
    /// Check if a nullifier exists in the appropriate shard
    /// 
    /// # Arguments
    /// 
    /// * `nullifier` - The nullifier to check
    /// 
    /// # Returns
    /// 
    /// A boolean indicating whether the nullifier exists (true) or not (false)
    pub fn contains_nullifier(&self, nullifier: &[u8; 32]) -> bool {
        let shard = Self::get_shard(nullifier);
        let db = self.nullifiers[shard].lock().expect("Failed to acquire lock on nullifier DB");
        db.contains(nullifier)
    }
    
    /// Check if a nullifier has already been spent
    /// 
    /// # Arguments
    /// 
    /// * `nullifier` - The nullifier to check
    /// 
    /// # Returns
    /// 
    /// A boolean indicating whether the nullifier has been spent (true) or not (false)
    pub fn is_nullifier_spent(&self, nullifier: &[u8; 32]) -> bool {
        self.contains_nullifier(nullifier)
    }
    
    /// Insert a proof of work hash into the appropriate shard
    /// 
    /// # Arguments
    /// 
    /// * `pow_hash` - The proof of work hash to insert
    /// 
    /// # Returns
    /// 
    /// A Result containing a boolean indicating whether the hash was newly inserted (true)
    /// or already present (false), or an error on failure
    pub fn insert_pow_hash(&self, pow_hash: [u8; 32]) -> std::io::Result<bool> {
        let shard = Self::get_shard(&pow_hash);
        let mut db = self.pow_hashes[shard].lock().expect("Failed to acquire lock on PoW hash DB");
        db.insert(pow_hash).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
    }
    
    /// Check if a proof of work hash exists in the appropriate shard
    /// 
    /// # Arguments
    /// 
    /// * `pow_hash` - The proof of work hash to check
    /// 
    /// # Returns
    /// 
    /// A boolean indicating whether the hash exists (true) or not (false)
    pub fn contains_pow_hash(&self, pow_hash: &[u8; 32]) -> bool {
        let shard = Self::get_shard(pow_hash);
        let db = self.pow_hashes[shard].lock().expect("Failed to acquire lock on PoW hash DB");
        db.contains(pow_hash)
    }
}

impl fmt::Debug for ShardedDB {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShardedDB")
            .field("nullifiers", &format!("[{} NullifierDBs]", self.nullifiers.len()))
            .field("pow_hashes", &format!("[{} NullifierDBs]", self.pow_hashes.len()))
            .finish()
    }
}

// Define new type for the database
type DB = Arc<ShardedDB>;
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

// Handler for serving the index.html page at the root path
#[get("/")]
async fn index() -> HttpResponse {
    HttpResponse::Ok()
        .content_type(ContentType::html())
        .body(INDEX_HTML)
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
                let nullifier = *proof.nullifier().as_bytes();
                if db.insert_nullifier(nullifier).map_err(|_e| ErrorInternalServerError("internal error"))? {
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

            // Hash the proof of work
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"TODO make configurable");
            hasher.update(&proof_of_work);
            let pow_hash = *hasher.finalize().as_bytes();

            // Check if this proof of work hash has been used before in our sharded database
            if db.contains_pow_hash(&pow_hash) {
                warn!("Attempted to reuse proof of work hash");
                return Err(ErrorBadRequest("proof of work hash already used"));
            }

            // For backward compatibility, also check in the SQL database
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

            let leading_zeros = leading_zeros(&pow_hash);
            debug!("leading_zeros = {}", leading_zeros);

            let c = if leading_zeros == 128 {
                Scalar::from(u128::MAX)
            } else {
                Scalar::from(2u128.pow(leading_zeros))
            };
            
            // Verify the issuance request
            if let Some(response) = private_key.issue(&params, &issuance_request, c, OsRng) {
                // Store the hash in our sharded database
                if !db.insert_pow_hash(pow_hash).map_err(|_e| ErrorInternalServerError("internal error"))? {
                    error!("Race condition: proof of work hash was already inserted by another request");
                    return Err(ErrorInternalServerError("database consistency error"));
                }

                // Also store in the legacy SQL database (to be removed later)
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
        Request::Split(spend_proof, issuance_requests, amounts) => {
            debug!("Processing split request with {} issuance requests", issuance_requests.len());
            
            // Verify that the number of issuance requests matches the number of amounts
            if issuance_requests.len() != amounts.len() {
                warn!("Mismatched issuance requests ({}) and amounts ({}) in split request", 
                     issuance_requests.len(), amounts.len());
                return Err(ErrorBadRequest("mismatched issuance requests and amounts"));
            }
            
            if issuance_requests.is_empty() {
                return Err(ErrorBadRequest("no issuance requests provided"));
            }
            
            // Sum up the total amount to be split into new tokens
            let total_amount: u128 = amounts.iter().sum();
            
            // Verify the spend proof
            debug!("Verifying spend proof for split request");
            if let Some(_) = private_key.refund(&params, &spend_proof, OsRng) {
                // Check if the nullifier has been seen before
                let nullifier = *spend_proof.nullifier().as_bytes();
                if db.contains_nullifier(&nullifier) {
                    warn!("Nullifier from spend proof has been seen before");
                    return Err(ErrorBadRequest("already seen nullifier"));
                }
                
                // Verify that the charge in the spend proof matches the total split amount
                let spend_charge = match scalar_to_u128(&spend_proof.charge()) {
                    Some(charge) => charge,
                    None => {
                        warn!("Failed to convert spend proof charge to u128");
                        return Err(ErrorBadRequest("invalid spend proof charge"));
                    }
                };
                
                if spend_charge != total_amount {
                    warn!("Total split amount ({}) does not match spend proof charge ({})", 
                         total_amount, spend_charge);
                    return Err(ErrorBadRequest("total split amount does not match spend proof charge"));
                }
            } else {
                warn!("Invalid spend proof for split request");
                return Err(ErrorBadRequest("invalid spend proof"));
            }
            
            // Insert the nullifier to prevent double-spending
            if !db.insert_nullifier(*spend_proof.nullifier().as_bytes()).map_err(|_e| ErrorInternalServerError("internal error"))? {
                error!("Race condition: nullifier was already inserted by another request");
                return Err(ErrorInternalServerError("database consistency error"));
            }
            
            // Issue tokens for each requested amount
            debug!("Issuing {} new tokens with split credits", amounts.len());
            
            // Process each issuance request and generate responses for each token
            let mut issuance_responses = Vec::with_capacity(issuance_requests.len());
            
            for (i, (issuance_request, amount)) in issuance_requests.iter().zip(amounts.iter()).enumerate() {
                debug!("Processing issuance request {} with amount {}", i, amount);
                let credit_scalar = Scalar::from(*amount);
                
                if let Some(response) = private_key.issue(&params, issuance_request, credit_scalar, OsRng) {
                    issuance_responses.push(response);
                } else {
                    warn!("Failed to issue split token {}", i);
                    return Err(ErrorBadRequest(format!("invalid issuance request at index {}", i)));
                }
            }
            
            debug!("Successfully issued {} split tokens", issuance_responses.len());
            Ok(Response::Issuances(issuance_responses))
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
                    let nullifier = *proof.nullifier().as_bytes();
                    if db.contains_nullifier(&nullifier) {
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
            for proof in &spend_proofs {
                let nullifier = *proof.nullifier().as_bytes();
                if !db.insert_nullifier(nullifier).map_err(|_e| ErrorInternalServerError("internal error"))? {
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
        },
        Request::CheckNullifier(nullifier) => {
            debug!("Checking if nullifier has been spent");
            let is_spent = db.is_nullifier_spent(&nullifier);
            debug!("Nullifier spent status: {}", is_spent);
            Ok(Response::NullifierStatus(is_spent))
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

/// Run a test version of the server for testing
pub async fn run_test_server() -> std::io::Result<()> {
    // Initialize the logger if not already initialized
    if std::env::var_os("RUST_LOG").is_none() {
        unsafe { std::env::set_var("RUST_LOG", "info"); }
    }
    
    info!("Starting test server with HTTPS");
    let private_key = initialize_keys();
    
    // Create a temp directory for our DB files
    let temp_dir = tempfile::tempdir().expect("Failed to create temporary directory");
    let temp_path = temp_dir.path().to_path_buf();
    
    // Create a full ShardedDB with 256 shards
    let db = match ShardedDB::create(&temp_path) {
        Ok(db) => {
            info!("Successfully created test sharded database with 256 shards");
            Arc::new(db)
        },
        Err(e) => {
            error!("Failed to create sharded database: {}", e);
            panic!("Failed to initialize sharded database");
        }
    };
    
    // Initialize the proof of work nonce database (temporary, will be removed later)
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
    
    info!("Test server initialized with private key, sharded database, proof of work nonce database, and TLS");
    
    // Start the HTTPS server
    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(db.clone()))
            .app_data(Data::new(nonce_db.clone()))
            .app_data(Data::new(Arc::new(private_key.clone())))
            .service(index)
            .service(process_token)
    })
    .bind_rustls("0.0.0.0:8443", rustls_config)?
    .run()
    .await
}

/// Run the server application with the specified configuration
pub async fn run_server() -> std::io::Result<()> {
    // Initialize the logger if not already initialized
    if std::env::var_os("RUST_LOG").is_none() {
        unsafe { std::env::set_var("RUST_LOG", "info"); }
    }
    
    info!("Starting anonymous credit server with HTTPS");
    let private_key = initialize_keys();
    
    // Initialize the sharded database for nullifiers and proof of work hashes
    let db = match ShardedDB::create(Path::new("./db")) {
        Ok(db) => {
            info!("Successfully created sharded database for nullifiers and proof of work hashes");
            Arc::new(db)
        },
        Err(e) => {
            error!("Failed to create sharded database: {}", e);
            panic!("Failed to initialize sharded database");
        }
    };
    
    // Initialize the proof of work nonce database (temporary, will be removed later)
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
    
    info!("Server initialized with private key, sharded database, proof of work nonce database, and TLS");
    
    // Start the HTTPS server
    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(db.clone()))
            .app_data(Data::new(nonce_db.clone()))
            .app_data(Data::new(Arc::new(private_key.clone())))
            .service(index)
            .service(process_token)
    })
    .bind_rustls("0.0.0.0:8443", rustls_config)?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use rand_core::{OsRng, RngCore};
    
    /// Basic test for ShardedDB creation and insertion/retrieval operations
    #[test]
    fn test_sharded_db() {
        // Create a temporary directory for our test databases
        let temp_dir = tempdir().expect("Failed to create temporary directory");
        let temp_path = temp_dir.path();
        
        // Create the sharded database
        let db = ShardedDB::create(temp_path).expect("Failed to create sharded database");
        
        // Create test data with different first bytes to hit different shards
        let mut test_data = vec![];
        for i in 0..10 {
            let mut data = [0u8; 32];
            data[0] = i as u8; // First byte determines the shard
            OsRng.try_fill_bytes(&mut data[1..]).expect("Failed to fill bytes"); // Fill the rest with random data
            test_data.push(data);
        }
        
        // Test inserting nullifiers
        for data in &test_data {
            assert!(db.insert_nullifier(*data).expect("Failed to insert nullifier"), 
                   "Expected nullifier to be newly inserted");
            
            // Verify it's in the database
            assert!(db.contains_nullifier(data), 
                   "Expected nullifier to be found after insertion");
                   
            // Try inserting again - should return false
            assert!(!db.insert_nullifier(*data).expect("Failed to check nullifier"), 
                   "Expected second insertion of same nullifier to return false");
        }
        
        // Test inserting proof of work hashes
        for data in &test_data {
            assert!(db.insert_pow_hash(*data).expect("Failed to insert PoW hash"), 
                   "Expected PoW hash to be newly inserted");
            
            // Verify it's in the database
            assert!(db.contains_pow_hash(data), 
                   "Expected PoW hash to be found after insertion");
                   
            // Try inserting again - should return false
            assert!(!db.insert_pow_hash(*data).expect("Failed to check PoW hash"), 
                   "Expected second insertion of same PoW hash to return false");
        }
        
        // Test that the ShardedDB correctly routes by first byte
        for i in 0..10 {
            let mut data1 = [0u8; 32];
            let mut data2 = [0u8; 32];
            
            // Create two different hashes with the same first byte
            data1[0] = i as u8;
            data2[0] = i as u8;
            
            OsRng.try_fill_bytes(&mut data1[1..]).expect("Failed to fill bytes");
            OsRng.try_fill_bytes(&mut data2[1..]).expect("Failed to fill bytes");
            
            // Insert the first hash and check it worked
            assert!(db.insert_nullifier(data1).expect("Failed to insert nullifier"), 
                   "Expected nullifier to be newly inserted");
                   
            // Insert the second hash and check it worked too
            assert!(db.insert_nullifier(data2).expect("Failed to insert nullifier"), 
                   "Expected nullifier to be newly inserted");
                   
            // Verify both hashes are in the database
            assert!(db.contains_nullifier(&data1), 
                   "Expected first nullifier to be found after insertion");
            assert!(db.contains_nullifier(&data2), 
                   "Expected second nullifier to be found after insertion");
        }
    }
    
    /// Test the shard calculation logic
    #[test]
    fn test_get_shard() {
        // Test that the shard index is correctly calculated from the first byte
        for i in 0..256 {
            let mut data = [0u8; 32];
            data[0] = i as u8;
            assert_eq!(ShardedDB::get_shard(&data), i, 
                       "Expected shard index to be the first byte of the hash");
        }
    }
    
    /// Test concurrent operations on different shards to verify parallelism
    #[test]
    fn test_sharded_db_concurrency() {
        // Create a temporary directory for our test databases
        let temp_dir = tempdir().expect("Failed to create temporary directory");
        let temp_path = temp_dir.path();
        
        // Create the sharded database
        let db = Arc::new(ShardedDB::create(temp_path).expect("Failed to create sharded database"));
        
        // Number of threads to use for testing concurrency
        let num_threads = 4;
        let operations_per_thread = 64; // Increased to hit more shards
        
        // Create a Vec to hold the thread handles
        let mut handles = Vec::with_capacity(num_threads);
        
        // Spawn threads that will access different shards concurrently
        for thread_id in 0..num_threads {
            let db_clone = db.clone();
            
            let handle = std::thread::spawn(move || {
                let mut results = Vec::new();
                
                for i in 0..operations_per_thread {
                    // Create data that will go to different shards
                    let mut data = [0u8; 32];
                    // Use the thread_id to ensure different threads target different shards
                    data[0] = ((thread_id * operations_per_thread + i) % 256) as u8;
                    OsRng.try_fill_bytes(&mut data[1..]).expect("Failed to fill bytes");
                    
                    // Insert into nullifiers DB
                    let nullifier_result = db_clone.insert_nullifier(data).expect("Failed to insert nullifier");
                    
                    // Insert into pow_hashes DB
                    let pow_result = db_clone.insert_pow_hash(data).expect("Failed to insert PoW hash");
                    
                    // Check it exists in both
                    let nullifier_exists = db_clone.contains_nullifier(&data);
                    let pow_exists = db_clone.contains_pow_hash(&data);
                    
                    results.push((nullifier_result, pow_result, nullifier_exists, pow_exists));
                }
                
                results
            });
            
            handles.push(handle);
        }
        
        // Join all threads and check results
        for handle in handles {
            let results = handle.join().expect("Thread panicked");
            
            for (nullifier_result, pow_result, nullifier_exists, pow_exists) in results {
                // First insertion should return true (new insertion)
                assert!(nullifier_result, "Expected nullifier to be newly inserted");
                assert!(pow_result, "Expected PoW hash to be newly inserted");
                
                // Should exist after insertion
                assert!(nullifier_exists, "Expected nullifier to exist after insertion");
                assert!(pow_exists, "Expected PoW hash to exist after insertion");
            }
        }
    }
    
    /// Test the behavior with collisions (same shard, different data)
    #[test]
    fn test_sharded_db_collision_handling() {
        // Create a temporary directory for our test databases
        let temp_dir = tempdir().expect("Failed to create temporary directory");
        let temp_path = temp_dir.path();
        
        // Create the sharded database
        let db = ShardedDB::create(temp_path).expect("Failed to create sharded database");
        
        // Create many nullifiers that all hash to the same shard
        let shard_value = 0x0A; // Arbitrary shard to test
        let num_collisions = 100;
        
        let mut nullifiers = Vec::with_capacity(num_collisions);
        
        for i in 0..num_collisions {
            let mut data = [0u8; 32];
            data[0] = shard_value; // Same shard for all
            data[1] = (i & 0xFF) as u8; // Different data
            data[2] = ((i >> 8) & 0xFF) as u8; // Ensure uniqueness for larger i
            
            nullifiers.push(data);
        }
        
        // Insert all nullifiers
        for nullifier in &nullifiers {
            assert!(db.insert_nullifier(*nullifier).expect("Failed to insert nullifier"),
                  "First insertion of unique nullifier should return true");
        }
        
        // Verify all nullifiers exist
        for nullifier in &nullifiers {
            assert!(db.contains_nullifier(nullifier),
                  "Nullifier should exist after insertion");
        }
        
        // Try to insert again - should all fail (return false)
        for nullifier in &nullifiers {
            assert!(!db.insert_nullifier(*nullifier).expect("Failed to check nullifier"),
                  "Second insertion of same nullifier should return false");
        }
    }
    
    /// Test the hash distribution across shards
    #[test]
    fn test_hash_distribution() {
        // Create a temporary directory for our test databases
        let temp_dir = tempdir().expect("Failed to create temporary directory");
        let temp_path = temp_dir.path();
        
        // Create the sharded database
        let db = ShardedDB::create(temp_path).expect("Failed to create sharded database");
        
        // Number of hashes to generate
        let num_hashes = 2560; // Increased to get better statistical coverage across 256 shards
        let shard_count = 256; // Using all 256 possible byte values as shards
        
        // Count distribution across shards
        let mut shard_counts = vec![0; shard_count];
        
        // Generate random hashes
        for _ in 0..num_hashes {
            let mut data = [0u8; 32];
            OsRng.try_fill_bytes(&mut data).expect("Failed to fill bytes");
            
            // Insert the hash and track which shard it goes to
            let shard = ShardedDB::get_shard(&data);
            shard_counts[shard] += 1;
            
            db.insert_nullifier(data).expect("Failed to insert nullifier");
        }
        
        // Check that hashes are reasonably distributed
        // For 2560 hashes across 256 shards, we expect ~10 per shard
        let expected_per_shard = num_hashes / shard_count;
        // Allow some variance (in real distribution, standard deviation is sqrt(n*p*(1-p)))
        let std_dev = (num_hashes as f64 * (1.0/shard_count as f64) * (1.0 - 1.0/shard_count as f64)).sqrt() as usize;
        // Using 3 standard deviations for a 99.7% confidence interval
        let acceptable_range = (expected_per_shard - 3*std_dev)..(expected_per_shard + 3*std_dev);
        
        // Check that most shards have a reasonable number of entries
        // With random distribution, we expect some empty shards and some with more entries
        // so we'll count how many are outside our expected range
        let mut outliers = 0;
        for (shard, &count) in shard_counts.iter().enumerate() {
            if !acceptable_range.contains(&count) {
                outliers += 1;
                println!("Shard {} has {} hashes, which is outside the expected range {:?}",
                       shard, count, acceptable_range);
            }
        }
        
        // We should have fewer than 5% outliers for a good distribution
        let max_outliers = (shard_count as f64 * 0.05) as usize;
        assert!(outliers <= max_outliers,
               "Too many shards ({}) have counts outside the expected range", outliers);
    }
    
    /// Test the is_nullifier_spent function
    #[test]
    fn test_nullifier_spent_check() {
        // Create a temporary directory for our test databases
        let temp_dir = tempdir().expect("Failed to create temporary directory");
        let temp_path = temp_dir.path();
        
        // Create the sharded database
        let db = ShardedDB::create(temp_path).expect("Failed to create sharded database");
        
        // Create some test nullifiers
        let mut nullifiers = Vec::new();
        for i in 0..10 {
            let mut data = [0u8; 32];
            data[0] = i as u8; // Ensure different shards
            OsRng.try_fill_bytes(&mut data[1..]).expect("Failed to fill bytes");
            nullifiers.push(data);
        }
        
        // Initially, no nullifiers should be spent
        for nullifier in &nullifiers {
            assert!(!db.is_nullifier_spent(nullifier), 
                   "Nullifier should not be spent before insertion");
        }
        
        // Insert some nullifiers (marking them as spent)
        for i in 0..5 {
            db.insert_nullifier(nullifiers[i]).expect("Failed to insert nullifier");
        }
        
        // Check that inserted nullifiers are now reported as spent
        for i in 0..10 {
            let expected = i < 5; // First 5 should be spent, rest should not
            assert_eq!(db.is_nullifier_spent(&nullifiers[i]), expected,
                      "Nullifier spent status incorrect for index {}", i);
        }
    }
}
