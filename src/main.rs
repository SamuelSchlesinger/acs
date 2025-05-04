use nullifierdb::NullifierDB;
use anonymous_credit_tokens::{PrivateKey, PublicKey, CreditToken, IssuanceRequest, IssuanceResponse, SpendProof, Refund, u32_to_scalar, Params};
use std::path::Path;
use std::sync::{Arc, Mutex};
use log::{info, warn, error, debug};
use rand_core::OsRng;
use actix_web::{web, App, HttpServer, post, HttpResponse};
use actix_web::web::{BytesMut, Data};
use actix_web::error::{ErrorBadRequest, ErrorInternalServerError};
use serde::{Deserialize, Serialize};
use bytes::Bytes;

type DB = Arc<Mutex<NullifierDB>>;

#[derive(Serialize, Deserialize)]
enum Request {
    Spend(SpendProof),
    Issue(IssuanceRequest, [u8; 32]),
    GetPublicKey,
}

#[derive(Serialize, Deserialize)]
enum Response {
    Refund(Refund),
    Issue(IssuanceResponse),
    PublicKey(PublicKey),
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

// Handler for processing token requests
#[post("/token")]
async fn process_token(
    data: Bytes,
    db: Data<DB>,
    private_key: Data<PrivateKey>,
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

            let leading_zeros = {
                let mut zs = 0;
                for byte in hash.iter().copied() {
                    if byte == 0 {
                        zs += 8;
                    } else {
                        zs += byte.leading_zeros() as u32;
                    }
                }
                std::cmp::max(zs, 32)
            };

            let c = if leading_zeros == 32 {
                u32_to_scalar(u32::MAX)
            } else {
                u32_to_scalar(2u32.pow(leading_zeros))
            };
            
            // Verify the issuance request
            if let Some(response) = private_key.issue(&params, &issuance_request, c, OsRng) {
                warn!("Invalid issuance request");
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize the logger
    env_logger::init();
    
    info!("Starting anonymous credit server");
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
    
    info!("Server initialized with private key and nullifier database");
    
    // Start the HTTP server
    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(db.clone()))
            .app_data(Data::new(Arc::new(private_key.clone())))
            .service(process_token)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
