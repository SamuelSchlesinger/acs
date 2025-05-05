use anonymous_credit_tokens::{
    self, IssuanceRequest, IssuanceResponse, Params, PreIssuance, PublicKey, 
    SpendProof, Refund, scalar_to_u128
};
use curve25519_dalek::Scalar;
use serde::{Deserialize, Serialize};
use rand_core::{OsRng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::io;
use std::thread;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use log::{info, error, debug};

// Re-export the CreditToken type from anonymous_credit_tokens
pub use anonymous_credit_tokens::CreditToken;

/// Extension trait that adds utility methods to CreditToken
pub trait CreditTokenExt {
    /// Returns the token's credit value as a u128
    fn get_value(&self) -> u128;
}

impl CreditTokenExt for CreditToken {
    fn get_value(&self) -> u128 {
        // Convert the credits scalar field to u128
        scalar_to_u128(&self.credits()).unwrap_or(0)
    }
}

// Export server module for tests and application use
pub mod server;

/// Request types for the anonymous credit token API
#[derive(Serialize, Deserialize)]
pub enum Request {
    /// Request to spend credits from a token
    Spend(SpendProof),
    /// Request to issue a new token with proof of work
    Issue(IssuanceRequest, [u8; 32]),
    /// Request to retrieve the server's public key
    GetPublicKey,
    /// Request to combine multiple spend proofs into a new token
    /// Boxed to avoid stack overflow when handling many proofs
    Combine(Vec<SpendProof>, IssuanceRequest),
    /// Request to split a token into multiple tokens with specified amounts
    Split(SpendProof, Vec<IssuanceRequest>, Vec<u128>),
}

/// Response types for the anonymous credit token API
#[derive(Serialize, Deserialize)]
pub enum Response {
    /// Response with refund information after spending
    Refund(Refund),
    /// Response with issuance information for a new token
    Issue(IssuanceResponse),
    /// Response containing the server's public key
    PublicKey(PublicKey),
    /// Response with multiple issuance responses for split operations
    Issuances(Vec<IssuanceResponse>),
}

/// Error types for the client operations
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// File system or I/O related errors
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    
    /// Network communication errors
    #[error("Network error: {0}")]
    Network(String),
    
    /// Errors during request serialization
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::error::EncodeError),
    
    /// Errors during response deserialization
    #[error("Deserialization error: {0}")]
    Deserialization(#[from] bincode::error::DecodeError),
    
    /// Database access or query errors
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
    
    /// User interface interaction errors
    #[error("UI interaction error: {0}")]
    Interaction(String),
    
    /// Server sent an unexpected response type
    #[error("Invalid response from server")]
    InvalidResponse,
    
    /// Token validation or verification failed
    #[error("Invalid token")]
    InvalidToken,
    
    /// Public key not available or not fetched
    #[error("No public key available")]
    NoPublicKey,
    
    /// Proof-of-work generation failed
    #[error("Proof-of-work generation failed")]
    PowFailed,
}

// Implement conversion from dialoguer::Error to our ClientError
impl From<dialoguer::Error> for ClientError {
    fn from(error: dialoguer::Error) -> Self {
        ClientError::Interaction(error.to_string())
    }
}

/// Result type for client operations, wrapping standard Result with ClientError
pub type Result<T> = std::result::Result<T, ClientError>;

/// Client for interacting with the Anonymous Credit Token server
/// 
/// Provides methods for issuing new tokens, spending credits, and managing the
/// client-server protocol flow. The client handles communication with the server,
/// cryptographic operations, and token management.
pub struct Client {
    /// The server endpoint URL (e.g., "https://example.com:8443")
    server_url: String,
    /// The cryptographic parameters for token operations
    params: Params,
    /// The server's public key (fetched during initialization)
    server_public_key: Option<PublicKey>,
}

impl Client {
    /// Creates a new client for interacting with an Anonymous Credit Token server
    ///
    /// # Arguments
    ///
    /// * `server_url` - The URL of the server endpoint
    ///
    /// # Returns
    ///
    /// A new `Client` instance
    pub fn new(server_url: String) -> Self {
        let params = Params::nothing_up_my_sleeve(b"innocence v0.1");
        Self {
            server_url,
            params,
            server_public_key: None,
        }
    }
    
    /// Splits a token into multiple tokens with specified amounts
    ///
    /// This method takes a single token and a vector of amounts, creates a spend proof
    /// for the token's full value, and issues multiple new tokens with the specified amounts.
    /// The sum of the specified amounts must equal the token's value.
    ///
    /// # Arguments
    ///
    /// * `token` - The credit token to split
    /// * `amounts` - A vector of amounts for each new token
    ///
    /// # Returns
    ///
    /// A vector of new credit tokens with the specified amounts if successful
    pub async fn split_token(&mut self, token: &CreditToken, amounts: Vec<u128>) -> Result<Vec<CreditToken>> {
        if amounts.is_empty() {
            return Err(ClientError::Interaction("No amounts provided for splitting".to_string()));
        }
        
        // Calculate the total amount
        let total_amount: u128 = amounts.iter().sum();
        
        // Get the token's value
        let token_value = token.get_value();
        
        // Ensure the total amount matches the token's value
        if total_amount != token_value {
            return Err(ClientError::Interaction(
                format!("Total amount ({}) does not match token value ({})", total_amount, token_value)
            ));
        }
        
        // Ensure we have the server's public key
        let public_key = self.get_public_key().await?;
        
        // Create a spend proof for the full value of the token
        debug!("Creating spend proof for token with value {}", token_value);
        let value_scalar = Scalar::from(token_value);
        let (spend_proof, _) = token.prove_spend(&self.params, value_scalar, OsRng);
        
        // Create pre-issuance states and requests for each new token
        debug!("Generating pre-issuance states for {} split tokens", amounts.len());
        let mut pre_issuances = Vec::with_capacity(amounts.len());
        let mut issuance_requests = Vec::with_capacity(amounts.len());
        
        for _ in &amounts {
            let pre_issuance = PreIssuance::random(OsRng);
            let issuance_request = pre_issuance.request(&self.params, OsRng);
            pre_issuances.push(pre_issuance);
            issuance_requests.push(issuance_request);
        }
        
        // Send the split request to the server
        debug!("Sending split request to server");
        let request = Request::Split(spend_proof, issuance_requests.clone(), amounts.clone());
        let response = self.send_request(request).await?;
        
        // Process the server's response
        match response {
            Response::Issuances(issuance_responses) => {
                debug!("Received issuances response with {} responses for split tokens", issuance_responses.len());
                
                if issuance_responses.len() != pre_issuances.len() {
                    error!("Server returned {} issuance responses but expected {}", 
                           issuance_responses.len(), pre_issuances.len());
                    return Err(ClientError::InvalidResponse);
                }
                
                let mut new_tokens = Vec::with_capacity(amounts.len());
                
                // Process each issuance response with its corresponding pre-issuance state and request
                for (i, ((pre_issuance, issuance_request), issuance_response)) in 
                    pre_issuances.iter().zip(issuance_requests.iter()).zip(issuance_responses.iter()).enumerate() {
                    
                    let token = pre_issuance.to_credit_token(
                        &self.params,
                        &public_key,
                        issuance_request,
                        issuance_response
                    ).ok_or(ClientError::InvalidToken)?;
                    
                    debug!("Created token {} with {} credits", i + 1, amounts[i]);
                    new_tokens.push(token);
                }
                
                info!("Successfully created {} split credit tokens", new_tokens.len());
                Ok(new_tokens)
            },
            // For backward compatibility, keep the old Issue response handler
            Response::Issue(issuance_response) => {
                debug!("Received legacy Issue response, creating split credit tokens");
                
                // The server is returning a single issuance response that we need to process
                // to create all the new tokens
                let mut new_tokens = Vec::with_capacity(amounts.len());
                
                for (i, (pre_issuance, issuance_request)) in pre_issuances.iter().zip(issuance_requests.iter()).enumerate() {
                    let token = pre_issuance.to_credit_token(
                        &self.params,
                        &public_key,
                        issuance_request,
                        &issuance_response
                    ).ok_or(ClientError::InvalidToken)?;
                    
                    debug!("Created token {} with {} credits", i + 1, amounts[i]);
                    new_tokens.push(token);
                }
                
                info!("Successfully created {} split credit tokens", new_tokens.len());
                Ok(new_tokens)
            },
            _ => {
                error!("Expected Issuances or Issue response for split request, got something else");
                Err(ClientError::InvalidResponse)
            }
        }
    }
    
    /// Combines multiple tokens by spending them and issuing a new token with the combined value
    ///
    /// This method takes multiple tokens, creates spend proofs for their full values,
    /// and issues a new token with the combined value of all the spent tokens.
    ///
    /// # Arguments
    ///
    /// * `tokens` - A vector of credit tokens to combine
    ///
    /// # Returns
    ///
    /// A new credit token with the combined value if successful
    pub async fn combine_tokens(&mut self, tokens: Vec<&CreditToken>) -> Result<CreditToken> {
        if tokens.is_empty() {
            return Err(ClientError::Interaction("No tokens provided for combining".to_string()));
        }
        
        // Ensure we have the server's public key
        let public_key = self.get_public_key().await?;
        
        // Create spend proofs for all tokens
        debug!("Creating spend proofs for {} tokens", tokens.len());
        let mut spend_proofs = Vec::with_capacity(tokens.len());
        
        // Track the total credits we're combining
        let mut total_credits = 0u128;
        
        for token in tokens {
            // Get the token's value
            let value = token.get_value();
            total_credits += value;
            
            // Create a spend proof for the full value
            let value_scalar = Scalar::from(value);
            let (spend_proof, _) = token.prove_spend(&self.params, value_scalar, OsRng);
            spend_proofs.push(spend_proof);
        }
        
        debug!("Created {} spend proofs with total value of {}", spend_proofs.len(), total_credits);
        
        // Create pre-issuance state and request for the new token
        debug!("Generating pre-issuance state for combined token");
        let pre_issuance = PreIssuance::random(OsRng);
        let issuance_request = pre_issuance.request(&self.params, OsRng);
        
        // Send the combine request to the server
        debug!("Sending combine request to server");
        let request = Request::Combine(spend_proofs, issuance_request.clone());
        let response = self.send_request(request).await?;
        
        // Process the server's response
        match response {
            Response::Issue(issuance_response) => {
                debug!("Received issuance response, creating combined credit token");
                let token = pre_issuance.to_credit_token(
                    &self.params,
                    &public_key,
                    &issuance_request,
                    &issuance_response
                ).ok_or(ClientError::InvalidToken)?;
                
                info!("Successfully created new combined credit token with {} credits", total_credits);
                Ok(token)
            },
            _ => {
                error!("Expected Issue response for combine request, got something else");
                Err(ClientError::InvalidResponse)
            }
        }
    }
    
    /// Fetches the server's public key if not already available
    ///
    /// # Returns
    ///
    /// The server's public key
    pub async fn get_public_key(&mut self) -> Result<PublicKey> {
        if let Some(ref pk) = self.server_public_key {
            return Ok(pk.clone());
        }
        
        debug!("Fetching server public key");
        let request = Request::GetPublicKey;
        let response = self.send_request(request).await?;
        
        match response {
            Response::PublicKey(pk) => {
                info!("Received server public key");
                self.server_public_key = Some(pk.clone());
                Ok(pk)
            },
            _ => {
                error!("Expected PublicKey response, got something else");
                Err(ClientError::InvalidResponse)
            }
        }
    }

    /// Generates a new credit token through the issuance protocol
    ///
    /// This method initiates the credit issuance protocol with the server.
    /// It generates a pre-issuance state, creates an issuance request with
    /// a proof of work, sends it to the server, and finalizes the token creation.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - A new credit token if the issuance was successful
    /// - The time taken to generate the proof of work
    pub async fn issue_new_token(&mut self, bits: u32) -> Result<(CreditToken, Duration)> {
        // Ensure we have the server's public key
        let public_key = self.get_public_key().await?;
        
        // Create pre-issuance state and request
        debug!("Generating pre-issuance state");
        let pre_issuance = PreIssuance::random(OsRng);
        let issuance_request = pre_issuance.request(&self.params, OsRng);
        
        // Generate proof of work
        debug!("Generating proof of work for {} bits", bits);
        let (pow, pow_time) = self.generate_proof_of_work(bits)?;
        
        // Log the time taken
        info!("Proof of work for {} bits took {:?}", bits, pow_time);
         
        // Send the issuance request to the server
        debug!("Sending issuance request to server");
        let request = Request::Issue(issuance_request.clone(), pow);
        let response = self.send_request(request).await?;
        
        // Process the server's response
        match response {
            Response::Issue(issuance_response) => {
                debug!("Received issuance response, creating credit token");
                let token = pre_issuance.to_credit_token(
                    &self.params,
                    &public_key,
                    &issuance_request,
                    &issuance_response
                ).ok_or(ClientError::InvalidToken)?;
                
                info!("Successfully created new credit token");
                Ok((token, pow_time))
            },
            _ => {
                error!("Expected Issue response, got something else");
                Err(ClientError::InvalidResponse)
            }
        }
    }

    /// Spends credits from a token and processes the refund
    ///
    /// This method initiates the spending protocol with the server.
    /// It creates a spend proof for the specified amount, sends it to
    /// the server, and processes the refund to create a new token with
    /// the remaining balance.
    ///
    /// # Arguments
    ///
    /// * `token` - The credit token to spend from
    /// * `amount` - The amount to spend
    ///
    /// # Returns
    ///
    /// A new credit token with the remaining balance if the spend was successful
    pub async fn spend(&mut self, token: &CreditToken, amount: u128) -> Result<CreditToken> {
        // Ensure we have the server's public key
        let public_key = self.get_public_key().await?;
        
        // Convert amount to scalar
        let amount_scalar = Scalar::from(amount);
        
        // Create spend proof
        debug!("Creating spend proof for {} credits", amount);
        let (spend_proof, pre_refund) = token.prove_spend(&self.params, amount_scalar, OsRng);
        
        // Send the spend request to the server
        debug!("Sending spend request to server");
        let request = Request::Spend(spend_proof.clone());
        let response = self.send_request(request).await?;
        
        // Process the server's response
        match response {
            Response::Refund(refund) => {
                debug!("Received refund response, creating new credit token");
                let new_token = pre_refund.to_credit_token(
                    &self.params,
                    &spend_proof,
                    &refund,
                    &public_key
                ).ok_or(ClientError::InvalidToken)?;
                
                info!("Successfully spent {} credits, new token created with remaining balance", amount);
                Ok(new_token)
            },
            _ => {
                error!("Expected Refund response, got something else");
                Err(ClientError::InvalidResponse)
            }
        }
    }

    /// Generates a proof of work for token issuance
    ///
    /// This is a multi-threaded proof of work implementation that tries to find a nonce
    /// that when hashed with blake3 has a specified number of leading zeros.
    /// It creates one thread per CPU core available and returns the first valid result.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - A 32-byte array containing the proof of work
    /// - The time taken to generate the proof of work
    fn generate_proof_of_work(&self, bits: u32) -> Result<([u8; 32], Duration)> {
        debug!("Starting proof-of-work calculation using multiple threads");
        
        // Start timing
        let start_time = Instant::now();
        
        // Get the number of available CPU cores
        let num_cores = num_cpus::get();
        debug!("Using {} CPU cores for mining", num_cores);
        
        // Create a flag to signal when a solution is found
        let found = Arc::new(AtomicBool::new(false));
        
        // Create a mutex to store the solution
        let solution = Arc::new(Mutex::new(None));
        
        // Create a vector to hold our thread handles
        let mut handles = Vec::with_capacity(num_cores);
        
        // Start mining threads
        for thread_id in 0..num_cores {
            // Create thread-local copies of shared state
            let found = found.clone();
            let solution = solution.clone();
            
            // Spawn a new thread for mining
            let handle = thread::spawn(move || {
                // Generate seed using OsRng
                let mut seed = [0u8; 32];
                OsRng.fill_bytes(&mut seed);
                
                // Create a ChaCha8Rng from the seed
                let mut rng = ChaCha8Rng::from_seed(seed);
                
                debug!("Thread {} started mining", thread_id);
                
                // Generate random nonces until we find a solution or another thread does
                let mut nonce = [0u8; 32];
                while !found.load(Ordering::Relaxed) {
                    // Generate a random nonce
                    rng.fill_bytes(&mut nonce);
                    
                    // Calculate the hash and check if it meets the difficulty requirement
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(b"TODO make configurable");
                    hasher.update(&nonce);
                    let zeros = leading_zeros(hasher.finalize().as_bytes());
                    
                    // If we found a solution, store it and signal other threads to stop
                    if zeros >= bits {
                        debug!("Thread {} found solution with {} leading zeros", thread_id, zeros);
                        let mut sol = solution.lock().unwrap();
                        *sol = Some(nonce);
                        found.store(true, Ordering::Relaxed);
                        break;
                    }
                }
                
                debug!("Thread {} finished", thread_id);
            });
            
            handles.push(handle);
        }
        
        // Wait for all threads to complete
        for handle in handles {
            let _ = handle.join();
        }
        
        // Calculate elapsed time
        let elapsed = start_time.elapsed();
        
        // Retrieve the solution
        match *solution.lock().unwrap() {
            Some(nonce) => {
                debug!("Proof-of-work completed successfully in {:?}", elapsed);
                Ok((nonce, elapsed))
            },
            None => {
                error!("Proof-of-work failed: no solution found after {:?}", elapsed);
                Err(ClientError::PowFailed)
            }
        }
    }

    /// Sends a request to the server and receives a response
    ///
    /// # Arguments
    ///
    /// * `request` - The request to send
    ///
    /// # Returns
    ///
    /// The server's response if successful
    async fn send_request(&self, request: Request) -> Result<Response> {
        // Serialize the request
        let request_bytes = bincode::serde::encode_to_vec(&request, bincode::config::standard())?;
        
        // Create a reqwest client with TLS
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true) // For self-signed certs
            // Add this option to disable SNI when connecting to IP addresses
            .tls_built_in_root_certs(false)
            .use_rustls_tls()
            .https_only(true)
            .build()
            .map_err(|e| ClientError::Network(e.to_string()))?;
        
        // Send the request to the server
        let response = client.post(&format!("{}/token", self.server_url))
            .body(request_bytes)
            .send()
            .await
            .map_err(|e| ClientError::Network(e.to_string()))?;
        
        // Check if the request was successful
        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await
                .unwrap_or_else(|_| String::from("Unknown error"));
            
            error!("Server returned error: {} - {}", status, error_text);
            return Err(ClientError::Network(format!("Server error: {} - {}", status, error_text)));
        }
        
        // Get the response bytes
        let response_bytes = response.bytes()
            .await
            .map_err(|e| ClientError::Network(e.to_string()))?;
        
        // Deserialize the response
        let (response, _): (Response, _) = bincode::serde::decode_from_slice(
            &response_bytes,
            bincode::config::standard()
        )?;
        
        Ok(response)
    }
}

pub fn leading_zeros(bytes: &[u8]) -> u32 {
    let mut zs = 0;
    for byte in bytes.iter().copied() {
        if byte == 0 {
            zs += 8;
        } else {
            zs += byte.leading_zeros() as u32;
            break; // Stop counting after the first non-zero byte
        }
    }
    std::cmp::min(zs, 127) // Increase to 127 to support up to 128 bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;

    #[test]
    fn test_leading_zeros() {
        // Test with all zeros
        let all_zeros = [0u8; 32];
        // The function caps at 127 maximum leading zeros
        assert_eq!(leading_zeros(&all_zeros), 127);
        
        // Test with bytes where the MSB is set in the first byte
        // In Rust, byte ordering is little-endian, but the leading_zeros function
        // counts from the start of the array (index 0)
        
        // Test with a single bit set at position 0 (most significant bit of first byte)
        let mut byte_with_msb = [0u8; 32];
        byte_with_msb[0] = 0b10000000;
        assert_eq!(leading_zeros(&byte_with_msb), 0); // No leading zeros
        
        // Test with a single bit set at position 1 of first byte
        let mut byte_with_second_bit = [0u8; 32];
        byte_with_second_bit[0] = 0b01000000;
        assert_eq!(leading_zeros(&byte_with_second_bit), 1); // One leading zero
        
        // Test with zeros in the first byte and a bit set in the second byte
        let mut byte_in_second_position = [0u8; 32];
        byte_in_second_position[0] = 0;  // First byte is all zeros (8 leading zeros)
        byte_in_second_position[1] = 0b10000000;  // Second byte has MSB set
        assert_eq!(leading_zeros(&byte_in_second_position), 8); // 8 leading zeros
        
        // Test with all bytes having all bits set
        let all_ones = [0xFF; 32];
        assert_eq!(leading_zeros(&all_ones), 0); // No leading zeros
        
        // Test with first three bytes as zero and bit set in fourth byte
        let mut pattern = [0u8; 32];
        pattern[3] = 0b00000001; // Fourth byte with LSB set
        assert_eq!(leading_zeros(&pattern), 3 * 8 + 7); // 3 bytes plus 7 bits = 31 zeros
        
        // Test with more bytes for u128 support (16 bytes)
        let mut large_pattern = [0u8; 32];
        large_pattern[15] = 0b00000001; // 16th byte with LSB set
        assert_eq!(leading_zeros(&large_pattern), 15 * 8 + 7); // 15 bytes plus 7 bits = 127 zeros
        
        // Edge case: empty array
        let empty: &[u8] = &[];
        assert_eq!(leading_zeros(empty), 0); // No bits, no leading zeros
    }

    #[test]
    fn test_proof_of_work() {
        // This test simulates the generation and verification of proof of work using multiple threads
        
        // Function to simulate proof-of-work generation with multi-threading and ChaCha8Rng
        fn generate_test_pow(bits: u32) -> [u8; 32] {
            // Number of threads to use (less in test environment to avoid excessive resource usage)
            let num_threads = 2; 
            
            // Create a flag to signal when a solution is found
            let found = Arc::new(AtomicBool::new(false));
            
            // Create a mutex to store the solution
            let solution = Arc::new(Mutex::new(None));
            
            // Create a vector to hold our thread handles
            let mut handles = Vec::with_capacity(num_threads);
            
            // Start mining threads
            for thread_id in 0..num_threads {
                // Create thread-local copies of shared state
                let found = found.clone();
                let solution = solution.clone();
                
                // Spawn a new thread for mining
                let handle = thread::spawn(move || {
                    // Generate seed using OsRng
                    let mut seed = [0u8; 32];
                    OsRng.fill_bytes(&mut seed);
                    
                    // Create a ChaCha8Rng from the seed
                    let mut rng = ChaCha8Rng::from_seed(seed);
                    
                    // Generate random nonces until we find a solution or another thread does
                    let mut nonce = [0u8; 32];
                    let mut attempts = 0;
                    let max_attempts = 5000; // Limit attempts per thread to avoid infinite loop in test
                    
                    while !found.load(Ordering::Relaxed) && attempts < max_attempts {
                        // Generate a random nonce
                        rng.fill_bytes(&mut nonce);
                        
                        // Calculate the hash and check if it meets the difficulty requirement
                        let zeros = leading_zeros(blake3::hash(&nonce).as_bytes());
                        
                        // If we found a solution, store it and signal other threads to stop
                        if zeros >= bits {
                            let mut sol = solution.lock().unwrap();
                            *sol = Some(nonce);
                            found.store(true, Ordering::Relaxed);
                            break;
                        }
                        
                        attempts += 1;
                    }
                });
                
                handles.push(handle);
            }
            
            // Wait for all threads to complete
            for handle in handles {
                let _ = handle.join();
            }
            
            // Retrieve the solution
            match *solution.lock().unwrap() {
                Some(nonce) => nonce,
                None => panic!("Failed to find proof of work with {} bits", bits),
            }
        }
        
        // Test with different difficulty levels
        for bits in [1, 2, 3, 4] {
            // Generate a proof of work with the required difficulty
            let pow = generate_test_pow(bits);
            
            // Verify that the proof of work has the required number of leading zeros
            let hash = *blake3::hash(&pow).as_bytes();
            let zeros = leading_zeros(&hash);
            
            assert!(zeros >= bits, 
                "Proof of work should have at least {} leading zeros, but got {}", bits, zeros);
            
            // Simulate server verification logic
            let credits = if zeros == 127 {
                u128::MAX
            } else {
                2u128.pow(zeros)
            };
            
            // Verify credits calculation
            assert!(credits >= 2u128.pow(bits), 
                "Credits ({}) should be at least 2^{} for {} leading zeros", 
                credits, bits, zeros);
        }
    }
}
