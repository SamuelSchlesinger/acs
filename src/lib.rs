use anonymous_credit_tokens::{
    self, IssuanceRequest, IssuanceResponse, Params, PreIssuance, PublicKey, 
    SpendProof, Refund, u32_to_scalar, scalar_to_u32
};
use serde::{Deserialize, Serialize};
use rand_core::{OsRng, RngCore};
use std::io;
use log::{info, error, debug};

// Re-export the CreditToken type from anonymous_credit_tokens
pub use anonymous_credit_tokens::CreditToken;

/// Extension trait that adds utility methods to CreditToken
pub trait CreditTokenExt {
    /// Returns the token's credit value as a u32
    fn get_value(&self) -> u32;
}

impl CreditTokenExt for CreditToken {
    fn get_value(&self) -> u32 {
        // Convert the credits scalar field to u32
        scalar_to_u32(&self.credits()).unwrap_or(0)
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
    Combine(Vec<SpendProof>, IssuanceRequest),
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
        let mut total_credits = 0;
        
        for token in tokens {
            // Get the token's value
            let value = token.get_value();
            total_credits += value;
            
            // Create a spend proof for the full value
            let value_scalar = u32_to_scalar(value);
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
    /// A new credit token if the issuance was successful
    pub async fn issue_new_token(&mut self, bits: u32) -> Result<CreditToken> {
        // Ensure we have the server's public key
        let public_key = self.get_public_key().await?;
        
        // Create pre-issuance state and request
        debug!("Generating pre-issuance state");
        let pre_issuance = PreIssuance::random(OsRng);
        let issuance_request = pre_issuance.request(&self.params, OsRng);
        
        // Generate proof of work
        debug!("Generating proof of work for {} bits", bits);
        let pow = self.generate_proof_of_work(bits)?;
         
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
                Ok(token)
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
    pub async fn spend(&mut self, token: &CreditToken, amount: u32) -> Result<CreditToken> {
        // Ensure we have the server's public key
        let public_key = self.get_public_key().await?;
        
        // Convert amount to scalar
        let amount_scalar = u32_to_scalar(amount);
        
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
    /// This is a simple proof of work implementation that tries to find a nonce
    /// that when hashed with blake3 has a specified number of leading zeros.
    ///
    /// # Returns
    ///
    /// A 32-byte array containing the proof of work
    fn generate_proof_of_work(&self, bits: u32) -> Result<[u8; 32]> {
        debug!("Starting proof-of-work calculation");
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        
        while {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"TODO make configurable");
            hasher.update(&nonce);
            leading_zeros(hasher.finalize().as_bytes())
        }< bits {
            // Generate random nonce
            OsRng.fill_bytes(&mut nonce);
        }
        
        debug!("Proof-of-work completed");
        Ok(nonce)
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
    std::cmp::min(zs, 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn test_leading_zeros() {
        // Test with all zeros
        let all_zeros = [0u8; 32];
        // The function caps at 31 maximum leading zeros
        assert_eq!(leading_zeros(&all_zeros), 31);
        
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
        
        // Edge case: empty array
        let empty: &[u8] = &[];
        assert_eq!(leading_zeros(empty), 0); // No bits, no leading zeros
    }

    #[test]
    fn test_proof_of_work() {
        // This test simulates the generation and verification of proof of work
        
        // Function to simulate proof-of-work generation (similar to Client::generate_proof_of_work)
        fn generate_test_pow(bits: u32) -> [u8; 32] {
            let mut nonce = [0u8; 32];
            let mut attempts = 0;
            let max_attempts = 10000; // Limit attempts to avoid infinite loop in test
            
            while leading_zeros(blake3::hash(&nonce).as_bytes()) < bits {
                // Generate random nonce
                OsRng.fill_bytes(&mut nonce);
                attempts += 1;
                
                if attempts >= max_attempts {
                    panic!("Failed to find proof of work after {} attempts", max_attempts);
                }
            }
            
            nonce
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
            let credits = if zeros == 31 {
                u32::MAX
            } else {
                2u32.pow(zeros)
            };
            
            // Verify credits calculation
            assert!(credits >= 2u32.pow(bits), 
                "Credits ({}) should be at least 2^{} for {} leading zeros", 
                credits, bits, zeros);
        }
    }
}
