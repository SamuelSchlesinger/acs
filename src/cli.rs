use acs::{Client, CreditToken, CreditTokenExt, ClientError, Result};
use clap::{Parser, Subcommand};
use console::{style, Term};
use dialoguer::{Input, Confirm, theme::ColorfulTheme};
use indicatif::{ProgressBar, ProgressStyle};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process;
use std::time::Instant;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;
use tokio::time::{self, Duration};
use log::{error, debug, info};
use rand::Rng;
use std::collections::HashMap;

// Configuration file structure
#[derive(Serialize, Deserialize)]
struct Config {
    server: ServerConfig,
}

#[derive(Serialize, Deserialize)]
struct ServerConfig {
    uri: String,
}

// The CLI commands structure
#[derive(Parser)]
#[command(author, version, about = "Anonymous Credit Token CLI client")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Issue a new credit token with proof of work
    Issue {
        /// Number of proof of work bits
        #[arg(short, long)]
        bits: u32,
    },
    
    /// List all stored credit tokens
    List {
        /// Show tokens with 0 credits
        #[arg(short, long)]
        show_zero: bool,
    },
    
    /// Spend credit from a token
    Spend {
        /// Token ID to spend from
        #[arg(short, long)]
        id: i64,
        
        /// Amount to spend
        #[arg(short, long)]
        amount: u128,
    },
    
    /// Show details of a credit token
    Show {
        /// Token ID to display
        #[arg(short, long)]
        id: i64,
    },
    
    /// Export a credit token to a file in hex format
    Export {
        /// Token ID to export
        #[arg(short, long)]
        id: i64,
        
        /// File path to save the hex representation
        #[arg(short, long)]
        file: PathBuf,
        
        /// Forget (delete) the token after export
        #[arg(long)]
        forget: bool,
    },
    
    /// Import a credit token from a hex file
    Import {
        /// File path containing the hex representation of a token
        #[arg(short, long)]
        file: PathBuf,
        
        /// Anonymize the token by spending 0 credits
        #[arg(long)]
        anonymize: bool,
    },
    
    /// Combine multiple tokens into a new token
    Combine {
        /// Token IDs to combine (comma-separated list)
        #[arg(short, long, value_delimiter = ',')]
        ids: Vec<i64>,
    },
    
    /// Split a token into multiple tokens with specified amounts
    Split {
        /// Token ID to split
        #[arg(short, long)]
        id: i64,
        
        /// Amounts for each new token (comma-separated list, must sum to token's value)
        #[arg(short, long, value_delimiter = ',')]
        amounts: Vec<u128>,
    },
    
    /// Forget (delete) a credit token from local storage
    Forget {
        /// Token ID to forget
        #[arg(short, long)]
        id: i64,
    },
    
    /// Check if a token's nullifier has been spent
    CheckNullifier {
        /// Token ID to check
        #[arg(short, long)]
        id: i64,
    },
    
    /// Get database stats including nullifier and proof-of-work hash counts
    Stats {
        /// Show detailed breakdown by type (nullifiers, proof-of-work hashes)
        #[arg(short, long)]
        detailed: bool,
    },

    /// Run a load test against the server to measure performance
    LoadTest {
        /// Number of concurrent users to simulate
        #[arg(short, long, default_value = "10")]
        users: usize,
        
        /// Duration of the test in seconds
        #[arg(short, long, default_value = "60")]
        duration: u64,
        
        /// Number of proof of work bits for token issuance
        #[arg(short, long, default_value = "8")]
        bits: u32,
        
        /// Maximum number of tokens to issue per user
        #[arg(short = 'm', long, default_value = "5")]
        max_tokens: usize,
        
        /// Percentage of operations that should be spend operations (0-100)
        #[arg(short, long, default_value = "60")]
        spend_percent: u8,
        
        /// Percentage of operations that should be combine operations (0-100)
        #[arg(short, long, default_value = "20")]
        combine_percent: u8,
        
        /// Percentage of operations that should be split operations (0-100)
        #[arg(short, long, default_value = "20")]
        split_percent: u8,
        
        /// Generate a detailed CSV report
        #[arg(long)]
        report: bool,
    },
}

// Database schema for tokens
struct TokenDatabase {
    conn: Connection,
}

impl TokenDatabase {
    fn new() -> Result<Self> {
        let home_dir = dirs::home_dir().ok_or_else(|| {
            ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound, 
                "Home directory not found"
            ))
        })?;

        let db_path = home_dir.join(".credit-tokens.db");
        let conn = Connection::open(db_path)?;
        
        // Create the tokens table if it doesn't exist
        conn.execute(
            "CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY,
                data BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;
        
        // Ensure we have indexes for fast lookups
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_tokens_created_at ON tokens(created_at)",
            [],
        )?;
        
        Ok(Self { conn })
    }
    
    fn store_token(&self, token: &CreditToken) -> Result<i64> {
        let encoded = bincode::serde::encode_to_vec(token, bincode::config::standard())?;
        self.conn.execute(
            "INSERT INTO tokens (data) VALUES (?)",
            params![encoded],
        )?;
        
        Ok(self.conn.last_insert_rowid())
    }
    
    fn update_token(&self, id: i64, token: &CreditToken) -> Result<()> {
        let encoded = bincode::serde::encode_to_vec(token, bincode::config::standard())?;
        let rows_affected = self.conn.execute(
            "UPDATE tokens SET data = ? WHERE id = ?",
            params![encoded, id],
        )?;
        
        if rows_affected == 0 {
            return Err(ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Token with ID {} not found", id),
            )));
        }
        
        Ok(())
    }
    
    fn delete_token(&self, id: i64) -> Result<()> {
        let rows_affected = self.conn.execute(
            "DELETE FROM tokens WHERE id = ?",
            params![id],
        )?;
        
        if rows_affected == 0 {
            return Err(ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Token with ID {} not found", id),
            )));
        }
        
        Ok(())
    }
    
    fn get_token(&self, id: i64) -> Result<CreditToken> {
        let mut stmt = self.conn.prepare("SELECT data FROM tokens WHERE id = ?")?;
        let mut rows = stmt.query(params![id])?;
        
        if let Some(row) = rows.next()? {
            let blob: Vec<u8> = row.get(0)?;
            let (token, _): (CreditToken, _) = bincode::serde::decode_from_slice(&blob, bincode::config::standard())?;
            Ok(token)
        } else {
            Err(ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Token with ID {} not found", id),
            )))
        }
    }
    
    fn list_tokens(&self) -> Result<Vec<(i64, CreditToken)>> {
        let mut stmt = self.conn.prepare("SELECT id, data FROM tokens ORDER BY created_at DESC")?;
        let rows = stmt.query_map([], |row| {
            let id = row.get(0)?;
            let blob: Vec<u8> = row.get(1)?;
            let (token, _): (CreditToken, _) = bincode::serde::decode_from_slice(&blob, bincode::config::standard())
                .map_err(|_| rusqlite::Error::InvalidColumnType(1, "".to_string(), rusqlite::types::Type::Blob))?;
            
            Ok((id, token))
        })?;
        
        let mut tokens = Vec::new();
        for token_result in rows {
            tokens.push(token_result?);
        }
        
        Ok(tokens)
    }
}

// Configuration management
fn get_config_path() -> PathBuf {
    let home_dir = dirs::home_dir().expect("Failed to find home directory");
    home_dir.join(".acs-config.toml")
}

fn load_config() -> Result<Config> {
    let config_path = get_config_path();
    let theme = ColorfulTheme::default();
    
    if !config_path.exists() {
        // Create config through interaction
        let term = Term::stdout();
        term.write_line(&format!("{}", style("Welcome to the Anonymous Credit Token CLI!").bold()))?;
        term.write_line("This appears to be your first time using the CLI. Let's set up your configuration.")?;
        
        let server_uri: String = Input::with_theme(&theme)
            .with_prompt("Enter the ACS server URI/IP and port (e.g., https://example.com:8443)")
            .validate_with(|input: &String| -> std::result::Result<(), &str> {
                if input.trim().is_empty() {
                    Err("Server URI cannot be empty")
                } else if !input.contains("://") && !input.contains(":") {
                    Err("URI should include protocol (http://) or port (:8443)")
                } else {
                    Ok(())
                }
            })
            .interact_text()
            .map_err(|e| ClientError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
        
        let config = Config {
            server: ServerConfig {
                uri: server_uri,
            },
        };
        
        // Save config
        let config_str = toml::to_string(&config)
            .map_err(|e| ClientError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
        
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        let mut file = File::create(&config_path)?;
        file.write_all(config_str.as_bytes())?;
        
        term.write_line(&format!("{}", style("Configuration saved successfully!").green()))?;
        
        return Ok(config);
    }
    
    // Load existing config
    let mut file = File::open(&config_path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    
    match toml::from_str::<Config>(&content) {
        Ok(config) => {
            debug!("Loaded configuration from {}", config_path.display());
            Ok(config)
        },
        Err(e) => {
            error!("Failed to parse config file: {}", e);
            
            // Ask user if they want to recreate the config
            if Confirm::with_theme(&theme)
                .with_prompt("Config file is invalid. Would you like to create a new one?")
                .default(true)
                .interact()
                .unwrap_or(false) 
            {
                // Delete the invalid config
                let _ = fs::remove_file(&config_path);
                // Recursively call to recreate
                load_config()
            } else {
                Err(ClientError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
            }
        }
    }
}

// Helper function to get token creation time
fn get_token_creation_time(id: i64, conn: &Connection) -> Option<String> {
    let mut stmt = match conn.prepare("SELECT created_at FROM tokens WHERE id = ?") {
        Ok(stmt) => stmt,
        Err(_) => return None,
    };
    
    let mut rows = match stmt.query(params![id]) {
        Ok(rows) => rows,
        Err(_) => return None,
    };
    
    if let Ok(Some(row)) = rows.next() {
        if let Ok(date_str) = row.get::<_, String>(0) {
            return Some(date_str);
        }
    }
    
    None
}

/// Operation metrics for load testing
#[derive(Debug, Clone)]
struct OperationMetrics {
    operation: String,
    success_count: usize,
    failure_count: usize,
    total_duration_ms: u128,
    min_duration_ms: u128,
    max_duration_ms: u128,
}

impl OperationMetrics {
    fn new(operation: &str) -> Self {
        Self {
            operation: operation.to_string(),
            success_count: 0,
            failure_count: 0,
            total_duration_ms: 0,
            min_duration_ms: u128::MAX,
            max_duration_ms: 0,
        }
    }
    
    fn record_success(&mut self, duration_ms: u128) {
        self.success_count += 1;
        self.total_duration_ms += duration_ms;
        
        // Only update min if it's the first success or if the new duration is smaller
        if self.success_count == 1 || duration_ms < self.min_duration_ms {
            self.min_duration_ms = duration_ms;
        }
        
        self.max_duration_ms = self.max_duration_ms.max(duration_ms);
    }
    
    fn record_failure(&mut self) {
        self.failure_count += 1;
    }
    
    fn avg_duration_ms(&self) -> f64 {
        if self.success_count > 0 {
            self.total_duration_ms as f64 / self.success_count as f64
        } else {
            0.0
        }
    }
}

/// Represents a virtual user in the load test
struct VirtualUser {
    id: usize,
    client: Client,
    db: Arc<Mutex<TokenDatabase>>,
    tokens: Vec<(i64, CreditToken)>,
    metrics_tx: mpsc::Sender<(String, bool, u128)>,
    bits: u32,
    max_tokens: usize,
    spend_threshold: u8,
    combine_threshold: u8,
    running: Arc<AtomicBool>,
}

impl VirtualUser {
    fn new(
        id: usize,
        server_uri: String,
        db: Arc<Mutex<TokenDatabase>>,
        metrics_tx: mpsc::Sender<(String, bool, u128)>,
        bits: u32,
        max_tokens: usize,
        spend_percent: u8,
        combine_percent: u8,
        running: Arc<AtomicBool>,
    ) -> Self {
        // Calculate operation thresholds for random distribution
        // Ensure we have valid thresholds even if percentages are 0
        let spend_threshold = spend_percent;
        let combine_threshold = spend_threshold + combine_percent;
        
        debug!("User {} operation thresholds: spend < {}, combine < {}, split >= {}", 
               id, spend_threshold, combine_threshold, combine_threshold);
        
        Self {
            id,
            client: Client::new(server_uri),
            db,
            tokens: Vec::new(),
            metrics_tx,
            bits,
            max_tokens,
            spend_threshold,
            combine_threshold,
            running,
        }
    }
    
    async fn run(&mut self) {
        info!("Virtual user {} started", self.id);
        
        // Each user starts by issuing one token
        if let Err(e) = self.issue_token().await {
            error!("User {} failed to issue initial token: {}", self.id, e);
            return;
        }
        
        // Run until the test is complete
        while self.running.load(Ordering::Relaxed) {
            // Remove any tokens with zero value
            self.tokens.retain(|(_, token)| token.get_value() > 0);
            
            // Check if we have no tokens, issue one
            if self.tokens.is_empty() {
                if let Err(e) = self.issue_token().await {
                    error!("User {} failed to issue token: {}", self.id, e);
                    // Small delay to avoid hammering the server
                    time::sleep(Duration::from_millis(500)).await;
                }
                continue;
            }
            
            // Choose a random operation based on distribution percentages
            // Create a new rng for each operation to avoid Send issues
            let op = rand::thread_rng().gen_range(0..100);
            
            let result = if op < self.spend_threshold && !self.tokens.is_empty() {
                // Spend operation
                // Choose a random amount within the function to avoid threading issues
                self.spend_random_token().await
            } else if op < self.combine_threshold && self.tokens.len() >= 2 {
                // Combine operation
                self.combine_random_tokens().await
            } else if self.tokens.len() >= 1 && (op >= self.combine_threshold || (self.combine_threshold == 0 && self.spend_threshold == 0)) {
                // Split operation - explicitly handle the case where spend and combine are 0%
                self.split_random_token().await
            } else {
                // If we don't have enough tokens for the operation, issue a new one
                self.issue_token().await
            };
            
            if let Err(e) = result {
                error!("User {} operation failed: {}", self.id, e);
                // Small delay to avoid hammering the server
                time::sleep(Duration::from_millis(500)).await;
            }
            
            // Small delay between operations - use a fixed delay
            time::sleep(Duration::from_millis(300)).await;
            
            // Issue more tokens if we're below max - use a fixed 25% chance
            // We'll increment a counter and use modulo to get a 25% probability instead of random
            static mut COUNTER: u32 = 0;
            let should_issue = unsafe {
                COUNTER = COUNTER.wrapping_add(1);
                COUNTER % 4 == 0
            };
            
            if self.tokens.len() < self.max_tokens && should_issue {
                if let Err(e) = self.issue_token().await {
                    error!("User {} failed to issue additional token: {}", self.id, e);
                }
            }
        }
        
        info!("Virtual user {} finished", self.id);
    }
    
    async fn issue_token(&mut self) -> Result<()> {
        let start = Instant::now();
        let operation = "issue";
        
        // Issue a new token
        debug!("User {} issuing token with {} bits", self.id, self.bits);
        match self.client.issue_new_token(self.bits).await {
            Ok((token, _)) => {
                // Store the token in the database
                let token_id = {
                    let db = self.db.lock().unwrap();
                    db.store_token(&token)?
                };
                
                self.tokens.push((token_id, token));
                let duration = start.elapsed().as_millis();
                
                // Send metrics
                if let Err(e) = self.metrics_tx.send((operation.to_string(), true, duration)).await {
                    error!("Failed to send metrics: {}", e);
                }
                
                debug!("User {} issued token ID {} in {}ms", self.id, token_id, duration);
                Ok(())
            },
            Err(e) => {
                // Send failed metrics
                if let Err(e2) = self.metrics_tx.send((operation.to_string(), false, 0)).await {
                    error!("Failed to send metrics: {}", e2);
                }
                
                Err(e)
            }
        }
    }
    
    async fn spend_random_token(&mut self) -> Result<()> {
        // Generate random amount here to avoid Send issues with ThreadRng
        let amount = rand::thread_rng().gen_range(1..100);
        if self.tokens.is_empty() {
            return Err(ClientError::Interaction("No tokens to spend".to_string()));
        }
        
        let start = Instant::now();
        let operation = "spend";
        
        // Select a random token - create a fresh rng
        let idx = rand::thread_rng().gen_range(0..self.tokens.len());
        
        // Clone the data we need to avoid borrow checker issues
        let token_id;
        let token;
        {
            let (id, t) = &self.tokens[idx];
            token_id = *id;
            token = t.clone();
        }
        
        // Determine valid amount to spend (1 to token value)
        let token_value = token.get_value();
        let spend_amount = amount.min(token_value.max(1) - 1);
        
        if spend_amount == 0 {
            // If token has no value, remove it
            self.tokens.remove(idx);
            return Ok(());
        }
        
        debug!("User {} spending {} from token {}", self.id, spend_amount, token_id);
        
        // Spend from the token
        match self.client.spend(&token, spend_amount).await {
            Ok(new_token) => {
                // Update the token in the database and our local list
                {
                    let db = self.db.lock().unwrap();
                    db.update_token(token_id, &new_token)?;
                }
                
                self.tokens[idx] = (token_id, new_token);
                let duration = start.elapsed().as_millis();
                
                // Send metrics
                if let Err(e) = self.metrics_tx.send((operation.to_string(), true, duration)).await {
                    error!("Failed to send metrics: {}", e);
                }
                
                debug!("User {} spent {} from token {} in {}ms", self.id, spend_amount, token_id, duration);
                Ok(())
            },
            Err(e) => {
                // Send failed metrics
                if let Err(e2) = self.metrics_tx.send((operation.to_string(), false, 0)).await {
                    error!("Failed to send metrics: {}", e2);
                }
                
                Err(e)
            }
        }
    }
    
    async fn combine_random_tokens(&mut self) -> Result<()> {
        if self.tokens.len() < 2 {
            return Err(ClientError::Interaction("Not enough tokens to combine".to_string()));
        }
        
        let start = Instant::now();
        let operation = "combine";
        
        // Local deterministic decision for how many tokens to combine
        // We'll use the count of tokens we have to decide
        let num_to_combine = if self.tokens.len() >= 3 { 
            // Every third call, use 3 tokens, otherwise use 2
            static mut COMBINE_COUNTER: u32 = 0;
            let choice = unsafe {
                COMBINE_COUNTER = COMBINE_COUNTER.wrapping_add(1);
                COMBINE_COUNTER % 3 == 0
            };
            if choice { 3 } else { 2 }
        } else { 
            2 
        };
        
        // Select indices without relying on ThreadRng
        let mut indices = Vec::new();
        
        // Create a pseudo-random selection without using thread_rng
        // We'll use the current nanoseconds as randomness source
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
            
        // Use simple algorithm to pick indices
        let mut available: Vec<usize> = (0..self.tokens.len()).collect();
        for _ in 0..num_to_combine {
            if available.is_empty() { break; }
            let idx = (seed as usize + indices.len()) % available.len();
            indices.push(available.remove(idx));
        }
        
        // Get the tokens to combine
        let token_ids: Vec<i64> = indices.iter().map(|&i| self.tokens[i].0).collect();
        let tokens: Vec<&CreditToken> = indices.iter().map(|&i| &self.tokens[i].1).collect();
        
        debug!("User {} combining tokens {:?}", self.id, token_ids);
        
        // Combine the tokens
        match self.client.combine_tokens(tokens).await {
            Ok(combined_token) => {
                // Store the new token
                let new_id = {
                    let db = self.db.lock().unwrap();
                    // Store the new token
                    let new_id = db.store_token(&combined_token)?;
                    
                    // Delete the original tokens
                    for id in &token_ids {
                        if let Err(e) = db.delete_token(*id) {
                            error!("Failed to delete token {}: {}", id, e);
                        }
                    }
                    
                    new_id
                };
                
                // Remove the original tokens from our list
                indices.sort_unstable_by(|a, b| b.cmp(a)); // Sort in reverse
                for idx in indices {
                    self.tokens.remove(idx);
                }
                
                // Add the new token
                self.tokens.push((new_id, combined_token));
                
                let duration = start.elapsed().as_millis();
                
                // Send metrics
                if let Err(e) = self.metrics_tx.send((operation.to_string(), true, duration)).await {
                    error!("Failed to send metrics: {}", e);
                }
                
                debug!("User {} combined tokens {:?} into {} in {}ms", self.id, token_ids, new_id, duration);
                Ok(())
            },
            Err(e) => {
                // Send failed metrics
                if let Err(e2) = self.metrics_tx.send((operation.to_string(), false, 0)).await {
                    error!("Failed to send metrics: {}", e2);
                }
                
                Err(e)
            }
        }
    }
    
    async fn split_random_token(&mut self) -> Result<()> {
        if self.tokens.is_empty() {
            return Err(ClientError::Interaction("No tokens to split".to_string()));
        }
        
        let start = Instant::now();
        let operation = "split";
        
        // First, collect the indices of tokens that have enough value
        let mut valid_indices = Vec::new();
        for (idx, (_, token)) in self.tokens.iter().enumerate() {
            if token.get_value() > 1 {
                valid_indices.push(idx);
            }
        }
            
        if valid_indices.is_empty() {
            // If no tokens have enough value, issue a new one
            return self.issue_token().await;
        }
        
        // Select a random valid token index
        let idx = valid_indices[rand::thread_rng().gen_range(0..valid_indices.len())];
        
        // Clone the token data to avoid borrowing issues
        let token_id;
        let token;
        {
            let (id, t) = &self.tokens[idx];
            token_id = *id;
            token = t.clone();
        }
        
        // Get the token value
        let value = token.get_value();
        
        // Decide how many pieces to split into (2 or 3)
        let pieces = rand::thread_rng().gen_range(2..=3);
        
        // Calculate random amounts that sum to value
        let mut amounts = Vec::with_capacity(pieces);
        let mut remaining = value;
        
        for i in 0..pieces {
            if i == pieces - 1 {
                // Last piece gets the remainder
                amounts.push(remaining);
            } else {
                // Generate a random amount
                // Convert to u128 to match types
                let pieces_u128 = pieces as u128;
                let i_u128 = i as u128;
                let max_amount = remaining - (pieces_u128 - i_u128 - 1);
                let min_amount = 1;
                
                if max_amount <= min_amount {
                    amounts.push(min_amount);
                } else {
                    let amount = rand::thread_rng().gen_range(min_amount..max_amount);
                    amounts.push(amount);
                }
                
                remaining -= amounts.last().unwrap();
            }
        }
        
        debug!("User {} splitting token {} into {:?}", self.id, token_id, amounts);
        
        // Split the token
        match self.client.split_token(&token, amounts).await {
            Ok(new_tokens) => {
                // Store the new tokens
                let mut new_ids = Vec::with_capacity(new_tokens.len());
                {
                    let db = self.db.lock().unwrap();
                    
                    // Delete the original token
                    if let Err(e) = db.delete_token(token_id) {
                        error!("Failed to delete token {}: {}", token_id, e);
                        // Continue anyway as we have the new tokens
                    }
                    
                    // Store the new tokens
                    for new_token in &new_tokens {
                        match db.store_token(new_token) {
                            Ok(id) => new_ids.push(id),
                            Err(e) => error!("Failed to store split token: {}", e),
                        }
                    }
                }
                
                // Remove the original token from our list
                self.tokens.remove(idx);
                
                // Add the new tokens
                for (i, new_token) in new_tokens.into_iter().enumerate() {
                    if i < new_ids.len() {
                        self.tokens.push((new_ids[i], new_token));
                    }
                }
                
                let duration = start.elapsed().as_millis();
                
                // Send metrics
                if let Err(e) = self.metrics_tx.send((operation.to_string(), true, duration)).await {
                    error!("Failed to send metrics: {}", e);
                }
                
                debug!("User {} split token {} into {:?} in {}ms", self.id, token_id, new_ids, duration);
                Ok(())
            },
            Err(e) => {
                // Send failed metrics
                if let Err(e2) = self.metrics_tx.send((operation.to_string(), false, 0)).await {
                    error!("Failed to send metrics: {}", e2);
                }
                
                Err(e)
            }
        }
    }
}

async fn run_load_test(
    client: &mut Client,
    _db: &TokenDatabase, // Prefix with underscore since we don't use it directly
    users: usize,
    duration: u64,
    bits: u32,
    max_tokens: usize,
    spend_percent: u8,
    combine_percent: u8,
    _split_percent: u8, // Prefix with underscore since we don't use it directly
    report: bool,
) -> Result<()> {
    let term = Term::stdout();
    
    // Verify server is reachable
    term.write_line("Testing connection to server...")?;
    match client.get_public_key().await {
        Ok(_) => term.write_line(&format!("{}", style("✓ Server is reachable").green()))?,
        Err(e) => {
            term.write_line(&format!("{}", style(format!("Error connecting to server: {}", e)).red()))?;
            return Err(e);
        }
    }
    
    // Create a channel for collecting metrics
    // Use a larger buffer to avoid blocking operations during high concurrency
    let (metrics_tx, mut metrics_rx) = mpsc::channel::<(String, bool, u128)>(users * 1000);
    
    // Create shared state
    let running = Arc::new(AtomicBool::new(true));
    let db = Arc::new(Mutex::new(TokenDatabase::new()?));
    
    // Setup metrics collection
    let mut metrics = HashMap::new();
    metrics.insert("issue".to_string(), OperationMetrics::new("issue"));
    metrics.insert("spend".to_string(), OperationMetrics::new("spend"));
    metrics.insert("combine".to_string(), OperationMetrics::new("combine"));
    metrics.insert("split".to_string(), OperationMetrics::new("split"));
    
    // Create a progress bar for the test duration
    let pb = ProgressBar::new(duration);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
            .unwrap()
            .progress_chars("##-")
    );
    pb.set_message("Running load test...");
    
    // Extract server URI from client config
    let config = load_config()?;
    let server_uri = config.server.uri;
    
    // Spawn virtual users
    let mut user_handles = Vec::with_capacity(users);
    for i in 0..users {
        let metrics_tx = metrics_tx.clone();
        let db_clone = db.clone();
        let running_clone = running.clone();
        let server_uri_clone = server_uri.clone();
        
        let handle = tokio::spawn(async move {
            let mut user = VirtualUser::new(
                i,
                server_uri_clone,
                db_clone,
                metrics_tx,
                bits,
                max_tokens,
                spend_percent,
                combine_percent,
                running_clone,
            );
            user.run().await;
        });
        
        user_handles.push(handle);
    }
    
    // Start the metrics collector
    let metrics_task = tokio::spawn({
        let mut metrics = metrics.clone();
        async move {
            while let Some((op, success, duration)) = metrics_rx.recv().await {
                let entry = metrics.entry(op.clone()).or_insert_with(|| OperationMetrics::new(&op));
                if success {
                    entry.record_success(duration);
                } else {
                    entry.record_failure();
                }
            }
            metrics
        }
    });
    
    // Run the test for the specified duration
    for _ in 0..duration {
        time::sleep(Duration::from_secs(1)).await;
        pb.inc(1);
    }
    
    // Signal the test is complete
    running.store(false, Ordering::Relaxed);
    pb.finish_with_message("Load test completed");
    
    // Wait a bit for operations to complete
    time::sleep(Duration::from_secs(2)).await;
    
    // Close the metrics channel and get the final metrics
    drop(metrics_tx);
    let final_metrics = metrics_task.await.unwrap_or(metrics);
    
    // Display results
    term.write_line("")?;
    term.write_line(&format!("{}", style("Load Test Results").bold()))?;
    term.write_line(&format!("{:-^50}", ""))?;
    
    // Calculate and display total metrics
    let mut total_ops = 0;
    let mut total_success = 0;
    let mut _total_failure = 0;
    let mut _total_duration = 0u128;
    
    for (op, metrics) in &final_metrics {
        let success = metrics.success_count;
        let failure = metrics.failure_count;
        let total = success + failure;
        let avg_ms = metrics.avg_duration_ms();
        let success_rate = if total > 0 {
            (success as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        
        total_ops += total;
        total_success += success;
        _total_failure += failure;
        _total_duration += metrics.total_duration_ms;
        
        // Skip operations with no metrics
        if total == 0 {
            continue;
        }
        
        term.write_line(&format!("Operation: {}", style(op).bold()))?;
        term.write_line(&format!("  Requests: {}", style(total).yellow()))?;
        term.write_line(&format!("  Success: {} ({:.1}%)", 
            style(success).green(), style(success_rate).green()))?;
        term.write_line(&format!("  Failures: {}", style(failure).red()))?;
        term.write_line(&format!("  Avg time: {:.1}ms", style(avg_ms).cyan()))?;
        if success > 0 {
            term.write_line(&format!("  Min/Max time: {}ms / {}ms",
                style(metrics.min_duration_ms).cyan(),
                style(metrics.max_duration_ms).cyan()))?;
        }
        term.write_line(&format!("{:-^50}", ""))?;
    }
    
    // Calculate overall metrics
    let ops_per_sec = total_ops as f64 / duration as f64;
    let overall_success_rate = if total_ops > 0 {
        (total_success as f64 / total_ops as f64) * 100.0
    } else {
        0.0
    };
    
    term.write_line(&format!("Total Operations: {}", style(total_ops).bold()))?;
    term.write_line(&format!("Operations/sec: {:.1}", style(ops_per_sec).green()))?;
    term.write_line(&format!("Overall Success Rate: {:.1}%", style(overall_success_rate).green()))?;
    term.write_line(&format!("{:-^50}", ""))?;
    
    // Generate CSV report if requested
    if report {
        match generate_report(&final_metrics) {
            Ok(path) => {
                term.write_line(&format!("{}", style(format!("Report saved to {}", path.display())).green()))?;
            },
            Err(e) => {
                term.write_line(&format!("{}", style(format!("Error generating report: {}", e)).red()))?;
            }
        }
    }
    
    Ok(())
}

fn generate_report(metrics: &HashMap<String, OperationMetrics>) -> std::io::Result<PathBuf> {
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let report_path = PathBuf::from(format!("load_test_report_{}.csv", timestamp));
    
    let mut file = File::create(&report_path)?;
    
    // Write header
    writeln!(file, "Operation,Requests,Success,Failures,Success Rate (%),Avg Time (ms),Min Time (ms),Max Time (ms)")?;
    
    // Write data for each operation
    for (_, metrics) in metrics {
        let total = metrics.success_count + metrics.failure_count;
        if total == 0 {
            continue;
        }
        
        let success_rate = (metrics.success_count as f64 / total as f64) * 100.0;
        
        writeln!(
            file,
            "{},{},{},{},{:.2},{:.2},{},{}",
            metrics.operation,
            total,
            metrics.success_count,
            metrics.failure_count,
            success_rate,
            metrics.avg_duration_ms(),
            if metrics.success_count > 0 { metrics.min_duration_ms } else { 0 },
            if metrics.success_count > 0 { metrics.max_duration_ms } else { 0 }
        )?;
    }
    
    Ok(report_path)
}


// Main function
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logger
    if std::env::var_os("RUST_LOG").is_none() {
        unsafe {
            std::env::set_var("RUST_LOG", "info");
        }
    }
    env_logger::init();
    
    // Handle all errors and provide user-friendly output
    if let Err(err) = run().await {
        let term = Term::stderr();
        term.write_line(&format!("{} {}", style("Error:").bold().red(), err))
            .expect("Failed to write to terminal");
        process::exit(1);
    }
    
    Ok(())
}

async fn run() -> Result<()> {
    // Load configuration
    let config = load_config()?;
    
    // Initialize the database
    let db = TokenDatabase::new()?;
    
    // Parse command line arguments
    let cli = Cli::parse();
    
    // Create client to interact with the server
    let mut client = Client::new(config.server.uri);
    
    // Execute the appropriate command
    match cli.command {
        Commands::LoadTest { users, duration, bits, max_tokens, spend_percent, combine_percent, split_percent, report } => {
            let term = Term::stdout();
            term.write_line(&format!("{}", style("Running Load Test").bold()))?;
            term.write_line(&format!("{:-^50}", ""))?;
            term.write_line(&format!("Users: {}", style(users).green()))?;
            term.write_line(&format!("Duration: {} seconds", style(duration).green()))?;
            term.write_line(&format!("PoW Bits: {}", style(bits).green()))?;
            term.write_line(&format!("Max Tokens Per User: {}", style(max_tokens).green()))?;
            term.write_line(&format!("Operation Mix: {}% spend, {}% combine, {}% split", 
                style(spend_percent).yellow(), style(combine_percent).yellow(), style(split_percent).yellow()))?;
            term.write_line(&format!("{:-^50}", ""))?;
            
            // Validate operation percentages
            if spend_percent + combine_percent + split_percent != 100 {
                term.write_line(&format!("{}", style("Error: Operation percentages must sum to 100").red()))?;
                return Err(ClientError::Interaction("Operation percentages must sum to 100".to_string()));
            }
            
            // Validate individual percentages are in range
            if spend_percent > 100 || combine_percent > 100 || split_percent > 100 {
                term.write_line(&format!("{}", style("Error: Each operation percentage must be between 0 and 100").red()))?;
                return Err(ClientError::Interaction("Invalid operation percentages".to_string()));
            }
            
            // Run the load test
            run_load_test(
                &mut client, 
                &db,
                users, 
                duration, 
                bits, 
                max_tokens, 
                spend_percent, 
                combine_percent, 
                split_percent, 
                report
            ).await?;
            
            Ok(())
        },
        Commands::Stats { detailed } => {
            let term = Term::stdout();
            term.write_line(&format!("{}", style("Retrieving database statistics...").bold()))?;
            
            // Create a progress spinner
            let spinner = ProgressBar::new_spinner();
            spinner.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} {msg}")
                    .unwrap()
            );
            spinner.set_message("Contacting server...");
            spinner.enable_steady_tick(std::time::Duration::from_millis(100));
            
            // Get the database counts
            match client.get_db_counts().await {
                Ok((nullifiers, pow_hashes)) => {
                    // Stop the spinner
                    spinner.finish_and_clear();
                    
                    term.write_line(&format!("{}", style("Database Statistics").bold()))?;
                    term.write_line(&format!("{:-^50}", ""))?;
                    
                    if detailed {
                        term.write_line(&format!("Nullifiers: {}", style(nullifiers).green()))?;
                        term.write_line(&format!("Proof-of-Work Hashes: {}", style(pow_hashes).green()))?;
                        term.write_line(&format!("{:-^50}", ""))?;
                        term.write_line(&format!("Total Entries: {}", style(nullifiers + pow_hashes).green().bold()))?;
                    } else {
                        term.write_line(&format!("Nullifiers: {}", style(nullifiers).green()))?;
                        term.write_line(&format!("Proof-of-Work Hashes: {}", style(pow_hashes).green()))?;
                        term.write_line(&format!("Total Entries: {}", style(nullifiers + pow_hashes).green().bold()))?;
                    }
                },
                Err(e) => {
                    // Stop the spinner
                    spinner.finish_and_clear();
                    term.write_line(&format!("{}", style(format!("Error retrieving database statistics: {}", e)).red()))?;
                }
            }
            
            Ok(())
        },
        Commands::Issue { bits } => {
            let term = Term::stdout();
            term.write_line(&format!("Issuing a new credit token with {} proof of work bits...", bits))?;
            term.write_line("This may take some time depending on the difficulty...")?;
            
            // Create a progress spinner
            let spinner = ProgressBar::new_spinner();
            spinner.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} {msg}")
                    .unwrap()
            );
            spinner.set_message("Generating proof of work and requesting token...");
            spinner.enable_steady_tick(std::time::Duration::from_millis(100));
            
            // Start timing the overall process
            let start_time = Instant::now();
            
            // Get the token and proof of work time
            let (token, pow_time) = client.issue_new_token(bits).await?;
            let id = db.store_token(&token)?;
            
            // Stop timing and calculate total elapsed time
            let total_elapsed = start_time.elapsed();
            
            // Stop the spinner and show success
            spinner.finish_and_clear();
            
            // Get the token value using our extension trait
            let value = token.get_value();
            
            term.write_line(&format!("{}", style("Successfully issued a new credit token!").green()))?;
            term.write_line(&format!("Token ID: {}", style(id).yellow()))?;
            term.write_line(&format!("Token Value: {}", style(value).green()))?;
            term.write_line(&format!("Proof of work time: {:.2?}", style(pow_time).cyan()))?;
            term.write_line(&format!("Total time: {:.2?}", style(total_elapsed).cyan()))?;
            
            Ok(())
        },
        
        Commands::Split { id, amounts } => {
            let term = Term::stdout();
            
            // Validate input
            if amounts.is_empty() {
                term.write_line(&format!("{}", style("Error: No amounts provided for splitting").red()))?;
                return Ok(());
            }
            
            // Get the token to split
            let token = db.get_token(id)?;
            
            // Calculate total amount
            let total_amount: u128 = amounts.iter().sum();
            
            // Get the token value using our extension trait
            let token_value = token.get_value();
            
            // Ensure the total amount matches the token's value
            if total_amount != token_value {
                term.write_line(&format!("{}", style(format!(
                    "Error: Total amount ({}) does not match token value ({})", 
                    total_amount, token_value
                )).red()))?;
                return Ok(());
            }
            
            // Display the token being split and the requested amounts
            term.write_line(&format!("{}", style(format!("Splitting token (ID: {}) with value {}", id, token_value)).bold()))?;
            term.write_line(&format!("{:-^50}", ""))?;
            term.write_line("Requested amounts:")?;
            
            for (i, amount) in amounts.iter().enumerate() {
                term.write_line(&format!("Token {}: {}", i+1, style(amount).green()))?;
            }
            
            term.write_line(&format!("{:-^50}", ""))?;
            term.write_line(&format!("Total: {}", style(total_amount).green().bold()))?;
            
            // Confirm the operation
            if !Confirm::new()
                .with_prompt(format!("Split this token into {} new tokens?", amounts.len()))
                .default(true)
                .interact()?
            {
                term.write_line("Operation cancelled.")?;
                return Ok(());
            }
            
            // Create a progress spinner
            let spinner = ProgressBar::new_spinner();
            spinner.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} {msg}")
                    .unwrap()
            );
            spinner.set_message("Splitting token...");
            spinner.enable_steady_tick(std::time::Duration::from_millis(100));
            
            // Perform the split operation
            let split_tokens = client.split_token(&token, amounts.clone()).await?;
            
            // Stop the spinner
            spinner.finish_and_clear();
            
            // Store the new tokens
            term.write_line(&format!("{}", style("Successfully split token!").green()))?;
            term.write_line("New tokens:")?;
            term.write_line(&format!("{:-^50}", ""))?;
            
            let mut new_ids = Vec::with_capacity(split_tokens.len());
            
            for (i, token) in split_tokens.iter().enumerate() {
                let new_id = db.store_token(token)?;
                new_ids.push(new_id);
                
                // Get the token value using our extension trait
                let value = token.get_value();
                
                term.write_line(&format!("Token {}: ID: {}, Value: {}", 
                    i+1, style(new_id).yellow(), style(value).green()))?;
            }
            
            term.write_line(&format!("{:-^50}", ""))?;
            
            // Delete the original token since it's been split and is no longer spendable
            term.write_line("Deleting the original token from the database...")?;
            match db.delete_token(id) {
                Ok(_) => {
                    term.write_line(&format!("Original token with ID {} deleted", style(id).yellow()))?;
                },
                Err(e) => {
                    term.write_line(&format!("{}", style(format!("Warning: Failed to delete original token with ID {}: {}", id, e)).yellow()))?;
                }
            }
            
            Ok(())
        },
        
        Commands::List { show_zero } => {
            let term = Term::stdout();
            let tokens = db.list_tokens()?;
            
            if tokens.is_empty() {
                term.write_line("No credit tokens found.")?;
                return Ok(());
            }
            
            // Filter out tokens with 0 value by default unless show_zero is true
            let filtered_tokens: Vec<(i64, CreditToken)> = if show_zero {
                tokens
            } else {
                tokens
                    .into_iter()
                    .filter(|(_, token)| token.get_value() > 0)
                    .collect()
            };
            
            if filtered_tokens.is_empty() {
                term.write_line("No tokens found matching your criteria.")?;
                return Ok(());
            }
            
            term.write_line(&format!("{}", style("Your credit tokens:").bold()))?;
            term.write_line(&format!("{:-^50}", ""))?;
            
            for (id, token) in filtered_tokens {
                // Get the token value using our extension trait
                let value = token.get_value();
                
                term.write_line(&format!("ID: {}", style(id).yellow()))?;
                term.write_line(&format!("Value: {}", style(value).green()))?;
                term.write_line(&format!("Created: {}", 
                    style(get_token_creation_time(id, &db.conn).unwrap_or_else(|| "Unknown".to_string()))
                ))?;
                term.write_line(&format!("{:-^50}", ""))?;
            }
            
            Ok(())
        },
        
        Commands::Spend { id, amount } => {
            let term = Term::stdout();
            let token = db.get_token(id)?;
            
            // Get the current token value using our extension trait
            let current_value = token.get_value();
            
            if amount > current_value {
                term.write_line(&format!("{}", style(format!("Error: Cannot spend {}. Token only has {} credits.", 
                    amount, current_value)).red()))?;
                return Ok(());
            }
            
            // Confirm the spend
            if !Confirm::new()
                .with_prompt(format!("Spend {} credits from token {}?", amount, id))
                .default(true)
                .interact()?
            {
                term.write_line("Operation cancelled.")?;
                return Ok(());
            }
            
            term.write_line(&format!("Spending {} credits from token {}...", amount, id))?;
            
            // Create a progress spinner
            let spinner = ProgressBar::new_spinner();
            spinner.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} {msg}")
                    .unwrap()
            );
            spinner.set_message("Processing spend transaction...");
            spinner.enable_steady_tick(std::time::Duration::from_millis(100));
            
            let new_token = client.spend(&token, amount).await?;
            db.update_token(id, &new_token)?;
            
            // Stop the spinner
            spinner.finish_and_clear();
            
            term.write_line(&format!("{}", style("Successfully spent credits!").green()))?;
            
            // Get the new token value using our extension trait
            let new_value = new_token.get_value();
            
            term.write_line(&format!("Remaining balance: {}", style(new_value).green()))?;
            
            Ok(())
        },
        
        Commands::Show { id } => {
            let term = Term::stdout();
            let token = db.get_token(id)?;
            
            // Get the token value using our extension trait
            let value = token.get_value();
            
            term.write_line(&format!("{}", style(format!("Credit Token (ID: {})", id)).bold()))?;
            term.write_line(&format!("{:-^50}", ""))?;
            term.write_line(&format!("Value: {}", style(value).green()))?;
            
            // Get creation time
            if let Some(created_time) = get_token_creation_time(id, &db.conn) {
                term.write_line(&format!("Created: {}", style(created_time).cyan()))?;
            }
            
            // Serialize token to bytes for hex representation
            let encoded = bincode::serde::encode_to_vec(&token, bincode::config::standard())?;
            term.write_line("Hex representation:")?;
            
            // Format hex in chunks for better readability
            let hex_str = hex::encode(&encoded);
            for chunk in hex_str.as_bytes().chunks(64) {
                if let Ok(s) = std::str::from_utf8(chunk) {
                    term.write_line(s)?;
                }
            }
            
            Ok(())
        },
        
        Commands::Export { id, file, forget } => {
            let term = Term::stdout();
            let token = db.get_token(id)?;
            
            // Get the token value using our extension trait
            let value = token.get_value();
            
            term.write_line(&format!("{}", style(format!("Exporting Credit Token (ID: {})", id)).bold()))?;
            term.write_line(&format!("Value: {}", style(value).green()))?;
            
            // Serialize token to bytes for hex representation
            let encoded = bincode::serde::encode_to_vec(&token, bincode::config::standard())?;
            let hex_str = hex::encode(&encoded);
            
            // Create the file and write the hex content
            let mut output_file = File::create(&file)?;
            output_file.write_all(hex_str.as_bytes())?;
            
            term.write_line(&format!("{}", style(format!("Token successfully exported to {}", file.display())).green()))?;
            
            // If forget flag is set, delete the token from the database
            if forget {
                // Additional warning if token has value
                if value > 0 {
                    term.write_line(&format!("{}", style(format!("Warning: This token has {} credits that will be forgotten.", value)).yellow()))?;
                }
                
                // Delete the token without confirmation (since user specified --forget flag)
                match db.delete_token(id) {
                    Ok(_) => {
                        term.write_line(&format!("{}", style(format!("Token with ID {} has been forgotten after export.", id)).green()))?;
                    },
                    Err(e) => {
                        term.write_line(&format!("{}", style(format!("Error: Failed to forget token with ID {}: {}", id, e)).red()))?;
                    }
                }
            }
            
            Ok(())
        },
        
        Commands::Import { file, anonymize } => {
            let term = Term::stdout();
            
            // Read the hex file
            let mut hex_content = String::new();
            File::open(&file)?.read_to_string(&mut hex_content)?;
            
            // Convert hex to bytes
            let bytes = match hex::decode(hex_content.trim()) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return Err(ClientError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Invalid hex content in file: {}", e)
                    )));
                }
            };
            
            // Decode the bytes to a token
            let (mut token, _): (CreditToken, _) = match bincode::serde::decode_from_slice(&bytes, bincode::config::standard()) {
                Ok(result) => result,
                Err(e) => {
                    return Err(ClientError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Failed to decode token data: {}", e)
                    )));
                }
            };
            
            // Get the token value
            let value = token.get_value();
            
            // If anonymize flag is set, spend 0 credits to get a new token
            if anonymize {
                term.write_line("Anonymizing token by spending 0 credits...")?;
                
                // Create a progress spinner
                let spinner = ProgressBar::new_spinner();
                spinner.set_style(
                    ProgressStyle::default_spinner()
                        .template("{spinner:.green} {msg}")
                        .unwrap()
                );
                spinner.set_message("Processing anonymization transaction...");
                spinner.enable_steady_tick(std::time::Duration::from_millis(100));
                
                token = client.spend(&token, 0).await?;
                
                // Stop the spinner
                spinner.finish_and_clear();
                term.write_line(&format!("{}", style("Token successfully anonymized!").green()))?;
            }
            
            // Store the token in the database
            let id = db.store_token(&token)?;
            
            term.write_line(&format!("{}", style("Successfully imported credit token!").green()))?;
            term.write_line(&format!("New Token ID: {}", style(id).yellow()))?;
            term.write_line(&format!("Token Value: {}", style(value).green()))?;
            
            Ok(())
        },
        
        Commands::Combine { ids } => {
            let term = Term::stdout();
            
            // Validate input
            if ids.is_empty() {
                term.write_line(&format!("{}", style("Error: No token IDs provided to combine").red()))?;
                return Ok(());
            }
            
            if ids.len() < 2 {
                term.write_line(&format!("{}", style("Error: At least two tokens are required for combining").red()))?;
                return Ok(());
            }
            
            // Display the tokens being combined
            term.write_line(&format!("{}", style("Tokens to combine:").bold()))?;
            term.write_line(&format!("{:-^50}", ""))?;
            
            let mut tokens = Vec::new();
            let mut total_value = 0u128;
            
            // Get all tokens and calculate total value
            for id in &ids {
                match db.get_token(*id) {
                    Ok(token) => {
                        let value = token.get_value();
                        total_value += value;
                        
                        term.write_line(&format!("ID: {}, Value: {}", 
                            style(*id).yellow(), style(value).green()))?;
                        
                        tokens.push(token);
                    },
                    Err(e) => {
                        term.write_line(&format!("{}", style(format!("Error: Could not find token with ID {}: {}", id, e)).red()))?;
                        return Ok(());
                    }
                }
            }
            
            term.write_line(&format!("{:-^50}", ""))?;
            term.write_line(&format!("Total value to combine: {}", style(total_value).green().bold()))?;
            
            // Confirm the operation
            if !Confirm::new()
                .with_prompt(format!("Combine these {} tokens into a new one?", tokens.len()))
                .default(true)
                .interact()?
            {
                term.write_line("Operation cancelled.")?;
                return Ok(());
            }
            
            // Create a progress spinner
            let spinner = ProgressBar::new_spinner();
            spinner.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} {msg}")
                    .unwrap()
            );
            spinner.set_message("Combining tokens...");
            spinner.enable_steady_tick(std::time::Duration::from_millis(100));
            
            // Create token references for the combine operation
            let token_refs: Vec<&CreditToken> = tokens.iter().collect();
            
            // Perform the combine operation
            let combined_token = client.combine_tokens(token_refs).await?;
            
            // Store the new token
            let new_id = db.store_token(&combined_token)?;
            
            // Stop the spinner
            spinner.finish_and_clear();
            
            // Get the combined token value using our extension trait
            let new_value = combined_token.get_value();
            
            term.write_line(&format!("{}", style("Successfully combined tokens!").green()))?;
            term.write_line(&format!("New token ID: {}", style(new_id).yellow()))?;
            term.write_line(&format!("Combined value: {}", style(new_value).green()))?;
            
            // Delete the old tokens since they've been combined and are no longer spendable
            term.write_line("Deleting the combined tokens from the database...")?;
            let mut all_deleted = true;
            for id in &ids {
                match db.delete_token(*id) {
                    Ok(_) => {
                        term.write_line(&format!("Token with ID {} deleted", style(*id).yellow()))?;
                    },
                    Err(e) => {
                        all_deleted = false;
                        term.write_line(&format!("{}", style(format!("Warning: Failed to delete token with ID {}: {}", id, e)).yellow()))?;
                    }
                }
            }
            
            if !all_deleted {
                term.write_line(&format!("{}", style("Warning: Some tokens could not be deleted. You may see invalid tokens in your list.").yellow()))?;
            }
            
            Ok(())
        },

        Commands::Forget { id } => {
            let term = Term::stdout();
            
            // First, retrieve the token to make sure it exists and show details to the user
            match db.get_token(id) {
                Ok(token) => {
                    // Get the token value using our extension trait
                    let value = token.get_value();
                    
                    term.write_line(&format!("{}", style(format!("Token to forget (ID: {})", id)).bold()))?;
                    term.write_line(&format!("{:-^50}", ""))?;
                    term.write_line(&format!("Value: {}", style(value).green()))?;
                    
                    // Get creation time
                    if let Some(created_time) = get_token_creation_time(id, &db.conn) {
                        term.write_line(&format!("Created: {}", style(created_time).cyan()))?;
                    }
                    term.write_line(&format!("{:-^50}", ""))?;
                    
                    // Confirm the operation, with more warnings if token has value
                    let warning_message = if value > 0 {
                        format!("Warning: This token has {} credits that will be permanently lost.", value)
                    } else {
                        "This token will be permanently removed from your database.".to_string()
                    };
                    
                    term.write_line(&format!("{}", style(warning_message).yellow()))?;
                    
                    if !Confirm::new()
                        .with_prompt(format!("Are you sure you want to forget token {}?", id))
                        .default(false) // Default to no for destructive operations
                        .interact()?
                    {
                        term.write_line("Operation cancelled.")?;
                        return Ok(());
                    }
                    
                    // Delete the token
                    match db.delete_token(id) {
                        Ok(_) => {
                            term.write_line(&format!("{}", style(format!("Token with ID {} has been forgotten.", id)).green()))?;
                        },
                        Err(e) => {
                            term.write_line(&format!("{}", style(format!("Error: Failed to forget token with ID {}: {}", id, e)).red()))?;
                        }
                    }
                },
                Err(e) => {
                    term.write_line(&format!("{}", style(format!("Error: Could not find token with ID {}: {}", id, e)).red()))?;
                }
            }
            
            Ok(())
        },
        
        Commands::CheckNullifier { id } => {
            let term = Term::stdout();
            
            // Get the token from the database
            match db.get_token(id) {
                Ok(token) => {
                    // Get the token value
                    let value = token.get_value();
                    
                    term.write_line(&format!("{}", style(format!("Checking token (ID: {})", id)).bold()))?;
                    term.write_line(&format!("{:-^50}", ""))?;
                    term.write_line(&format!("Value: {}", style(value).green()))?;
                    
                    // Get creation time
                    if let Some(created_time) = get_token_creation_time(id, &db.conn) {
                        term.write_line(&format!("Created: {}", style(created_time).cyan()))?;
                    }
                    term.write_line(&format!("{:-^50}", ""))?;
                    
                    // Create a progress spinner
                    let spinner = ProgressBar::new_spinner();
                    spinner.set_style(
                        ProgressStyle::default_spinner()
                            .template("{spinner:.green} {msg}")
                            .unwrap()
                    );
                    spinner.set_message("Checking nullifier status on server...");
                    spinner.enable_steady_tick(std::time::Duration::from_millis(100));
                    
                    // Get the token's nullifier
                    let nullifier = token.nullifier();
                    
                    // Check if the nullifier has been spent
                    // Convert Scalar nullifier to bytes for the API call
                    let nullifier_bytes: [u8; 32] = *nullifier.as_bytes();
                    match client.is_nullifier_spent(&nullifier_bytes).await {
                        Ok(is_spent) => {
                            // Stop the spinner
                            spinner.finish_and_clear();
                            
                            if is_spent {
                                term.write_line(&format!("{}", style("Token's nullifier has been spent.").yellow()))?;
                                term.write_line(&format!("{}", style("Warning: This token cannot be spent and may be invalid.").yellow()))?;
                            } else {
                                term.write_line(&format!("{}", style("Token's nullifier has not been spent.").green()))?;
                                term.write_line(&format!("{}", style("The token appears to be valid and can be spent.").green()))?;
                            }
                        },
                        Err(e) => {
                            // Stop the spinner
                            spinner.finish_and_clear();
                            term.write_line(&format!("{}", style(format!("Error checking nullifier status: {}", e)).red()))?;
                        }
                    }
                },
                Err(e) => {
                    term.write_line(&format!("{}", style(format!("Error: Could not find token with ID {}: {}", id, e)).red()))?;
                }
            }
            
            Ok(())
        },
    }
}
