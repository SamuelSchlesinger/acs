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
use log::{error, debug};

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
        amount: u32,
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
    
    /// Forget (delete) a credit token from local storage
    Forget {
        /// Token ID to forget
        #[arg(short, long)]
        id: i64,
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
            
            // Get the token
            let token = client.issue_new_token(bits).await?;
            let id = db.store_token(&token)?;
            
            // Stop the spinner and show success
            spinner.finish_and_clear();
            
            // Get the token value using our extension trait
            let value = token.get_value();
            
            term.write_line(&format!("{}", style("Successfully issued a new credit token!").green()))?;
            term.write_line(&format!("Token ID: {}", style(id).yellow()))?;
            term.write_line(&format!("Token Value: {}", style(value).green()))?;
            
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
            let mut total_value = 0;
            
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
            for id in &ids {
                match db.delete_token(*id) {
                    Ok(_) => {
                        term.write_line(&format!("Token with ID {} deleted", style(*id).yellow()))?;
                    },
                    Err(e) => {
                        term.write_line(&format!("{}", style(format!("Warning: Failed to delete token with ID {}: {}", id, e)).yellow()))?;
                    }
                }
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
    }
}
