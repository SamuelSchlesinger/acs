use acs::Client;
use acs::server;
use anonymous_credit_tokens::{u32_to_scalar, scalar_to_u32};
use std::thread;
use tokio::time::{sleep, Duration};
use log::info;

#[tokio::test]
async fn test_server_client_interaction() {
    // Initialize logger
    let _ = env_logger::try_init_from_env(env_logger::Env::default().default_filter_or("info"));
    
    // Start the server in a separate thread
    let server_handle = thread::spawn(|| {
        unsafe { std::env::set_var("RUST_LOG", "info"); }
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            server::run_server().await.expect("Server failed to start");
        });
    });
    
    // Give the server time to start up
    sleep(Duration::from_secs(2)).await;
    
    // Create a client
    let mut client = Client::new("https://localhost:8443".to_string());
    
    // Test 1: Get public key
    info!("Test 1: Getting server public key");
    let public_key = client.get_public_key().await.expect("Failed to get public key");
    
    // Test 2: Issue a new token
    info!("Test 2: Issuing a new token");
    let token = client.issue_new_token(5).await.expect("Failed to issue new token");
    assert!(scalar_to_u32(&token.credits()).unwrap() >= 2u32.pow(5));
    
    // Test 3: Spend some credits
    info!("Test 3: Spending credits");
    let initial_credits = scalar_to_u32(&token.credits()).unwrap();
    info!("Initial credits: {}", initial_credits);
    
    // Attempt to spend a small amount of credits, like 5
    let amount_to_spend = 5;
    assert!(amount_to_spend < initial_credits, "Not enough credits to spend");
    
    let new_token = client.spend(&token, amount_to_spend).await.expect("Failed to spend credits");
    let remaining_credits = scalar_to_u32(&new_token.credits()).unwrap();
    
    info!("Spent {} credits, remaining: {}", amount_to_spend, remaining_credits);
    assert_eq!(remaining_credits, initial_credits - amount_to_spend, 
        "Remaining credits should be initial minus spent amount");
    
    // We don't actually stop the server in this test as it would be running in the background
    // In a real scenario, we might want to add a shutdown endpoint or mechanism
    
    // Since we're not stopping the server, we'll just consider the test complete
    // The server thread will continue running until the process exits
    info!("Integration test completed successfully");
}

// Helper function to create a shutdown signal handler
// This is not used in this example but could be implemented for a cleaner shutdown
#[allow(dead_code)]
fn setup_shutdown_handler() -> tokio::sync::oneshot::Receiver<()> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    
    // Set up Ctrl+C handler
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        shutdown_tx.send(()).ok();
    });
    
    shutdown_rx
}
