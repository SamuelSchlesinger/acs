use acs::Client;
use acs::server;
use anonymous_credit_tokens::scalar_to_u128;
use std::thread;
use tokio::time::{sleep, Duration};
use log::info;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_server_client_interaction() {
    // Initialize logger
    let _ = env_logger::try_init_from_env(env_logger::Env::default().default_filter_or("info"));
    
    // Start the server in a separate thread - using a Builder for better control
    let _server_handle = thread::spawn(|| {
        unsafe { std::env::set_var("RUST_LOG", "info"); }
        
        // Use a Runtime builder with explicit thread settings
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
            
        rt.block_on(async {
            // Create a timeout for the server
            let timeout = tokio::time::timeout(
                Duration::from_secs(300), // 5 minute timeout
                server::run_server()
            );
            
            // Run the server with timeout
            match timeout.await {
                Ok(result) => {
                    result.expect("Server failed to start");
                },
                Err(_) => {
                    println!("Server timed out after 5 minutes");
                }
            }
        });
    });
    
    // Give the server time to start up
    sleep(Duration::from_secs(3)).await;
    
    // Create a client
    let mut client = Client::new("https://localhost:8443".to_string());
    
    // Test 1: Get public key
    info!("Test 1: Getting server public key");
    let _public_key = client.get_public_key().await.expect("Failed to get public key");
    
    // Test 2: Issue tokens for testing both spend and combine operations
    info!("Test 2: Issuing tokens");
    
    // Issue a token for spending test (using smaller values for testing)
    info!("Issuing a token for spending test");
    let (token_to_spend, pow_time) = client.issue_new_token(2).await.expect("Failed to issue token for spending");
    info!("Token generated in {:?}", pow_time);
    let token_to_spend_value = scalar_to_u128(&token_to_spend.credits()).unwrap();
    assert!(token_to_spend_value >= 2u128.pow(2));
    
    // Issue tokens specifically for combine test (using smaller values for testing)
    info!("Issuing tokens for combining test");
    let (combine_token1, _) = client.issue_new_token(1).await.expect("Failed to issue first token for combining");
    let (combine_token2, _) = client.issue_new_token(1).await.expect("Failed to issue second token for combining");
    
    // Issue token for split test (using smaller values for testing)
    info!("Issuing a token for split test");
    let (token_to_split, _) = client.issue_new_token(2).await.expect("Failed to issue token for splitting");
    
    // Store the values for verification
    let combine_token1_value = scalar_to_u128(&combine_token1.credits()).unwrap();
    let combine_token2_value = scalar_to_u128(&combine_token2.credits()).unwrap();
    let token_to_split_value = scalar_to_u128(&token_to_split.credits()).unwrap();
    
    info!("Spending test token value: {}", token_to_spend_value);
    info!("Combine tokens values: {} and {}", combine_token1_value, combine_token2_value);
    info!("Split test token value: {}", token_to_split_value);
    
    // Test 3: Spend some credits
    info!("Test 3: Spending credits");
    
    // Attempt to spend a small amount of credits, like 5
    let amount_to_spend = 5u128;
    assert!(amount_to_spend < token_to_spend_value, "Not enough credits to spend");
    
    let new_token = client.spend(&token_to_spend, amount_to_spend).await.expect("Failed to spend credits");
    let remaining_credits = scalar_to_u128(&new_token.credits()).unwrap();
    
    info!("Spent {} credits, remaining: {}", amount_to_spend, remaining_credits);
    assert_eq!(remaining_credits, token_to_spend_value - amount_to_spend, 
        "Remaining credits should be initial minus spent amount");
    
    // Test 4: Combine tokens - using the dedicated combine tokens, not the spent one
    info!("Test 4: Combining tokens");
    // Create a set of tokens to combine
    let tokens_to_combine = vec![&combine_token1, &combine_token2];
    
    // Expected total value after combining
    let expected_combined_value = combine_token1_value + combine_token2_value;
    info!("Expected combined value: {}", expected_combined_value);
    
    // Perform the combine operation
    let combined_token = client.combine_tokens(tokens_to_combine).await
        .expect("Failed to combine tokens");
    
    // Verify the combined token has the correct value
    let combined_value = scalar_to_u128(&combined_token.credits()).unwrap();
    info!("Actual combined value: {}", combined_value);
    
    assert_eq!(combined_value, expected_combined_value, 
        "Combined token value should equal the sum of the individual token values");
    
    // Verify that the original tokens can no longer be spent (their nullifiers have been used)
    info!("Verifying original tokens can no longer be spent");
    
    // Try to spend from the first combine token
    let spend_result = client.spend(&combine_token1, 1u128).await;
    assert!(spend_result.is_err(), "Should not be able to spend from a token that was combined");
    
    // Try to spend from the second combine token
    let spend_result = client.spend(&combine_token2, 1u128).await;
    assert!(spend_result.is_err(), "Should not be able to spend from a token that was combined");
    
    // Test 5: Split token
    info!("Test 5: Splitting token");
    
    // Define the amounts for each new token after splitting
    let split_amounts = vec![token_to_split_value / 3, token_to_split_value / 3, token_to_split_value - (2 * (token_to_split_value / 3))];
    let total_split_amount: u128 = split_amounts.iter().sum();
    
    // Verify that the total split amount equals the token value
    assert_eq!(total_split_amount, token_to_split_value, "Split amounts must sum to the token value");
    info!("Splitting token into amounts: {:?}", split_amounts);
    
    // Perform the split operation
    let split_tokens = client.split_token(&token_to_split, split_amounts.clone()).await
        .expect("Failed to split token");
    
    // Verify that we got the correct number of tokens
    assert_eq!(split_tokens.len(), split_amounts.len(), "Should get the same number of tokens as requested splits");
    
    // Verify each token has the correct amount
    for (i, token) in split_tokens.iter().enumerate() {
        let token_value = scalar_to_u128(&token.credits()).unwrap();
        info!("Split token {} value: {}", i, token_value);
        assert_eq!(token_value, split_amounts[i], "Split token value should match the requested amount");
    }
    
    // Verify that the original token can no longer be spent (its nullifier has been used)
    let spend_result = client.spend(&token_to_split, 1u128).await;
    assert!(spend_result.is_err(), "Should not be able to spend from a token that was split");
    
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