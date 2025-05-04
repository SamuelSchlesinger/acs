use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::tempdir;

// This test verifies that the CLI can be built and run with basic commands
#[test]
fn test_cli_build_and_help() {
    // Build the CLI
    let build_output = Command::new("cargo")
        .args(["build", "--bin", "acs-cli"])
        .output()
        .expect("Failed to execute cargo build");
        
    assert!(build_output.status.success(), 
        "Failed to build CLI: {}", 
        String::from_utf8_lossy(&build_output.stderr));
    
    // Test the help output
    let help_output = Command::new("cargo")
        .args(["run", "--bin", "acs-cli", "--", "--help"])
        .output()
        .expect("Failed to execute CLI with --help");
        
    assert!(help_output.status.success(), 
        "CLI failed with --help: {}", 
        String::from_utf8_lossy(&help_output.stderr));
        
    let help_text = String::from_utf8_lossy(&help_output.stdout);
    
    // Verify that our commands are listed in the help text
    assert!(help_text.contains("issue"), "Help should contain 'issue' command");
    assert!(help_text.contains("list"), "Help should contain 'list' command");
    assert!(help_text.contains("spend"), "Help should contain 'spend' command");
    assert!(help_text.contains("show"), "Help should contain 'show' command");
    assert!(help_text.contains("combine"), "Help should contain 'combine' command");
}

// Configuration file creation test removed as it required interactive input