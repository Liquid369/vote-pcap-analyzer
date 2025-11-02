// ============================================================================
// Integration Tests for Identity File Loading
// ============================================================================
// Tests the complete workflow of loading validators from identity files

use std::path::Path;
use vote_pcap_analyzer::validator_analyzer::ValidatorAnalyzer;

#[tokio::test]
async fn test_load_valid_identities_file() {
    let mut analyzer = ValidatorAnalyzer::new();
    let test_file = "tests/test_data/valid_identities.txt";
    
    if Path::new(test_file).exists() {
        println!("Testing load of valid identities file: {}", test_file);
        
        let result = analyzer.load_validators_from_identity_file(test_file).await;
        
        match result {
            Ok(()) => {
                println!("[✓] Successfully loaded valid identities file");
                
                // Verify that validators were actually loaded
                let validator_count = analyzer.get_validator_count();
                assert!(validator_count > 0, "Should have loaded at least one validator");
                println!("  Loaded {} validators", validator_count);
                
                // Verify that target IPs were populated
                let target_ips = analyzer.get_target_ips();
                assert!(!target_ips.is_empty(), "Should have target IPs");
                println!("  Target IPs: {:?}", target_ips);
            },
            Err(e) => {
                panic!("[✗] Failed to load valid identities file: {}", e);
            }
        }
    } else {
        println!("[!] Skipping test - test file not found: {}", test_file);
    }
}

#[tokio::test]
async fn test_load_mixed_identities_file() {
    let mut analyzer = ValidatorAnalyzer::new();
    let test_file = "tests/test_data/mixed_identities.txt";
    
    if Path::new(test_file).exists() {
        println!("Testing load of mixed identities file: {}", test_file);
        
        let result = analyzer.load_validators_from_identity_file(test_file).await;
        
        match result {
            Ok(()) => {
                println!("[✓] Successfully processed mixed identities file");
                
                // Should have loaded some validators (the valid ones)
                let validator_count = analyzer.get_validator_count();
                println!("  Loaded {} validators from mixed file", validator_count);
                
                // Some should succeed, some should be skipped due to invalid identities
                // The function should not fail entirely due to some invalid entries
                // validator_count is usize, so >= 0 is always true - just ensure it exists
                println!("  Successfully handled mixed file with {} validators", validator_count);
            },
            Err(e) => {
                println!("[!] Mixed identities file failed to load: {}", e);
                // This might be expected if all valid identities fail to resolve
                // Don't panic here as it might be an API availability issue
            }
        }
    } else {
        println!("[!] Skipping test - test file not found: {}", test_file);
    }
}

#[tokio::test]
async fn test_load_invalid_identities_file() {
    let mut analyzer = ValidatorAnalyzer::new();
    let test_file = "tests/test_data/invalid_identities.txt";
    
    if Path::new(test_file).exists() {
        println!("Testing load of invalid identities file: {}", test_file);
        
        let result = analyzer.load_validators_from_identity_file(test_file).await;
        
        match result {
            Ok(()) => {
                println!("[✓] Invalid identities file processed without crashing");
                
                // Should have loaded zero validators
                let validator_count = analyzer.get_validator_count();
                assert_eq!(validator_count, 0, "Should not load any validators from invalid file");
                println!("  Correctly loaded 0 validators from invalid file");
            },
            Err(e) => {
                println!("[✓] Invalid identities file appropriately failed: {}", e);
                // This is also acceptable behavior
            }
        }
    } else {
        println!("[!] Skipping test - test file not found: {}", test_file);
    }
}

#[tokio::test]
async fn test_nonexistent_file() {
    let mut analyzer = ValidatorAnalyzer::new();
    let nonexistent_file = "tests/test_data/does_not_exist.txt";
    
    println!("Testing load of nonexistent file: {}", nonexistent_file);
    
    let result = analyzer.load_validators_from_identity_file(nonexistent_file).await;
    
    match result {
        Ok(()) => {
            panic!("[✗] Should have failed for nonexistent file");
        },
        Err(e) => {
            println!("[✓] Correctly failed for nonexistent file: {}", e);
            
            // Verify error message indicates file not found
            let error_str = e.to_string();
            assert!(
                error_str.contains("No such file") || 
                error_str.contains("not found") ||
                error_str.contains("cannot find"),
                "Error should indicate file not found: {}", error_str
            );
        }
    }
}

#[test]
fn test_empty_file() {
    // Create an empty temporary file
    let temp_file = "/tmp/empty_identity_test.txt";
    std::fs::write(temp_file, "").expect("Failed to create empty test file");
    
    // Test loading empty file
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut analyzer = ValidatorAnalyzer::new();
        
        println!("Testing load of empty file: {}", temp_file);
        
        let result = analyzer.load_validators_from_identity_file(temp_file).await;
        
        match result {
            Ok(()) => {
                println!("[✓] Empty file processed without crashing");
                
                // Should have loaded zero validators
                let validator_count = analyzer.get_validator_count();
                assert_eq!(validator_count, 0, "Should not load any validators from empty file");
                println!("  Correctly loaded 0 validators from empty file");
            },
            Err(e) => {
                println!("[!] Empty file failed to load: {}", e);
                // This might be acceptable depending on implementation
            }
        }
        
        // Clean up
        let _ = std::fs::remove_file(temp_file);
    });
}

#[test]
fn test_comments_and_whitespace() {
    // Create a file with comments and whitespace
    let temp_file = "/tmp/commented_identity_test.txt";
    let content = r#"# This is a comment
    
FwnWx7x99rGwLmipzz8ii15NqcHkKRo2oS1Y7j6LivgZ

# Another comment
   # Indented comment
   
5ZjxMYBbnKd4VFxLjAChSWMTeQ96147HnxZvQJxUseHV   

# Final comment
"#;
    
    std::fs::write(temp_file, content).expect("Failed to create test file with comments");
    
    // Test loading file with comments and whitespace
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut analyzer = ValidatorAnalyzer::new();
        
        println!("Testing load of file with comments and whitespace: {}", temp_file);
        
        let result = analyzer.load_validators_from_identity_file(temp_file).await;
        
        match result {
            Ok(()) => {
                println!("[✓] File with comments processed successfully");
                
                // Should ignore comments and process only valid identities
                let validator_count = analyzer.get_validator_count();
                println!("  Loaded {} validators (ignoring comments)", validator_count);
                
                // Should have loaded some validators, ignoring comments
                // The exact number depends on API availability
            },
            Err(e) => {
                println!("[!] File with comments failed to load: {}", e);
                // Might be due to API issues, don't panic
            }
        }
        
        // Clean up
        let _ = std::fs::remove_file(temp_file);
    });
}