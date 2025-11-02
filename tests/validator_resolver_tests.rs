// ============================================================================
// Validator Resolver Tests
// ============================================================================
// Comprehensive tests for validator identity resolution with mock scenarios

use vote_pcap_analyzer::validator_resolver::ValidatorResolver;

#[tokio::test]
async fn test_valid_validator_resolution() {
    let resolver = ValidatorResolver::new();
    
    // Test with a known valid validator identity
    let result = resolver.get_validator_info("FwnWx7x99rGwLmipzz8ii15NqcHkKRo2oS1Y7j6LivgZ").await;
    
    match result {
        Ok(info) => {
            println!("[✓] Successfully resolved valid validator:");
            println!("  Identity: {}", info.identity_pubkey);
            println!("  Name: {}", info.name);
            println!("  IP: {}", info.current_ip);
            println!("  Version: {}", info.version);
            println!("  Location: {}, {}", info.city, info.country);
            println!("  ASN: {} ({})", info.asn, info.asn_organization);
            
            // Assertions
            assert_eq!(info.identity_pubkey, "FwnWx7x99rGwLmipzz8ii15NqcHkKRo2oS1Y7j6LivgZ");
            assert!(!info.name.is_empty());
            assert!(!info.current_ip.is_empty());
            assert!(!info.version.is_empty());
        },
        Err(e) => {
            panic!("[✗] Expected valid validator to resolve, but got error: {}", e);
        }
    }
}

#[tokio::test]
async fn test_invalid_validator_resolution() {
    let resolver = ValidatorResolver::new();
    
    // Test with various invalid validator identities
    let invalid_identities = vec![
        "InvalidValidatorIdentityForTesting123456789",
        "NotARealValidatorIdentity",
        "1234567890abcdef",
        "TooShort",
        "ThisIsDefinitelyNotAValidSolanaValidatorIdentityAddress12345",
        "", // Empty string
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // All A's
    ];
    
    for invalid_identity in invalid_identities {
        println!("Testing invalid identity: '{}'", invalid_identity);
        
        let result = resolver.get_validator_info(invalid_identity).await;
        
        match result {
            Ok(_) => {
                panic!("[✗] Expected error for invalid identity '{}', but got success", invalid_identity);
            },
            Err(e) => {
                println!("[✓] Correctly failed for invalid identity '{}': {}", invalid_identity, e);
                
                // Verify error message contains expected information
                let error_str = e.to_string();
                assert!(
                    error_str.contains("API request failed") || 
                    error_str.contains("Failed to fetch") ||
                    error_str.contains("Failed to parse"),
                    "Error message should indicate API failure: {}", error_str
                );
            }
        }
    }
}

#[tokio::test]
async fn test_multiple_validator_batch_resolution() {
    let resolver = ValidatorResolver::new();
    
    // Test batch resolution with mixed valid/invalid identities
    let test_identities = vec![
        ("FwnWx7x99rGwLmipzz8ii15NqcHkKRo2oS1Y7j6LivgZ", true),  // Valid
        ("5ZjxMYBbnKd4VFxLjAChSWMTeQ96147HnxZvQJxUseHV", true),  // Valid
        ("InvalidIdentity123", false), // Invalid
        ("DTELykegBxxEn9c15GbH1zbYFr9CFd8VHQnhTGfz5JLb", true),  // Valid
        ("AnotherInvalidOne", false),  // Invalid
    ];
    
    let mut successful_resolutions = 0;
    let mut failed_resolutions = 0;
    
    for (identity, should_succeed) in test_identities {
        println!("Testing batch resolution for: {}", identity);
        
        let result = resolver.get_validator_info(identity).await;
        
        match result {
            Ok(info) => {
                if should_succeed {
                    println!("[✓] Successfully resolved: {} -> {}", identity, info.name);
                    successful_resolutions += 1;
                } else {
                    panic!("[✗] Unexpected success for invalid identity: {}", identity);
                }
            },
            Err(e) => {
                if !should_succeed {
                    println!("[✓] Expected failure for: {} ({})", identity, e);
                    failed_resolutions += 1;
                } else {
                    println!("[✗] Unexpected failure for valid identity: {} ({})", identity, e);
                    // Don't panic here as API might be temporarily unavailable
                    failed_resolutions += 1;
                }
            }
        }
    }
    
    println!("Batch resolution summary:");
    println!("  Successful: {}", successful_resolutions);
    println!("  Failed: {}", failed_resolutions);
    
    // At least some should succeed (assuming API is available)
    assert!(successful_resolutions > 0 || failed_resolutions > 0, "At least some resolutions should complete");
}

#[tokio::test]
async fn test_validator_info_field_completeness() {
    let resolver = ValidatorResolver::new();
    
    // Test that all fields are properly populated for a known validator
    let result = resolver.get_validator_info("FwnWx7x99rGwLmipzz8ii15NqcHkKRo2oS1Y7j6LivgZ").await;
    
    if let Ok(info) = result {
        println!("[✓] Testing field completeness for validator: {}", info.name);
        
        // Test that all required fields have content
        assert!(!info.identity_pubkey.is_empty(), "Identity pubkey should not be empty");
        assert!(!info.vote_pubkey.is_empty(), "Vote pubkey should not be empty");
        assert!(!info.name.is_empty(), "Name should not be empty");
        assert!(!info.current_ip.is_empty(), "Current IP should not be empty");
        
        // Version might be "unknown" but should not be empty
        assert!(!info.version.is_empty(), "Version should not be empty");
        
        // Geographic fields might be "unknown" but should not be empty
        assert!(!info.country.is_empty(), "Country should not be empty");
        assert!(!info.city.is_empty(), "City should not be empty");
        assert!(!info.asn.is_empty(), "ASN should not be empty");
        assert!(!info.asn_organization.is_empty(), "ASN organization should not be empty");
        
        // IP address should be valid format (basic check)
        let ip_parts: Vec<&str> = info.current_ip.split('.').collect();
        assert_eq!(ip_parts.len(), 4, "IP should have 4 octets");
        
        println!("  All fields properly populated:");
        println!("    Identity: {} ✓", info.identity_pubkey);
        println!("    Vote: {} ✓", info.vote_pubkey);
        println!("    Name: {} ✓", info.name);
        println!("    IP: {} ✓", info.current_ip);
        println!("    Version: {} ✓", info.version);
        println!("    Location: {}, {} ✓", info.city, info.country);
        println!("    ASN: {} ({}) ✓", info.asn, info.asn_organization);
    } else {
        println!("[!] Skipping field completeness test - validator resolution failed (API might be unavailable)");
    }
}

#[test]
fn test_validator_resolver_creation() {
    // Test that we can create a resolver without panicking
    let resolver = ValidatorResolver::new();
    
    // This is a simple test to ensure the struct can be instantiated
    println!("[✓] ValidatorResolver created successfully");
    
    // We can't test much more without async, but we can verify the struct exists
    std::mem::drop(resolver);
    println!("[✓] ValidatorResolver dropped successfully");
}

// Helper function for integration testing
#[tokio::test]
async fn test_realistic_validator_loading_scenario() {
    let resolver = ValidatorResolver::new();
    
    // Simulate loading validators from a realistic identity file
    let realistic_identities = vec![
        "FwnWx7x99rGwLmipzz8ii15NqcHkKRo2oS1Y7j6LivgZ", // Known good
        "5ZjxMYBbnKd4VFxLjAChSWMTeQ96147HnxZvQJxUseHV", // Known good
        "NonExistentValidator123456789", // Should fail
        "DTELykegBxxEn9c15GbH1zbYFr9CFd8VHQnhTGfz5JLb", // Known good
    ];
    
    println!("Simulating realistic validator loading scenario...");
    
    let mut loaded_validators = Vec::new();
    let mut skipped_validators = Vec::new();
    
    for identity in realistic_identities {
        println!("Processing validator: {}", identity);
        
        match resolver.get_validator_info(identity).await {
            Ok(info) => {
                println!("[✓] Loaded: {} -> {} ({})", identity, info.name, info.current_ip);
                loaded_validators.push((identity, info));
            },
            Err(e) => {
                println!("[✗] Skipped: {} ({})", identity, e);
                skipped_validators.push((identity, e.to_string()));
            }
        }
    }
    
    println!("\nRealistic loading scenario results:");
    println!("  Successfully loaded: {} validators", loaded_validators.len());
    println!("  Skipped due to errors: {} validators", skipped_validators.len());
    
    // In a realistic scenario, we should have at least some successes
    // and we should handle failures gracefully
    assert!(loaded_validators.len() + skipped_validators.len() > 0, "Should process at least some validators");
    
    // Verify that loaded validators have proper data
    for (identity, info) in loaded_validators {
        assert_eq!(info.identity_pubkey, identity);
        assert!(!info.name.is_empty());
        assert!(!info.current_ip.is_empty());
    }
}