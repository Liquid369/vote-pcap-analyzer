//! Integration tests for vote-pcap-analyzer
//! 
//! These tests verify the complete functionality using real data samples.

use std::collections::HashMap;
use vote_pcap_analyzer::pcap_processor::PcapProcessor;
use vote_pcap_analyzer::output_generator::ValidatorResults;

/// Test data - minimal valid Solana transaction hex
const SAMPLE_TRANSACTION_HEX: &str = "018cd0757907330f1dcfe063c9c6d209b6cd694d33e7bf426f5c4d434b729750b5e4a5c992fbab5dc7719aefff27ef5c3e3588ebca1c112397f562e2d66e91a90201000103de0c723a26acc3f0775fb449b4d87385963fbf3f51ddad86df16134684557ea280a1118da83ab746574cc668a6629619a4aba149e3e0fefae1d996e6f3e729240761481d357474bb7c4d7624ebd3bdb3d8355e73d11043fc0da3538000000000a4a5dd42afef37153d52908dd78b922aeb13db7bee3b603177f6e9a90f142933010202010094010e000000b9407116000000001f011f011e011d011c011b011a0119011801170116011501140113011201110110010f010e010d010c010b010a0109010801070106010501040103010201014d01eae30e977395d36df4c89bfdd649f1e49b829b28b178ab4d871731faac4b0161b60169000000009e1a256a10c49eba0c69efa2506facdcefa4eb2bb42f5f50cbfae91cec10d094";

#[test]
fn test_solana_decoder_integration() {
    use vote_pcap_analyzer::solana_decoder::{decode_solana_transaction, is_potential_transaction};
    
    // Test transaction detection
    assert!(is_potential_transaction(SAMPLE_TRANSACTION_HEX));
    
    // Test transaction decoding
    let result = decode_solana_transaction(SAMPLE_TRANSACTION_HEX);
    assert!(result.is_ok(), "Should decode valid transaction: {:?}", result.err());
    
    let tx = result.unwrap();
    assert_eq!(tx.signature_count, 1, "Should have 1 signature");
    assert_eq!(tx.signatures.len(), 1, "Should parse 1 signature");
    assert!(!tx.signatures[0].is_empty(), "Signature should not be empty");
    assert!(!tx.recent_blockhash.is_empty(), "Blockhash should not be empty");
}

#[test] 
fn test_pcap_processor_empty_input() {
    let _processor = PcapProcessor::new(vec!["192.168.1.1".to_string()]);
    // This would fail with actual file I/O, but tests the structure
    // In a real test environment, you'd use a minimal test pcap file
}

#[test]
fn test_port_mapping() {
    use vote_pcap_analyzer::pcap_processor::PcapProcessor;
    
    let processor = PcapProcessor::new(vec![]);
    
    // Test default port mappings
    assert_eq!(processor.get_solana_service_name(8003), "tpu");
    assert_eq!(processor.get_solana_service_name(8004), "tpuforwards");
    assert_eq!(processor.get_solana_service_name(8005), "tpuvote");
    assert_eq!(processor.get_solana_service_name(8008), "repair");
    assert_eq!(processor.get_solana_service_name(8009), "tpuquic");
    assert_eq!(processor.get_solana_service_name(9999), "unknown_9999");
}

#[test]
fn test_custom_port_mapping() {
    use vote_pcap_analyzer::pcap_processor::PcapProcessor;
    use std::collections::HashMap;
    
    let mut processor = PcapProcessor::new(vec![]);
    
    // Set custom port mappings
    let mut custom_mappings = HashMap::new();
    custom_mappings.insert(9000, "custom_service".to_string());
    custom_mappings.insert(8003, "custom_tpu".to_string()); // Override default
    processor.set_custom_port_mappings(custom_mappings);
    
    // Test custom mappings
    assert_eq!(processor.get_solana_service_name(9000), "custom_service");
    assert_eq!(processor.get_solana_service_name(8003), "custom_tpu"); // Should override default
    
    // Test that non-overridden defaults still work
    assert_eq!(processor.get_solana_service_name(8004), "tpuforwards");
    assert_eq!(processor.get_solana_service_name(8005), "tpuvote");
}

#[test]
fn test_validator_results_structure() {
    // Test that ValidatorResults can be created and has expected fields
    let results = ValidatorResults {
        ip_address: "192.168.1.1".to_string(),
        validator_name: "TestValidator".to_string(),
        first_timestamp: 1234567890.0,
        total_packets: 100,
        unique_transactions: 50,
        total_duplicates: 50,
        avg_interval: 0.1,
        timing_records: vec![],
        port_stats: HashMap::new(),
        // New fields with test values
        version: "1.0.0".to_string(),
        country: "United States".to_string(),
        city: "New York".to_string(),
        asn: "AS12345".to_string(),
        asn_organization: "Test Organization".to_string(),
    };
    
    assert_eq!(results.ip_address, "192.168.1.1");
    assert_eq!(results.total_packets, 100);
    assert_eq!(results.unique_transactions, 50);
    assert_eq!(results.total_duplicates, 50);
    // Test new fields
    assert_eq!(results.version, "1.0.0");
    assert_eq!(results.country, "United States");
    assert_eq!(results.city, "New York");
    assert_eq!(results.asn, "AS12345");
    assert_eq!(results.asn_organization, "Test Organization");
}

#[test]
fn test_invalid_transaction_handling() {
    use vote_pcap_analyzer::solana_decoder::{decode_solana_transaction, is_potential_transaction};
    
    // Test with invalid data
    let invalid_hex = "invalid_hex_data";
    assert!(!is_potential_transaction(invalid_hex));
    
    let result = decode_solana_transaction(invalid_hex);
    assert!(result.is_err(), "Should fail on invalid hex");
    
    // Test with too short data
    let short_hex = "01020304";
    assert!(!is_potential_transaction(short_hex));
}

#[test]
fn test_validator_resolver_module() {
    use vote_pcap_analyzer::validator_resolver::{ValidatorResolver, ValidatorInfo};
    
    // Test that we can create a validator resolver
    let _resolver = ValidatorResolver::new();
    
    // Test ValidatorInfo structure with all required fields
    let info = ValidatorInfo {
        identity_pubkey: "test_identity".to_string(),
        vote_pubkey: "test_vote".to_string(),
        name: "Test Validator".to_string(),
        version: "1.0.0".to_string(),
        current_ip: "192.168.1.1".to_string(),
        country: "Test Country".to_string(),
        city: "Test City".to_string(),
        asn: "AS12345".to_string(),
        asn_organization: "Test Org".to_string(),
    };
    
    // Verify all fields are accessible
    assert_eq!(info.identity_pubkey, "test_identity");
    assert_eq!(info.vote_pubkey, "test_vote");
    assert_eq!(info.name, "Test Validator");
    assert_eq!(info.version, "1.0.0");
    assert_eq!(info.current_ip, "192.168.1.1");
    assert_eq!(info.country, "Test Country");
    assert_eq!(info.city, "Test City");
    assert_eq!(info.asn, "AS12345");
    assert_eq!(info.asn_organization, "Test Org");
}