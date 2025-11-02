// ============================================================================
// Vote PCAP Analyzer Library
// ============================================================================

pub mod console_display;
pub mod output_generator;
pub mod pcap_processor;
pub mod solana_decoder;
pub mod validator_analyzer;
pub mod validator_resolver;

// Re-export main types for testing
pub use validator_analyzer::ValidatorAnalyzer;

#[derive(Debug)]
pub struct ValidatorConfig {
    pub name: String,
    pub identity_address: String,
    pub version: String,
    pub country: String,
    pub city: String,
    pub asn: String,
    pub asn_organization: String,
}