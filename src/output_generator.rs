// ============================================================================
// Output Generation Module
// ============================================================================
// CSV and JSON file generation

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, create_dir_all};
use std::io::Write;
use std::path::{Path, PathBuf};
use chrono::{DateTime, Local};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingRecord {
    pub packet_number: u64,
    pub timestamp: f64,
    pub since_first: f64,
    pub since_prev: f64,
    pub dest_port: u16,
    pub solana_service: String,
    pub protocol: String,
    pub payload_size: usize,
    pub data_suffix: String,
    pub is_transaction: bool,
    pub signature_count: Option<u8>,
    pub signatures: Vec<String>,
    pub recent_blockhash: Option<String>,
    pub instruction_count: Option<u8>,
    pub vote_account: Option<String>,
    pub validator_identity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorResults {
    pub ip_address: String,
    pub validator_name: String,
    pub first_timestamp: f64,
    pub total_packets: usize,
    pub unique_transactions: usize,
    pub total_duplicates: usize,
    pub avg_interval: f64,
    pub timing_records: Vec<TimingRecord>,
    pub port_stats: HashMap<u16, PortStat>,
    // Additional validator fields
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default = "default_country")]
    pub country: String,
    #[serde(default = "default_city")]
    pub city: String,
    #[serde(default = "default_asn")]
    pub asn: String,
    #[serde(default = "default_asn_organization")]
    pub asn_organization: String,
}

// Fallback values
fn default_version() -> String { "unknown".to_string() }
fn default_country() -> String { "unknown".to_string() }
fn default_city() -> String { "unknown".to_string() }
fn default_asn() -> String { "unknown".to_string() }
fn default_asn_organization() -> String { "unknown".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortStat {
    pub port: u16,
    pub service_name: String,
    pub packet_count: u32,
    pub total_bytes: u64,
    pub avg_packet_size: f64,
}

pub struct OutputGenerator;

impl OutputGenerator {
    /// Creates organized directory structure and saves individual files per validator
    pub fn save_organized_output<P: AsRef<Path>>(
        results: &HashMap<String, ValidatorResults>, 
        validators: &HashMap<String, crate::ValidatorConfig>, 
        ip_to_identity: &HashMap<String, String>,
        output_dir: P
    ) -> Result<(String, Vec<String>)> {
        let output_dir = output_dir.as_ref();
        
        // Create timestamp folder
        let now: DateTime<Local> = Local::now();
        let timestamp_folder = now.format("%Y%m%d_%H%M%S").to_string();
        let session_dir = output_dir.join(&timestamp_folder);
        
        // Create subdirectories
        let csv_dir = session_dir.join("csv_files");
        let json_dir = session_dir.join("json_files");
        
        create_dir_all(&csv_dir)?;
        create_dir_all(&json_dir)?;
        
        let mut saved_files = Vec::new();
        
        // Save individual files per validator
        for (ip, analysis) in results {
            // Get the identity address for file naming using IP mapping first, then fallback to validator lookup
            let identity_address = ip_to_identity.get(ip)
                .cloned()
                .or_else(|| validators.get(ip).map(|config| config.identity_address.clone()))
                .unwrap_or_else(|| format!("Unknown_Identity_{}", ip));
            
            // Sanitize identity address for filename
            let safe_identity = identity_address
                .replace("/", "_")
                .replace("\\", "_")
                .replace(":", "_")
                .replace("*", "_")
                .replace("?", "_")
                .replace("\"", "_")
                .replace("<", "_")
                .replace(">", "_")
                .replace("|", "_");
            
            // Save individual CSV
            let csv_file = csv_dir.join(format!("{}.csv", safe_identity));
            Self::save_individual_csv(analysis, &csv_file)?;
            saved_files.push(format!("csv_files/{}.csv", safe_identity));
            
            // Save individual JSON
            let json_file = json_dir.join(format!("{}.json", safe_identity));
            Self::save_individual_json(analysis, &json_file)?;
            saved_files.push(format!("json_files/{}.json", safe_identity));
        }
        
        Ok((timestamp_folder, saved_files))
    }
    
    /// Save CSV for a single validator
    fn save_individual_csv(analysis: &ValidatorResults, output_path: &PathBuf) -> Result<()> {
        let mut writer = csv::Writer::from_path(output_path)?;
        
        writer.write_record([
            "ip_address", "validator_name", "packet_number", "timestamp",
            "since_first", "since_prev", "dest_port", "solana_service",
            "protocol", "payload_size", "data_suffix", 
            "is_transaction", "signature_count", "signatures", "recent_blockhash",
            "instruction_count", "vote_account", "validator_identity", "total_packets", "avg_interval",
            // New validator info fields
            "version", "country", "city", "asn", "asn_organization"
        ])?;

        for record in &analysis.timing_records {
            writer.write_record([
                &analysis.ip_address,
                &analysis.validator_name,
                &record.packet_number.to_string(),
                &record.timestamp.to_string(),
                &record.since_first.to_string(),
                &record.since_prev.to_string(),
                &record.dest_port.to_string(),
                &record.solana_service,
                &record.protocol,
                &record.payload_size.to_string(),
                &record.data_suffix,
                &record.is_transaction.to_string(),
                &record.signature_count.map_or("".to_string(), |c| c.to_string()),
                &record.signatures.join(";"),
                record.recent_blockhash.as_ref().unwrap_or(&"".to_string()),
                &record.instruction_count.map_or("".to_string(), |c| c.to_string()),
                record.vote_account.as_ref().unwrap_or(&"".to_string()),
                record.validator_identity.as_ref().unwrap_or(&"".to_string()),
                &analysis.total_packets.to_string(),
                &format!("{:.6}", analysis.avg_interval),
                // New validator info fields
                &analysis.version,
                &analysis.country,
                &analysis.city,
                &analysis.asn,
                &analysis.asn_organization,
            ])?;
        }

        writer.flush()?;
        Ok(())
    }
    
    /// Save JSON for a single validator
    fn save_individual_json(analysis: &ValidatorResults, output_path: &PathBuf) -> Result<()> {
        let json = serde_json::to_string_pretty(analysis)?;
        let mut file = File::create(output_path)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    pub fn save_csv<P: AsRef<Path>>(results: &HashMap<String, ValidatorResults>, output_path: P) -> Result<()> {
        let mut writer = csv::Writer::from_path(output_path)?;
        
        writer.write_record([
            "ip_address", "validator_name", "packet_number", "timestamp",
            "since_first", "since_prev", "dest_port", "solana_service",
            "protocol", "payload_size", "data_suffix", 
            "is_transaction", "signature_count", "signatures", "recent_blockhash",
            "instruction_count", "vote_account", "validator_identity", "total_packets", "avg_interval",
            // New validator info fields
            "version", "country", "city", "asn", "asn_organization"
        ])?;

        for (ip, analysis) in results {
            for record in &analysis.timing_records {
                writer.write_record([
                    ip,
                    &analysis.validator_name,
                    &record.packet_number.to_string(),
                    &record.timestamp.to_string(),
                    &format!("{:.6}", record.since_first),
                    &format!("{:.6}", record.since_prev),
                    &record.dest_port.to_string(),
                    &record.solana_service,
                    &record.protocol,
                    &record.payload_size.to_string(),
                    &record.data_suffix,
                    &record.is_transaction.to_string(),
                    &record.signature_count.map(|c| c.to_string()).unwrap_or_default(),
                    &record.signatures.join(";"),
                    record.recent_blockhash.as_deref().unwrap_or(""),
                    &record.instruction_count.map(|c| c.to_string()).unwrap_or_default(),
                    record.vote_account.as_deref().unwrap_or(""),
                    record.validator_identity.as_deref().unwrap_or(""),
                    &analysis.total_packets.to_string(),
                    &format!("{:.6}", analysis.avg_interval),
                    // New validator info fields
                    &analysis.version,
                    &analysis.country,
                    &analysis.city,
                    &analysis.asn,
                    &analysis.asn_organization,
                ])?;
            }
        }

        writer.flush()?;
        Ok(())
    }

    pub fn save_json<P: AsRef<Path>>(results: &HashMap<String, ValidatorResults>, output_path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(results)?;
        let mut file = File::create(output_path)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    pub fn print_summary(results: &HashMap<String, ValidatorResults>) {
        println!("\n=== VALIDATOR PACKET ANALYSIS ===");
        println!("{:<20} {:<15} {:<8} {:<12} {:<15}", 
            "Validator", "IP", "Packets", "Avg Interval", "Duplicates");
        println!("{}", "-".repeat(75));

        for (ip, analysis) in results {
            let name_short = if analysis.validator_name.len() > 20 { 
                &analysis.validator_name[..17] 
            } else { 
                &analysis.validator_name 
            };
            
            println!("{:<20} {:<15} {:<8} {:<12.3} {:<6}/{:<6}", 
                name_short, ip, analysis.total_packets, analysis.avg_interval,
                analysis.total_duplicates, analysis.unique_transactions);
        }

        println!("\n=== PORT/SERVICE STATISTICS ===");
        for (ip, analysis) in results {
            println!("\n{} ({}):", analysis.validator_name, ip);
            
            let mut port_stats: Vec<_> = analysis.port_stats.values().collect();
            port_stats.sort_by_key(|s| s.port);
            
            for stats in port_stats {
                println!("  Port {}: {} - {} packets, {:.1} avg bytes", 
                    stats.port, stats.service_name, stats.packet_count, stats.avg_packet_size);
            }
        }
    }
}