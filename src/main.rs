// ============================================================================
// Main Application Entry Point
// ============================================================================

use anyhow::Result;
use clap::{Arg, Command};
use colored::*;
use std::collections::{HashMap, HashSet};

use vote_pcap_analyzer::output_generator::OutputGenerator;
use vote_pcap_analyzer::console_display::ConsoleDisplay;
use vote_pcap_analyzer::validator_analyzer::ValidatorAnalyzer;
use vote_pcap_analyzer::validator_resolver::ValidatorResolver;

pub fn main() -> Result<()> {
    // Use tokio to handle async operations
    tokio::runtime::Runtime::new()?.block_on(async_main())
}

pub async fn async_main() -> Result<()> {
    let matches = Command::new("Validator Analyzer")
        .version("0.1.0")
        .about("Analyzes Solana validator behavior from pcap files")
        .arg(Arg::new("pcap")
            .short('f').long("pcap").value_name("FILE")
            .help("Path to pcap file").required(true))
        .arg(Arg::new("ip")
            .short('i').long("ip").value_name("IP")
            .help("Target IP address(es) to analyze")
            .action(clap::ArgAction::Append))
        .arg(Arg::new("identity")
            .long("identity").value_name("IDENTITY_OR_FILE")
            .help("Validator identity address(es) to analyze (single, comma-separated, or file path)")
            .action(clap::ArgAction::Append))
        .arg(Arg::new("output-dir")
            .short('o').long("output-dir").value_name("DIR")
            .help("Path to directory where CSV and JSON files will be saved").default_value("output"))
        .arg(Arg::new("simple")
            .short('s').long("simple")
            .help("Show simple table output instead of detailed analysis")
            .action(clap::ArgAction::SetTrue))
        .arg(Arg::new("port-map")
            .short('p').long("port-map").value_name("PORT:NAME")
            .help("Custom port mappings (format: PORT:NAME, can be used multiple times)")
            .action(clap::ArgAction::Append))
        .get_matches();

    let pcap_file = matches.get_one::<String>("pcap").unwrap();
    let output_dir = matches.get_one::<String>("output-dir").unwrap();
    let simple_display = matches.get_flag("simple");

    // Use detailed output unless table format is requested
    let show_detailed = !simple_display;

    // Parse custom port mappings
    let mut custom_port_mappings = HashMap::new();
    if let Some(port_maps) = matches.get_many::<String>("port-map") {
        for mapping in port_maps {
            if let Some((port_str, name)) = mapping.split_once(':') {
                match port_str.parse::<u16>() {
                    Ok(port) => {
                        custom_port_mappings.insert(port, name.to_string());
                        println!("Custom port mapping: {} -> {}", port, name);
                    }
                    Err(_) => {
                        eprintln!("Warning: Invalid port number '{}' in mapping '{}'", port_str, mapping);
                    }
                }
            } else {
                eprintln!("Warning: Invalid port mapping format '{}'. Expected 'PORT:NAME'", mapping);
            }
        }
    }

    let mut analyzer = ValidatorAnalyzer::new();
    analyzer.set_custom_port_mappings(custom_port_mappings);

    // Load validators from identity list file
    if let Some(identity_file) = matches.get_one::<String>("identity-list") {
        println!("Loading validators from identity file: {}", identity_file);
        analyzer.load_validators_from_identity_file(identity_file).await?;
    }

    // Load validators from unified identity input (file, single, or comma-separated)
    if let Some(identities) = matches.get_many::<String>("identity") {
        for identity_input in identities {
            // Path detection: file path vs identity value(s)
            if identity_input.contains('/') || identity_input.contains('\\') || identity_input.ends_with(".txt") {
                // Treat as file path
                println!("Loading validators from identity file: {}", identity_input);
                analyzer.load_validators_from_identity_file(identity_input).await?;
            } else {
                // Treat as identity value(s) - could be single or comma-separated
                for identity in identity_input.split(',') {
                    let identity = identity.trim();
                    if !identity.is_empty() {
                        println!("Resolving validator identity: {}", identity);
                        // Use current IP resolution (no historical lookup)
                        analyzer.load_validator_from_identity_string(identity).await?;
                    }
                }
            }
        }
    }

    // Load validators from IP addresses
    if let Some(ips) = matches.get_many::<String>("ip") {
        for ip_str in ips {
            for ip in ip_str.split(',') {
                let ip = ip.trim();
                if !ip.is_empty() {
                    analyzer.add_validator_simple(ip.to_string(), None, None);
                }
            }
        }
    }

    if analyzer.get_validator_count() == 0 {
        eprintln!("No target IPs specified. Use --ip or --identity options.");
        std::process::exit(1);
    }

    println!("Analyzing {} validators", analyzer.get_validator_count());
    for ip in analyzer.get_target_ips() {
        if let Some(config_name) = analyzer.get_validator_name(ip) {
            println!("  - {} ({})", config_name, ip);
        }
    }

    let (mut results, total_processed) = analyzer.process_pcap(pcap_file)?;
    
    // Track historical IP mappings for filename resolution
    let mut historical_ip_mappings: HashMap<String, String> = HashMap::new();
    
    // Fallback: If any identity-based validators returned zero packets, try historical IP lookup
    if let Some(identities) = matches.get_many::<String>("identity") {
        // Check which validators have zero packets
        let target_ips = analyzer.get_target_ips();
        let mut zero_packet_validators = Vec::new();
        
        for ip in target_ips.iter() {
            if !results.contains_key(ip) {
                // This IP has zero packets - need to identify which validator it belongs to
                if let Some(validator_name) = analyzer.get_validator_name(ip) {
                    zero_packet_validators.push((ip.clone(), validator_name));
                }
            }
        }
        
        if !zero_packet_validators.is_empty() {
            println!("\n{} {} validators with zero packets found. Trying historical IP lookup...", 
                     "[INFO]".blue().bold(), zero_packet_validators.len());
            
            for (ip, name) in &zero_packet_validators {
                println!("  - {} ({}) - zero packets", name, ip);
            }
            
            // Initialize retry analyzer with historical lookup for zero-packet identities
            let mut retry_analyzer = ValidatorAnalyzer::new();
            retry_analyzer.set_custom_port_mappings(analyzer.get_custom_port_mappings().clone());
            
            // Get the identity for each zero-packet validator by checking the ValidatorConfig
            let zero_packet_ips: HashSet<String> = zero_packet_validators.iter().map(|(ip, _)| ip.clone()).collect();
            
            // Single resolver instance to avoid duplicate API calls
            let resolver = ValidatorResolver::new();
            
            // Collect all identities that need historical lookup (avoiding duplicates)
            let mut identities_to_retry = HashSet::new();
            
            for identity_input in identities {
                if identity_input.contains('/') || identity_input.contains('\\') || identity_input.ends_with(".txt") {
                    // Handle identity file
                    println!("Reading identity file for historical lookup: {}", identity_input);
                    let content = std::fs::read_to_string(identity_input)?;
                    
                    for line in content.lines() {
                        let identity = line.trim();
                        if identity.starts_with('#') || identity.is_empty() {
                            continue;
                        }
                        identities_to_retry.insert(identity.to_string());
                    }
                } else {
                    // Handle direct identity strings
                    for identity in identity_input.split(',') {
                        let identity = identity.trim();
                        if !identity.is_empty() {
                            identities_to_retry.insert(identity.to_string());
                        }
                    }
                }
            }
            
            // Process each unique identity once
            for identity in identities_to_retry {
                // Check if this identity's current IP had zero packets
                if let Ok(validator_info) = resolver.get_validator_info(&identity).await {
                    if zero_packet_ips.contains(&validator_info.current_ip) {
                        println!("Historical lookup for: {}", identity);
                        if let Ok(()) = retry_analyzer.load_validator_from_identity_with_pcap(&identity, pcap_file).await {
                            // Capture historical IP mapping
                            for target_ip in retry_analyzer.get_target_ips() {
                                if target_ip != &validator_info.current_ip {
                                    // This is likely a historical IP
                                    historical_ip_mappings.insert(target_ip.clone(), identity.clone());
                                }
                            }
                        } else {
                            eprintln!("{} Historical lookup failed for {}", 
                                     "[WARN]".yellow().bold(), identity);
                        }
                    }
                }
            }
            
            if retry_analyzer.get_validator_count() > 0 {
                println!("Retrying PCAP processing with {} historical IPs...", retry_analyzer.get_validator_count());
                let (retry_results, _) = retry_analyzer.process_pcap(pcap_file)?;
                
                // Merge results: keep successful ones from original, add new ones from retry
                for (ip, analysis) in retry_results {
                    results.insert(ip, analysis);
                }
                
                // Create combined IP mapping from both analyzers before overwriting
                let main_mapping = analyzer.create_ip_to_identity_mapping(None);
                let retry_mapping = retry_analyzer.create_ip_to_identity_mapping(Some(&historical_ip_mappings));
                
                // Merge mappings - retry mapping takes precedence for overlaps
                historical_ip_mappings.clear();
                for (ip, identity) in main_mapping {
                    historical_ip_mappings.insert(ip, identity);
                }
                for (ip, identity) in retry_mapping {
                    historical_ip_mappings.insert(ip, identity);
                }
                
                // Use retry_analyzer for output generation when historical lookup was used
                analyzer = retry_analyzer;
            }
        }
    }
    
    if show_detailed {
        // Display analysis with timing details
        ConsoleDisplay::print_detailed_analysis_with_processed_count(&results, total_processed as u64);
    } else {
        // Display tabular summary output
        OutputGenerator::print_summary(&results);
    }
    
    // Save organized output files
    // Use pre-computed IP mapping if available
    let ip_to_identity_mapping = if historical_ip_mappings.is_empty() {
        analyzer.create_ip_to_identity_mapping(None)
    } else {
        historical_ip_mappings.clone()
    };
    let (timestamp_folder, saved_files) = OutputGenerator::save_organized_output(&results, analyzer.get_validators(), &ip_to_identity_mapping, output_dir)?;

    eprintln!("\nResults saved to organized directory structure:");
    eprintln!("  Session: {}/{}", output_dir, timestamp_folder);
    eprintln!("  Files saved:");
    for file_path in saved_files {
        eprintln!("    - {}", file_path);
    }
    
    Ok(())
}