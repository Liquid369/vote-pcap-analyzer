// ============================================================================
// PCAP Network Processing Module
// ============================================================================
// PCAP file reading and packet parsing

use anyhow::{Result, Context};
use pcap::Capture;
use colored::*;
use pnet::packet::{
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    udp::UdpPacket,
    Packet,
};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct RawPacket {
    pub packet_number: u64,
    pub timestamp: f64,
    pub source_ip: String,
    pub dest_port: u16,
    pub protocol: String,
    pub solana_service: String,
    pub data_hex: String,
    pub data_suffix: String,
    pub payload_size: usize,
}

pub struct PcapProcessor {
    target_ips: Vec<String>,
    custom_port_mappings: HashMap<u16, String>,
}

impl PcapProcessor {
    pub fn new(target_ips: Vec<String>) -> Self {
        Self { 
            target_ips,
            custom_port_mappings: HashMap::new(),
        }
    }

    pub fn set_custom_port_mappings(&mut self, mappings: HashMap<u16, String>) {
        self.custom_port_mappings = mappings;
    }

    pub fn process_pcap<P: AsRef<Path>>(&self, pcap_path: P) -> Result<(HashMap<String, Vec<RawPacket>>, u64)> {
        let mut capture = Capture::from_file(pcap_path)
            .context("Failed to open pcap file")?;

        let mut results: HashMap<String, Vec<RawPacket>> = HashMap::new();
        let mut packet_number = 0u64;
        let mut matched_packets = 0u64;

        eprintln!("{}", "Processing pcap file...".dimmed());
        eprintln!("{}", format!("Looking for {} validators", self.target_ips.len()).dimmed());

        while let Ok(packet) = capture.next_packet() {
            packet_number += 1;
            
            if packet_number.is_multiple_of(50000) {
                eprintln!("{}", format!("Processed {} packets, found {} matching", packet_number, matched_packets).dimmed());
            }

            if let Some(raw_packet) = self.parse_packet(packet.header, packet.data, packet_number)? {
                if self.target_ips.contains(&raw_packet.source_ip) {
                    matched_packets += 1;
                    results
                        .entry(raw_packet.source_ip.clone())
                        .or_default()
                        .push(raw_packet);
                }
            }
        }

        Ok((results, packet_number))
    }

    fn parse_packet(&self, header: &pcap::PacketHeader, data: &[u8], packet_number: u64) -> Result<Option<RawPacket>> {
        // Linux SLL2 header is 20 bytes
        if data.len() < 20 {
            return Ok(None);
        }

        let ip_data = &data[20..];
        let ipv4 = match Ipv4Packet::new(ip_data) {
            Some(ip) => ip,
            None => return Ok(None),
        };
        
        if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
            return Ok(None);
        }

        let udp = match UdpPacket::new(ipv4.payload()) {
            Some(udp) => udp,
            None => return Ok(None),
        };
        
        let payload = udp.payload();
        if payload.is_empty() {
            return Ok(None);
        }

        let source_ip = ipv4.get_source().to_string();
        let dest_port = udp.get_destination();
        let data_hex = hex::encode(payload);
        let data_suffix = if data_hex.len() >= 6 {
            data_hex[data_hex.len() - 6..].to_string()
        } else {
            data_hex.clone()
        };

        let protocol = Self::detect_protocol(payload, dest_port);
        let solana_service = self.get_solana_service_name(dest_port);
        let timestamp = header.ts.tv_sec as f64 + (header.ts.tv_usec as f64 / 1_000_000.0);

        Ok(Some(RawPacket {
            packet_number,
            timestamp,
            source_ip,
            dest_port,
            protocol,
            solana_service,
            data_hex,
            data_suffix,
            payload_size: payload.len(),
        }))
    }

    pub fn get_solana_service_name(&self, port: u16) -> String {
        // Check custom mappings first
        if let Some(custom_name) = self.custom_port_mappings.get(&port) {
            return custom_name.clone();
        }
        
        // Use predefined port mappings
        match port {
            8003 => "tpu".to_string(),
            8004 => "tpuforwards".to_string(),
            8005 => "tpuvote".to_string(), 
            8008 => "repair".to_string(),
            8009 => "tpuquic".to_string(),
            _ => format!("unknown_{}", port),
        }
    }

    fn detect_protocol(payload: &[u8], dest_port: u16) -> String {
        if dest_port == 8009 || Self::is_quic_packet(payload) {
            "QUIC".to_string()
        } else {
            "UDP".to_string()
        }
    }

    fn is_quic_packet(payload: &[u8]) -> bool {
        if payload.len() < 4 {
            return false;
        }
        
        let first_byte = payload[0];
        (first_byte & 0x80) != 0 || (first_byte & 0xC0) == 0x40
    }
    
    /// IP extraction for scanning
    pub fn extract_source_ip_optimized(data: &[u8]) -> Option<String> {
        if data.len() < 40 {
            return None;
        }
        
        // Test IPv4 header positions for Linux SLL2
        let positions = [20, 14, 16, 18, 22]; // Potential positions for IP header
        
        for &pos in &positions {
            if pos + 15 < data.len() && data[pos] == 0x45 {
                let src_bytes = &data[pos + 12..pos + 16];
                return Some(format!("{}.{}.{}.{}", src_bytes[0], src_bytes[1], src_bytes[2], src_bytes[3]));
            }
        }
        
        None
    }
    
    /// Test which IPs from the list are present in a PCAP file
    /// Scan for IP presence detection
    pub fn scan_for_ips<P: AsRef<Path>>(ips: &[String], pcap_path: P) -> Result<Vec<String>> {
        use std::collections::HashSet;
        
        let mut found_ips = HashSet::new();
        let target_ips: HashSet<String> = ips.iter().cloned().collect();
        
        println!("Scanning PCAP for target IPs: {:?}", ips);
        
        let mut cap = Capture::from_file(pcap_path)
            .context("Failed to open PCAP file for IP scanning")?;
        
        let mut packet_count = 0;
        let start_time = std::time::Instant::now();
        
        // Scan all packets
        while let Ok(packet) = cap.next_packet() {
            packet_count += 1;
            
            // IP extraction - check multiple potential locations
            if let Some(ip) = Self::extract_source_ip_optimized(&packet.data) {
                if target_ips.contains(&ip) {
                    found_ips.insert(ip);
                    // Continue scanning for completeness
                }
            }
            
            // Progress every 100K packets
            if packet_count % 100000 == 0 {
                let elapsed = start_time.elapsed();
                println!("   Processed {} packets in {:.2}s, found {} IPs", 
                         packet_count, elapsed.as_secs_f64(), found_ips.len());
            }
            
            // Early exit if ALL target IPs found
            if found_ips.len() == target_ips.len() {
                break;
            }
        }
        
        let elapsed = start_time.elapsed();
        let result: Vec<String> = found_ips.into_iter().collect();
        println!("Scan complete: Found {} of {} IPs in {} packets ({:.2}s, {:.0} packets/sec)", 
                 result.len(), ips.len(), packet_count, elapsed.as_secs_f64(), 
                 packet_count as f64 / elapsed.as_secs_f64());
        
        Ok(result)
    }
}