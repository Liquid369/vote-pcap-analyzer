// ============================================================================
// Validator Resolver Module
// ============================================================================
// Validator identity to IP address resolution

use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const API_BASE_URL: &str = "https://bigbrother.art3mis.cloud/api";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub identity_pubkey: String,
    pub vote_pubkey: String,
    pub name: String,
    pub version: String,
    pub current_ip: String,
    pub country: String,
    pub city: String,
    pub asn: String,
    pub asn_organization: String,
}

#[derive(Debug, Clone)]
pub struct ResolvedValidator {
    pub info: ValidatorInfo,
    pub active_ips: Vec<String>,     // IPs found in PCAP
    pub all_possible_ips: Vec<String>, // All known IPs
    pub has_multiple_ips_alert: bool,  // Security alert flag
}

#[derive(Debug, Deserialize)]
struct ApiValidatorResponse {
    identity_pubkey: String,
    vote_pubkey: String,
    name: String,
    version: String,
    ip: String,
    geolocation: ApiGeolocation,
}

#[derive(Debug, Deserialize)]
struct ApiGeolocation {
    country: String,
    city: String,
    asn: String,
    asn_organization: String,
}

#[derive(Debug, Deserialize)]
struct ApiHistoryResponse {
    data: Vec<ApiHistoryEvent>,
}

#[derive(Debug, Deserialize)]
struct ApiHistoryEvent {
    event_type: String,
    old_value: Option<String>,
    new_value: Option<String>,
    #[allow(dead_code)]
    epoch: Option<u64>,  // Some events have epoch as integer
}

pub struct ValidatorResolver {
    client: reqwest::Client,
}

impl Default for ValidatorResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidatorResolver {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    /// Fetch current validator information from API
    pub async fn get_validator_info(&self, identity: &str) -> Result<ValidatorInfo> {
        let url = format!("{}/validators/{}", API_BASE_URL, identity);
        
        let response = self.client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("Failed to fetch validator info for {}", identity))?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "API request failed with status: {} for validator {}", 
                response.status(), 
                identity
            ));
        }

        let api_response: ApiValidatorResponse = response
            .json()
            .await
            .with_context(|| format!("Failed to parse validator response for {}", identity))?;

        Ok(ValidatorInfo {
            identity_pubkey: api_response.identity_pubkey,
            vote_pubkey: api_response.vote_pubkey,
            name: api_response.name,
            version: api_response.version,
            current_ip: api_response.ip,
            country: api_response.geolocation.country,
            city: api_response.geolocation.city,
            asn: api_response.geolocation.asn,
            asn_organization: api_response.geolocation.asn_organization,
        })
    }

    /// Fetch historical IP addresses from API
    pub async fn get_historical_ips(&self, identity: &str) -> Result<Vec<String>> {
        let url = format!("{}/history", API_BASE_URL);
        
        let response = self.client
            .get(&url)
            .query(&[("validator", identity), ("event_type", "ip_change")])
            .send()
            .await
            .with_context(|| format!("Failed to fetch history for {}", identity))?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "History API request failed with status: {} for validator {}", 
                response.status(), 
                identity
            ));
        }

        let api_response: ApiHistoryResponse = response
            .json()
            .await
            .with_context(|| format!("Failed to parse history response for {}", identity))?;

        // Extract unique IPs from IP change events
        let mut ips = HashSet::new();
        
        for event in api_response.data {
            if event.event_type == "ip_change" {
                if let Some(old_ip) = event.old_value {
                    ips.insert(old_ip);
                }
                if let Some(new_ip) = event.new_value {
                    ips.insert(new_ip);
                }
            }
        }

        Ok(ips.into_iter().collect())
    }

    /// Get all possible IP addresses for a validator (current + historical)
    pub async fn get_all_possible_ips(&self, identity: &str) -> Result<Vec<String>> {
        let validator_info = self.get_validator_info(identity).await?;
        let historical_ips = self.get_historical_ips(identity).await?;

        let mut all_ips = HashSet::new();
        all_ips.insert(validator_info.current_ip);
        
        for ip in historical_ips {
            all_ips.insert(ip);
        }

        Ok(all_ips.into_iter().collect())
    }

    /// Test which IPs from the list are present in a PCAP file
    /// Delegates to PcapProcessor for separation of concerns
    pub fn test_ips_in_pcap(&self, ips: &[String], pcap_path: &str) -> Result<Vec<String>> {
        use crate::pcap_processor::PcapProcessor;
        PcapProcessor::scan_for_ips(ips, pcap_path)
    }

    /// Complete resolution process for a validator identity
    pub async fn resolve_validator(&self, identity: &str, pcap_path: &str) -> Result<ResolvedValidator> {
        println!("Resolving validator: {}", identity);
        
        let validator_info = self.get_validator_info(identity).await
            .with_context(|| format!("Failed to resolve validator {}", identity))?;
        
        let all_possible_ips = self.get_all_possible_ips(identity).await
            .with_context(|| format!("Failed to get IPs for validator {}", identity))?;
        
        let active_ips = self.test_ips_in_pcap(&all_possible_ips, pcap_path)
            .with_context(|| format!("Failed to test IPs in PCAP for validator {}", identity))?;

        // Security check: Alert if multiple IPs found in PCAP
        let has_multiple_ips_alert = active_ips.len() > 1;
        
        if has_multiple_ips_alert {
            eprintln!("🚨 SECURITY ALERT: Validator {} has multiple IPs in PCAP: {:?}", 
                     identity, active_ips);
            eprintln!("🚨 This could indicate validator compromise or IP spoofing!");
        }

        Ok(ResolvedValidator {
            info: validator_info,
            active_ips,
            all_possible_ips,
            has_multiple_ips_alert,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_resolver_creation() {
        let _resolver = ValidatorResolver::new();
        // Verify resolver instantiation succeeds
    }

    #[test]
    fn test_validator_info_structure() {
        let info = ValidatorInfo {
            identity_pubkey: "test_identity".to_string(),
            vote_pubkey: "test_vote".to_string(),
            name: "Test Validator".to_string(),
            version: "1.0.0".to_string(),
            current_ip: "192.168.1.1".to_string(),
            country: "United States".to_string(),
            city: "New York".to_string(),
            asn: "AS12345".to_string(),
            asn_organization: "Test Organization".to_string(),
        };

        assert_eq!(info.name, "Test Validator");
        assert_eq!(info.current_ip, "192.168.1.1");
        assert_eq!(info.asn_organization, "Test Organization");
    }

    #[test]
    fn test_resolved_validator_structure() {
        let info = ValidatorInfo {
            identity_pubkey: "test".to_string(),
            vote_pubkey: "test".to_string(),
            name: "test".to_string(),
            version: "test".to_string(),
            current_ip: "192.168.1.1".to_string(),
            country: "test".to_string(),
            city: "test".to_string(),
            asn: "test".to_string(),
            asn_organization: "test".to_string(),
        };

        let resolved = ResolvedValidator {
            info,
            active_ips: vec!["192.168.1.1".to_string()],
            all_possible_ips: vec!["192.168.1.1".to_string(), "192.168.1.2".to_string()],
            has_multiple_ips_alert: false,
        };

        assert_eq!(resolved.active_ips.len(), 1);
        assert_eq!(resolved.all_possible_ips.len(), 2);
        assert!(!resolved.has_multiple_ips_alert);
    }
}