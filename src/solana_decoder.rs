// ============================================================================
// SOLANA TRANSACTION DECODER - SPEC-COMPLIANT VERSION
// ============================================================================
// Solana transaction binary parser with compact-u16 (shortvec) encoding support.
//
// Test data that confirms this works:
// Input hex: 015a42bc90098863d5fff98c93a4c7209636d370579efe37fc3b1b2c27d9cade4bd590141edb802689aabd8ea7a7ec93a00306f66b852e13050dc45b3eaf35d80101000103ecc712c52acfd48b8a3f01d66bb87391a512f821efa57be11f13a362246e7fe1285215d03459fac3afa0a552cf8cbb79e4aab18c044e6d0c721f03da2df9036a0761481d357474bb7c4d7624ebd3bdb3d8355e73d11043fc0da353800000000050e4fd8be098d333868c8456391569e6d9e302f9a1bd85836be6217621c098ef010202010094010e000000c7407116000000001f011f011e011d011c011b011a0119011801170116011501140113011201110110010f010e010d010c010b010a0109010801070106010501040103010201014c5cc7bcce0c91fdf5cb114c299bebe1d7e3edb40d1b58b1f2c10e8c31c0158d0166b6016900000000c31dff7d910b47d708fe0d5be0452f6922e0ee26a9e532b3c25c3fbb11b30538
// Expected output:
// - Signature: 2ofgAxDPBmtygFYRTsTVWhnB99KaU7KbNdNQmHsaCAJaBKeuF1bxWwphJCAUVtajYHgwu9yyuct8px9sorVpuBSY
// - Recent blockhash: 6Sn8trn8BMETbULe4FeDpPCo7KpEkp3kcnApLyLJfDSv
// - Vote account: 3iPuTgpWaaC6jYEY7kd993QBthGsQTK3yPCrNJyPMhCD
// - Validator identity: GwHH8ciFhR8vejWCqmg8FWZUCNtubPY2esALvy5tBvji (ART3MIS.CLOUD ☘️)
// ============================================================================

use std::error::Error;

/// Helper function to decode Solana's compact-u16 (shortvec) encoding
/// This is the variable-length integer format used by Solana
fn read_compact_u16(data: &[u8]) -> Result<(usize, usize), Box<dyn Error>> {
    let mut result = 0usize;
    let mut shift = 0;
    let mut consumed = 0;

    for byte in data {
        let b = *byte;
        result |= ((b & 0x7F) as usize) << shift;
        consumed += 1;
        if b & 0x80 == 0 {
            return Ok((result, consumed));
        }
        shift += 7;
        
        // Safety check to prevent infinite loops
        if consumed > 5 {
            return Err("Compact-u16 encoding too long".into());
        }
    }

    Err("Invalid compact-u16 encoding".into())
}

/// Decoded Solana transaction data
#[derive(Debug, Clone)]
pub struct SolanaTransaction {
    pub signature_count: u8,
    pub signatures: Vec<String>,
    #[allow(dead_code)]  // Used in tests and for vote_account/validator_identity extraction
    pub account_keys: Vec<String>,
    pub recent_blockhash: String,
    pub instruction_count: u8,
    pub vote_account: Option<String>,      // For vote transactions: account_keys[1]
    pub validator_identity: Option<String>, // For vote transactions: account_keys[0]
}

/// Main decoder function - replaces bash script pipeline
/// hex -> xxd -r -p -> base64 -> solana decode-transaction
pub fn decode_solana_transaction(hex_data: &str) -> Result<SolanaTransaction, Box<dyn Error>> {
    // Minimum size check: 1 byte sig count + 64 byte signature + 3 byte header + 1 byte account count + 32 byte account + 32 byte blockhash + 1 byte instruction count
    // = 1 + 64 + 3 + 1 + 32 + 32 + 1 = 134 bytes = 268 hex chars
    if hex_data.len() < 268 {
        return Err("Transaction too short".into());
    }

    let data = hex::decode(hex_data)?;
    let mut cursor = 0;

    // Parse signature count (compact-u16)
    if cursor >= data.len() {
        return Err("Data too short for signature count".into());
    }
    let (signature_count_usize, sig_count_len) = read_compact_u16(&data[cursor..])?;
    cursor += sig_count_len;
    
    // Convert to u8 for compatibility (most transactions have 1-10 signatures)
    let signature_count = signature_count_usize as u8;

    // Validate signature count (range 1-10 for standard transactions)
    if signature_count == 0 || signature_count > 10 {
        return Err("Invalid signature count".into());
    }

    // Parse signatures (64 bytes each)
    let mut signatures = Vec::new();
    for _ in 0..signature_count {
        if cursor + 64 > data.len() {
            return Err("Data too short for signatures".into());
        }
        let sig_bytes = &data[cursor..cursor + 64];
        let sig_base58 = bs58::encode(sig_bytes).into_string();
        signatures.push(sig_base58);
        cursor += 64;
    }

    // Parse message header (3 bytes)
    if cursor + 3 > data.len() {
        return Err("Data too short for message header".into());
    }
    let _num_required_signatures = data[cursor];
    let _num_readonly_signed_accounts = data[cursor + 1];
    let _num_readonly_unsigned_accounts = data[cursor + 2];
    cursor += 3;

    // Parse account count (compact-u16)
    if cursor >= data.len() {
        return Err("Data too short for account count".into());
    }
    let (account_count_usize, acc_count_len) = read_compact_u16(&data[cursor..])?;
    cursor += acc_count_len;
    
    // Convert to u8 for compatibility  
    let account_count = account_count_usize as u8;

    // Validate account count
    if account_count == 0 || account_count > 50 {
        return Err("Invalid account count".into());
    }

    // Parse account keys (32 bytes each)
    let mut account_keys = Vec::new();
    for _ in 0..account_count {
        if cursor + 32 > data.len() {
            return Err("Data too short for account keys".into());
        }
        let account_bytes = &data[cursor..cursor + 32];
        let account_base58 = bs58::encode(account_bytes).into_string();
        account_keys.push(account_base58);
        cursor += 32;
    }

    // Parse recent blockhash (32 bytes)
    if cursor + 32 > data.len() {
        return Err("Data too short for recent blockhash".into());
    }
    let blockhash_bytes = &data[cursor..cursor + 32];
    let recent_blockhash = bs58::encode(blockhash_bytes).into_string();
    cursor += 32;

    // Parse instruction count (compact-u16)
    if cursor >= data.len() {
        return Err("Data too short for instruction count".into());
    }
    let (instruction_count_usize, _ix_count_len) = read_compact_u16(&data[cursor..])?;
    let instruction_count = instruction_count_usize as u8;

    // Extract vote-specific data (for vote transactions)
    let vote_account = if account_keys.len() > 1 { Some(account_keys[1].clone()) } else { None };
    let validator_identity = if !account_keys.is_empty() { Some(account_keys[0].clone()) } else { None };

    Ok(SolanaTransaction {
        signature_count,
        signatures,
        account_keys,
        recent_blockhash,
        instruction_count,
        vote_account,
        validator_identity,
    })
}

/// Validate hex data for potential Solana transaction structure
pub fn is_potential_transaction(hex_data: &str) -> bool {
    // Must be at least minimum transaction size
    if hex_data.len() < 268 {
        return false;
    }
    
    // Check if first byte is valid signature count (1-10)
    if let Ok(data) = hex::decode(&hex_data[0..2]) {
        let sig_count = data[0];
        return sig_count > 0 && sig_count <= 10;
    }
    
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_transaction() {
        let hex_data = "015a42bc90098863d5fff98c93a4c7209636d370579efe37fc3b1b2c27d9cade4bd590141edb802689aabd8ea7a7ec93a00306f66b852e13050dc45b3eaf35d80101000103ecc712c52acfd48b8a3f01d66bb87391a512f821efa57be11f13a362246e7fe1285215d03459fac3afa0a552cf8cbb79e4aab18c044e6d0c721f03da2df9036a0761481d357474bb7c4d7624ebd3bdb3d8355e73d11043fc0da353800000000050e4fd8be098d333868c8456391569e6d9e302f9a1bd85836be6217621c098ef010202010094010e000000c7407116000000001f011f011e011d011c011b011a0119011801170116011501140113011201110110010f010e010d010c010b010a0109010801070106010501040103010201014c5cc7bcce0c91fdf5cb114c299bebe1d7e3edb40d1b58b1f2c10e8c31c0158d0166b6016900000000c31dff7d910b47d708fe0d5be0452f6922e0ee26a9e532b3c25c3fbb11b30538";
        
        let result = decode_solana_transaction(hex_data).unwrap();
        
        assert_eq!(result.signature_count, 1);
        assert_eq!(result.signatures[0], "2ofgAxDPBmtygFYRTsTVWhnB99KaU7KbNdNQmHsaCAJaBKeuF1bxWwphJCAUVtajYHgwu9yyuct8px9sorVpuBSY");
        assert_eq!(result.recent_blockhash, "6Sn8trn8BMETbULe4FeDpPCo7KpEkp3kcnApLyLJfDSv");
        assert_eq!(result.vote_account.unwrap(), "3iPuTgpWaaC6jYEY7kd993QBthGsQTK3yPCrNJyPMhCD");
        assert_eq!(result.validator_identity.unwrap(), "GwHH8ciFhR8vejWCqmg8FWZUCNtubPY2esALvy5tBvji");
    }

    #[test]
    fn test_complete_transaction_fields() {
        // Test with captured hex data from ART3MIS.CLOUD validator
        let hex_data = "015a42bc90098863d5fff98c93a4c7209636d370579efe37fc3b1b2c27d9cade4bd590141edb802689aabd8ea7a7ec93a00306f66b852e13050dc45b3eaf35d80101000103ecc712c52acfd48b8a3f01d66bb87391a512f821efa57be11f13a362246e7fe1285215d03459fac3afa0a552cf8cbb79e4aab18c044e6d0c721f03da2df9036a0761481d357474bb7c4d7624ebd3bdb3d8355e73d11043fc0da353800000000050e4fd8be098d333868c8456391569e6d9e302f9a1bd85836be6217621c098ef010202010094010e000000c7407116000000001f011f011e011d011c011b011a0119011801170116011501140113011201110110010f010e010d010c010b010a0109010801070106010501040103010201014c5cc7bcce0c91fdf5cb114c299bebe1d7e3edb40d1b58b1f2c10e8c31c0158d0166b6016900000000c31dff7d910b47d708fe0d5be0452f6922e0ee26a9e532b3c25c3fbb11b30538";
        
        let result = decode_solana_transaction(hex_data).unwrap();
        
        // Test signature count and signatures array
        assert_eq!(result.signature_count, 1, "Should have exactly 1 signature");
        assert_eq!(result.signatures.len(), 1, "Signatures array should have 1 element");
        assert_eq!(
            result.signatures[0], 
            "2ofgAxDPBmtygFYRTsTVWhnB99KaU7KbNdNQmHsaCAJaBKeuF1bxWwphJCAUVtajYHgwu9yyuct8px9sorVpuBSY",
            "Signature should match expected base58 value"
        );
        
        // Test accountKeys array (expected 3 accounts)
        assert_eq!(result.account_keys.len(), 3, "Should have exactly 3 account keys");
        assert_eq!(
            result.account_keys[0], 
            "GwHH8ciFhR8vejWCqmg8FWZUCNtubPY2esALvy5tBvji",
            "First account (ART3MIS.CLOUD validator identity) should match"
        );
        assert_eq!(
            result.account_keys[1], 
            "3iPuTgpWaaC6jYEY7kd993QBthGsQTK3yPCrNJyPMhCD",
            "Second account (ART3MIS.CLOUD vote account) should match"
        );
        assert_eq!(
            result.account_keys[2], 
            "Vote111111111111111111111111111111111111111",
            "Third account (vote program) should match"
        );
        
        // Test recentBlockhash
        assert_eq!(
            result.recent_blockhash, 
            "6Sn8trn8BMETbULe4FeDpPCo7KpEkp3kcnApLyLJfDSv",
            "Recent blockhash should match expected value"
        );
        
        // Test instruction count 
        assert_eq!(result.instruction_count, 1, "Should have exactly 1 instruction");
        
        // Test vote-specific extracted fields
        assert_eq!(
            result.validator_identity.as_ref().unwrap(), 
            "GwHH8ciFhR8vejWCqmg8FWZUCNtubPY2esALvy5tBvji",
            "ART3MIS.CLOUD validator identity should be first account"
        );
        assert_eq!(
            result.vote_account.as_ref().unwrap(), 
            "3iPuTgpWaaC6jYEY7kd993QBthGsQTK3yPCrNJyPMhCD",
            "ART3MIS.CLOUD vote account should be second account"
        );
        
        // Verify this matches the JSON structure:
        // "signatures": ["2ofgAxDPBmtygFYRTsTVWhnB99KaU7KbNdNQmHsaCAJaBKeuF1bxWwphJCAUVtajYHgwu9yyuct8px9sorVpuBSY"]
        // "accountKeys": ["GwHH8ciFhR8vejWCqmg8FWZUCNtubPY2esALvy5tBvji", "3iPuTgpWaaC6jYEY7kd993QBthGsQTK3yPCrNJyPMhCD", "Vote111111111111111111111111111111111111111"]
        // "recentBlockhash": "6Sn8trn8BMETbULe4FeDpPCo7KpEkp3kcnApLyLJfDSv"
        // "instructions": [{"programIdIndex": 2, "accounts": [1, 0], "data": "..."}] (count = 1)
        
        println!("✅ All fields match the expected JSON structure for ART3MIS.CLOUD!");
        println!("📋 Signatures: {:?}", result.signatures);
        println!("🔑 Account Keys: {:?}", result.account_keys);
        println!("🧱 Recent Blockhash: {}", result.recent_blockhash);
        println!("⚙️  Instructions: {}", result.instruction_count);
        println!("🗳️  Vote Account: {:?}", result.vote_account);
        println!("👤 Validator Identity: {:?}", result.validator_identity);
    }
}