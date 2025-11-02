# Vote PCAP Analyzer

Analyzes Solana network traffic from PCAP dumps

## Overview

Reads PCAP files, identifies decodable transactions, decodes, and generates analysis reports

## Core Features

### Transaction Detection
- Binary packet classification (transaction/protocol communication)
- Compact-u16 variable-length integer decoding
- Signature and blockhash extraction
- Vote account and validator identity resolution

### Network Analysis
- Port-based service classification
- Timing interval analysis (duplicate detection, block intervals)
- Payload size distribution

### Output Generation
- CSV format with transaction and validator metadata
- JSON structured data export to support frontend applications
- Organized timestamp-based directory structure
- Console table with visual indicators

### Validator Resolution
- Identity address to IP mapping via API (bigbrother.art3mis.cloud)
- Historical IP change detection
- Multiple IP association handling

## PCAP Capture

To capture Solana validator traffic for analysis:

```bash
# Capture Solana consensus ports (replace <host_ip> with your server IP)
tcpdump -i any '(dst port 8003 or dst port 8004 or dst port 8005 or dst port 8008 or dst port 8009)' and 'not src host <host_ip>' -n -s 0 -w file.pcap
```

## Usage



```bash
# Basic analysis
vote-pcap-analyzer --pcap file.pcap --ip 192.168.1.100

# Single OR multiple identity input
vote-pcap-analyzer --pcap file.pcap --identity validator1,validator2

# File-based identity input ( list of identity )
vote-pcap-analyzer --pcap file.pcap --identity identities.txt

# Custom output directory ( default is ./output )
vote-pcap-analyzer --pcap file.pcap --ip 192.168.1.100 --output-dir results

# Simple table
vote-pcap-analyzer --pcap file.pcap --ip 192.168.1.100 --simple
```

### Default Port Mappings

By default, the analyzer recognizes these standard Solana ports:

- **8003**: `tpu` - Transaction Processing Unit
- **8004**: `tpuforwards` - TPU Forwards  
- **8005**: `tpuvote` - TPU Vote
- **8008**: `repair` - Repair Service
- **8009**: `tpuquic` - TPU QUIC

```bash
# Custom name to port mapping for better readability
vote-pcap-analyzer --pcap file.pcap --ip 192.168.1.100 --port-map 9000:custom_tpu --port-map 8003:custom_tpu_quic
```

## Output Structure

```
output/
  YYYYMMDD_HHMMSS/
    csv_files/
      Identity_IP.csv
    json_files/
      Identity_IP.json
```

### CSV Fields
- `packet_number`, `timestamp`, `since_first`, `since_prev`
- `dest_port`, `solana_service`, `protocol`, `payload_size`
- `data_suffix`, `is_transaction`
- `signature_count`, `signatures`, `recent_blockhash`
- `validator_identity`, `vote_account`

### JSON Structure
- Complete packet timing records with transaction metadata
- Decoded transaction signatures and blockhashes
- Port statistics and service classifications
- Validator information (name, version, location)

### Console Display
Transaction indicator column shows:
- `✓` Decodable transaction
- `✗` Protocol communication ( repair or other non-transaction packets )

## Technical Details

### Transaction Decoding
- Validates potential transaction structure via header analysis
- Attempts binary deserialization with error handling
- Caches decode results to avoid redundant processing
- Extracts compact-u16 encoded field counts

### Timing Analysis
- Duplicate interval: Time between identical transaction patterns
- Block interval: Time between different transaction types
- Gap detection: Identifies burst vs. isolated packets (100ms threshold)

## Build Requirements

- Rust 1.70+
- libpcap-dev (Linux) / WinPcap (Windows)
- System packet capture permissions

```bash
# Development build
cargo build

# Optimized release
cargo build --release

# Run tests
cargo test --all-targets
```
