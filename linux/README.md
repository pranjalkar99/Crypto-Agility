# TLS Packet Analyzer - Quantum Vulnerability Detection Tool

## Overview
Real-time TLS packet capture and analysis tool for detecting quantum-vulnerable cryptographic algorithms in network communications.

## Key Features
- Real-time/offline TLS traffic capture and analysis
- Post-Quantum Cryptography (PQC) algorithm detection
- ML-KEM (Kyber), Falcon, SPHINCS+, ML-DSA support
- TLS 1.0-1.3 protocol quantum vulnerability assessment
- SNI filtering for specific domain analysis
- X.509 certificate inspection and expiry analysis
- Automated CSV report generation (Excel compatible)
- Multi-interface support

## Security Assessment Criteria

### TLS Version Security Levels
- High (H): TLS 1.3 - Enhanced security, mandatory Forward Secrecy
- Medium (M): TLS 1.2 - Safe when properly configured
- Low (L): TLS <=1.1 - Vulnerable to quantum/classical attacks

### Cryptographic Algorithm Classification
- Quantum Resistant: AES-256, SHA-384, ChaCha20, PQC Level 3+ algorithms
- Partially Vulnerable: AES-128, SHA-256 (security reduced by Grover's algorithm)
- Quantum Vulnerable: RSA, ECDSA, ECDHE, DH (completely broken by Shor's algorithm)

## Installation and Quick Start for New Users

### IMPORTANT: This is a Pre-Compiled Binary Package
- NO COMPILATION REQUIRED - Ready to use immediately
- Compatible with Kali Linux, Ubuntu 18.04+, Debian 10+
- Root privileges needed for packet capture only

### Complete Setup Process

1. Download and Extract Package  
   tar -xzf tls_analyzer_v1.0.tar.gz  
   cd tls_analyzer_package

2. Install Dependencies (One-time setup)  
   chmod +x install_dependencies.sh  
   ./install_dependencies.sh  

   Installed packages:  
   - libpcap0.8: Packet capture library  
   - libssl3: OpenSSL cryptographic library  
   - libc6: Standard C library

3. Set Execution Permissions (One-time setup)  
   chmod +x Kali_tls_capture  
   chmod +x run_tls_analyzer.sh

4. Ready to Use! (No compilation required)  
   sudo ./Kali_tls_capture -h  
   sudo ./Kali_tls_capture -L  
   sudo ./Kali_tls_capture

### System Requirements
- Kali Linux, Ubuntu 18.04+, Debian 10+ or compatible distributions
- Root privileges (for packet capture)
- Minimum 100MB disk space
- Network interface access

### Alternative: Easy Installation Script
If available, use the automated installer:  
chmod +x easy_install.sh  
./easy_install.sh

## Usage

### Basic Command Format
sudo ./Kali_tls_capture [options]  
or  
sudo ./run_tls_analyzer.sh [options]

### Command Options

-h                Show help message  
                  Example: ./Kali_tls_capture -h  

-L                List available network interfaces  
                  Example: sudo ./Kali_tls_capture -L  

-I                Interactive interface selection mode  
                  Example: sudo ./Kali_tls_capture -I  

-i [interface]    Specify network interface  
                  Example: sudo ./Kali_tls_capture -i eth0  

-r [file]         Offline PCAP file analysis  
                  Example: ./Kali_tls_capture -r capture.pcap  

-f [file]         Batch domain analysis from file  
                  Example: ./Kali_tls_capture -f domains.txt  

-l                Local testing mode (port 4450)  
                  Example: sudo ./Kali_tls_capture -l  

-p [port]         Specify port (default: 443)  
                  Example: sudo ./Kali_tls_capture -p 8443  

-w [file]         Save packets to PCAP file  
                  Example: sudo ./Kali_tls_capture -w output.pcap

### Practical Examples

1. Real-time HTTPS Traffic Analysis (Recommended)  
   Auto interface selection:  
   sudo ./Kali_tls_capture  

   Use specific interface:  
   sudo ./Kali_tls_capture -i wlan0

2. SNI Filtering for Specific Sites  
   sudo ./Kali_tls_capture  
   Answer 'yes' to SNI filtering prompt  
   Enter domains: google amazon naver

3. Analyze Saved Packet Files  
   ./Kali_tls_capture -r network_capture.pcap  
   ./Kali_tls_capture -r wireshark_dump.pcapng

4. Batch Domain Analysis  
   Create domains.txt file:  
   echo -e "google.com\ngithub.com\namazon.com" > domains.txt  
   
   Run batch analysis:  
   ./Kali_tls_capture -f domains.txt

5. Local Development Server Testing  
   Analyze local TLS server (port 4450):  
   sudo ./Kali_tls_capture -l  
   
   Custom port analysis:  
   sudo ./Kali_tls_capture -p 8443

## Output Analysis

### Real-time Output Example
[14:32:15] TLS Connection #1  
[+] 192.168.1.100:54321 → 142.250.191.14:443  
  └─ Server Name (SNI): www.google.com  
  └─ Client TLS Version: TLS 1.2  
  └─ Negotiated TLS Version: TLS 1.3  
  └─ Cipher Suite: TLS_AES_256_GCM_SHA384  
  └─ Key Exchange Group: x25519_mlkem768 (PQC Hybrid Level 3)  
  └─ Security Level: High (Post-Quantum Hybrid Key Exchange)  

[INFO] Certificate Issuer: Google Trust Services LLC  
[INFO] Certificate expires: 2024-12-15 (89 days)  
[INFO] Public Key: ECDSA  

### CSV Report File
- Filename: tls_pqc_report_YYYYMMDD_HHMMSS.csv
- Excel compatible format
- Included information:  
  Session #, SNI, TLS Version, Security Level  
  Cipher Suite, Vulnerable Field, Vulnerability Level  
  Certificate Issuer, Expiry Date, Public Key Algorithm  
  Migration Required, Overall Assessment

### Security Level Indicators
H = High (High quantum resistance)  
M = Medium (Partial quantum vulnerability)  
L = Low (Completely vulnerable to quantum attacks)  
O = Required (Certificate renewal required within 90 days)  
X = Not Required (Certificate renewal not required)

### Quantum Vulnerability Analysis Output
Quantum Computer Vulnerability Analysis:  
[INFO] PQC Security Level: 3 (192-bit equivalent)  
[INFO] Recommended security level for most applications  
[WARNING] Hybrid contains quantum-vulnerable classic component  
[RECOMMENDATION] Consider migrating to Level 3+ algorithms

## Troubleshooting

### Common Issues

1. Permission denied error
   Solution: Run with root privileges
   sudo ./Kali_tls_capture -L

2. "No such file or directory" error
   Solution: Check execution permissions
   chmod +x run_tls_analyzer.sh
   chmod +x Kali_tls_capture

3. "Could not open device" error
   Solution: Verify correct interface
   sudo ./Kali_tls_capture -L
   sudo ./Kali_tls_capture -i [correct_interface_name]

4. "Library not found" error
   Solution: Reinstall dependencies
   ./install_dependencies.sh
   sudo apt install -y libpcap0.8 libssl3

5. No packets captured
   Check network traffic: ping google.com
   Check interface status: ip link show
   Check firewall: sudo iptables -L

### Advanced Usage Tips

Running in Docker Environment:  
docker run --net=host --privileged -v $(pwd):/app ubuntu:20.04  

High Traffic Environment:  
sudo sysctl -w net.core.rmem_max=134217728   
sudo sysctl -w net.core.rmem_default=134217728  

Save Analysis Logs:  
sudo ./Kali_tls_capture 2>&1 | tee analysis_log.txt

## File Structure

tls_analyzer_package/  
├── Kali_tls_capture              # Main executable (compiled binary)  
├── run_tls_analyzer.sh           # Wrapper script for easier execution  
├── install_dependencies.sh       # Dependency installation script  
├── sample_domains.txt            # Sample domain list for batch analysis  
├── easy_install.sh               # Automated installation script (if available)  
└── README.md                     # This documentation file

## Manual Installation (Advanced Users)

For manual system-wide installation:  
sudo apt update  
sudo apt install -y libpcap0.8 libssl3 libc6  
sudo cp Kali_tls_capture /usr/local/bin/tls_analyzer  
sudo chmod +x /usr/local/bin/tls_analyzer

## Quick Reference

### First Time Setup
1. tar -xzf tls_analyzer_v1.0.tar.gz
2. cd tls_analyzer_package  
3. ./install_dependencies.sh
4. chmod +x Kali_tls_capture run_tls_analyzer.sh

### Daily Usage
1. Check interfaces: sudo ./Kali_tls_capture -L
2. Start analysis: sudo ./Kali_tls_capture
3. Stop with Ctrl+C and review CSV report

### Alternative Commands (Using Wrapper Script)
1. Check interfaces: sudo ./run_tls_analyzer.sh -L
2. Start analysis: sudo ./run_tls_analyzer.sh
3. Stop with Ctrl+C and review CSV report

## Important Notes for End Users
- This package contains a PRE-COMPILED binary - no compilation needed
- Dependencies are automatically installed via script
- Root privileges required only for live packet capture
- PCAP file analysis can be done without root privileges
- Compatible with most Debian-based Linux distributions
- One-time setup per system

## Development Information
- Version: 1.0  
- Source File: Kali_tls_capture.c  
- Compiled Binary: Kali_tls_capture  
- Development Language: C  
- Supported Platforms: Linux (Kali, Ubuntu, Debian)  
- Dependencies: libpcap, OpenSSL
