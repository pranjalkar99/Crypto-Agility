# TLS Packet Analyzer - Quantum Vulnerability Detection Tool

## Overview
Real-time TLS packet capture and analysis tool for detecting quantum-vulnerable cryptographic algorithms in network communications.

## Key Features
- Real-time/offline TLS traffic capture and analysis
- Post-Quantum Cryptography (PQC) algorithm prototype detection
- ML-KEM (Kyber), Falcon, SPHINCS+, ML-DSA prototype support
- TLS 1.0-1.3 protocol quantum vulnerability assessment
- SNI filtering for specific domain analysis
- X.509 certificate inspection and expiry analysis
- Automated Excel report generation (.xlsx)
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
- Compatible with Windows 10/11 (64-bit)
- Administrator privileges required only for packet capture

### Complete Setup Process

1. Download and Extract Package
   Place the provided files in your desired directory.

2. Verify OpenSSL
   Make sure OpenSSL is in the same directory or added to the system PATH.

3. Open the Proper Command Prompt
   Launch “x64 Native Tools Command Prompt for VS 2022”  
   Right-click and select Run as administrator (required for packet capture)

4. Ready to Use! (No compilation required)
   windows_tls_capture.exe

### System Requirements
- Windows 10/11 (64-bit)
- x64 Native Tools Command Prompt (Visual Studio 2022 Community Edition)
- Win64 OpenSSL

## Usage

### Basic Command Format
- Live capture mode: windows_tls_capture.exe
- Offline PCAP analysis mode: windows_tls_capture.exe example.pcapng

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

### Excel Report File
- Filename: TLS_Quantum_Vulnerability_Report_YYYYMMDD_HHMMSS.xlsx
- Included information:  
  Session #, SNI, TLS Version, Security Level  
  Cipher Suite, Vulnerable Field, Vulnerability Level  
  Certificate Issuer, Expiry Date, Public Key Algorithm  
  Migration Required, Overall Assessment

### Security Level Indicators
H = High (High quantum resistance)  
M = Medium (Partial quantum vulnerability)  
L = Low (Completely vulnerable to quantum attacks)  
T = Required (Certificate renewal required within 90 days)  
F = Not Required (Certificate renewal not required)  

### Quantum Vulnerability Analysis Output
Quantum Computer Vulnerability Analysis:  
[INFO] PQC Security Level: 3 (192-bit equivalent)  
[INFO] Recommended security level for most applications  
[WARNING] Hybrid contains quantum-vulnerable classic component  
[RECOMMENDATION] Consider migrating to Level 3+ algorithms

## File Structure

windows_tls_analyzer_package/  
├── windows_tls_capture.exe&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# Main executable  
├── windows_tls_capture.c&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# Source code  
├── z.dll&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# External library  
├── libs/&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# External libraries  
├── npcap-sdk-1.15/&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# Npcap SDK for packet capture  
├── .vscode/&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# VSCode settings  
└── README.md&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;# Documentation file  


## Development Information
- Version: 1.0  
- Source File: windows_tls_capture.c  
- Compiled Binary: windows_tls_capture.exe  
- Development Language: C  
- Supported Platforms: Windows 10/11 (64-bit)  
- Dependencies: Npcap SDK, OpenSSL, libxlsxwriter, zlib
