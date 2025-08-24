# TLS Quantum Vulnerability Analyzer

An automated tool for analyzing quantum-vulnerable TLS configurations through packet inspection.   

## Introduction

This framework collects and analyzes TLS packets to automatically identify the cipher suites and certificate structures used by common applications such as browsers and messaging platforms. Based on this analysis, it classifies whether each application relies on quantum-vulnerable algorithms or relatively secure ones, while emphasizing the associated security risks. In addition, it provides a scalable foundation for the future integration of Post-Quantum Cryptography (PQC) mechanisms. The goals of this framework are as follows:

- Real-time/offline TLS traffic capture and analysis
- Post-Quantum Cryptography (PQC) algorithm prototype detection
- ML-KEM (Kyber), Falcon, SPHINCS+, ML-DSA prototype support
- TLS 1.0-1.3 protocol quantum vulnerability assessment
- SNI filtering for specific domain analysis
- X.509 certificate inspection and expiry analysis
- Automated Excel report generation (.csv or .xlsx)
- Multi-interface support



## Security Assessment Criteria

### TLS Version Security Levels
Security Level Indicators
- H = High (High quantum resistance)
- M = Medium (Partial quantum vulnerability)
- L = Low (Completely vulnerable to quantum attacks)
- T = Required (Certificate renewal required within 90 days)
- F = Not Required (Certificate renewal not required)



## Output
### Real-time Output Example

```
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
```

### Excel Report File
Filename: TLS_Quantum_Vulnerability_Report_YYYYMMDD_HHMMSS.xlsx
Included information:
- Session #, SNI, TLS Version, Security Level
- Cipher Suite, Vulnerable Field, Vulnerability Level
- Certificate Issuer, Expiry Date, Public Key Algorithm
- Migration Required, Overall Assessment

## Setup/Installation 

### 1) windows
It is compatible with 64-bit Windows 10/11 environments, and administrator privileges are required only for packet capture operations.

- We provide a precompiled .exe, but you can also run the binary directly as shown below. Replace the placeholders with your own PATH settings as needed.
```
cl windows_tls_capture.c /I"npcap-sdk-1.15\Include" /link /LIBPATH:"npcap-sdk-1.15\Lib\x64" wpcap.lib packet.lib ws2_32.lib
```

#### System Requirements
- Development Language: C  
- Windows 10/11 (64-bit)
- x64 Native Tools Command Prompt (Visual Studio 2022 Community Edition)
- Win64 OpenSSL
- Source File: windows_tls_capture.c  
- Compiled Binary: windows_tls_capture.exe  
- Dependencies: Npcap SDK, OpenSSL, libxlsxwriter, zlib

#### Installing openSSL 
We use OpenSSL to extract and analyze cryptographic artifacts such as certificates and keys, enabling deeper inspection that goes beyond what plain packet capture can provide.
- Install OpenSSL on Windows (64-bit) using the [official Win64 installer](https://slproweb.com/products/Win32OpenSSL.html), add its bin directory to your system PATH (if not done automatically), and verify with openssl version. For convenience, use the commonly distributed Windows binaries.

#### Installing x64 Native Tools Command Prompt
Use the “[x64 Native Tools Command Prompt for VS](https://visualstudio.microsoft.com/ko/vs/pricing/?tab=individual)” to ensure a correct 64-bit C/C++ toolchain (MSVC, linker, headers/libraries) is preconfigured for your build, preventing architecture mismatches and link-time errors.

#### npcap 
Npcap is a modern packet capture/injection driver and library for Windows, developed by the Nmap Project. It provides the Pcap API on top of an NDIS 6 driver and supports raw capture, kernel‑level BPF filtering, loopback capture, and packet injection. In our project, the Npcap library is included in the runtime environment, so no separate installation is required.

#### libxlsxwriter
We support Excel features on Windows to improve readability. This functionality is also included in the runtime environment.

### 2) linux


## Bibliography 
When referring to this framework in academic literature, please consider using the following bibTeX excerpt:
```
@misc{PQM4,
  title = {Crypto Agility:  TLS Quantum Vulnerability Analyzer},
  author = {subeen Cho and Yulim Hyoung and Hagyeong Kim and Hyunji Kim and Minjoo Sim and hwajeong Seo},
  note = {\url{https://github.com/kpqc-cryptocraft/Crypto-Agility.git}}
}
```
