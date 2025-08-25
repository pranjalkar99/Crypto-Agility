# TLS Quantum Vulnerability Analyzer

An automated tool for analyzing quantum-vulnerable TLS configurations through packet inspection.   

## Introduction

This framework collects and analyzes TLS packets to automatically identify the cipher suites and certificate structures used by common applications such as browsers and messaging platforms. Based on this analysis, it classifies whether each application relies on quantum-vulnerable algorithms or relatively secure ones, while emphasizing the associated security risks. In addition, it provides a scalable foundation for the future integration of Post-Quantum Cryptography (PQC) mechanisms. The goals of this framework are as follows:


| Feature | Status |
|---|---|
| Free Distribution | ✅ |
| Real‑time Support (live capture) | ✅ |
| Offline Support (captured packets) | ✅ |
| Hybrid PQC Detection | ✅ |
| QV Detection | ✅ |
| Cipher Suite Detection | ✅ |
| CA detection | ✅ |
| Report(.csv) Generation | ✅ |
| SNI (domain) Filtering | ✅ |
| GUI Support | 🛠️ In progress |

- We plan to add macOS support and a GUI in future updates.

## Security Assessment Criteria

### TLS Version Security Levels
Security Level Indicators
- H = High (High quantum resistance)
- M = Medium (Partial quantum vulnerability)
- L = Low (Completely vulnerable to quantum attacks)
Certificate Level
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

### Report File
We provide report outputs as CSV files to facilitate downstream processing. An example CSV is included in the repository.

Filename: [TLS_Quantum_Vulnerability_Report_YYYYMMDD_HHMMSS.csv](output.csv)

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
cl windows_tls_capture.c /MD /I"C:\Program Files\OpenSSL-Win64\include" /I".\npcap-sdk-1.15\Include" /I".\libs\xlsxwriter" /link /LIBPATH:"C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD" /LIBPATH:".\npcap-sdk-1.15\Lib\x64" /LIBPATH:".\libs" ws2_32.lib wpcap.lib packet.lib libssl.lib libcrypto.lib xlsxwriter.lib z.lib
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
It is compatible with Kali Linux, Ubuntu 18.04+, Debian 10+ environments, and root privileges are required only for packet capture operations.

- We provide a precompiled .exe, but you can also run the binary directly as shown below.

```
gcc src/Kali_tls_capture.c -o tls_capture -lpcap -lssl -lcrypto
```

#### System Requirements
- Kali Linux, Ubuntu 18.04+, Debian 10+ or compatible distributions
- Root privileges (for packet capture only)
- Minimum 100MB disk space
- Network interface access
- Source File: Kali_tls_capture.c
- Compiled Binary: Kali_tls_capture
- Development Language: C
- Dependencies: libpcap, OpenSSL

#### Installing packages
- libpcap0.8 — In this framework, it is used as the primary ingestion layer to capture and collect packets from live interfaces and PCAP files, leveraging the portable pcap_* API as-is.
- libssl3 — In this framework, it is used to parse/verify TLS handshakes, cipher suites, and certificates, and to run optional TLS tests; TLS 1.3/DTLS are provided via libssl and core cryptographic primitives via libcrypto.
- libc6 — In this framework, it is used as the standard runtime (glibc) that capture/analysis modules depend on across Linux, providing system-call, memory/threading, and networking APIs.

```
sudo apt update
sudo apt install -y libpcap0.8 libssl3 libc6
sudo cp Kali_tls_capture /usr/local/bin/tls_analyzer
sudo chmod +x /usr/local/bin/tls_analyzer
```

#### Usage
- For real-time packet capture, set Execution Permissions and run it using the following sudo command.

```
//set execution permissions
chmod +x Kali_tls_capture

// Usage
sudo ./Kali_tls_capture [options]
```

## Framework-Supported TLS Key Exchange, Signatures, and Cipher Suites

### Key exchange
| Category | Algorithm | Hex |
|----------|------------|------------------|
| **TLS 1.3 Traditional** | X25519 | `0x001D` |
| | X448 | `0x001E` |
| | secp256r1 | `0x0017` |
| | secp384r1 | `0x0018` |
| | secp521r1 | `0x0019` |
| | ffdhe2048 | `0x0100` |
| | ffdhe3072 | `0x0101` |
| **Hybrid PQC (ML-KEM + ECDHE)** | X25519Kyber512Draft00 | `0x0768` |
| | X25519Kyber768Draft00 | `0x0769` |
| | X25519Kyber1024Draft00 | `0x076A` |
| | X25519MLKEM512 | `0x6399` |
| | X25519MLKEM768 | `0x639A` |
| **Pure PQC (ML-KEM)** | ML-KEM-512 | `0x023A` |
| | ML-KEM-768 | `0x023B` |
| | ML-KEM-1024 | `0x023C` |

### Signatures
| Category | Algorithm | Hex |
|----------|------------|------------------|
| **RSASSA-PSS** | RSA-PSS-SHA256 | `0x0804` |
| | RSA-PSS-SHA384 | `0x0805` |
| | RSA-PSS-SHA512 | `0x0806` |
| **EdDSA** | Ed25519 | `0x0807` |
| | Ed448 | `0x0808` |
| **RSASSA-PKCS1 v1.5** | RSA-PKCS1-SHA256 | `0x0401` |
| | RSA-PKCS1-SHA384 | `0x0501` |
| | RSA-PKCS1-SHA512 | `0x0601` |
| **ECDSA** | ECDSA-SHA256 | `0x0403` |
| | ECDSA-SHA384 | `0x0503` |
| | ECDSA-SHA512 | `0x0603` |
| **Legacy** | RSA-PKCS1-SHA1 | `0x0201` |
| | ECDSA-SHA1 | `0x0203` |
| **PQC (ML-DSA)** | ML-DSA-44 | `0x0B01` |
| | ML-DSA-65 | `0x0B02` |
| | ML-DSA-87 | `0x0B03` |

### Cipher Suites
- TLS 1.2

| Cipher Suite | Hex |
|------------|-----|
| TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | `0xC02F` |
| TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | `0xC030` |
| TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 | `0xC02B` |
| TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 | `0xC02C`  |
| TLS_RSA_WITH_AES_128_CBC_SHA | `0x002F`  |
| TLS_RSA_WITH_AES_256_CBC_SHA | `0x0035`  |
| TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA | `0xC013`  |
| TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA | `0xC014`  |
| TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 | `0xCCA8`  |
| TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 | `0xCCA9`  |


- TLS 1.3

| Cipher Suite | Hex |
|------------|-----|
| TLS_AES_128_GCM_SHA256 | `0x1301`  |
| TLS_AES_256_GCM_SHA384 | `0x1302`  |
| TLS_CHACHA20_POLY1305_SHA256 | `0x1303`  |
| TLS_AES_128_CCM_SHA256 | `0x1304`  |
| TLS_AES_128_CCM_8_SHA256 | `0x1305`  |

- TLS 1.3 Hybrid PQC Suites (Examples)

| Cipher Suite | Hex |
|------------|-----|
| TLS_ML_KEM_512_X25519_AES_128_GCM_SHA256 | `0x2F01` |
| TLS_ML_KEM_768_X25519_AES_256_GCM_SHA384 | `0x2F02` |
| TLS_ML_KEM_1024_X448_CHACHA20_POLY1305_SHA256 | `0x2F03` |
| TLS_ML_KEM_512_P256_AES_128_GCM_SHA256 | `0x2F04` |
| TLS_ML_KEM_768_P384_AES_256_GCM_SHA384 | `0x2F05` |
| TLS_ML_KEM_1024_P521_CHACHA20_POLY1305_SHA256 | `0x2F06` |
| TLS_HQC_128_X25519_AES_128_GCM_SHA256 | `0x2F10` |
| TLS_HQC_192_X25519_AES_256_GCM_SHA384 | `0x2F11` |
| TLS_HQC_256_X448_CHACHA20_POLY1305_SHA256 | `0x2F12` |
| TLS_HQC_128_P256_AES_128_GCM_SHA256 | `0x2F13` |
| TLS_HQC_192_P384_AES_256_GCM_SHA384 | `0x2F14` |
| TLS_HQC_256_P521_CHACHA20_POLY1305_SHA256 | `0x2F15`  |
| TLS_FALCON_512_ECDHE_P256_AES_128_GCM_SHA256 | `0x2F20`  |
| TLS_FALCON_1024_ECDHE_P384_AES_256_GCM_SHA384 | `0x2F21`  |
| TLS_SPHINCS_SHA256_128S_ECDHE_P256_AES_128_GCM | `0x2F30` |
| TLS_SPHINCS_SHAKE256_128F_ECDHE_P384_AES_256_GCM | `0x2F31`  |




## Bibliography 
When referring to this framework in academic literature, please consider using the following bibTeX excerpt:
```
@misc{craft_CA,
  title = {Crypto Agility:  TLS Quantum Vulnerability Analyzer},
  author = {Subeen Cho, Yulim Hyoung, Hagyeong Kim, Minjoo Sim, Anupam Chattopadhyay, Hwajeong Seo, and Hyunji Kim,},
  note = {\url{https://github.com/kpqc-cryptocraft/Crypto-Agility.git}}
}
```
