#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <iphlpapi.h>
    #include <pcap.h>
    // Macro definition for Windows
    #define close(s) closesocket(s)
    typedef int socklen_t;
    
    // IP header structure for Windows (compatible with Linux)
    struct iphdr {
        unsigned char ihl:4;
        unsigned char version:4;
        unsigned char tos;
        unsigned short tot_len;
        unsigned short id;
        unsigned short frag_off;
        unsigned char ttl;
        unsigned char protocol;
        unsigned short check;
        unsigned int saddr;
        unsigned int daddr;
    };
    
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "iphlpapi.lib")
    #pragma comment(lib, "wpcap.lib")
#else
    // Headers for Linux/Unix (all Linux headers collected here)
    #include <pcap.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/ip6.h>
    #include <netinet/if_ether.h>
    #include <netinet/ether.h>
    #include <net/ethernet.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netdb.h>
    #include <getopt.h>
    #include <fcntl.h>
    #include <errno.h>
    #include <ctype.h>
    #include <sys/select.h>
#endif

// Common headers (available for both Windows and Linux)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>

// ANSI Color codes for terminal output
#define COLOR_RED     "\033[91m"
#define COLOR_GREEN   "\033[92m"
#define COLOR_YELLOW  "\033[93m"
#define COLOR_BLUE    "\033[94m"
#define COLOR_PURPLE  "\033[95m"
#define COLOR_CYAN    "\033[96m"
#define COLOR_WHITE   "\033[97m"
#define COLOR_RESET   "\033[0m"
#define COLOR_BOLD    "\033[1m"

// TLS Protocol Constants
#define TLS_RECORD_TYPE_HANDSHAKE 0x16
#define TLS_HANDSHAKE_CLIENT_HELLO 0x01
#define TLS_HANDSHAKE_SERVER_HELLO 0x02
#define TLS_HANDSHAKE_CERTIFICATE 0x0b
#define TLS_HANDSHAKE_SERVER_KEY_EXCHANGE 0x0c
#define TLS_HANDSHAKE_CERTIFICATE_VERIFY 0x0f
#define TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE 0x10
#define TLS_HANDSHAKE_FINISHED 0x14

// TLS Extension Types
#define TLS_EXT_SERVER_NAME 0x0000
#define TLS_EXT_SUPPORTED_VERSIONS 0x002b

// Application Constants
#define MAX_SESSIONS 1000
#define MAX_SNI_LEN 256
#define MAX_CIPHER_LEN 128
#define MAX_IP_LEN 16
#define MAX_FILTER_LEN 256
#define MAX_KEYWORDS 20
#define MAX_KEYWORD_LEN 64
#define MAX_ISSUER_LEN 256
#define MAX_EXPIRY_LEN 32

// OID constant definitions
static const unsigned char RSA_OID[] = {
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
};

static const unsigned char ECDSA_OID[] = {
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01
};

static const unsigned char ED25519_OID[] = {
    0x06, 0x03, 0x2b, 0x65, 0x70
};

static const unsigned char ML_DSA_44_OID[] = {
    0x06, 0x0b, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11
};

static const unsigned char ML_DSA_65_OID[] = {
    0x06, 0x0b, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12
};

static const unsigned char ML_DSA_87_OID[] = {
    0x06, 0x0b, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13
};

static const unsigned char FALCON_512_OID[] = {
    0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x02, 0x82, 0x0b, 0x01
};

static const unsigned char FALCON_1024_OID[] = {
    0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x02, 0x82, 0x0b, 0x02
};

static const unsigned char CN_OID[] = {
    0x06, 0x03, 0x55, 0x04, 0x03
};

static const unsigned char ORG_OID[] = {
    0x06, 0x03, 0x55, 0x04, 0x0a
};

static const unsigned char UTC_TIME_TAG = 0x17;
static const unsigned char GENERALIZED_TIME_TAG = 0x18;

typedef struct {
    const unsigned char* oid;
    size_t oid_len;
    const char* name;
    int is_pqc;
    int security_level;
} algorithm_info_t;

static const algorithm_info_t public_key_algorithms[] = {
    {RSA_OID, sizeof(RSA_OID), "RSA", 0, 0},
    {ECDSA_OID, sizeof(ECDSA_OID), "ECDSA", 0, 0},
    {ED25519_OID, sizeof(ED25519_OID), "Ed25519", 0, 0},
    {ML_DSA_44_OID, sizeof(ML_DSA_44_OID), "ML-DSA-44", 1, 1},
    {ML_DSA_65_OID, sizeof(ML_DSA_65_OID), "ML-DSA-65", 1, 3},
    {ML_DSA_87_OID, sizeof(ML_DSA_87_OID), "ML-DSA-87", 1, 5},
    {FALCON_512_OID, sizeof(FALCON_512_OID), "Falcon-512", 1, 1},
    {FALCON_1024_OID, sizeof(FALCON_1024_OID), "Falcon-1024", 1, 5},
    {NULL, 0, NULL, 0, 0}
};

#define TLS_EXT_SUPPORTED_GROUPS 0x000a    // Supported Groups Extension
#define TLS_EXT_KEY_SHARE 0x0033           // Key Share Extension
#define TLS_EXT_KEY_SHARE_HRR 0x0028       // Key Share (Hello Retry Request)

// Supported Groups values (p256_mlkem512 etc)
#define GROUP_P256_MLKEM512 0x1741         // p256_mlkem512 hybrid group
#define GROUP_X25519_MLKEM768 0x11EC       // Google Chrome current usage
#define GROUP_KYBER768_X25519 0x6399       // Chrome Legacy

// TLS Groups structure for mapping
typedef struct {
    uint16_t group_id;
    const char* name;
    int is_pqc_hybrid;
    const char* pqc_algorithm;
    int security_level;  // 1, 3, 5
} tls_group_t;

// Enhanced Session Information Structure with PQC support
typedef struct {
    char sni[MAX_SNI_LEN];                // Server Name Indication
    char src_ip[MAX_IP_LEN];              // Source IP address
    char dst_ip[MAX_IP_LEN];              // Destination IP address
    int src_port;                         // Source port
    int dst_port;                         // Destination port
    char negotiated_tls_version[32];      // Actually negotiated TLS version
    char client_tls_version[32];          // Client proposed TLS version
    char cipher_suite[MAX_CIPHER_LEN];    // Negotiated cipher suite
    char vulnerabilities[256];            // Vulnerability assessment
    char issuer[MAX_ISSUER_LEN];          // Certificate issuer
    char expiry_date[MAX_EXPIRY_LEN];     // Certificate expiry date
    int expiry_days;                      // Days until certificate expiry
    int risk_score;                       // Calculated risk score
    char handshake_msgs[256];             // Handshake message types seen
    int is_tls13;                         // TLS 1.3 flag
    char supported_versions[128];         // Client supported TLS versions
    int has_certificate;                  // Certificate captured flag
    char pub_key_type[64];                // Public Key Algorithm Type
    int is_pqc_hybrid;                    // Post-Quantum Cryptography hybrid flag
    char pqc_kem[64];                     // PQC Key Encapsulation Mechanism
    char pqc_sig[64];                     // PQC Digital Signature algorithm
    int classic_vuln;                     // Classic cryptography vulnerable
    int pqc_vuln;                         // PQC vulnerable
    char negotiated_group[64];            // Negotiated key exchange group
    int is_pqc_key_exchange;              // PQC key exchange usage flag
    char pqc_kex_details[128];            // PQC key exchange details
} session_info_t;

// TLS Version Structure for version mapping
typedef struct {
    uint16_t version;
    const char* name;
} tls_version_t;

// Cipher Suite Structure with PQC support
typedef struct {
    uint16_t value;
    const char* name;
    int is_pqc_hybrid;
    const char* kem_algorithm;
    const char* sig_algorithm;
} cipher_suite_t;

// Statistics Structure for analysis tracking
typedef struct {
    int total_packets;                    // Total packets processed
    int tls_packets;                      // TLS packets found
    int total_sessions;                   // Total TLS sessions
    int vulnerable_sessions;              // Sessions with vulnerabilities
    session_info_t sessions[MAX_SESSIONS]; // Session data array
    int tls_12_count;                     // TLS 1.2 session count
    int tls_13_count;                     // TLS 1.3 session count
    int weak_hash_count;                  // Weak hash algorithm count
    int rsa_ecdhe_count;                  // RSA+ECDHE combination count
    int safe_connections;                 // Quantum-safe connections
    int partial_connections;              // Partially vulnerable connections
    int vulnerable_connections;           // Fully vulnerable connections
    int pqc_hybrid_count;                 // PQC hybrid connections
    int pqc_safe_count;                   // PQC safe connections
} statistics_t;

// SNI Filter Structure for targeted analysis
typedef struct {
    char keywords[MAX_KEYWORDS][MAX_KEYWORD_LEN];
    int keyword_count;
} sni_filter_t;

// Global variables
static pcap_t *handle = NULL;             // Packet capture handle
static pcap_dumper_t *dumper = NULL;      // PCAP file dumper
static statistics_t stats = {0};          // Analysis statistics
static int running = 1;                   // Main loop control flag
static int sni_filter_enabled = 0;        // SNI filtering enabled flag
static sni_filter_t sni_filter = {0};     // SNI filter configuration

// SNI Tracking for duplicate removal
#define MAX_DISPLAYED_SNIS 1000
static char displayed_snis[MAX_DISPLAYED_SNIS][MAX_SNI_LEN];
static int displayed_sni_count = 0;

// Connection State Tracking for completed connections only
#define MAX_PENDING_CONNECTIONS 500
typedef struct {
    char connection_id[64];               // Unique connection identifier
    char sni[MAX_SNI_LEN];                // Server Name Indication
    char client_version[32];              // Client TLS version
    char src_ip[MAX_IP_LEN];              // Source IP
    char dst_ip[MAX_IP_LEN];              // Destination IP
    int src_port;                         // Source port
    int dst_port;                         // Destination port
    char supported_versions[128];         // Supported TLS versions
    char supported_groups[256];           // Supported Groups information
    int has_client_hello;                 // ClientHello received flag
    time_t start_time;                    // Connection start time
} pending_connection_t;

static pending_connection_t pending_connections[MAX_PENDING_CONNECTIONS];
static int pending_count = 0;

char pubKey[64] = "Error";

// TLS Version mapping table
static tls_version_t tls_versions[] = {
    {0x0300, "SSL 3.0"},
    {0x0301, "TLS 1.0"},
    {0x0302, "TLS 1.1"},
    {0x0303, "TLS 1.2"},
    {0x0304, "TLS 1.3"},
    
    // TLS 1.3 Draft versions (historically used by Chrome/Google)
    {0x7f12, "TLS 1.3 Draft-18"},
    {0x7f13, "TLS 1.3 Draft-19"},
    {0x7f14, "TLS 1.3 Draft-20"},
    {0x7f15, "TLS 1.3 Draft-21"},
    {0x7f16, "TLS 1.3 Draft-22"},
    {0x7f17, "TLS 1.3 Draft-23"},
    {0x7f18, "TLS 1.3 Draft-24"},
    {0x7f19, "TLS 1.3 Draft-25"},
    {0x7f1a, "TLS 1.3 Draft-26"},
    {0x7f1b, "TLS 1.3 Draft-27"},
    {0x7f1c, "TLS 1.3 Draft-28"},
    
    // Future versions
    {0x0305, "TLS 1.4 (Draft)"},
    {0x0306, "TLS 1.5 (Draft)"},
    
    {0x0000, NULL}
};

// Enhanced TLS Cipher Suites with PQC Hybrid support
static cipher_suite_t cipher_suites[] = {
    // Standard TLS 1.3 Cipher Suites (keep existing)
    {0x1301, "TLS_AES_128_GCM_SHA256", 0, NULL, NULL},
    {0x1302, "TLS_AES_256_GCM_SHA384", 0, NULL, NULL},
    {0x1303, "TLS_CHACHA20_POLY1305_SHA256", 0, NULL, NULL},
    {0x1304, "TLS_AES_128_CCM_SHA256", 0, NULL, NULL},
    {0x1305, "TLS_AES_128_CCM_8_SHA256", 0, NULL, NULL},
    
    // ====== REAL-WORLD DEPLOYED PQC (Level 3 - Currently Active) ======
    
    // Google Chrome/BoringSSL - Currently Deployed (Level 3)
    {0x11EC, "TLS_ML_KEM_768_X25519_AES_256_GCM_SHA384", 1, "ML-KEM-768+X25519", "ECDSA"},     // Chrome 131+ (Current)
    {0x6399, "TLS_KYBER_768_X25519_AES_256_GCM_SHA384", 1, "Kyber768+X25519", "ECDSA"},        // Chrome 116-130 (Legacy)
    
    // Cloudflare Production (Level 3)
    {0x2F71, "TLS_CLOUDFLARE_ML_KEM_768_X25519_AES_256_GCM", 1, "ML-KEM-768+X25519", "ECDSA"}, // Cloudflare Current
    {0x2F72, "TLS_CLOUDFLARE_KYBER_768_P384_AES_256_GCM", 1, "Kyber768+P384", "ECDSA"},        // Cloudflare Alternative
    
    // ====== NIST Post-Quantum Security Level 3 (AES-192 equivalent) ======
    
    // ML-KEM (Kyber) Hybrid Key Exchange - Level 3
    {0x2F05, "TLS_ML_KEM_768_X25519_AES_256_GCM_SHA384", 1, "ML-KEM-768+X25519", "ML-DSA"},
    {0x2F06, "TLS_ML_KEM_768_P384_AES_256_GCM_SHA384", 1, "ML-KEM-768+P384", "ML-DSA"},
    {0x2F08, "TLS_ML_KEM_768_X448_AES_256_GCM_SHA384", 1, "ML-KEM-768+X448", "ML-DSA"},
    
    // Dilithium3 + ECDHE Hybrid - Level 3
    {0x2F40, "TLS_DILITHIUM3_ECDHE_P384_AES_256_GCM_SHA384", 1, "ECDHE-P384", "Dilithium3"},
    {0x2F41, "TLS_DILITHIUM3_X25519_AES_256_GCM_SHA384", 1, "X25519", "Dilithium3"},
    
    // Falcon1024 + ECDHE Hybrid - Level 3
    {0x2F21, "TLS_FALCON_1024_ECDHE_P384_AES_256_GCM_SHA384", 1, "ECDHE-P384", "Falcon-1024"},
    {0x2F22, "TLS_FALCON_1024_X25519_AES_256_GCM_SHA384", 1, "X25519", "Falcon-1024"},
    
    // SPHINCS+ + ECDHE Hybrid - Level 3
    {0x2F31, "TLS_SPHINCS_SHA256_192S_ECDHE_P384_AES_256_GCM", 1, "ECDHE-P384", "SPHINCS+-SHA256-192s"},
    {0x2F32, "TLS_SPHINCS_SHA256_192F_X25519_AES_256_GCM", 1, "X25519", "SPHINCS+-SHA256-192f"},
    
    // ====== NIST Post-Quantum Security Level 5 (AES-256 equivalent) ======
    
    // ML-KEM (Kyber) Hybrid Key Exchange - Level 5
    {0x2F07, "TLS_ML_KEM_1024_P521_AES_256_GCM_SHA384", 1, "ML-KEM-1024+P521", "ML-DSA"},
    {0x2F09, "TLS_ML_KEM_1024_X448_AES_256_GCM_SHA384", 1, "ML-KEM-1024+X448", "ML-DSA"},
    
    // Dilithium5 + ECDHE Hybrid - Level 5
    {0x2F42, "TLS_DILITHIUM5_ECDHE_P521_AES_256_GCM_SHA384", 1, "ECDHE-P521", "Dilithium5"},
    {0x2F43, "TLS_DILITHIUM5_X448_AES_256_GCM_SHA384", 1, "X448", "Dilithium5"},
    
    // SPHINCS+ + ECDHE Hybrid - Level 5
    {0x2F33, "TLS_SPHINCS_SHA256_256S_ECDHE_P521_AES_256_GCM", 1, "ECDHE-P521", "SPHINCS+-SHA256-256s"},
    {0x2F34, "TLS_SPHINCS_SHA256_256F_X448_AES_256_GCM", 1, "X448", "SPHINCS+-SHA256-256f"},
    
    // ====== PQC-ONLY (Pure Post-Quantum) ======
    
    // Level 3 PQC-Only
    {0x2F50, "TLS_DILITHIUM3_ML_KEM_768_AES_256_GCM_SHA384", 1, "ML-KEM-768", "Dilithium3"},
    {0x2F51, "TLS_FALCON_1024_ML_KEM_768_AES_256_GCM_SHA384", 1, "ML-KEM-768", "Falcon-1024"},
    
    // Level 5 PQC-Only
    {0x2F52, "TLS_DILITHIUM5_ML_KEM_1024_AES_256_GCM_SHA384", 1, "ML-KEM-1024", "Dilithium5"},
    {0x2F53, "TLS_SPHINCS_256S_ML_KEM_1024_AES_256_GCM", 1, "ML-KEM-1024", "SPHINCS+-SHA256-256s"},
    
    // ====== NIST Post-Quantum Security Level 1 (AES-128 equivalent) ======
    
    // Original Level 1 PQC values (kept for compatibility)
    // ML-KEM (Kyber) Hybrid Key Exchange - Level 1
    {0x2F01, "TLS_ML_KEM_512_X25519_AES_128_GCM_SHA256", 1, "ML-KEM-512+X25519", "ML-DSA"},
    {0x2F04, "TLS_ML_KEM_512_P256_AES_128_GCM_SHA256", 1, "ML-KEM-512+P256", "ML-DSA"},
    {0x2F4C, "p384_mlkem768", 1, "P384+ML-KEM-768", "ML-DSA"},   
    {0x2FB6, "x25519_mlkem512", 1, "X25519+ML-KEM-512", "ML-DSA"},   
    {0x11EB, "SecP256r1MLKEM768", 1, "secp256r1+ML-KEM-768", "ML-DSA"},
    
    // HQC Hybrid Key Exchange - Level 1 
    {0x2F10, "TLS_HQC_128_X25519_AES_128_GCM_SHA256", 1, "HQC-128+X25519", "Falcon"},
    {0x2F13, "TLS_HQC_128_P256_AES_128_GCM_SHA256", 1, "HQC-128+P256", "ML-DSA"},
    
    // Falcon + ECDHE Hybrid - Level 1
    {0x2F20, "TLS_FALCON_512_ECDHE_P256_AES_128_GCM_SHA256", 1, "ECDHE-P256", "Falcon-512"},
    
    // SPHINCS+ + ECDHE Hybrid - Level 1
    {0x2F30, "TLS_SPHINCS_SHA256_128S_ECDHE_P256_AES_128_GCM", 1, "ECDHE-P256", "SPHINCS+-SHA256-128s"},
    
    // Real-world experimental values - Level 1
    // Chrome/BoringSSL - Kyber512 (Level 1) experimental
    {0xFE31, "TLS_KYBER512_X25519_AES_256_GCM_SHA384", 1, "Kyber512+X25519", "ECDSA"},
    
    // OpenSSL/liboqs - Kyber512 (Level 1) experimental
    {0x0200, "KYBER512_ECDH_NISTP256_WITH_AES_128_GCM_SHA256", 1, "Kyber512+P256", "ECDSA"},
    
    // Cloudflare - Kyber512 (Level 1) experimental
    {0x2F39, "X25519Kyber512Draft00", 1, "X25519+Kyber512", "ECDSA"},
    
    // AWS/Microsoft - Kyber512 (Level 1) experimental
    {0x0507, "TLS_KYBER_512_SECP256R1_AES128_GCM_SHA256", 1, "Kyber512+secp256r1", "ECDSA"},
    
    // TLS 1.2 Cipher Suites (keep existing)
    {0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0, NULL, NULL},
    {0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 0, NULL, NULL},
    {0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0, NULL, NULL},
    {0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 0, NULL, NULL},
    {0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA", 0, NULL, NULL},
    {0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA", 0, NULL, NULL},
    {0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0, NULL, NULL},
    {0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 0, NULL, NULL},
    {0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0, NULL, NULL},
    {0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 0, NULL, NULL},
    {0x0000, NULL, 0, NULL, NULL}
};

// TLS Groups mapping table
static tls_group_t tls_groups[] = {
    // ====== STANDARD ECDHE GROUPS ======
    {0x0017, "secp256r1", 0, NULL, 0},
    {0x0018, "secp384r1", 0, NULL, 0},
    {0x0019, "secp521r1", 0, NULL, 0},
    {0x001D, "x25519", 0, NULL, 0},
    {0x001E, "x448", 0, NULL, 0},
    
    // ====== PQC HYBRID GROUPS - REAL WORLD ======
    
    // Google Chrome/BoringSSL - Currently Deployed
    {0x11EC, "mlkem768_x25519", 1, "ML-KEM-768+X25519", 3},      // Chrome 131+ Current
    {0x6399, "kyber768_x25519", 1, "Kyber768+X25519", 3},        // Chrome 116-130 Legacy
    
    // Cloudflare Production Groups
    {0x2F71, "cloudflare_mlkem768_x25519", 1, "ML-KEM-768+X25519", 3},
    {0x2F72, "cloudflare_kyber768_p384", 1, "Kyber768+P384", 3},
    
    // ====== IETF DRAFT PQC HYBRID GROUPS ======
    
    // ML-KEM Hybrid Groups (IETF Draft)
    {0x2F39, "x25519_kyber512", 1, "X25519+Kyber512", 1},        // Cloudflare Experimental
    {0x1741, "p256_mlkem512", 1, "P256+ML-KEM-512", 1},          // Key! This should be detected
    {0x2F70, "x25519_mlkem512", 1, "X25519+ML-KEM-512", 1},
    {0x2F73, "p384_mlkem768", 1, "P384+ML-KEM-768", 3},
    {0x2F74, "p521_mlkem1024", 1, "P521+ML-KEM-1024", 5},
    
    // OpenSSL/liboqs Specific Groups
    {0x0200, "p256_ml_kem_512_oqs", 1, "P256+ML-KEM-512", 1},
    {0x0201, "p384_ml_kem_768_oqs", 1, "P384+ML-KEM-768", 3},
    {0x0202, "p521_ml_kem_1024_oqs", 1, "P521+ML-KEM-1024", 5},
    
    // ====== DETECTED IN REAL TEST - ADD MISSING GROUP IDs ======
    {0x2F4B, "p256_mlkem512_liboqs", 1, "P256+ML-KEM-512", 1},   // ** DETECTED GROUP ID **
    {0x2F4C, "p384_mlkem768", 1, "P384+ML-KEM-768", 3},          // ** MISSING GROUP ID - ADD THIS **
    {0x2FB6, "x25519_mlkem512", 1, "X25519+ML-KEM-512", 1},      // ** MISSING GROUP ID - ADD THIS **
    {0x11EB, "SecP256r1MLKEM768", 1, "secp256r1+ML-KEM-768", 3}, // ** MISSING GROUP ID - ADD THIS **
    
    // Additional real-world detected values
    {0x2F01, "ml_kem_512_x25519", 1, "ML-KEM-512+X25519", 1},    // IETF Draft
    {0x2F04, "ml_kem_512_p256", 1, "ML-KEM-512+P256", 1},        // IETF Draft
    
    // ====== PURE PQC GROUPS ======
    {0x0100, "mlkem512", 1, "ML-KEM-512", 1},                    // Pure ML-KEM-512
    {0x0101, "mlkem768", 1, "ML-KEM-768", 3},                    // Pure ML-KEM-768
    {0x0102, "mlkem1024", 1, "ML-KEM-1024", 5},                  // Pure ML-KEM-1024
    
    // Chrome Experimental Values
    {0xFE31, "kyber512_x25519_experimental", 1, "Kyber512+X25519", 1},
    
    // AWS/Microsoft Values
    {0x0507, "aws_kyber512_secp256r1", 1, "Kyber512+secp256r1", 1},
    
    {0x0000, NULL, 0, NULL, 0}  // Terminator
};

// Function prototypes
void print_analysis_results(void);
void save_analysis_csv_report(void);
void analyze_pcap_file(const char* filename, int port);
void list_interfaces(void);
char* select_interface(void);
int is_interface_available(const char* interface_name);
const char* get_interface_type_and_purpose(const char* name, const char* description);
const char* get_cipher_suite_name(uint16_t value);
cipher_suite_t* get_cipher_suite_details(uint16_t value);
const char* get_tls_version_name(uint16_t version);
void analyze_quantum_vulnerability(const char* cipher_name, session_info_t* session);
char* extract_sni_and_versions(const unsigned char* data, int len, char* client_version, char* supported_versions, char* supported_groups);
char* parse_server_hello_enhanced(const unsigned char* data, int len, char* negotiated_version, char* cipher_name, char* negotiated_group);
void add_session_info_enhanced(const char* sni, const char* src_ip, const char* dst_ip, int src_port, int dst_port, 
                              const char* client_version, const char* negotiated_version, 
                              const char* cipher_suite, const char* supported_versions);
void ask_sni_filter(void);
int matches_sni_filter(const char* sni);
const char* get_tls_level(const char* version);
const char* get_vulnerable_field(const char* cipher_suite);
const char* get_vulnerability_level(const char* vulnerable_field);
int is_pqc_algorithm_vulnerable(const char* algorithm);
void analyze_certificate(const unsigned char* cert_data, int cert_len, session_info_t* session);
void analyze_certificate_from_sni(const char* hostname, session_info_t* session);
void analyze_domains_from_file(const char* filename);
int is_sni_already_displayed(const char* sni);
void mark_sni_as_displayed(const char* sni);
pending_connection_t* find_or_create_pending_connection(const char* src_ip, int src_port, const char* dst_ip, int dst_port);
void display_completed_connection_enhanced(pending_connection_t* conn, const char* negotiated_version, const char* cipher_name, const char* negotiated_group);
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void process_tls_packet(const unsigned char* data, int len, struct iphdr* ip_hdr, struct tcphdr* tcp_hdr);
void parse_certificate_message(const unsigned char* data, int len);
void signal_handler(int sig);
void print_usage(const char* prog_name);
void print_banner(void);
int get_pqc_security_level(const char* kem, const char* sig);
void normalize_connection_key(char *key, const char *src_ip, int src_port, const char *dst_ip, int dst_port);

// Hybrid parsing function prototypes
const unsigned char* find_pattern(const unsigned char* haystack, size_t haystack_len, const unsigned char* needle, size_t needle_len);
const char* extract_public_key_algorithm_fast(const unsigned char* cert_data, size_t cert_len);
int extract_issuer_cn_fast(const unsigned char* cert_data, size_t cert_len, char* issuer_buffer, size_t buffer_size);
int detect_validity_period_fast(const unsigned char* cert_data, size_t cert_len, int* has_short_validity);
void analyze_certificate_hybrid(const unsigned char* cert_data, int cert_len, session_info_t* session);
static int validate_certificate_input(const unsigned char* cert_data, size_t cert_len);

// TLS Groups functions
const char* get_group_name(uint16_t group_id);
tls_group_t* get_group_details(uint16_t group_id);
int is_pqc_key_exchange_group(uint16_t group_id);
int is_pqc_key_exchange_group_by_name(const char* group_name);
int get_pqc_security_level_by_group(uint16_t group_id);
tls_group_t* get_group_details_by_name(const char* group_name);

// TLS Group name retrieval function
const char* get_group_name(uint16_t group_id) {
    for (int i = 0; tls_groups[i].name != NULL; i++) {
        if (tls_groups[i].group_id == group_id) {
            return tls_groups[i].name;
        }
    }
    
    static char unknown_group[32];
    snprintf(unknown_group, sizeof(unknown_group), "Unknown (0x%04X)", group_id);
    return unknown_group;
}

// TLS Group details retrieval function
tls_group_t* get_group_details(uint16_t group_id) {
    for (int i = 0; tls_groups[i].name != NULL; i++) {
        if (tls_groups[i].group_id == group_id) {
            return &tls_groups[i];
        }
    }
    return NULL;
}

// Check if PQC key exchange group (Group ID based)
int is_pqc_key_exchange_group(uint16_t group_id) {
    tls_group_t* group = get_group_details(group_id);
    return (group && group->is_pqc_hybrid);
}

// Check if PQC key exchange group (name based)
int is_pqc_key_exchange_group_by_name(const char* group_name) {
    if (!group_name) return 0;
    
    for (int i = 0; tls_groups[i].name != NULL; i++) {
        if (strcmp(tls_groups[i].name, group_name) == 0) {
            return tls_groups[i].is_pqc_hybrid;
        }
    }
    return 0;
}

// Get PQC security level by group
int get_pqc_security_level_by_group(uint16_t group_id) {
    tls_group_t* group = get_group_details(group_id);
    return group ? group->security_level : 0;
}

// Get group details by name
tls_group_t* get_group_details_by_name(const char* group_name) {
    if (!group_name) return NULL;
    
    for (int i = 0; tls_groups[i].name != NULL; i++) {
        if (strcmp(tls_groups[i].name, group_name) == 0) {
            return &tls_groups[i];
        }
    }
    return NULL;
}

// Display application banner and feature information
void print_banner(void) {
    printf("\n%s==============================================================================\n", COLOR_CYAN);
    printf(    "                         TLS Packet Analyzer for Linux\n");
    printf(    "                      With Quantum Vulnerability Analysis\n");
    printf(    "                                 C Version 1.0\n");
    printf("===============================================================================%s\n\n", COLOR_RESET);
    
    printf("%s[INFO] Key Features:%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("    • Live/offline TLS capture & interface selection\n");
    printf("    • Post-Quantum Cryptography detection (ML-KEM, Falcon, SPHINCS+)\n");
    printf("    • Quantum vulnerability assessment for TLS 1.0-1.3 protocols\n");
    printf("    • SNI filtering & X.509 certificate inspection\n");
    printf("    • Automated Excel reporting with security recommendations\n\n");
    
    printf("%s[INFO] Post-Quantum Cryptography Support:%s\n", COLOR_GREEN, COLOR_RESET);
    printf("    • ML-KEM (Kyber) 512/768/1024 + ECDHE hybrid key exchange\n");
    printf("    • HQC-128 + ECDHE hybrid key exchange\n");
    printf("    • Falcon-512/1024, Dilithium3/5, ML-DSA, SPHINCS+ digital signatures\n");
    printf("    • Security Level 1/3/5 based vulnerability assessment\n");
    printf("    • Real-world Chrome/Cloudflare PQC detection (Level 3)\n");
    printf("    • TLS 1.3 hybrid and PQC-only algorithms\n\n");
    
    printf("%s[INFO] Quantum Vulnerable Algorithms:%s\n", COLOR_RED, COLOR_RESET);
    printf("    • RSA: Shor's algorithm can factor large numbers\n");
    printf("    • ECDSA/ECDHE: Shor's algorithm can solve discrete log\n");
    printf("    • DH/DHE: Vulnerable to quantum discrete log attacks\n");
    printf("    • AES-128: Security reduced to 64-bit by Grover's algorithm\n");
    printf("    • Level 1 PQC: Conservative analysis flags as vulnerable\n\n");
    
    printf("%s[INFO] Quantum Resistant:%s\n", COLOR_GREEN, COLOR_RESET);
    printf("    • AES-256: Recommended (AES-128 reduced security)\n");
    printf("    • SHA-384/512: Recommended (SHA-256 reduced security)\n");
    printf("    • ChaCha20: Symmetric ciphers with sufficient key lengths\n");
    printf("    • ML-KEM Level 3/5: Post-quantum key encapsulation\n");
    printf("    • Dilithium3/5, Falcon-1024, SPHINCS+ Level 3/5: Post-quantum signatures\n\n");

    printf("%s[QUICK START]%s\n", COLOR_CYAN, COLOR_RESET);
    printf("    • List interfaces: sudo %s -L\n", "tls_analyzer");
    printf("    • Interactive mode: sudo %s -I\n", "tls_analyzer");
    printf("    • Auto capture: sudo %s\n", "tls_analyzer");
    printf("    • Local testing: sudo %s -l\n", "tls_analyzer");
    printf("    • Stop capture and see analysis results: Ctrl+C \n");
}

// Check if a PQC algorithm is vulnerable based on NIST security levels
int is_pqc_algorithm_vulnerable(const char* algorithm) {
    if (!algorithm) return 0;
    
    // Level 1 (128-bit security) - Consider vulnerable for conservative analysis
    if (strstr(algorithm, "ML-KEM-512") || strstr(algorithm, "Kyber512")) {
        return 1; // Level 1 KEM
    }
    if (strstr(algorithm, "Falcon-512")) {
        return 1; // Level 1 signature
    }
    if (strstr(algorithm, "128s") || strstr(algorithm, "128f")) {
        return 1; // SPHINCS+ Level 1
    }
    if (strstr(algorithm, "HQC-128")) {
        return 1; // HQC Level 1
    }
    if (strstr(algorithm, "Dilithium2")) {
        return 1; // Level 1 signature
    }
    
    // Level 3 (192-bit security) - Consider safe
    if (strstr(algorithm, "ML-KEM-768") || strstr(algorithm, "Kyber768")) {
        return 0; // Level 3 KEM - SAFE
    }
    if (strstr(algorithm, "Falcon-1024")) {
        return 0; // Level 5 signature (actually) - SAFE
    }
    if (strstr(algorithm, "192s") || strstr(algorithm, "192f")) {
        return 0; // SPHINCS+ Level 3 - SAFE
    }
    if (strstr(algorithm, "Dilithium3")) {
        return 0; // Level 3 signature - SAFE
    }
    
    // Level 5 (256-bit security) - Consider safe
    if (strstr(algorithm, "ML-KEM-1024") || strstr(algorithm, "Kyber1024")) {
        return 0; // Level 5 KEM - SAFE
    }
    if (strstr(algorithm, "Dilithium5")) {
        return 0; // Level 5 signature - SAFE
    }
    if (strstr(algorithm, "256s") || strstr(algorithm, "256f")) {
        return 0; // SPHINCS+ Level 5 - SAFE
    }
    
    return 0; // Default to safe for unknown algorithms
}

// Hybrid parsing functions
const unsigned char* find_pattern(const unsigned char* haystack, size_t haystack_len,
                                        const unsigned char* needle, size_t needle_len) {
    if (needle_len == 0 || haystack_len < needle_len) {
        return NULL;
    }
    
    // For small patterns like OIDs, use optimized linear search
    if (needle_len <= 16) {
        const unsigned char first_byte = needle[0];
        const unsigned char last_byte = needle[needle_len - 1];
        
        for (size_t i = 0; i <= haystack_len - needle_len; i++) {
            // Quick first/last byte check before full comparison
            if (haystack[i] == first_byte && haystack[i + needle_len - 1] == last_byte) {
                if (memcmp(haystack + i, needle, needle_len) == 0) {
                    return haystack + i;
                }
            }
        }
    } else {
        // Fallback to standard search for longer patterns
        for (size_t i = 0; i <= haystack_len - needle_len; i++) {
            if (memcmp(haystack + i, needle, needle_len) == 0) {
                return haystack + i;
            }
        }
    }
    return NULL;
}

static int validate_certificate_input(const unsigned char* cert_data, size_t cert_len) {
    if (!cert_data || cert_len < 20) {
        return 0; // Too small to be a valid certificate
    }
    
    // Basic ASN.1 DER validation - should start with SEQUENCE
    if (cert_data[0] != 0x30) {
        return 0;
    }
    
    // Check if length encoding is reasonable
    if (cert_data[1] & 0x80) {
        // Long form length
        int len_bytes = cert_data[1] & 0x7f;
        if (len_bytes > 4 || len_bytes == 0) {
            return 0; // Invalid length encoding
        }
    }
    
    return 1;
}

const char* extract_public_key_algorithm_fast(const unsigned char* cert_data, size_t cert_len) {
    for (int i = 0; public_key_algorithms[i].oid != NULL; i++) {
        const algorithm_info_t* alg = &public_key_algorithms[i];
        
        if (find_pattern(cert_data, cert_len, alg->oid, alg->oid_len)) {
                    if (alg->is_pqc) {
            } else {
                printf("%s[SUCCESS] Classical Algorithm detected: %s via FAST parsing%s\n",
                       COLOR_GREEN, alg->name, COLOR_RESET);
            }
            return alg->name;
        }
    }
    
    return NULL;
}

int extract_issuer_cn_fast(const unsigned char* cert_data, size_t cert_len, 
                          char* issuer_buffer, size_t buffer_size) {
    const unsigned char* oid_pos = NULL;
    size_t oid_size = 0;
    
    // Try CN first
    oid_pos = find_pattern(cert_data, cert_len, CN_OID, sizeof(CN_OID));
    if (oid_pos) {
        oid_size = sizeof(CN_OID);
    } else {
        // Try Organization if CN not found
        oid_pos = find_pattern(cert_data, cert_len, ORG_OID, sizeof(ORG_OID));
        if (!oid_pos) {
            return 0;
        }
        oid_size = sizeof(ORG_OID);
    }
    
    // Move past the OID
    const unsigned char* data_pos = oid_pos + oid_size;
    size_t remaining = cert_len - (data_pos - cert_data);
    
    if (remaining < 3) {
        return 0;
    }
    
    // Look for ASN.1 string types within next 10 bytes
    for (int skip = 0; skip < 10 && skip < remaining - 2; skip++) {
        unsigned char tag = data_pos[skip];
        // ASN.1 string types: UTF8String(0x0c), PrintableString(0x13), T61String(0x14), IA5String(0x16)
        if (tag == 0x0c || tag == 0x13 || tag == 0x14 || tag == 0x16) {
            unsigned char length = data_pos[skip + 1];
            if (length > 0 && length < 128 && length < buffer_size - 1 && 
                skip + 2 + length <= remaining) {
                
                memcpy(issuer_buffer, data_pos + skip + 2, length);
                issuer_buffer[length] = '\0';
                
                // Clean problematic characters for CSV compatibility
                for (int i = 0; issuer_buffer[i]; i++) {
                    if (issuer_buffer[i] == ',' || issuer_buffer[i] == '"' || 
                        issuer_buffer[i] == '\n' || issuer_buffer[i] == '\r') {
                        issuer_buffer[i] = '_';
                    }
                }
                
                return 1;
            }
        }
    }
    
    return 0;
}

int detect_validity_period_fast(const unsigned char* cert_data, size_t cert_len, 
                               int* has_short_validity) {
    
    *has_short_validity = 0;
    
    int utc_time_count = 0;
    int gen_time_count = 0;
    
    for (size_t i = 0; i < cert_len - 1; i++) {
        if (cert_data[i] == UTC_TIME_TAG) {
            utc_time_count++;
        } else if (cert_data[i] == GENERALIZED_TIME_TAG) {
            gen_time_count++;
        }
    }
    
    if (utc_time_count + gen_time_count >= 2) {
        printf("%s[INFO] Certificate validity period detected (%d UTC, %d GeneralizedTime)%s\n",
               COLOR_GREEN, utc_time_count, gen_time_count, COLOR_RESET);
        
        if (cert_len < 2048) {
            *has_short_validity = 1;
        }
        
        return 1;
    }
    
    return 0;
}

void analyze_certificate_hybrid(const unsigned char* cert_data, int cert_len, 
                               session_info_t* session) {
    // Validation
    if (!validate_certificate_input(cert_data, cert_len)) {
        strcpy(session->pub_key_type, "Invalid_Format");
        strcpy(session->issuer, "Invalid_Format");
        strcpy(session->expiry_date, "Invalid_Format");
        session->expiry_days = -1;
        return;
    }
    
    int need_openssl_pubkey = 0;
    int need_openssl_issuer = 0;
    int need_openssl_validity = 1;
    
    // Try fast public key extraction
    const char* fast_pubkey = extract_public_key_algorithm_fast(cert_data, cert_len);
    if (fast_pubkey) {
        strncpy(session->pub_key_type, fast_pubkey, 63);
        session->pub_key_type[63] = '\0';
        strcpy(pubKey, fast_pubkey);
    } else {
        need_openssl_pubkey = 1;
    }
    
    // Try fast issuer extraction
    char fast_issuer[MAX_ISSUER_LEN];
    if (extract_issuer_cn_fast(cert_data, cert_len, fast_issuer, sizeof(fast_issuer))) {
        strncpy(session->issuer, fast_issuer, MAX_ISSUER_LEN - 1);
        session->issuer[MAX_ISSUER_LEN - 1] = '\0';
    } else {
        need_openssl_issuer = 1;
    }
    
    // Fast validity detection (informational only)
    int has_short_validity = 0;
    detect_validity_period_fast(cert_data, cert_len, &has_short_validity);
    
    // OpenSSL fallback for missing fields
    if (need_openssl_pubkey || need_openssl_issuer || need_openssl_validity) {
        X509 *cert = NULL;
        const unsigned char *p = cert_data;
        
        cert = d2i_X509(NULL, &p, cert_len);
        if (!cert) {
            if (!fast_pubkey) strcpy(session->pub_key_type, "Parse_Failed");
            if (need_openssl_issuer) strcpy(session->issuer, "Parse_Failed");
            return;
        }
        
        session->has_certificate = 1;
        
        // OpenSSL public key extraction if fast method failed
        if (need_openssl_pubkey) {
            EVP_PKEY *pkey = X509_get_pubkey(cert);
            if (pkey) {
                int key_type = EVP_PKEY_base_id(pkey);
                switch (key_type) {
                    case EVP_PKEY_RSA:
                        strcpy(session->pub_key_type, "RSA");
                        strcpy(pubKey, "RSA");
                        break;
                    case EVP_PKEY_EC:
                        strcpy(session->pub_key_type, "ECDSA");
                        strcpy(pubKey, "ECDSA");
                        break;
                    default:
                        snprintf(session->pub_key_type, 63, "Unknown_Type_%d", key_type);
                        strcpy(pubKey, "Unknown");
                        break;
                }
                EVP_PKEY_free(pkey);
            } else {
                strcpy(session->pub_key_type, "Extract_Failed");
                strcpy(pubKey, "Extract_Failed");
            }
        }
        
        // OpenSSL issuer extraction if fast method failed
        if (need_openssl_issuer) {
            X509_NAME *issuer_name = X509_get_issuer_name(cert);
            if (issuer_name) {
                // Try CN first
                char *cn = NULL;
                int cn_len = X509_NAME_get_text_by_NID(issuer_name, NID_commonName, NULL, 0);
                if (cn_len > 0) {
                    cn = malloc(cn_len + 1);
                    if (cn && X509_NAME_get_text_by_NID(issuer_name, NID_commonName, cn, cn_len + 1) > 0) {
                        strncpy(session->issuer, cn, MAX_ISSUER_LEN - 1);
                        session->issuer[MAX_ISSUER_LEN - 1] = '\0';
                        free(cn);
                        goto openssl_issuer_done;
                    }
                    if (cn) free(cn);
                }
                
                // Try Organization if CN failed
                char *org = NULL;
                int org_len = X509_NAME_get_text_by_NID(issuer_name, NID_organizationName, NULL, 0);
                if (org_len > 0) {
                    org = malloc(org_len + 1);
                    if (org && X509_NAME_get_text_by_NID(issuer_name, NID_organizationName, org, org_len + 1) > 0) {
                        strncpy(session->issuer, org, MAX_ISSUER_LEN - 1);
                        session->issuer[MAX_ISSUER_LEN - 1] = '\0';
                        free(org);
                        goto openssl_issuer_done;
                    }
                    if (org) free(org);
                }
                
                // Use full DN as last resort
                char *dn_str = X509_NAME_oneline(issuer_name, NULL, 0);
                if (dn_str) {
                    strncpy(session->issuer, dn_str, MAX_ISSUER_LEN - 1);
                    session->issuer[MAX_ISSUER_LEN - 1] = '\0';
                    OPENSSL_free(dn_str);
                }
                
                openssl_issuer_done:;
            } else {
                strcpy(session->issuer, "Extract_Failed");
            }
        }
        
        // Always use OpenSSL for validity (most reliable)
        const ASN1_TIME *not_after = X509_get0_notAfter(cert);
        if (not_after) {
            struct tm tm_expiry;
            memset(&tm_expiry, 0, sizeof(tm_expiry));
            
            if (ASN1_TIME_to_tm(not_after, &tm_expiry)) {
                tm_expiry.tm_isdst = -1;
                if (strftime(session->expiry_date, MAX_EXPIRY_LEN - 1, "%Y-%m-%d", &tm_expiry) > 0) {
                    time_t now = time(NULL);
                    time_t expiry_time = mktime(&tm_expiry);
                    if (expiry_time != -1) {
                        double diff = difftime(expiry_time, now);
                        session->expiry_days = (int)(diff / (24.0 * 3600.0));
                    } else {
                        session->expiry_days = -1;
                    }
                } else {
                    strcpy(session->expiry_date, "Format_Error");
                    session->expiry_days = -1;
                }
            } else {
                strcpy(session->expiry_date, "Parse_Error");
                session->expiry_days = -1;
            }
        } else {
            strcpy(session->expiry_date, "No_Expiry");
            session->expiry_days = -1;
        }
        
        X509_free(cert);
    }
    
    // Simple output like the original code
    printf("%s[INFO] Public Key: %s%s\n", COLOR_YELLOW, session->pub_key_type, COLOR_RESET);
    printf("%s[INFO] Certificate Issuer: %s%s\n", COLOR_GREEN, session->issuer, COLOR_RESET);
    printf("%s[INFO] Certificate expires: %s (%d days)%s\n", 
           COLOR_CYAN, session->expiry_date, session->expiry_days, COLOR_RESET);
    
    if (session->expiry_days <= 30 && session->expiry_days >= 0) {
        printf("%s[WARNING] Certificate expires soon!%s\n", COLOR_RED, COLOR_RESET);
    }
}

// Enhanced cipher suite name retrieval with PQC support
const char* get_cipher_suite_name(uint16_t value) {
    for (int i = 0; cipher_suites[i].name != NULL; i++) {
        if (cipher_suites[i].value == value) {
            return cipher_suites[i].name;
        }
    }
    
    // Check for PQC experimental and production range
    if ((value >= 0x2F01 && value <= 0x2F09) ||  // ML-KEM Series (Level 1,3,5)
        (value >= 0x2F10 && value <= 0x2F13) ||  // HQC-128 (Level 1)
        (value >= 0x2F20 && value <= 0x2F22) ||  // Falcon (Level 1,3,5)
        (value >= 0x2F30 && value <= 0x2F34) ||  // SPHINCS+ (Level 1,3,5)
        (value >= 0x2F39 && value <= 0x2F39) ||  // Cloudflare Experimental
        (value >= 0x2F40 && value <= 0x2F43) ||  // Dilithium (Level 3,5)
        (value >= 0x2F50 && value <= 0x2F53) ||  // PQC-Only combinations
        (value >= 0x2F71 && value <= 0x2F72) ||  // Cloudflare Production
        (value >= 0x0200 && value <= 0x0200) ||  // OpenSSL/liboqs
        (value >= 0x0507 && value <= 0x0507) ||  // AWS/Microsoft
        (value >= 0x6399 && value <= 0x6399) ||  // Chrome Legacy Kyber768
        (value >= 0x11EC && value <= 0x11EC) ||  // Chrome Current ML-KEM768
        (value >= 0xFE31 && value <= 0xFE31)) {  // Chrome Experimental
        
        // Determine security level
        cipher_suite_t* details = get_cipher_suite_details(value);
        if (details) {
            if (strstr(details->kem_algorithm, "512") || strstr(details->sig_algorithm, "512") ||
                strstr(details->kem_algorithm, "128") || strstr(details->sig_algorithm, "128s")) {
                return "PQC Hybrid Cipher Suite (Level 1)";
            } else if (strstr(details->kem_algorithm, "768") || strstr(details->sig_algorithm, "Dilithium3") ||
                      strstr(details->sig_algorithm, "192")) {
                return "PQC Hybrid Cipher Suite (Level 3)";
            } else if (strstr(details->kem_algorithm, "1024") || strstr(details->sig_algorithm, "Dilithium5") ||
                      strstr(details->sig_algorithm, "256")) {
                return "PQC Hybrid Cipher Suite (Level 5)";
            }
        }
        return "PQC Hybrid Cipher Suite";
    }

    // Check if it is TLS 1.3
    if ((value >= 0x1301 && value <= 0x1305) || value == 0x1307) {
        return "TLS 1.3 Cipher Suite";
    }
    
    static char unknown_cipher[64];
    snprintf(unknown_cipher, sizeof(unknown_cipher), "Unknown (0x%04X)", value);
    return unknown_cipher;
}

// Get PQC cipher suite details
cipher_suite_t* get_cipher_suite_details(uint16_t value) {
    for (int i = 0; cipher_suites[i].name != NULL; i++) {
        if (cipher_suites[i].value == value) {
            return &cipher_suites[i];
        }
    }
    return NULL;
}

// Convert TLS version number to human-readable string
const char* get_tls_version_name(uint16_t version) {
    for (int i = 0; tls_versions[i].name != NULL; i++) {
        if (tls_versions[i].version == version) {
            return tls_versions[i].name;
        }
    }
    
    // Check for GREASE values (RFC 8701)
    if ((version & 0x0f0f) == 0x0a0a) {
        static char grease_buf[32];
        snprintf(grease_buf, sizeof(grease_buf), "GREASE (0x%04X)", version);
        return grease_buf;
    }
    
    // Check for other TLS 1.3 draft versions
    if ((version >= 0x7f00 && version <= 0x7fff)) {
        static char draft_buf[32];
        snprintf(draft_buf, sizeof(draft_buf), "TLS 1.3 Draft (0x%04X)", version);
        return draft_buf;
    }
    
    // Future TLS versions
    if (version >= 0x0305 && version <= 0x030f) {
        static char future_buf[32];
        snprintf(future_buf, sizeof(future_buf), "Future TLS (0x%04X)", version);
        return future_buf;
    }
    
    // Completely unknown
    static char unknown_buf[32];
    snprintf(unknown_buf, sizeof(unknown_buf), "Unknown (0x%04X)", version);
    return unknown_buf;
}

// Determine security level based on TLS version
const char* get_tls_level(const char* version) {
    if (strstr(version, "TLS 1.3")) {
        return "H";
    } else if (strstr(version, "TLS 1.2")) {
        return "M";
    } else if (strstr(version, "TLS 1.1") || strstr(version, "TLS 1.0")) {
        return "L";
    } else if (strstr(version, "SSL")) {
        return "L";
    }
    return "L";
}

// Identify vulnerable cryptographic components in cipher suite
const char* get_vulnerable_field(const char* cipher_suite) {
    // Check for PQC hybrid first
    if (strstr(cipher_suite, "ML_KEM") || strstr(cipher_suite, "HQC")) {
        return "PQC_Hybrid";
    } else if (strstr(cipher_suite, "FALCON") || strstr(cipher_suite, "SPHINCS")) {
        return "PQC_Hybrid";
    } else if (strstr(cipher_suite, "RSA") && strstr(cipher_suite, "ECDHE")) {
        return "RSA+ECDHE";
    } else if (strstr(cipher_suite, "RSA")) {
        return "RSA";
    } else if (strstr(cipher_suite, "ECDHE") || strstr(cipher_suite, "ECDSA")) {
        return "ECDHE";
    } else if (strstr(cipher_suite, "AES_128")) {
        return "AES_128";
    } else if (strstr(cipher_suite, "DH")) {
        return "DH";
    } else if (strstr(cipher_suite, "TLS_AES") || strstr(cipher_suite, "TLS_CHACHA20")) {
        return "None";
    }
    return "Unknown";
}

// Determine vulnerability level based on identified components
const char* get_vulnerability_level(const char* vulnerable_field) {
    if (strcmp(vulnerable_field, "None") == 0) {
        return "H";
    } else if (strcmp(vulnerable_field, "PQC_Hybrid") == 0) {
        return "H"; // Will be determined by detailed analysis
    } else if (strcmp(vulnerable_field, "AES_128") == 0) {
        return "M";
    } else if (strstr(vulnerable_field, "RSA") || strstr(vulnerable_field, "ECDHE") || strstr(vulnerable_field, "DH")) {
        return "L";
    }
    return "L";
}

// Get PQC security level based on algorithm names
int get_pqc_security_level(const char* kem, const char* sig) {
    // KEM algorithm based level determination
    if (strstr(kem, "512") || strstr(sig, "512")) return 1;
    if (strstr(kem, "768") || strstr(sig, "Dilithium3")) return 3;
    if (strstr(kem, "1024") || strstr(sig, "Dilithium5") || strstr(sig, "Falcon-1024")) return 5;
    if (strstr(sig, "128s")) return 1;
    if (strstr(sig, "192s")) return 3;
    if (strstr(sig, "256s")) return 5;
    
    return 1; // Default value
}

// Enhanced quantum vulnerability analysis with PQC hybrid support
void analyze_quantum_vulnerability(const char* cipher_name, session_info_t* session) {
    printf("\n%sQuantum Computer Vulnerability Analysis:%s\n", COLOR_BOLD, COLOR_RESET);
    
    int vulnerable_count = 0;
    int total_algorithms = 0;
    
    // Initialize PQC flags
    session->is_pqc_hybrid = 0;
    session->classic_vuln = 0;
    session->pqc_vuln = 0;
    strcpy(session->pqc_kem, "None");
    strcpy(session->pqc_sig, "None");
    
    // Check for PQC Hybrid
    if (strstr(cipher_name, "ML_KEM") || strstr(cipher_name, "HQC") || 
        strstr(cipher_name, "FALCON") || strstr(cipher_name, "SPHINCS") ||
        strstr(cipher_name, "KYBER")) {
        
        session->is_pqc_hybrid = 1;
        stats.pqc_hybrid_count++;
        
        // Analyze KEM (Key Encapsulation) - All Levels
        if (strstr(cipher_name, "ML_KEM_512") || strstr(cipher_name, "KYBER512")) {
            strcpy(session->pqc_kem, "ML-KEM-512");
            session->pqc_vuln = is_pqc_algorithm_vulnerable("ML-KEM-512");
        } else if (strstr(cipher_name, "ML_KEM_768") || strstr(cipher_name, "KYBER_768")) {
            strcpy(session->pqc_kem, "ML-KEM-768");
            session->pqc_vuln = is_pqc_algorithm_vulnerable("ML-KEM-768");
        } else if (strstr(cipher_name, "ML_KEM_1024") || strstr(cipher_name, "KYBER_1024")) {
            strcpy(session->pqc_kem, "ML-KEM-1024");
            session->pqc_vuln = is_pqc_algorithm_vulnerable("ML-KEM-1024");
        } else if (strstr(cipher_name, "HQC_128")) {
            strcpy(session->pqc_kem, "HQC-128");
            session->pqc_vuln = is_pqc_algorithm_vulnerable("HQC-128");
        }
        
        // Analyze classic component in hybrid
        if (strstr(cipher_name, "X25519") || strstr(cipher_name, "X448")) {
            session->classic_vuln = 1;
        } else if (strstr(cipher_name, "P256") || strstr(cipher_name, "P384") || strstr(cipher_name, "P521")) {
            session->classic_vuln = 1;
        } else if (strstr(cipher_name, "ECDHE")) {
            session->classic_vuln = 1;
        }
        
        // Analyze signature - All Levels
        if (strstr(cipher_name, "FALCON_512")) {
            strcpy(session->pqc_sig, "Falcon-512");
            session->pqc_vuln |= is_pqc_algorithm_vulnerable("Falcon-512");
        } else if (strstr(cipher_name, "FALCON_1024")) {
            strcpy(session->pqc_sig, "Falcon-1024");
            session->pqc_vuln |= is_pqc_algorithm_vulnerable("Falcon-1024");
        } else if (strstr(cipher_name, "DILITHIUM3")) {
            strcpy(session->pqc_sig, "Dilithium3");
            session->pqc_vuln |= is_pqc_algorithm_vulnerable("Dilithium3");
        } else if (strstr(cipher_name, "DILITHIUM5")) {
            strcpy(session->pqc_sig, "Dilithium5");
            session->pqc_vuln |= is_pqc_algorithm_vulnerable("Dilithium5");
        } else if (strstr(cipher_name, "SPHINCS")) {
            if (strstr(cipher_name, "128s") || strstr(cipher_name, "128f")) {
                strcpy(session->pqc_sig, "SPHINCS+-128");
                session->pqc_vuln |= is_pqc_algorithm_vulnerable("128s");
            } else if (strstr(cipher_name, "192s") || strstr(cipher_name, "192f")) {
                strcpy(session->pqc_sig, "SPHINCS+-192");
                session->pqc_vuln |= is_pqc_algorithm_vulnerable("192s");
            } else if (strstr(cipher_name, "256s") || strstr(cipher_name, "256f")) {
                strcpy(session->pqc_sig, "SPHINCS+-256");
                session->pqc_vuln |= is_pqc_algorithm_vulnerable("256s");
            } else {
                strcpy(session->pqc_sig, "SPHINCS+-Unknown");
            }
        } else {
            strcpy(session->pqc_sig, "ML-DSA");
        }
        
        total_algorithms++;
        
    } else if (strstr(cipher_name, "TLS_AES") || strstr(cipher_name, "TLS_CHACHA20")) {
        total_algorithms++;
    } else {
        // Analyze traditional key exchange
        if (strstr(cipher_name, "ECDHE")) {
            vulnerable_count++;
            session->classic_vuln = 1;
        } else if (strstr(cipher_name, "RSA") && !strstr(cipher_name, "ECDHE")) {
            vulnerable_count++;
            session->classic_vuln = 1;
        } else if (strstr(cipher_name, "DHE")) {
            vulnerable_count++;
            session->classic_vuln = 1;
        }
        total_algorithms++;
        
        // Analyze authentication silently
        if (strstr(cipher_name, "ECDSA") || strstr(cipher_name, "RSA")) {
            vulnerable_count++;
        }
        total_algorithms++;
    }
    
    // Update statistics with enhanced PQC analysis
    if (session->is_pqc_hybrid) {
        int security_level = get_pqc_security_level(session->pqc_kem, session->pqc_sig);
        
        // Print security level information
        switch (security_level) {
            case 1:
                printf("%s[INFO] PQC Security Level: 1 (128-bit equivalent)%s\n", COLOR_YELLOW, COLOR_RESET);
                if (session->classic_vuln) {
                    printf("%s[WARNING] Hybrid contains quantum-vulnerable classic component%s\n", COLOR_RED, COLOR_RESET);
                }
                break;
                
            case 3:
                printf("%s[INFO] PQC Security Level: 3 (192-bit equivalent)%s\n", COLOR_GREEN, COLOR_RESET);
                printf("%s[INFO] Recommended security level for most applications%s\n", COLOR_GREEN, COLOR_RESET);
                break;
                
            case 5:
                printf("%s[INFO] PQC Security Level: 5 (256-bit equivalent)%s\n", COLOR_GREEN, COLOR_RESET);
                printf("%s[INFO] Maximum security - suitable for long-term protection%s\n", COLOR_GREEN, COLOR_RESET);
                break;
        }
        
        // Migration recommendations
        if (security_level == 1) {
            printf("%s[RECOMMENDATION] Consider migrating to Level 3+ algorithms%s\n", COLOR_CYAN, COLOR_RESET);
        }
        
        // For PQC hybrid: safe if at least one component is safe
        if (!(session->classic_vuln && session->pqc_vuln)) {
            stats.pqc_safe_count++;
        }
    } else {
        // Traditional logic for non-PQC
        if (vulnerable_count == 0) {
            stats.safe_connections++;
        } else if (vulnerable_count < total_algorithms) {
            stats.partial_connections++;
        } else {
            stats.vulnerable_connections++;
        }
    }
}

// Ask user for SNI filtering preferences
void ask_sni_filter(void) {
    char input[10];
    memset(input, 0, sizeof(input));

    printf("\n%s==============================================================================\n", COLOR_YELLOW);
    printf("%s                         SNI filtering mode? (yes / no): %s", COLOR_YELLOW, COLOR_RESET);
    printf("\n%s==============================================================================\n", COLOR_YELLOW);
    
    if (fgets(input, sizeof(input), stdin) != NULL) {
        if (input[0] == 'y' || input[0] == 'Y') {
            sni_filter_enabled = 1;
            char filter_input[MAX_FILTER_LEN];
            memset(filter_input, 0, sizeof(filter_input));
            
            printf("\n==============================================================================\n");
            printf("%s    Enter SNI to filter:%s\n\n", COLOR_CYAN, COLOR_RESET);
            printf("    Input example:\n");
            printf("    > 'google' 'amazon' etc\n\n");
            printf("    Guide: \n");
            printf("    Enter 'google' for related TLS communication\n");
            printf("    or 'www.google.com' for specific TLS communication\n");
            printf("\n%s==============================================================================\n", COLOR_YELLOW, COLOR_RESET);
            printf("%s> %s", COLOR_CYAN, COLOR_RESET);
            
            if (fgets(filter_input, sizeof(filter_input), stdin) != NULL) {
                // Remove newline character
                filter_input[strcspn(filter_input, "\n")] = '\0';
                
                // Parse keywords separated by spaces
                sni_filter.keyword_count = 0;
                char *token = strtok(filter_input, " \t");
                
                while (token != NULL && sni_filter.keyword_count < MAX_KEYWORDS) {
                    strncpy(sni_filter.keywords[sni_filter.keyword_count], token, MAX_KEYWORD_LEN - 1);
                    sni_filter.keywords[sni_filter.keyword_count][MAX_KEYWORD_LEN - 1] = '\0';
                    sni_filter.keyword_count++;
                    token = strtok(NULL, " \t");
                }
                
                if (sni_filter.keyword_count > 0) {
                    printf("\n%s[INFO] SNI filtering enabled. %d keyword(s) loaded%s\n", COLOR_YELLOW, sni_filter.keyword_count, COLOR_RESET);
                    printf("\n==============================================================================\n");
                    printf("                                    Check\n");
                    printf("==============================================================================\n");
                    printf("[INFO] Mode: Real-time packet capture\n");
                    printf("[INFO] Target SNI: ");
                    for (int i = 0; i < sni_filter.keyword_count; i++) {
                        printf("%s", sni_filter.keywords[i]);
                        if (i < sni_filter.keyword_count - 1) {
                            printf(", ");
                        }
                    }
                    printf("\n");
                    printf("[INFO] Press Ctrl+C to stop capture and see analysis results\n\n");
                    
                    printf("=== TLS Packet Analysis Started ===\n");
                    
                } else {
                    sni_filter_enabled = 0;
                    printf("%s[INFO] No valid keywords found. SNI filtering disabled.%s\n", COLOR_RED, COLOR_RESET);
                }
            } else {
                sni_filter_enabled = 0;
                printf("%s[INFO] Invalid input. SNI filtering disabled.%s\n", COLOR_RED, COLOR_RESET);
            }
        } else {
            sni_filter_enabled = 0;
            printf("%s[INFO] SNI filtering disabled%s\n", COLOR_CYAN, COLOR_RESET);
            printf("\n==============================================================================\n");
            printf("                                    Check\n");
            printf("==============================================================================\n");
            printf("[INFO] Mode: Real-time packet capture\n");
            printf("[INFO] Target SNI: All domains (no filter)\n");
            printf("[INFO] Press Ctrl+C to stop capture and see analysis results\n\n");
            
            printf("=== TLS Packet Analysis Started ===\n");
        }
    }
}

// Check if SNI matches the configured filter
int matches_sni_filter(const char* sni) {
    if (!sni_filter_enabled || sni_filter.keyword_count == 0) {
        return 1; // No filter or filter disabled
    }
    
    if (!sni || strlen(sni) == 0 || strcmp(sni, "localhost") == 0) {
        return 1; // Allow empty SNI or localhost when filtering is enabled
    }

    if (!sni || strlen(sni) == 0) {
        return 0; // No SNI to match
    }
    
    // Convert SNI to lowercase for case-insensitive matching
    char sni_lower[MAX_SNI_LEN];
    strncpy(sni_lower, sni, MAX_SNI_LEN - 1);
    sni_lower[MAX_SNI_LEN - 1] = '\0';
    
    for (int i = 0; sni_lower[i]; i++) {
        sni_lower[i] = tolower(sni_lower[i]);
    }
    
    // Check if any keyword matches
    for (int i = 0; i < sni_filter.keyword_count; i++) {
        char keyword_lower[MAX_KEYWORD_LEN];
        strncpy(keyword_lower, sni_filter.keywords[i], MAX_KEYWORD_LEN - 1);
        keyword_lower[MAX_KEYWORD_LEN - 1] = '\0';
        
        for (int j = 0; keyword_lower[j]; j++) {
            keyword_lower[j] = tolower(keyword_lower[j]);
        }
        
        if (strstr(sni_lower, keyword_lower) != NULL) {
            return 1; // Match found
        }
    }
    
    return 0; // No match found
}

// Enhanced SNI extraction with version parsing and groups support
char* extract_sni_and_versions(const unsigned char* data, int len, char* client_version, char* supported_versions, char* supported_groups) {
    if (len < 5 || data[0] != TLS_RECORD_TYPE_HANDSHAKE || data[5] != TLS_HANDSHAKE_CLIENT_HELLO) {
        return NULL;
    }
    
    // Initialize outputs
    strcpy(client_version, "Unknown");
    strcpy(supported_versions, "");
    strcpy(supported_groups, "");
    
    int pos = 9;  // Skip TLS record header(5) + handshake header(4)
    
    // Read ClientHello version (legacy field)
    if (pos + 2 <= len) {
        uint16_t legacy_version = (data[pos] << 8) | data[pos + 1];
        strcpy(client_version, get_tls_version_name(legacy_version));
        pos += 2;
    } else return NULL;
    
    // Skip Random (32 bytes)
    if (pos + 32 > len) return NULL;
    pos += 32;
    
    // Read Session ID Length and skip
    if (pos + 1 > len) return NULL;
    int session_id_len = data[pos++];
    if (pos + session_id_len > len) return NULL;
    pos += session_id_len;
    
    // Read Cipher Suites Length and skip
    if (pos + 2 > len) return NULL;
    int cipher_suites_len = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    if (pos + cipher_suites_len > len) return NULL;
    pos += cipher_suites_len;
    
    // Read Compression Methods Length and skip
    if (pos + 1 > len) return NULL;
    int compression_methods_len = data[pos++];
    if (pos + compression_methods_len > len) return NULL;
    pos += compression_methods_len;
    
    // Extensions
    if (pos + 2 > len) return NULL;
    int extensions_len = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    int extensions_end = pos + extensions_len;
    
    if (extensions_end > len) {
        return NULL;
    }
    
    char* sni = NULL;
    char pqc_groups_buffer[256] = "";
    
    while (pos + 4 <= extensions_end && pos + 4 <= len) {
        uint16_t ext_type = (data[pos] << 8) | data[pos + 1];
        pos += 2;
        uint16_t ext_len = (data[pos] << 8) | data[pos + 1];
        pos += 2;
        
        if (pos + ext_len > extensions_end || pos + ext_len > len) {
            break;
        }
        
        // Server Name Indication (SNI)
        if (ext_type == TLS_EXT_SERVER_NAME && ext_len >= 5) {
            if (pos + 2 > len) break;
            int server_name_list_len = (data[pos] << 8) | data[pos + 1];
            int name_pos = pos + 2;
            
            if (name_pos + 3 <= pos + ext_len && name_pos + 3 <= len && data[name_pos] == 0x00) {
                int name_len = (data[name_pos + 1] << 8) | data[name_pos + 2];
                name_pos += 3;
                
                if (name_len > 0 && name_len < 256 && name_pos + name_len <= pos + ext_len && name_pos + name_len <= len) {
                    sni = malloc(name_len + 1);
                    if (sni) {
                        memcpy(sni, &data[name_pos], name_len);
                        sni[name_len] = '\0';
                    }
                }
            }
        }
        
        // Supported Groups Extension (Key PQC detection!)
        else if (ext_type == TLS_EXT_SUPPORTED_GROUPS && ext_len >= 2) {
            if (pos + 2 > len) break;
            int groups_len = (data[pos] << 8) | data[pos + 1];
            int groups_pos = pos + 2;
            
            strcpy(pqc_groups_buffer, "Groups: ");
            
            if (groups_pos + groups_len <= pos + ext_len && groups_pos + groups_len <= len) {
                for (int i = 0; i < groups_len; i += 2) {
                    if (groups_pos + i + 1 < len) {
                        uint16_t group_id = (data[groups_pos + i] << 8) | data[groups_pos + i + 1];
                        const char* group_name = get_group_name(group_id);
                        
                        if (i > 0) strcat(pqc_groups_buffer, ", ");
                        strncat(pqc_groups_buffer, group_name, 200);
                    }
                }
            }
        }
        
        pos += ext_len;
    }
    
    // Copy groups info to output
    if (strlen(pqc_groups_buffer) > 0) {
        strncpy(supported_groups, pqc_groups_buffer, 255);
        supported_groups[255] = '\0';
    }
    
    return sni;
}

// Enhanced ServerHello parsing with negotiated group support
char* parse_server_hello_enhanced(const unsigned char* data, int len, char* negotiated_version, char* cipher_name, char* negotiated_group) {
    if (len < 6 || data[0] != TLS_RECORD_TYPE_HANDSHAKE || data[5] != TLS_HANDSHAKE_SERVER_HELLO) {
        return NULL;
    }
    
    strcpy(negotiated_version, "Unknown");
    strcpy(cipher_name, "Unknown");
    strcpy(negotiated_group, "Unknown");
    
    int pos = 9;  // Skip headers
    
    if (pos + 2 > len) return NULL;
    
    // Read ServerHello version (legacy field)
    uint16_t legacy_version = (data[pos] << 8) | data[pos + 1];
    strcpy(negotiated_version, get_tls_version_name(legacy_version));
    pos += 2;
    
    // Skip Random (32 bytes)
    if (pos + 32 > len) return NULL;
    pos += 32;
    
    // Read Session ID Length and skip
    if (pos + 1 > len) return NULL;
    int session_id_len = data[pos++];
    if (pos + session_id_len > len) return NULL;
    pos += session_id_len;
    
    // Read Cipher Suite
    if (pos + 2 > len) return NULL;
    uint16_t cipher_suite = (data[pos] << 8) | data[pos + 1];
    strcpy(cipher_name, get_cipher_suite_name(cipher_suite));
    pos += 2;
    
    // Skip Compression Method
    if (pos + 1 > len) return NULL;
    pos++;
    
    // Extensions (TLS 1.3 and key exchange group detection)
    if (pos + 2 <= len) {
        int extensions_len = (data[pos] << 8) | data[pos + 1];
        pos += 2;
        int extensions_end = pos + extensions_len;
        
        while (pos < extensions_end && pos + 4 <= len) {
            uint16_t ext_type = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            uint16_t ext_len = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            
            if (pos + ext_len > len) break;
            
            // Key Share Extension (Key! Actual negotiated group)
            if (ext_type == TLS_EXT_KEY_SHARE && ext_len >= 4) {
                uint16_t selected_group = (data[pos] << 8) | data[pos + 1];
                const char* group_name = get_group_name(selected_group);
                
                strcpy(negotiated_group, group_name);
            }
            
            // Supported Versions Extension in ServerHello
            else if (ext_type == TLS_EXT_SUPPORTED_VERSIONS && ext_len == 2) {
                uint16_t selected_version = (data[pos] << 8) | data[pos + 1];
                strcpy(negotiated_version, get_tls_version_name(selected_version));
                
                if (selected_version == 0x0304) {
                    strcpy(negotiated_version, "TLS 1.3");
                }
            }
            
            pos += ext_len;
        }
    }
    
    return strdup(negotiated_version);
}

// Add enhanced session information with PQC analysis
void add_session_info_enhanced(const char* sni, const char* src_ip, const char* dst_ip, int src_port, int dst_port, 
                              const char* client_version, const char* negotiated_version, 
                              const char* cipher_suite, const char* supported_versions) {
    if (stats.total_sessions >= MAX_SESSIONS) return;

    session_info_t* session = &stats.sessions[stats.total_sessions];
    
    strcpy(pubKey, "Unknown");
    strcpy(session->pub_key_type, "Unknown");
    strncpy(session->sni, sni ? sni : "Unknown", MAX_SNI_LEN - 1);
    strncpy(session->src_ip, src_ip, MAX_IP_LEN - 1);
    strncpy(session->dst_ip, dst_ip, MAX_IP_LEN - 1);
    session->src_port = src_port;
    session->dst_port = dst_port;
    strncpy(session->client_tls_version, client_version, 31);
    strncpy(session->negotiated_tls_version, negotiated_version, 31);
    strncpy(session->cipher_suite, cipher_suite, MAX_CIPHER_LEN - 1);
    strncpy(session->supported_versions, supported_versions, 127);
    
    // Initialize certificate-related fields
    strcpy(session->issuer, "Unknown");
    strcpy(session->expiry_date, "Unknown");
    session->expiry_days = -1;
    session->has_certificate = 0;
    
    // Initialize PQC fields
    session->is_pqc_hybrid = 0;
    strcpy(session->pqc_kem, "None");
    strcpy(session->pqc_sig, "None");
    session->classic_vuln = 0;
    session->pqc_vuln = 0;
    
    // TLS 1.3 detection
    session->is_tls13 = (strstr(negotiated_version, "TLS 1.3") != NULL) ||
                        (strstr(cipher_suite, "TLS_AES") != NULL) ||
                        (strstr(cipher_suite, "TLS_CHACHA20") != NULL) ||
                        (strstr(cipher_suite, "ML_KEM") != NULL) ||
                        (strstr(cipher_suite, "HQC") != NULL) ||
                        (strstr(cipher_suite, "KYBER") != NULL);
    
    // Check for PQC hybrid
    if (strstr(cipher_suite, "ML_KEM") || strstr(cipher_suite, "HQC") || 
        strstr(cipher_suite, "FALCON") || strstr(cipher_suite, "SPHINCS") ||
        strstr(cipher_suite, "KYBER")) {
        session->is_pqc_hybrid = 1;
    }
    
    // Analyze vulnerabilities
    session->risk_score = 0;
    session->vulnerabilities[0] = '\0';
    
    // Version-based risk assessment
    if (session->is_tls13 && session->is_pqc_hybrid) {
        strcat(session->vulnerabilities, "TLS1.3-PQC-Hybrid");
        stats.tls_13_count++;
    } else if (session->is_tls13) {
        strcat(session->vulnerabilities, "TLS1.3-PostQuantumReady");
        stats.tls_13_count++;
    } else if (strstr(negotiated_version, "TLS 1.2")) {
        strcat(session->vulnerabilities, "TLS1.2-LegacyProtocol");
        session->risk_score += 1;
        stats.tls_12_count++;
    } else {
        strcat(session->vulnerabilities, "OldTLS-HighRisk");
        session->risk_score += 3;
    }
    
    // Cipher suite vulnerabilities
    if (strstr(cipher_suite, "RSA") && strstr(cipher_suite, "ECDHE")) {
        strcat(session->vulnerabilities, ",RSA+ECDHE-QuantumVuln");
        session->risk_score += 2;
        stats.rsa_ecdhe_count++;
    }
    
    if (session->risk_score > 0 && !session->is_tls13) {
        stats.vulnerable_sessions++;
    }
    
    stats.total_sessions++;

    // Conditional Certificate parsing - Distinguish between localhost and external connections
    if (sni && strlen(sni) > 0 && strcmp(sni, "Unknown") != 0) {
        // Check if it's localhost or local IP address
        int is_local_connection = (strcmp(sni, "localhost") == 0) ||
                                 (strcmp(dst_ip, "127.0.0.1") == 0) ||
                                 (strcmp(dst_ip, "::1") == 0) ||
                                 (strstr(dst_ip, "192.168.") != NULL) ||
                                 (strstr(dst_ip, "10.0.") != NULL) ||
                                 (strstr(dst_ip, "172.") != NULL && dst_port != 443);
        
        // Perform Certificate analysis only for external HTTPS traffic
        if (!is_local_connection && dst_port == 443) {
            analyze_certificate_from_sni(sni, session);
            strcpy(session->pub_key_type, pubKey);
        } else {
            // Set default values for local connections
            strcpy(session->issuer, "Local Certificate");
            strcpy(session->expiry_date, "N/A");
            session->expiry_days = -1;
            session->has_certificate = 0;
        }
    }

    if (strcmp(session->pub_key_type, "Unknown") == 0) {
        if (strstr(cipher_suite, "RSA")) {
            strcpy(session->pub_key_type, "RSA_Inferred");
        } else if (strstr(cipher_suite, "ECDSA") || strstr(cipher_suite, "ECDHE")) {
            strcpy(session->pub_key_type, "ECDSA_Inferred");
        } else {
            strcpy(session->pub_key_type, "Cipher_Based");
        }
    }
    
}

// Check if SNI has already been displayed
int is_sni_already_displayed(const char* sni) {
    if (!sni || strlen(sni) == 0) {
        return 0; // Unknown SNI, allow display
    }
    
    for (int i = 0; i < displayed_sni_count; i++) {
        if (strcmp(displayed_snis[i], sni) == 0) {
            return 1; // Already displayed
        }
    }
    return 0; // Not yet displayed
}

// Mark SNI as displayed
void mark_sni_as_displayed(const char* sni) {
    if (!sni || strlen(sni) == 0 || displayed_sni_count >= MAX_DISPLAYED_SNIS) {
        return;
    }
    
    // Check if already marked
    if (is_sni_already_displayed(sni)) {
        return;
    }
    
    strncpy(displayed_snis[displayed_sni_count], sni, MAX_SNI_LEN - 1);
    displayed_snis[displayed_sni_count][MAX_SNI_LEN - 1] = '\0';
    displayed_sni_count++;
}

void normalize_connection_key(char *key, const char *src_ip, int src_port, const char *dst_ip, int dst_port) {
    // For connections with port 443, always normalize as client:high_port->server:443
    if (dst_port == 443) {
        // Client -> Server (normal)
        snprintf(key, 64, "%s:%d->%s:%d", src_ip, src_port, dst_ip, dst_port);
    } else if (src_port == 443) {
        // Server -> Client (reverse, so flip for storage)
        snprintf(key, 64, "%s:%d->%s:%d", dst_ip, dst_port, src_ip, src_port);
    } else {
        // General case: sort by IP address
        int ip_cmp = strcmp(src_ip, dst_ip);
        if (ip_cmp < 0 || (ip_cmp == 0 && src_port < dst_port)) {
            snprintf(key, 64, "%s:%d->%s:%d", src_ip, src_port, dst_ip, dst_port);
        } else {
            snprintf(key, 64, "%s:%d->%s:%d", dst_ip, dst_port, src_ip, src_port);
        }
    }
}

// Find or create pending connection for state tracking
pending_connection_t* find_or_create_pending_connection(const char* src_ip, int src_port, const char* dst_ip, int dst_port) {
    char conn_id[64];
    
    // Normalize connection key
    normalize_connection_key(conn_id, src_ip, src_port, dst_ip, dst_port);
    
    // Find existing pending connection
    for (int i = 0; i < pending_count; i++) {
        if (strcmp(pending_connections[i].connection_id, conn_id) == 0) {
            return &pending_connections[i];
        }
    }
    
    // Create new pending connection
    if (pending_count < MAX_PENDING_CONNECTIONS) {
        pending_connection_t* conn = &pending_connections[pending_count++];
        strcpy(conn->connection_id, conn_id);
        
        // Set client and server IP/port correctly
        if (dst_port == 443) {
            // Client -> Server
            strcpy(conn->src_ip, src_ip);
            strcpy(conn->dst_ip, dst_ip);
            conn->src_port = src_port;
            conn->dst_port = dst_port;
        } else if (src_port == 443) {
            // Server -> Client (reverse, so flip for storage)
            strcpy(conn->src_ip, dst_ip);
            strcpy(conn->dst_ip, src_ip);
            conn->src_port = dst_port;
            conn->dst_port = src_port;
        } else {
            // General case
            strcpy(conn->src_ip, src_ip);
            strcpy(conn->dst_ip, dst_ip);
            conn->src_port = src_port;
            conn->dst_port = dst_port;
        }
        
        conn->has_client_hello = 0;
        conn->start_time = time(NULL);
        strcpy(conn->sni, "Unknown");
        strcpy(conn->client_version, "Unknown");
        strcpy(conn->supported_versions, "");
        strcpy(conn->supported_groups, "");
        
        return conn;
    }
    
    return NULL;
}

// Display completed TLS connection information with enhanced PQC support
void display_completed_connection_enhanced(pending_connection_t* conn, const char* negotiated_version, const char* cipher_name, const char* negotiated_group) {
    // Check if this SNI was already displayed
    if (is_sni_already_displayed(conn->sni)) {
        return; // Skip duplicate SNI
    }
    
    // Apply SNI filter
    if (!matches_sni_filter(conn->sni)) {
        return;
    }
    
    // Mark this SNI as displayed
    mark_sni_as_displayed(conn->sni);
    
    // Display completed connection info
    stats.tls_packets++; // Count only displayed connections
    
    time_t now;
    struct tm *tm_info;
    char timestamp[64];
    time(&now);
    tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", tm_info);
    
    printf("\n%s[%s] TLS Connection #%d%s\n", COLOR_BOLD, timestamp, stats.tls_packets, COLOR_RESET);
    printf("%s[+] %s:%d → %s:%d%s\n", COLOR_GREEN, 
           conn->src_ip, conn->src_port, conn->dst_ip, conn->dst_port, COLOR_RESET);
    
    if (strlen(conn->sni) > 0 && strcmp(conn->sni, "Unknown") != 0) {
        printf("%s  └─ Server Name (SNI): %s%s\n", COLOR_CYAN, conn->sni, COLOR_RESET);
    }
    
    printf("%s  └─ Client TLS Version: %s%s\n", COLOR_BLUE, conn->client_version, COLOR_RESET);
    
    if (strlen(conn->supported_versions) > 0) {
        printf("%s  └─ %s%s\n", COLOR_PURPLE, conn->supported_versions, COLOR_RESET);
    }
    
    printf("%s  └─ Negotiated TLS Version: %s%s\n", COLOR_GREEN, negotiated_version, COLOR_RESET);
    printf("%s  └─ Cipher Suite: %s%s\n", COLOR_YELLOW, cipher_name, COLOR_RESET);

    // Key exchange group information display (Key improvement!)
    if (strcmp(negotiated_group, "Unknown") != 0) {
        if (is_pqc_key_exchange_group_by_name(negotiated_group)) {
            tls_group_t* group_details = get_group_details_by_name(negotiated_group);
            printf("%s  └─ Key Exchange Group: %s (PQC Hybrid Level %d)%s\n", 
                   COLOR_GREEN, negotiated_group, 
                   group_details ? group_details->security_level : 0, COLOR_RESET);
            printf("%s  └─ Security Level: High (Post-Quantum Hybrid)%s\n", 
                   COLOR_GREEN, COLOR_RESET);
        } else {
            printf("%s  └─ Key Exchange Group: %s%s\n", 
                   COLOR_CYAN, negotiated_group, COLOR_RESET);
        }
    }
    
    // Security level assessment (existing but considering PQC key exchange)
    const char* security_level;
    if (strstr(negotiated_version, "TLS 1.3")) {
        if (is_pqc_key_exchange_group_by_name(negotiated_group)) {
            security_level = "High (Post-Quantum Hybrid Key Exchange)";
        } else if (strstr(cipher_name, "ML_KEM") || strstr(cipher_name, "KYBER")) {
            security_level = "High (Post-Quantum Hybrid)";
        } else {
            security_level = "High (TLS 1.3)";
        }
    } else if (strstr(cipher_name, "GCM") || strstr(cipher_name, "CHACHA20")) {
        security_level = "Mid (Legacy)";
    } else {
        security_level = "Low (Legacy)";
    }
    printf("%s  └─ Security Level: %s%s\n", COLOR_CYAN, security_level, COLOR_RESET);
    
    // Store session info (existing logic maintained)
    add_session_info_enhanced(conn->sni, conn->src_ip, conn->dst_ip, conn->src_port, conn->dst_port,
                              conn->client_version, negotiated_version, cipher_name, conn->supported_versions);
    
    // Update session with complete info including PQC key exchange
    if (stats.total_sessions > 0) {
        session_info_t* session = &stats.sessions[stats.total_sessions - 1];
        session->is_tls13 = (strstr(negotiated_version, "TLS 1.3") != NULL);
        
        // PQC key exchange information update
        if (is_pqc_key_exchange_group_by_name(negotiated_group)) {
            session->is_pqc_key_exchange = 1;
            strncpy(session->negotiated_group, negotiated_group, 63);
            session->negotiated_group[63] = '\0';
            
            tls_group_t* group_details = get_group_details_by_name(negotiated_group);
            if (group_details) {
                snprintf(session->pqc_kex_details, 127, "%s (Level %d)", 
                         group_details->pqc_algorithm, group_details->security_level);
            }
        }
        
        // Existing PQC cipher suite detection
        if (strstr(cipher_name, "ML_KEM") || strstr(cipher_name, "HQC") || 
            strstr(cipher_name, "FALCON") || strstr(cipher_name, "SPHINCS") ||
            strstr(cipher_name, "KYBER")) {
            session->is_pqc_hybrid = 1;
        }
        
        if (session->is_tls13) {
            stats.tls_13_count++;
            if (session->is_pqc_hybrid || session->is_pqc_key_exchange) {
                strcpy(session->vulnerabilities, "TLS1.3-PQC-Hybrid");
            } else {
                strcpy(session->vulnerabilities, "TLS1.3-PostQuantumReady");
            }
            session->risk_score = 0;
        }
        
        // Perform quantum vulnerability analysis
        analyze_quantum_vulnerability(cipher_name, session);
        analyze_certificate_from_sni(conn->sni, session);
    }
}

// Parse TLS Certificate message and extract certificate data
void parse_certificate_message(const unsigned char* data, int len) {
    if (len < 15) {
        return;
    }
    
    // TLS Record Header (5 bytes) + Handshake Header (4 bytes) = 9 bytes
    int pos = 9;
    
    // Check TLS 1.3
    int is_tls13 = 0;
    if (stats.total_sessions > 0) {
        session_info_t* last_session = &stats.sessions[stats.total_sessions - 1];
        is_tls13 = last_session->is_tls13;
    }
    
    if (is_tls13) {
        // TLS 1.3: certificate_request_context_length (1 byte)
        if (pos + 1 > len) {
            return;
        }
        int context_len = data[pos++];
        
        if (pos + context_len > len) {
            return;
        }
        pos += context_len;
    }

    // Certificate list length (3 bytes)
    if (pos + 3 > len) {
        return;
    }
    
    int cert_list_len = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2];
    pos += 3;
    
    if (pos + cert_list_len > len) {
        return;
    }
    
    // Parse first certificate
    if (cert_list_len >= 3 && pos + 3 <= len) {
        // First certificate length (3 bytes)
        int cert_len = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2];
        pos += 3;
        
        if (pos + cert_len <= len && cert_len > 0) {
            // Get the last session to update with certificate info
            if (stats.total_sessions > 0) {
                session_info_t* last_session = &stats.sessions[stats.total_sessions - 1];
                
                // Process certificates parsed from packets
                analyze_certificate(&data[pos], cert_len, last_session);
                
                // Skip extensions in TLS 1.3 (if necessary)
                if (is_tls13) {
                    pos += cert_len;
                    if (pos + 2 <= len) {
                        int ext_len = (data[pos] << 8) | data[pos + 1];
                        pos += 2 + ext_len;
                    }
                }
            }
        }
    }
}

// Analyze X.509 certificate and extract relevant information (UPDATED WITH HYBRID STRATEGY)
void analyze_certificate(const unsigned char* cert_data, int cert_len, session_info_t* session) {
    analyze_certificate_hybrid(cert_data, cert_len, session);

    printf("%s[INFO] Public Key: %s%s\n", COLOR_YELLOW, session->pub_key_type, COLOR_RESET);
    printf("%s[INFO] Certificate Issuer: %s%s\n", COLOR_GREEN, session->issuer, COLOR_RESET);
    printf("%s[INFO] Certificate expires: %s (%d days)%s\n", COLOR_CYAN, session->expiry_date, session->expiry_days, COLOR_RESET);

}

// Enhanced certificate analysis via SNI hostname connection with improved failure handling
void analyze_certificate_from_sni(const char* hostname, session_info_t* session) {
    
    if (!hostname || strlen(hostname) == 0) {
        strncpy(session->issuer, "Invalid Hostname", MAX_ISSUER_LEN - 1);
        session->issuer[MAX_ISSUER_LEN - 1] = '\0';
        session->expiry_days = -1;
        strcpy(session->expiry_date, "Invalid Hostname");
        return;
    }

    strcpy(pubKey, "Analysis_Failed");
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    X509 *cert = NULL;
    int sock = -1;
    struct timeval timeout;
    fd_set writefds;
    int result = 0;
    
    // Initialize to show we attempted
    strncpy(session->issuer, "Connection Failed", MAX_ISSUER_LEN - 1);
    session->issuer[MAX_ISSUER_LEN - 1] = '\0';
    session->expiry_days = -1;
    strcpy(session->expiry_date, "Connection Failed");
    
    // OpenSSL initialization (one-time)
    static int ssl_initialized = 0;
    if (!ssl_initialized) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        ssl_initialized = 1;
    }
    
    // Create SSL context
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx) {
        strncpy(session->issuer, "SSL Context Failed", MAX_ISSUER_LEN - 1);
        session->issuer[MAX_ISSUER_LEN - 1] = '\0';
        return;
    }
    
    SSL_CTX_set_timeout(ctx, 5);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    
    // DNS resolution
    struct hostent *host_entry = gethostbyname(hostname);
    if (!host_entry) {
        struct addrinfo hints, *addr_result;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        
        if (getaddrinfo(hostname, "443", &hints, &addr_result) != 0) {
            strncpy(session->issuer, "DNS Failed", MAX_ISSUER_LEN - 1);
            session->issuer[MAX_ISSUER_LEN - 1] = '\0';
            strcpy(session->expiry_date, "DNS Failed");
            goto cleanup;
        }
        freeaddrinfo(addr_result);
        goto cleanup;
    }
    
    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        strncpy(session->issuer, "Socket Failed", MAX_ISSUER_LEN - 1);
        session->issuer[MAX_ISSUER_LEN - 1] = '\0';
        strcpy(session->expiry_date, "Socket Failed");
        goto cleanup;
    }
    
    // Set socket timeout
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    
    // Set non-blocking mode for connect
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    // Connect
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(443);
    memcpy(&server_addr.sin_addr, host_entry->h_addr_list[0], host_entry->h_length);
    
    result = connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (result < 0 && errno != EINPROGRESS) {
        strncpy(session->issuer, "Connect Failed", MAX_ISSUER_LEN - 1);
        session->issuer[MAX_ISSUER_LEN - 1] = '\0';
        strcpy(session->expiry_date, "Connect Failed");
        goto cleanup;
    }
    
    // Wait for connection
    FD_ZERO(&writefds);
    FD_SET(sock, &writefds);
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    
    result = select(sock + 1, NULL, &writefds, NULL, &timeout);
    if (result <= 0) {
        strncpy(session->issuer, "Connect Timeout", MAX_ISSUER_LEN - 1);
        session->issuer[MAX_ISSUER_LEN - 1] = '\0';
        strcpy(session->expiry_date, "Connect Timeout");
        goto cleanup;
    }
    
    // Check connection status
    int sock_error;
    socklen_t len = sizeof(sock_error);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &sock_error, &len) < 0 || sock_error != 0) {
        if (sock_error == ECONNREFUSED) {
            strncpy(session->issuer, "Connection Refused", MAX_ISSUER_LEN - 1);
            strcpy(session->expiry_date, "Connection Refused");
        } else if (sock_error == ETIMEDOUT) {
            strncpy(session->issuer, "Connection Timeout", MAX_ISSUER_LEN - 1);
            strcpy(session->expiry_date, "Connection Timeout");
        } else if (sock_error == EHOSTUNREACH) {
            strncpy(session->issuer, "Host Unreachable", MAX_ISSUER_LEN - 1);
            strcpy(session->expiry_date, "Host Unreachable");
        } else {
            snprintf(session->issuer, MAX_ISSUER_LEN - 1, "Socket Error (%d)", sock_error);
            strcpy(session->expiry_date, "Socket Error");
        }
        session->issuer[MAX_ISSUER_LEN - 1] = '\0';
        goto cleanup;
    }
    
    // Set back to blocking mode
    fcntl(sock, F_SETFL, flags);
    
    // Create SSL connection
    ssl = SSL_new(ctx);
    if (!ssl) {
        strncpy(session->issuer, "SSL Create Failed", MAX_ISSUER_LEN - 1);
        session->issuer[MAX_ISSUER_LEN - 1] = '\0';
        strcpy(session->expiry_date, "SSL Create Failed");
        goto cleanup;
    }
    
    SSL_set_fd(ssl, sock);
    SSL_set_tlsext_host_name(ssl, hostname);
        
    // SSL handshake
    result = SSL_connect(ssl);
    if (result <= 0) {
        int ssl_error = SSL_get_error(ssl, result);
        switch (ssl_error) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                strncpy(session->issuer, "SSL Handshake Timeout", MAX_ISSUER_LEN - 1);
                strcpy(session->expiry_date, "SSL Handshake Timeout");
                break;
            case SSL_ERROR_SYSCALL:
                strncpy(session->issuer, "SSL System Error", MAX_ISSUER_LEN - 1);
                strcpy(session->expiry_date, "SSL System Error");
                break;
            case SSL_ERROR_SSL:
                strncpy(session->issuer, "SSL Protocol Error", MAX_ISSUER_LEN - 1);
                strcpy(session->expiry_date, "SSL Protocol Error");
                break;
            default:
                strncpy(session->issuer, "SSL Handshake Failed", MAX_ISSUER_LEN - 1);
                strcpy(session->expiry_date, "SSL Handshake Failed");
                break;
        }
        session->issuer[MAX_ISSUER_LEN - 1] = '\0';
        goto cleanup;
    }
    
    // Get certificate
    cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        strncpy(session->issuer, "No Certificate", MAX_ISSUER_LEN - 1);
        session->issuer[MAX_ISSUER_LEN - 1] = '\0';
        strcpy(session->expiry_date, "No Certificate");
        goto cleanup;
    }
   
    // Mark as having certificate
    session->has_certificate = 1;
    
    // Core: Convert certificate to DER format and perform hybrid parsing
    unsigned char *cert_der = NULL;
    int cert_der_len = i2d_X509(cert, &cert_der);
    
    if (cert_der && cert_der_len > 0) {
        analyze_certificate_hybrid(cert_der, cert_der_len, session);
        
        OPENSSL_free(cert_der);
    } else {        
        // Fallback: OpenSSL direct parsing for critical fields only
        EVP_PKEY *pkey = X509_get_pubkey(cert);
        if (pkey) {
            int key_type = EVP_PKEY_base_id(pkey);
            switch (key_type) {
                case EVP_PKEY_RSA:
                    strcpy(pubKey, "RSA");
                    strcpy(session->pub_key_type, "RSA");
                    break;
                case EVP_PKEY_EC:
                    strcpy(pubKey, "ECDSA");
                    strcpy(session->pub_key_type, "ECDSA");
                    break;
                default:
                    strcpy(pubKey, "Unknown");
                    strcpy(session->pub_key_type, "Unknown");
                    break;
            }
            EVP_PKEY_free(pkey);
        }
        
        // Extract issuer CN using OpenSSL
        X509_NAME *issuer_name = X509_get_issuer_name(cert);
        if (issuer_name) {
            char *cn = NULL;
            int cn_len = X509_NAME_get_text_by_NID(issuer_name, NID_commonName, NULL, 0);
            if (cn_len > 0) {
                cn = malloc(cn_len + 1);
                if (cn && X509_NAME_get_text_by_NID(issuer_name, NID_commonName, cn, cn_len + 1) > 0) {
                    strncpy(session->issuer, cn, MAX_ISSUER_LEN - 1);
                    session->issuer[MAX_ISSUER_LEN - 1] = '\0';
                    free(cn);
                } else {
                    strcpy(session->issuer, "CN_Extract_Failed");
                    if (cn) free(cn);
                }
            } else {
                strcpy(session->issuer, "No_CN_Found");
            }
        }
        
        // Extract expiry date using OpenSSL
        const ASN1_TIME *not_after = X509_get0_notAfter(cert);
        if (not_after) {
            struct tm tm_expiry;
            memset(&tm_expiry, 0, sizeof(tm_expiry));
            if (ASN1_TIME_to_tm(not_after, &tm_expiry)) {
                tm_expiry.tm_isdst = -1;
                if (strftime(session->expiry_date, MAX_EXPIRY_LEN - 1, "%Y-%m-%d", &tm_expiry) > 0) {
                    time_t now = time(NULL);
                    time_t expiry_time = mktime(&tm_expiry);
                    if (expiry_time != -1) {
                        double diff = difftime(expiry_time, now);
                        session->expiry_days = (int)(diff / (24.0 * 3600.0));
                    } else {
                        session->expiry_days = -1;
                    }
                } else {
                    strcpy(session->expiry_date, "Date_Format_Error");
                    session->expiry_days = -1;
                }
            } else {
                strcpy(session->expiry_date, "Date_Parse_Error");
                session->expiry_days = -1;
            }
        } else {
            strcpy(session->expiry_date, "No_Expiry_Date");
            session->expiry_days = -1;
        }
    }

cleanup:
    if (cert) X509_free(cert);
    if (ssl) SSL_free(ssl);
    if (sock >= 0) close(sock);
    if (ctx) SSL_CTX_free(ctx);
}

void analyze_domains_from_file(const char* filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        printf("%s[ERROR] Could not open file: %s%s\n", COLOR_RED, filename, COLOR_RESET);
        return;
    }
    
    char domain[256];
    int domain_count = 0;
    
    printf("\n%s=== BATCH DOMAIN ANALYSIS ===%s\n", COLOR_CYAN, COLOR_RESET);
    printf("Reading domains from: %s\n\n", filename);
    
    while (fgets(domain, sizeof(domain), file)) {
        // Remove newline
        domain[strcspn(domain, "\n\r")] = '\0';
        
        if (strlen(domain) == 0 || domain[0] == '#') continue; // Skip empty lines and comments
        
        domain_count++;
        printf("%s[%d] Analyzing: %s%s\n", COLOR_YELLOW, domain_count, domain, COLOR_RESET);
        
        // Create a session for this domain
        session_info_t session = {0};
        strcpy(session.sni, domain);
        strcpy(session.dst_ip, "BATCH_MODE");
        session.dst_port = 443;
        
        // Analyze certificate from SNI
        analyze_certificate_from_sni(domain, &session);
        
        // Add to stats
        if (stats.total_sessions < MAX_SESSIONS) {
            memcpy(&stats.sessions[stats.total_sessions], &session, sizeof(session_info_t));
            stats.total_sessions++;
        }
        
        printf("  └─ Result: %s | %s | %s\n\n", 
               session.pub_key_type, session.issuer, session.expiry_date);
    }
    
    fclose(file);
    printf("%s[INFO] Batch analysis completed. %d domains analyzed.%s\n", 
           COLOR_GREEN, domain_count, COLOR_RESET);
}

// Process TLS packet and extract handshake information
void process_tls_packet(const unsigned char* data, int len, struct iphdr* ip_hdr, struct tcphdr* tcp_hdr) {
    if (len < 6) {
        return;
    }
    
    // More permissive TLS record type check
    if (data[0] < 0x14 || data[0] > 0x18) {
        return;
    }
    
    // More permissive TLS version check
    if (data[1] != 0x03) {
        return;
    }
    
    if (data[0] == TLS_RECORD_TYPE_HANDSHAKE) {
        if (len < 6) {
            return;
        }
        
        char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
        if (ip_hdr->version == 6) {
            // For IPv6, handle as localhost
            strcpy(src_ip, "::1");
            strcpy(dst_ip, "::1");
        } else {
            inet_ntop(AF_INET, &ip_hdr->saddr, src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &ip_hdr->daddr, dst_ip, INET_ADDRSTRLEN);
        }
        
        unsigned char handshake_type = data[5];
        char* sni = NULL;
        
        switch (handshake_type) {
            case TLS_HANDSHAKE_CLIENT_HELLO: {
                // Store ClientHello info without displaying
                pending_connection_t* conn = find_or_create_pending_connection(
                    src_ip, ntohs(tcp_hdr->source), dst_ip, ntohs(tcp_hdr->dest));
                
                if (conn) {
                    char client_version[32];
                    char supported_versions[128];
                    char supported_groups[256];
                    
                    sni = extract_sni_and_versions(data, len, client_version, supported_versions, supported_groups);
                    strncpy(conn->supported_groups, supported_groups, 255);
                    conn->supported_groups[255] = '\0';

                    if (sni) {
                        strncpy(conn->sni, sni, MAX_SNI_LEN - 1);
                        conn->sni[MAX_SNI_LEN - 1] = '\0';
                        free(sni);
                    } else {
                        strcpy(conn->sni, "localhost");
                    }
                    
                    strncpy(conn->client_version, client_version, 31);
                    conn->client_version[31] = '\0';
                    strncpy(conn->supported_versions, supported_versions, 127);
                    conn->supported_versions[127] = '\0';
                    conn->has_client_hello = 1;
                }
                break;
            }
            
            case TLS_HANDSHAKE_SERVER_HELLO: {
                // Find corresponding ClientHello and display completed connection
                pending_connection_t* conn = find_or_create_pending_connection(
                    src_ip, ntohs(tcp_hdr->source), dst_ip, ntohs(tcp_hdr->dest));
                
                if (conn && conn->has_client_hello) {
                    char negotiated_version[32];
                    char cipher_name[MAX_CIPHER_LEN];
                    char negotiated_group[64];
                    
                    char* result = parse_server_hello_enhanced(data, len, negotiated_version, cipher_name, negotiated_group);
                    if (result) {
                        free(result);
                    }
                    
                    display_completed_connection_enhanced(conn, negotiated_version, 
                                                        cipher_name, negotiated_group);
                }
                break;
            }
            
            case TLS_HANDSHAKE_CERTIFICATE: {
                // Parse certificate message to extract certificate info
                parse_certificate_message(data, len);
                break;
            }
            
            default:
                break;
        }
    }
}

// Main packet handler with IPv6 support
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    static int total_packet_count = 0;
    total_packet_count++;
    
    struct iphdr *ip_hdr;
    struct tcphdr *tcp_hdr;
    const unsigned char *payload;
    int payload_len;
    int link_header_len = 0;
    int is_ipv6 = 0;
    
    stats.total_packets++;
    
    if (dumper) {
        pcap_dump((u_char*)dumper, pkthdr, packet);
    }
    
    int datalink = pcap_datalink(handle);
    switch (datalink) {
        case DLT_EN10MB: link_header_len = 14; break;     // Ethernet
        case DLT_LINUX_SLL: link_header_len = 16; break;  // Linux cooked
        case DLT_NULL: link_header_len = 4; break;        // BSD loopback
        case DLT_RAW: link_header_len = 0; break;         // Raw IP
        case DLT_LOOP: link_header_len = 4; break;        // OpenBSD loopback
        default: link_header_len = 14; break;
    }
    
    if (pkthdr->len < link_header_len + sizeof(struct iphdr) + sizeof(struct tcphdr)) {
        return;
    }
    
    ip_hdr = (struct iphdr*)(packet + link_header_len);
    
    // IPv6 packet detection and processing
    if (ip_hdr->version == 6) {
        is_ipv6 = 1;
        
        // IPv6 header is 40 bytes fixed, find TCP header
        if (pkthdr->len < link_header_len + 40 + 20) {
            return;
        }
        
        // Check Next Header in IPv6 (6th byte is Next Header)
        unsigned char *ipv6_header = (unsigned char*)(packet + link_header_len);
        uint8_t next_header = ipv6_header[6];  // Next Header field
        
        if (next_header != IPPROTO_TCP) {
            return;
        }
        
        // IPv6 TCP header and payload calculation
        tcp_hdr = (struct tcphdr*)(packet + link_header_len + 40);  // Skip 40-byte IPv6 header
        payload = (unsigned char*)tcp_hdr + (tcp_hdr->doff * 4);
        payload_len = pkthdr->len - link_header_len - 40 - (tcp_hdr->doff * 4);
        
    } else if (ip_hdr->version != 4 || ip_hdr->protocol != IPPROTO_TCP) {
        return;
    } else {
        // Existing IPv4 processing
        is_ipv6 = 0;
        tcp_hdr = (struct tcphdr*)((unsigned char*)ip_hdr + (ip_hdr->ihl * 4));
        payload = (unsigned char*)tcp_hdr + (tcp_hdr->doff * 4);
        payload_len = pkthdr->len - link_header_len - (ip_hdr->ihl * 4) - (tcp_hdr->doff * 4);
    }

    if (payload_len > 0) {
        // Check if this looks like TLS
        if (payload_len >= 6 && 
            (payload[0] >= 0x14 && payload[0] <= 0x17) && // TLS record types
            payload[1] == 0x03) { // TLS version major
            
            if (is_ipv6) {
                // For IPv6, create fake IPv4 header (since process_tls_packet requires IPv4 header)
                struct iphdr fake_ip4;
                memset(&fake_ip4, 0, sizeof(fake_ip4));
                fake_ip4.version = 6; // Mark as IPv6
                fake_ip4.saddr = 0x0100007f; // 127.0.0.1 (localhost)
                fake_ip4.daddr = 0x0100007f; // 127.0.0.1 (localhost)
                process_tls_packet(payload, payload_len, &fake_ip4, tcp_hdr);
            } else {
                process_tls_packet(payload, payload_len, ip_hdr, tcp_hdr);
            }
        }
    }
}


//version_TLS_clean ( TLS 1.3 -> 1.3 )
const char* clean_tls_version(const char* version) {
    if (!version) return "Unknown";
    
    if (strncmp(version, "TLS ", 4) == 0) {
        return version + 4;  
    }
    
    // Remove "SSL " string if present
    if (strncmp(version, "SSL ", 4) == 0) {
        return version + 4;  
    }
    
    return version; 
}

//cipher_Suite_TLS_clean ( TLS_AES_... -> AES_...)
const char* clean_cipher_suite(const char* cipher) {
    if (!cipher) return "Unknown";
    

    if (strncmp(cipher, "TLS_", 4) == 0) {
        return cipher + 4; 
    }
    
    return cipher;
}

// Print comprehensive analysis results
void print_analysis_results(void) {
    printf("\n%s%s==============================================================================%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("%s%s                        TLS PQC ANALYSIS RESULTS                            %s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("%s%s==============================================================================%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("%sTotal packets processed: %s%d%s\n", COLOR_BLUE, COLOR_YELLOW, stats.total_packets, COLOR_RESET);
    printf("%sTLS sessions detected: %s%d%s\n", COLOR_BLUE, COLOR_YELLOW, stats.total_sessions, COLOR_RESET);
    printf("%sVulnerable sessions: %s%d%s\n", COLOR_BLUE, COLOR_RED, stats.vulnerable_sessions, COLOR_RESET);
    
    if (sni_filter_enabled) {
        printf("%sSNI Filter: %s", COLOR_BLUE, COLOR_CYAN);
        for (int i = 0; i < sni_filter.keyword_count; i++) {
            printf("%s", sni_filter.keywords[i]);
            if (i < sni_filter.keyword_count - 1) {
                printf(", ");
            }
        }
        printf("%s\n", COLOR_RESET);
    }
    else if (sni_filter_enabled == 0) {
        printf("%sAll domains (no filter)\n%s", COLOR_BLUE, COLOR_CYAN);
    }
     
    printf("%s%s==============================================================================%s\n\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    
    printf("%s%s[DETAILED SESSION ANALYSIS WITH PQC SUPPORT]%s\n", COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    
    // Adjusted table header with wider columns to fit actual data
    printf("+----------+----------------------------------+--------------+---------+----------------------------------+-----+------------------+-------+-------------------------------------+---------------+------------+------------+------------+\n");
    printf("| %-8s | %-32s | %-12s | %-7s | %-32s | %-3s | %-16s | %-5s | %-35s | %-13s | %-10s |  %-10s | %-10s |\n", 
           "Session#", "SNI", "TLS ver", "level", "Cipher Suite", "PQC", "Vulnerable Field", "level", "Issuer", "Expiry Date", "Public Key", "migration", "total");
    printf("+----------+----------------------------------+--------------+---------+----------------------------------+-----+------------------+-------+-------------------------------------+---------------+------------+------------+------------+\n");
    
    for (int i = 0; i < stats.total_sessions; i++) {
        session_info_t* session = &stats.sessions[i];
        
        const char* tls_level = get_tls_level(session->negotiated_tls_version);
        const char* vulnerable_field = get_vulnerable_field(session->cipher_suite);
        const char* vuln_level = get_vulnerability_level(vulnerable_field);
        // Improved migration calculation logic - check for valid expiry_days and reasonable range
        const char* migration_required = (session->expiry_days >= 0 && session->expiry_days <= 90) ? "O" : "X";
        const char* pqc_status = session->is_pqc_hybrid ? "YES" : "NO";
        
        // Truncate strings to fit the adjusted column widths
        char sni_truncated[33];
        char tls_ver_truncated[13];
        char cipher_truncated[33];
        char vuln_field_truncated[17];
        char issuer_truncated[36];
        char expiry_truncated[14];
        char total_truncated[11];
        char public_truncated[11];
        
        char tls_char = (strcmp(tls_level, "H") == 0) ? 'H' : 
                        (strcmp(tls_level, "M") == 0) ? 'M' : 'L';
        char vuln_char = (strcmp(vuln_level, "H") == 0) ? 'H' :
                        (strcmp(vuln_level, "M") == 0) ? 'M' : 'L';
        
        // Truncate with proper ellipsis if needed
        const char* clean_version = clean_tls_version(session->negotiated_tls_version);
        const char* clean_cipher = clean_cipher_suite(session->cipher_suite);
        
        if (strlen(session->sni) > 32) {
            strncpy(sni_truncated, session->sni, 29);
            strcpy(sni_truncated + 29, "...");
        } else {
            strcpy(sni_truncated, session->sni);
        }
        
        if (strlen(clean_version) > 12) {
            strncpy(tls_ver_truncated, clean_version, 9);
            strcpy(tls_ver_truncated + 9, "...");
        } else {
            strcpy(tls_ver_truncated, clean_version);
        }

        if (strlen(clean_cipher) > 32) {
            strncpy(cipher_truncated, clean_cipher, 29);
            strcpy(cipher_truncated + 29, "...");
        } else {
            strcpy(cipher_truncated, clean_cipher);
        }
        
        if (strlen(vulnerable_field) > 16) {
            strncpy(vuln_field_truncated, vulnerable_field, 13);
            strcpy(vuln_field_truncated + 13, "...");
        } else {
            strcpy(vuln_field_truncated, vulnerable_field);
        }
        
        if (strlen(session->issuer) > 35) {
            strncpy(issuer_truncated, session->issuer, 32);
            strcpy(issuer_truncated + 32, "...");
        } else {
            strcpy(issuer_truncated, session->issuer);
        }
        
        if (strlen(session->expiry_date) > 13) {
            strncpy(expiry_truncated, session->expiry_date, 10);
            strcpy(expiry_truncated + 10, "...");
        } else {
            strcpy(expiry_truncated, session->expiry_date);
        }

        if (strlen(session->pub_key_type) > 10) {
            strncpy(public_truncated, session->pub_key_type, 7);
            strcpy(public_truncated + 7, "...");
        } else {
            strcpy(public_truncated, session->pub_key_type);
        }    

        snprintf(total_truncated, sizeof(total_truncated), "TLS_%c_CS_%c", tls_char, vuln_char);
        
        // Print row with adjusted column widths
        printf("| %s%8d%s | %s%-32s%s | %s%-12s%s | %s%-7s%s | %s%-32s%s | %s%-3s%s | %s%-16s%s | %s%-5s%s | %s%-35s%s | %s%-13s%s | %s%-10s%s | %s%-10s%s |%s%-10s%s |\n",
               COLOR_WHITE, i + 1, COLOR_RESET,
               COLOR_GREEN, sni_truncated, COLOR_RESET,
               session->is_tls13 ? COLOR_GREEN : COLOR_YELLOW, tls_ver_truncated, COLOR_RESET,
               strcmp(tls_level, "H") == 0 ? COLOR_GREEN : (strcmp(tls_level, "M") == 0 ? COLOR_YELLOW : COLOR_RED), tls_level, COLOR_RESET,
               COLOR_WHITE, cipher_truncated, COLOR_RESET,
               session->is_pqc_hybrid ? COLOR_GREEN : COLOR_WHITE, pqc_status, COLOR_RESET,
               strcmp(vulnerable_field, "None") == 0 ? COLOR_GREEN : (strcmp(vulnerable_field, "PQC_Hybrid") == 0 ? COLOR_CYAN : COLOR_RED), vuln_field_truncated, COLOR_RESET,
               strcmp(vuln_level, "H") == 0 ? COLOR_GREEN : (strcmp(vuln_level, "M") == 0 ? COLOR_YELLOW : COLOR_RED), vuln_level, COLOR_RESET,
               COLOR_CYAN, issuer_truncated, COLOR_RESET,
               COLOR_WHITE, expiry_truncated, COLOR_RESET,
               COLOR_WHITE, public_truncated, COLOR_RESET,
               strcmp(migration_required, "O") == 0 ? COLOR_RED : COLOR_GREEN, migration_required, COLOR_RESET,
               COLOR_WHITE, total_truncated, COLOR_RESET);
    }
    
    printf("+----------+----------------------------------+--------------+---------+----------------------------------+-----+------------------+-------+-------------------------------------+---------------+------------+------------+------------+\n\n");

    // Save Excel report
    save_analysis_csv_report();
}



// Save comprehensive analysis report as CSV
void save_analysis_csv_report(void) {
    time_t now;
    struct tm *tm_info;
    char timestamp[32];
    char filename[64];
    FILE *csv_temp;
    
    // Generate filename with current timestamp
    time(&now);
    tm_info = localtime(&now);
    if (tm_info == NULL) {
        // Fallback if localtime fails
        snprintf(filename, sizeof(filename), "tls_pqc_report_unknown.csv");
    } else {
        if (strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info) == 0) {
            // Fallback if strftime fails
            snprintf(filename, sizeof(filename), "tls_pqc_report_error.csv");
        } else {
            snprintf(filename, sizeof(filename), "tls_pqc_report_%s.csv", timestamp);
        }
    }
    
    // Create temporary CSV file that can be imported to Excel
    csv_temp = fopen(filename, "w");
    if (csv_temp == NULL) {
        printf("[INFO] Could not create report file: %s\n", filename);
        return;
    }
    
    // Report header information
    fprintf(csv_temp, "==================================================================\n");
    fprintf(csv_temp, "            TLS QUANTUM VULNERABILITY ANALYSIS REPORT\n");
    fprintf(csv_temp, "\n");
    fprintf(csv_temp, "Report Generated: %s\n", timestamp);
    fprintf(csv_temp, "Analysis Tool: TLS Packet Analyzer for Kali Linux\n");
    fprintf(csv_temp, "\n");
    fprintf(csv_temp, "Total packets: %d\n", stats.total_packets);
    fprintf(csv_temp, "TLS sessions: %d\n", stats.total_sessions);
    fprintf(csv_temp, "Vulnerable sessions: %d\n", stats.vulnerable_sessions);

    // SNI filter information - Fixed to prevent Excel #NAME? error
    if (sni_filter_enabled && sni_filter.keyword_count > 0) {
        fprintf(csv_temp, "\"SNI Filter: ");
        for (int i = 0; i < sni_filter.keyword_count; i++) {
            fprintf(csv_temp, "%s", sni_filter.keywords[i]);
            if (i < sni_filter.keyword_count - 1) {
                fprintf(csv_temp, ", ");
            }
        }
        fprintf(csv_temp, "\"\n");
    } else {
        fprintf(csv_temp, "\"SNI Filter: (all sessions analyzed)\"\n");
    }

    fprintf(csv_temp, "==================================================================\n");

    // Enhanced CSV header with PQC fields
    fprintf(csv_temp, "Session #,SNI,TLS Version,TLS Level,Cipher Suite,Vulnerable Field,Vulnerability Level,Issuer,Expiry Date,Public Key Algorithm, Migration Required, Total\n");

    // Write session data
    for (int i = 0; i < stats.total_sessions; i++) {
        session_info_t* session = &stats.sessions[i];
        
        const char* tls_level = get_tls_level(session->negotiated_tls_version);
        const char* vulnerable_field = get_vulnerable_field(session->cipher_suite);
        const char* vuln_level = get_vulnerability_level(vulnerable_field);
        // Improved migration calculation logic
        const char* migration_required = (session->expiry_days >= 0 && session->expiry_days <= 90) ? "O" : "X";

        // Clean expiry_date for CSV (remove commas and quotes)
        char clean_expiry[MAX_EXPIRY_LEN];
        strncpy(clean_expiry, session->expiry_date, MAX_EXPIRY_LEN - 1);
        clean_expiry[MAX_EXPIRY_LEN - 1] = '\0';

        // Replace problematic characters
        for (int j = 0; clean_expiry[j]; j++) {
            if (clean_expiry[j] == ',' || clean_expiry[j] == '"') {
                clean_expiry[j] = ' ';
            }
        }

        // Calculate total field based on TLS level and Vulnerability level
        char total_field[16];
        char tls_char = (strcmp(tls_level, "H") == 0) ? 'H' : 
                        (strcmp(tls_level, "M") == 0) ? 'M' : 'L';
        char vuln_char = (strcmp(vuln_level, "H") == 0) ? 'H' :
                        (strcmp(vuln_level, "M") == 0) ? 'M' : 'L';
                        
        snprintf(total_field, sizeof(total_field), "TLS_%c_CS_%c", tls_char, vuln_char);
        
        const char* clean_version = clean_tls_version(session->negotiated_tls_version);
        const char* clean_cipher = clean_cipher_suite(session->cipher_suite);

        fprintf(csv_temp, "%d,\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
            i + 1,
            session->sni,
            clean_version,
            tls_level,
            clean_cipher,
            vulnerable_field,
            vuln_level,
            session->issuer,
            clean_expiry,
            session->pub_key_type,
            migration_required,
            total_field);
    }
    
    fclose(csv_temp);
    
    printf("%s[INFO] PQC analysis report saved: %s%s%s\n", COLOR_GREEN, COLOR_CYAN, filename, COLOR_RESET);
    printf("%s    CSV file created - Import to Excel for full functionality%s\n", COLOR_YELLOW, COLOR_RESET);
}

// Analyze PCAP file offline
void analyze_pcap_file(const char* filename, int port) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *file_handle;
    struct pcap_pkthdr header;
    const u_char *packet;
    int packet_count = 0;
    
    // Display initial mode information
    printf("%s[INFO] Mode: Offline PCAP file analysis %s%s\n", COLOR_GREEN, filename, COLOR_RESET);
    
    // Ask for SNI filtering (offline mode)
    char input[10];
    printf("\n%s==============================================================================\n", COLOR_YELLOW);
    printf("%s                         SNI filtering mode? (yes / no): %s", COLOR_YELLOW, COLOR_RESET);
    printf("\n%s==============================================================================\n", COLOR_YELLOW);
    
    if (fgets(input, sizeof(input), stdin) != NULL) {
        if (input[0] == 'y' || input[0] == 'Y') {
            sni_filter_enabled = 1;
            char filter_input[MAX_FILTER_LEN];
            
            printf("%s==============================================================================\n");
            printf("%s    Enter SNI to filter:%s\n\n", COLOR_CYAN, COLOR_RESET);
            printf("    Input example:\n");
            printf("    > 'google' 'amazon' etc\n\n");
            printf("    Guide: \n");
            printf("    Enter 'google' for related TLS communication\n");
            printf("    or 'www.google.com' for specific TLS communication\n");
            printf("\n%s==============================================================================\n", COLOR_YELLOW, COLOR_RESET);
            printf("%s> %s", COLOR_CYAN, COLOR_RESET);
            
            if (fgets(filter_input, sizeof(filter_input), stdin) != NULL) {
                // Remove newline character
                filter_input[strcspn(filter_input, "\n")] = '\0';
                
                // Parse keywords separated by spaces
                sni_filter.keyword_count = 0;
                char *token = strtok(filter_input, " \t");
                
                while (token != NULL && sni_filter.keyword_count < MAX_KEYWORDS) {
                    strncpy(sni_filter.keywords[sni_filter.keyword_count], token, MAX_KEYWORD_LEN - 1);
                    sni_filter.keywords[sni_filter.keyword_count][MAX_KEYWORD_LEN - 1] = '\0';
                    sni_filter.keyword_count++;
                    token = strtok(NULL, " \t");
                }
                
                if (sni_filter.keyword_count > 0) {
                    printf("\n%s[INFO] SNI filtering enabled. %d keyword(s) loaded%s\n", COLOR_YELLOW, sni_filter.keyword_count, COLOR_RESET);
                } else {
                    sni_filter_enabled = 0;
                    printf("%s[INFO] No valid keywords found. SNI filtering disabled.%s\n", COLOR_RED, COLOR_RESET);
                }
            } else {
                sni_filter_enabled = 0;
                printf("%s[INFO] Invalid input. SNI filtering disabled.%s\n", COLOR_RED, COLOR_RESET);
            }
        } else {
            sni_filter_enabled = 0;
            printf("%s[INFO] SNI filtering disabled%s\n", COLOR_CYAN, COLOR_RESET);
        }
    }
    
    // Display Check section
    printf("\n==============================================================================\n");
    printf("                                    Check\n");
    printf("==============================================================================\n");
    printf("[INFO] Mode: Offline PCAP file analysis (%s)\n", filename);
    printf("[INFO] Target SNI: ");
    
    if (sni_filter_enabled && sni_filter.keyword_count > 0) {
        for (int i = 0; i < sni_filter.keyword_count; i++) {
            printf("%s", sni_filter.keywords[i]);
            if (i < sni_filter.keyword_count - 1) {
                printf(", ");
            }
        }
        printf("\n");
    } else {
        printf("All domains (no filter)\n");
    }
    
    printf("=== TLS Packet Analysis Started ===\n\n");
    
    // Open and analyze PCAP file
    file_handle = pcap_open_offline(filename, errbuf);
    if (file_handle == NULL) {
        printf("%s[ERROR] Could not open PCAP file %s: %s%s\n", COLOR_RED, filename, errbuf, COLOR_RESET);
        return;
    }
    
    while ((packet = pcap_next(file_handle, &header)) != NULL) {
        packet_count++;
        stats.total_packets++;
        
        struct iphdr *ip_hdr;
        struct tcphdr *tcp_hdr;
        const unsigned char *payload;
        int payload_len;
        int link_header_len = 0;
        
        int datalink = pcap_datalink(file_handle);
        switch (datalink) {
            case DLT_EN10MB: link_header_len = 14; break;
            case DLT_LINUX_SLL: link_header_len = 16; break;
            case DLT_NULL: link_header_len = 4; break;
            case DLT_RAW: link_header_len = 0; break;
            default: link_header_len = 14; break;
        }
        
        if (header.len < link_header_len + sizeof(struct iphdr) + sizeof(struct tcphdr)) {
            continue;
        }
        
        ip_hdr = (struct iphdr*)(packet + link_header_len);
        
        if (ip_hdr->version != 4 || ip_hdr->protocol != IPPROTO_TCP) {
            continue;
        }
        
        tcp_hdr = (struct tcphdr*)((unsigned char*)ip_hdr + (ip_hdr->ihl * 4));
        
        if (ntohs(tcp_hdr->source) != port && ntohs(tcp_hdr->dest) != port) {
            continue;
        }
        
        payload = (unsigned char*)tcp_hdr + (tcp_hdr->doff * 4);
        payload_len = header.len - link_header_len - (ip_hdr->ihl * 4) - (tcp_hdr->doff * 4);
        
        if (payload_len > 0) {
            process_tls_packet(payload, payload_len, ip_hdr, tcp_hdr);
        }
    }
    
    pcap_close(file_handle);
    
    printf("\n%s[INFO] Enhanced PQC file analysis completed%s\n", COLOR_GREEN, COLOR_RESET);
    printf("%s    Total packets processed: %d%s\n", COLOR_CYAN, packet_count, COLOR_RESET);
    print_analysis_results();
}

// List all available network interfaces
void list_interfaces(void) {
    pcap_if_t *alldevs, *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("%s[INFO] Error finding devices: %s%s\n", COLOR_RED, errbuf, COLOR_RESET);
        return;
    }
     
    printf("\n%s==============================================================================%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s                      AVAILABLE NETWORK INTERFACES                           %s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s==============================================================================%s\n", COLOR_CYAN, COLOR_RESET);
    
    printf("\n%sAll available network interfaces:%s\n", COLOR_YELLOW, COLOR_RESET);
    
    // Display all available interfaces
    for (device = alldevs; device != NULL; device = device->next) {
        
        // Display IP address
        pcap_addr_t *addr;
        char ip_str[INET_ADDRSTRLEN] = "No IP";
        for (addr = device->addresses; addr != NULL; addr = addr->next) {
            if (addr->addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in*)addr->addr;
                strcpy(ip_str, inet_ntoa(sin->sin_addr));
                break;
            }
        }
        
        // Display interface number and type/purpose first
        const char* type_info = get_interface_type_and_purpose(device->name, device->description);
        printf("\n    %s%2d%s. %s%s%s", COLOR_GREEN, i+1, COLOR_RESET, COLOR_YELLOW, type_info, COLOR_RESET);

        // Then display interface name and IP
        printf("\n        %s%-12s%s", COLOR_CYAN, device->name, COLOR_RESET);
        printf(" %s[%s]%s", COLOR_WHITE, ip_str, COLOR_RESET);

        // Display additional description if available
        if (device->description && strlen(device->description) > 0) {
            printf("\n        %s%s%s", COLOR_BLUE, device->description, COLOR_RESET);
        }
        
        i++;
    }
    
    if (i == 0) {
        printf("%s[INFO] No network interfaces found%s\n", COLOR_RED, COLOR_RESET);
    } else {
        printf("\n\n%sInterface Selection Guide:%s\n", COLOR_BOLD, COLOR_RESET);
        printf("%s    • eth0/enp0s3: Primary network connection - Best for HTTPS traffic%s\n", COLOR_GREEN, COLOR_RESET);
        printf("%s    • lo (Loopback): Local testing and development%s\n", COLOR_GREEN, COLOR_RESET);
        printf("%s    • wlan0: Wireless interface - Wi-Fi traffic capture%s\n", COLOR_GREEN, COLOR_RESET);
        printf("%s    • docker0: Docker bridge - Container traffic analysis%s\n", COLOR_GREEN, COLOR_RESET);
        printf("%s    • Virtual interfaces: VM and container networking%s\n", COLOR_GREEN, COLOR_RESET);
        
        printf("\n%sFor TLS analysis, typically use:%s\n", COLOR_YELLOW, COLOR_RESET);
        printf("%s    • Primary network interface for real-world HTTPS traffic%s\n", COLOR_CYAN, COLOR_RESET);
        printf("%s    • Loopback interface for local server testing%s\n", COLOR_CYAN, COLOR_RESET);
        printf("%s    • Virtual interfaces for containerized applications%s\n", COLOR_CYAN, COLOR_RESET);
    }

    pcap_freealldevs(alldevs);
}

// Check if interface is available for packet capture
int is_interface_available(const char* interface_name) {
    if (!interface_name || strlen(interface_name) == 0) {
        return 0;
    }
    
    pcap_if_t *alldevs, *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    int found = 0;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return 0;
    }
    
    for (device = alldevs; device != NULL; device = device->next) {
        if (strcmp(device->name, interface_name) == 0) {
            found = 1;
            break;
        }
    }
    
    pcap_freealldevs(alldevs);
    return found;
}

// Enhanced interface selection function for Kali Linux
char* select_interface(void) {
    pcap_if_t *alldevs, *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;
    int choice;
    char input[10];
    char *selected_interface = NULL;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("%s[INFO] Error finding devices: %s%s\n", COLOR_RED, errbuf, COLOR_RESET);
        return NULL;
    }
    
    printf("\n%s==============================================================================%s\n", COLOR_YELLOW, COLOR_RESET);
    printf(  "%s                            NETWORK INTERFACE SELECT                          %s\n", COLOR_YELLOW, COLOR_RESET);
    printf("%s==============================================================================%s\n", COLOR_YELLOW, COLOR_RESET);
    
    printf("\n%sAvailable network interfaces for TLS capture:%s\n", COLOR_YELLOW, COLOR_RESET);
    
    // First, display only interfaces with IP addresses
    for (device = alldevs; device != NULL; device = device->next) {
        // Check IP address
        pcap_addr_t *addr;
        char ip_str[INET_ADDRSTRLEN] = "No IP";
        int has_ip = 0;
        
        for (addr = device->addresses; addr != NULL; addr = addr->next) {
            if (addr->addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in*)addr->addr;
                strcpy(ip_str, inet_ntoa(sin->sin_addr));
                has_ip = 1;
                break;
            }
        }
        
        // Display only if interface has IP address
        if (has_ip) {
            // Display interface number and type/purpose first
            const char* type_info = get_interface_type_and_purpose(device->name, device->description);
            printf("\n    %s%2d%s. %s%s%s", COLOR_GREEN, i+1, COLOR_RESET, COLOR_YELLOW, type_info, COLOR_RESET);

            // Then display interface name and IP
            printf("\n        %s%-12s%s", COLOR_CYAN, device->name, COLOR_RESET);
            printf(" %s[%s]%s", COLOR_WHITE, ip_str, COLOR_RESET);

            // Display additional description if available
            if (device->description && strlen(device->description) > 0) {
                printf("\n        %s%s%s", COLOR_BLUE, device->description, COLOR_RESET);
            }
            
            i++; // Count only interfaces with IP addresses
        }
    }
    
    if (i == 0) {
        printf("%s[INFO] No interfaces with IP addresses found for TLS capture%s\n", COLOR_RED, COLOR_RESET);
        pcap_freealldevs(alldevs);
        return NULL;
    }
    
    printf("\n%sSelect interface number (1-%d): %s", COLOR_YELLOW, i, COLOR_RESET);
    
    if (fgets(input, sizeof(input), stdin) != NULL) {
        choice = atoi(input);
        
        if (choice >= 1 && choice <= i) {
            // Find the selected interface (count only those with IP addresses)
            int current_index = 0;
            for (device = alldevs; device != NULL; device = device->next) {
                // Check IP address
                pcap_addr_t *addr;
                int has_ip = 0;
                
                for (addr = device->addresses; addr != NULL; addr = addr->next) {
                    if (addr->addr->sa_family == AF_INET) {
                        has_ip = 1;
                        break;
                    }
                }
                
                if (has_ip) {
                    if (current_index == choice - 1) {
                        break;
                    }
                    current_index++;
                }
            }
            
            if (device) {
                selected_interface = strdup(device->name);
                
                printf("\n%s[INFO] Interface selected: %s%s%s\n", COLOR_GREEN, COLOR_CYAN, selected_interface, COLOR_RESET);
                
                // Display detailed information about selected interface
                pcap_addr_t *addr;
                for (addr = device->addresses; addr != NULL; addr = addr->next) {
                    if (addr->addr->sa_family == AF_INET) {
                        struct sockaddr_in *sin = (struct sockaddr_in*)addr->addr;
                        printf("%s[INFO] IP Address: %s%s%s\n", COLOR_CYAN, COLOR_WHITE, inet_ntoa(sin->sin_addr), COLOR_RESET);
                        break;
                    }
                }
                
                const char* type_info = get_interface_type_and_purpose(device->name, device->description);
                printf("%s[INFO] Interface Type: %s%s\n", COLOR_CYAN, type_info, COLOR_RESET);
                
                if (device->description) {
                    printf("%s[INFO] Description: %s%s%s\n", COLOR_CYAN, COLOR_WHITE, device->description, COLOR_RESET);
                }
            }
        } else {
            printf("%s[INFO] Invalid choice. Please select a number between 1 and %d.%s\n", COLOR_RED, i, COLOR_RESET);
        }
    }
    
    pcap_freealldevs(alldevs);
    return selected_interface;
}

// Interface type and purpose determination function
const char* get_interface_type_and_purpose(const char* name, const char* description) {
    // Loopback interface
    if (strcmp(name, "lo") == 0) {
        return "Loopback - Local testing (127.0.0.1)";
    }
    
    // Physical ethernet interfaces
    if (strncmp(name, "eth", 3) == 0 || strncmp(name, "enp", 3) == 0) {
        return "Ethernet - Main network connection";
    }
    
    // Wireless interfaces
    if (strncmp(name, "wlan", 4) == 0 || strncmp(name, "wlp", 3) == 0) {
        return "Wi-Fi - Wireless network connection";
    }
    
    // VirtualBox related interfaces
    if (strncmp(name, "vbox", 4) == 0) {
        return "VirtualBox - Virtual network adapter";
    }
    
    // Docker related interfaces
    if (strncmp(name, "docker", 6) == 0 || strncmp(name, "br-", 3) == 0) {
        return "Docker - Container network bridge";
    }
    
    // Virtual ethernet interfaces
    if (strncmp(name, "veth", 4) == 0) {
        return "Virtual Ethernet - Container interface";
    }
    
    // Tunnel/VPN interfaces
    if (strncmp(name, "tun", 3) == 0 || strncmp(name, "tap", 3) == 0) {
        return "VPN/Tunnel - Encrypted connection";
    }
    
    // Monitor mode wireless interfaces (Kali Linux specific)
    if (strstr(name, "mon") != NULL) {
        return "Monitor Mode - Wireless packet capture";
    }
    
    // Other virtual interfaces
    if (strncmp(name, "virbr", 5) == 0) {
        return "Virtual Bridge - KVM/libvirt network";
    }
    
    // USB network interfaces
    if (strncmp(name, "usb", 3) == 0) {
        return "USB Network - USB tethering/adapter";
    }
    
    // PPP interfaces
    if (strncmp(name, "ppp", 3) == 0) {
        return "PPP - Point-to-Point Protocol";
    }
    
    return "Network Interface - Check interface details";
}

// Signal handler for graceful shutdown
void signal_handler(int sig) {
    running = 0;
    printf("\n%s[INFO] Capture stopped%s\n", COLOR_YELLOW, COLOR_RESET);
    
    print_analysis_results();

    usleep(100000); 

    if (handle) {
        pcap_close(handle);
    }
    if (dumper) {
        pcap_dump_close(dumper);
    }
    
    exit(0);
}

// Print usage information
void print_usage(const char* prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -i interface    Network interface to capture on\n");
    printf("  -I              Interactive interface selection mode\n");
    printf("  -p port         Port to capture (default: 443)\n");
    printf("  -w file         Write packets to PCAP file\n");
    printf("  -r file         Read and analyze PCAP file (offline mode)\n");
    printf("  -f file         Analyze domains from text file (batch mode)\n");
    printf("  -l              Capture local traffic (port 4450)\n");
    printf("  -L              List all available network interfaces\n");
    printf("  -h              Show this help message\n");
    
    printf("\nExamples:\n");
    printf("  sudo %s -L                     # List all available interfaces\n", prog_name);
    printf("  sudo %s -I                     # Interactive interface selection\n", prog_name);
    printf("  sudo %s                        # Capture HTTPS traffic (auto-select interface)\n", prog_name);
    printf("  sudo %s -i eth0 -p 443         # Live capture on eth0\n", prog_name);
    printf("  sudo %s -l -w capture.pcap     # Local capture and save\n", prog_name);
    printf("  %s -r capture.pcapng           # Analyze saved pcap file\n", prog_name);

    printf("\nNote: Enhanced with Post-Quantum Cryptography (PQC) hybrid detection\n");
    printf("      Supports ML-KEM, HQC, Falcon, ML-DSA, SPHINCS+ algorithms\n");
    printf("      PQC analysis requires TLS 1.3 connections\n");
    printf("      Multiple keywords can be used for SNI filtering (space-separated)\n");
    printf("      Analysis results are saved as CSV file for Excel import\n");
}

// Main function
int main(int argc, char *argv[]) {
    char *interface = NULL;
    int port = 443;
    char *pcap_file = NULL;
    char *read_file = NULL;
    char *batch_file = NULL;
    int local_mode = 0;
    int interactive_mode = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter_str[100];
    struct bpf_program filter;
    
    int opt;
while ((opt = getopt(argc, argv, "i:Ip:w:r:f:lLh:")) != -1) {  
        switch (opt) {
            case 'i': interface = optarg; break;
            case 'I': interactive_mode = 1; break;
            case 'p': port = atoi(optarg); break;
            case 'w': pcap_file = optarg; break;
            case 'r': read_file = optarg; break;
            case 'f': batch_file = optarg; break;
            case 'l': local_mode = 1; port = 4450; interface = "lo"; break;
            case 'L': list_interfaces(); return 0;
            case 'h': print_usage(argv[0]); return 0;
            default: print_usage(argv[0]); return 1;
        }
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    print_banner();
    
    if (read_file) {
        printf("%s\n[INFO] Mode: Offline PQC Analysis Mode%s\n", COLOR_YELLOW, COLOR_RESET);
        analyze_pcap_file(read_file, port);
        return 0;
    }
    
    if (batch_file) {
        printf("%s[INFO] Mode: Batch Domain Analysis%s\n", COLOR_YELLOW, COLOR_RESET);
        
        
        analyze_domains_from_file(batch_file);
        
        print_analysis_results();
        return 0;
    }

    if (geteuid() != 0) {
        printf("%s[INFO] Live capture requires root privileges%s\n", COLOR_RED, COLOR_RESET);
        printf("%s[INFO] Run with: sudo %s%s\n", COLOR_YELLOW, argv[0], COLOR_RESET);
        return 1;
    }
    
    // Ask for SNI filtering
    ask_sni_filter();
    
    // Interface selection logic
    if (!interface) {
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL) {
            printf("%s[INFO] Could not find devices: %s%s\n", COLOR_RED, errbuf, COLOR_RESET);
            return 1;
        }
        
        // Interactive mode or manual selection
        interface = select_interface();
        if (!interface) {
            printf("%s[INFO] No interface selected. Trying auto-selection...%s\n", COLOR_YELLOW, COLOR_RESET);
            
            // Auto-selection logic (fallback)
            if (port == 443 && !local_mode) {
                pcap_if_t *dev = alldevs;
                while (dev != NULL) {
                    if (!(dev->flags & PCAP_IF_LOOPBACK) && dev->addresses != NULL) {
                        pcap_addr_t *addr;
                        for (addr = dev->addresses; addr != NULL; addr = addr->next) {
                            if (addr->addr && addr->addr->sa_family == AF_INET) {
                                struct sockaddr_in *sin = (struct sockaddr_in*)addr->addr;
                                if (sin->sin_addr.s_addr != 0) {
                                    interface = strdup(dev->name);
                                    printf("%s[INFO] Auto-selected interface: %s%s\n", COLOR_GREEN, interface, COLOR_RESET);
                                    break;
                                }
                            }
                        }
                        if (interface) break;
                    }
                    dev = dev->next;
                }
            }
            
            // If still no interface, select first available interface
            if (!interface) {
                pcap_if_t *dev = alldevs;
                if (dev != NULL) {
                    interface = strdup(dev->name);
                    printf("%s[INFO] Auto-selected interface: %s%s\n", COLOR_CYAN, interface, COLOR_RESET);
                }
            }
        }
        
        pcap_freealldevs(alldevs);
    }
    
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("%s[INFO] Could not open device %s: %s%s\n", COLOR_RED, interface, errbuf, COLOR_RESET);
        return 1;
    }
    
    if (pcap_file) {
        dumper = pcap_dump_open(handle, pcap_file);
        if (dumper == NULL) {
            printf("%s[INFO] Could not open dump file %s%s\n", COLOR_RED, pcap_file, COLOR_RESET);
            pcap_close(handle);
            return 1;
        }
    }
    
    snprintf(filter_str, sizeof(filter_str), "tcp port %d", port);
    if (pcap_compile(handle, &filter, filter_str, 0, 0) == -1) {
        printf("%s[INFO] Could not compile filter %s: %s%s\n", COLOR_RED, filter_str, pcap_geterr(handle), COLOR_RESET);
        if (dumper) pcap_dump_close(dumper);
        pcap_close(handle);
        return 1;
    }
    
    if (pcap_setfilter(handle, &filter) == -1) {
        printf("%s[INFO] Could not apply filter %s: %s%s\n", COLOR_RED, filter_str, pcap_geterr(handle), COLOR_RESET);
        pcap_freecode(&filter);
        if (dumper) pcap_dump_close(dumper);
        pcap_close(handle);
        return 1;
    }
    
    
    pcap_loop(handle, 0, packet_handler, NULL);
    
    pcap_freecode(&filter);
    if (dumper) pcap_dump_close(dumper);
    pcap_close(handle);
    
    return 0;
}
