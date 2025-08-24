#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pcap.h>
#include <winsock2.h>
#include <windows.h>
#include <time.h>
#include <locale.h>
#include <ctype.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/applink.c>
#include "libs/xlsxwriter.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib") 
#pragma comment(lib, "packet.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

// Network packet structures
#pragma pack(1)
typedef struct {
    unsigned char dest_mac[6];
    unsigned char src_mac[6];
    unsigned short ether_type;
} ethernet_header;

pcap_t* global_handle = NULL;

typedef struct {
    unsigned char version_ihl;
    unsigned char type_of_service;
    unsigned short total_length;
    unsigned short identification;
    unsigned short flags_fragment;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short header_checksum;
    unsigned int src_addr;
    unsigned int dest_addr;
} ip_header;

typedef struct {
    unsigned short src_port;
    unsigned short dest_port;
    unsigned int sequence;
    unsigned int acknowledge;
    unsigned char data_offset;
    unsigned char flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_pointer;
} tcp_header;
#pragma pack()

// TLS Analysis structures
typedef struct {
    unsigned short code;
    const char *name;
    int is_quantum_vulnerable;
} cipher_suite_info;

typedef struct {
    unsigned short code;
    const char *name;
    int is_quantum_vulnerable;
} signature_algorithm_info;

typedef struct {
    unsigned short code;
    const char *name;
    int is_quantum_vulnerable;
} key_exchange_info;

// Session analysis result
typedef struct {
    char timestamp[32];
    char src_ip[16];
    char dst_ip[16];
    unsigned short src_port;
    unsigned short dst_port;
    char sni[256];
    char tls_version[16];
    char cipher_suite[64];
    char public_key_algo[32];
    char signature_algo[32];
    char key_exchange[32];
    char cert_subject[64];
    char handshake_types[128];
    int vulnerability_count;
    char vulnerabilities[512];
    char detailed_vulnerabilities[1024];
    char vulnerable_field[32];
    char pubkey_type[32];
    char subject_cn[128];
    char cert_issuer[256];
    char cert_expiry_date[64];
} tls_session_analysis;

typedef struct {
    tls_session_analysis* sessions;
    int capacity;
    int count;
} session_manager_t;
static session_manager_t session_mgr = {NULL, 0, 0};

// SNI Tracking for duplicate removal
#define MAX_DISPLAYED_SNIS 1000
#define MAX_SNI_LEN 256
static char displayed_snis[MAX_DISPLAYED_SNIS][MAX_SNI_LEN];
static int displayed_sni_count = 0;

typedef struct pending_connection {
    char src_ip[16];
    char dst_ip[16];
    unsigned short src_port;
    unsigned short dst_port;
    char sni[256];
    time_t created_time;
    int handshake_state;
    struct pending_connection* next;
} pending_connection_t;
static pending_connection_t* pending_head = NULL;
static int pending_count = 0;

// Global data tables
static const cipher_suite_info cipher_suites[] = {
    {0x1301, "TLS_AES_128_GCM_SHA256", 0},
    {0x1302, "TLS_AES_256_GCM_SHA384", 0},
    {0x1303, "TLS_CHACHA20_POLY1305_SHA256", 0},
    {0x1304, "TLS_AES_128_CCM_SHA256", 0}, 
    {0x1305, "TLS_AES_128_CCM_8_SHA256", 0},  
    {0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 1},
    {0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 1},
    {0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 1},
    {0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 1},
    {0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA", 1},
    {0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA", 1},
    {0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 1},
    {0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 1},
    {0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 1},
    {0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", 1},
    {0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 1},
    {0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 1},
};

static const signature_algorithm_info signature_algorithms[] = {
    // Classical signature algorithms (quantum vulnerable)
    {0x0804, "RSA-PSS-SHA256", 1},
    {0x0805, "RSA-PSS-SHA384", 1},
    {0x0806, "RSA-PSS-SHA512", 1},
    {0x0807, "Ed25519", 1}, 
    {0x0808, "Ed448", 1},   
    {0x0401, "RSA-PKCS1-SHA256", 1},
    {0x0501, "RSA-PKCS1-SHA384", 1},
    {0x0601, "RSA-PKCS1-SHA512", 1},
    {0x0403, "ECDSA-SHA256", 1},
    {0x0503, "ECDSA-SHA384", 1},
    {0x0603, "ECDSA-SHA512", 1},
    {0x0201, "RSA-PKCS1-SHA1", 1},
    {0x0203, "ECDSA-SHA1", 1},

    // Post-Quantum Digital Signatures (IANA assigned codes)
    {0x0B01, "ML-DSA-44", 0},               // NIST ML-DSA (Dilithium2) - 128-bit security
    {0x0B02, "ML-DSA-65", 0},               // NIST ML-DSA (Dilithium3) - 192-bit security
    {0x0B03, "ML-DSA-87", 0},               // NIST ML-DSA (Dilithium5) - 256-bit security
    {0x0B04, "Falcon-512", 0},              // NIST Falcon 512-bit
    {0x0B05, "Falcon-1024", 0},             // NIST Falcon 1024-bit
    {0x0B06, "SPHINCS+-SHA256-128s", 0},    // NIST SPHINCS+ 128-bit security, small signature
    {0x0B07, "SPHINCS+-SHA256-192s", 0},    // NIST SPHINCS+ 192-bit security, small signature
    {0x0B08, "SPHINCS+-SHA256-256s", 0},    // NIST SPHINCS+ 256-bit security, small signature
    
    // Experimental/Draft codes for testing
    {0xFE00, "ML-DSA-44-Draft", 0},         // Draft implementation for testing
    {0xFE01, "ML-DSA-65-Draft", 0},         // Draft implementation for testing
};

static const key_exchange_info key_exchanges[] = {
    // Classical key exchange algorithms (quantum vulnerable)
    {0x001D, "X25519", 1},
    {0x001E, "X448", 1},
    {0x0017, "secp256r1", 1},
    {0x0018, "secp384r1", 1},
    {0x0019, "secp521r1", 1},
    {0x0100, "ffdhe2048", 1},
    {0x0101, "ffdhe3072", 1},

    // Post-Quantum Key Exchange (IANA assigned codes)
    {0x023A, "ML-KEM-512", 0},              // NIST ML-KEM (Kyber) 512-bit security
    {0x023B, "ML-KEM-768", 0},              // NIST ML-KEM (Kyber) 768-bit security
    {0x023C, "ML-KEM-1024", 0},             // NIST ML-KEM (Kyber) 1024-bit security
    
    // Hybrid mode: Classical + Post-Quantum for transition period
    {0x0768, "X25519Kyber512Draft00", 0},   // X25519 + Kyber512 hybrid
    {0x0769, "X25519Kyber768Draft00", 0},   // X25519 + Kyber768 hybrid
    {0x076A, "X25519Kyber1024Draft00", 0},  // X25519 + Kyber1024 hybrid
    {0x6399, "X25519MLKEM512", 0},          // Experimental X25519 + ML-KEM-512
    {0x639A, "X25519MLKEM768", 0},          // Experimental X25519 + ML-KEM-768
    
    // Other Post-Quantum algorithms
    {0x2F39, "BIKE-L1", 0},                 // BIKE Round 4 candidate
    {0x2F3A, "BIKE-L3", 0},                 // BIKE Round 4 candidate
    {0x2F3B, "BIKE-L5", 0},                 // BIKE Round 4 candidate
};

//SNI filtering
int enable_sni_filtering = 0;  // 0: OFF, 1: ON
char custom_sni_keywords[10][128];
int keyword_count = 0;

// Global variables
static int connection_counter = 0;
static char current_timestamp[32];
int vulnerable_count = 0;
static int total_packets = 0;
static int tls_packets = 0;
char sni_filter_status[512] = "";

// Function declarations
int is_sni_already_displayed(const char* sni);
void mark_sni_as_displayed(const char* sni);
int is_migration_required(const char* expiry_date_str);
void print_analysis_start_info(const char* mode_filename);
const char* get_cipher_suite_name(unsigned short code);
const char* get_signature_algorithm_name(unsigned short code);
const char* get_key_exchange_name(unsigned short code);
const char* get_tls_level(const char* version, int short_format);
const char* get_cipher_level(const char* field, int short_format);
int is_cipher_vulnerable(unsigned short code);
int is_signature_vulnerable(unsigned short code);
int is_key_exchange_vulnerable(unsigned short code);
void print_header(void);
void print_session_summary(void);
char* format_ip(unsigned int ip);
void detect_tls_version(const unsigned char* payload, size_t len, char* version_out);
void extract_sni(const unsigned char* payload, size_t len, char* sni_out);
void extract_cipher_suite(const unsigned char* payload, size_t len, char* cipher_out);
void extract_signature_algorithm(const unsigned char* payload, size_t len, char* sig_out);
void extract_key_exchange(const unsigned char* payload, size_t len, char* kex_out);
void analyze_certificate_from_sni(const char* hostname, tls_session_analysis* session);
void analyze_certificate(const unsigned char* payload, size_t len,
                         char* pubkey_out, char* subject_out,
                         char* issuer_out, char* expiry_out,
                         const char* sni, tls_session_analysis* session);
int extract_cert_expiry_date(const u_char* data, int length, char* out_date);
const char* get_handshake_type_name(unsigned char type);
void analyze_tls_session(const unsigned char* payload, size_t payload_len,
                        const char* src_ip, const char* dst_ip,
                        unsigned short src_port, unsigned short dst_port);
void packet_handler(unsigned char* args, const struct pcap_pkthdr* header, const unsigned char* packet);
void* memmem(const void* haystack, size_t haystacklen, const void* needle, size_t needlelen);

// TLS extension parsing functions for PQC algorithm detection
int parse_tls_extensions(const unsigned char* payload, size_t len, size_t extensions_start, 
                        char* supported_groups, char* signature_algs, char* supported_versions);
void extract_signature_algorithms_ext(const unsigned char* payload, size_t len, char* sig_out);
void extract_supported_groups_ext(const unsigned char* payload, size_t len, char* groups_out);

// Utility function implementations
const char* get_cipher_suite_name(unsigned short code) {
    for (int i = 0; i < sizeof(cipher_suites) / sizeof(cipher_suites[0]); i++) {
        if (cipher_suites[i].code == code) {
            return cipher_suites[i].name;
        }
    }
    return "Unknown";
}

const char* get_signature_algorithm_name(unsigned short code) {
    for (int i = 0; i < sizeof(signature_algorithms) / sizeof(signature_algorithms[0]); i++) {
        if (signature_algorithms[i].code == code) {
            return signature_algorithms[i].name;
        }
    }
    return "Unknown";
}

const char* get_key_exchange_name(unsigned short code) {
    for (int i = 0; i < sizeof(key_exchanges) / sizeof(key_exchanges[0]); i++) {
        if (key_exchanges[i].code == code) {
            return key_exchanges[i].name;
        }
    }
    return "Unknown";
}

int is_cipher_vulnerable(unsigned short code) {
    for (int i = 0; i < sizeof(cipher_suites) / sizeof(cipher_suites[0]); i++) {
        if (cipher_suites[i].code == code) {
            return cipher_suites[i].is_quantum_vulnerable;
        }
    }
    return 0;
}

int is_signature_vulnerable(unsigned short code) {
    for (int i = 0; i < sizeof(signature_algorithms) / sizeof(signature_algorithms[0]); i++) {
        if (signature_algorithms[i].code == code) {
            return signature_algorithms[i].is_quantum_vulnerable;
        }
    }
    return 0;
}

int is_key_exchange_vulnerable(unsigned short code) {
    for (int i = 0; i < sizeof(key_exchanges) / sizeof(key_exchanges[0]); i++) {
        if (key_exchanges[i].code == code) {
            return key_exchanges[i].is_quantum_vulnerable;
        }
    }
    return 0;
}

int is_custom_sni_match(const char* hostname) {
    if (!enable_sni_filtering) return 1;

    if (!hostname || strlen(hostname) == 0) return 0;

    for (int i = 0; i < keyword_count; i++) {
        if (strstr(hostname, custom_sni_keywords[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

int extract_cert_expiry_date(const u_char* data, int length, char* out_date) {
    for (int i = 0; i < length - 16; i++) {

        if (data[i] == '2' && data[i + 1] == '0') {
            // check if the next 13 characters are all digits or 'Z'
            int valid = 1;
            for (int j = 0; j < 14; j++) {
                if (!(isdigit(data[i + j]) || data[i + j] == 'Z')) {
                    valid = 0;
                    break;
                }
            }

            if (valid) {
                char buf[15] = {0};
                strncpy(buf, (const char*)&data[i], 14);  // e.g., "20250709000000Z

                char year[5], month[3], day[3];
                strncpy(year, buf, 4);
                strncpy(month, buf + 4, 2);
                strncpy(day, buf + 6, 2);
                year[4] = month[2] = day[2] = '\0';

                snprintf(out_date, 20, "%s-%s-%s", year, month, day);
                return 1;
            }
        }
    }
    return 0;
}


char* format_ip(unsigned int ip) {
    static char ip_str[16];
    sprintf(ip_str, "%d.%d.%d.%d",
            (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF, ip & 0xFF);
    return ip_str;
}

void update_current_timestamp(void) {
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    strftime(current_timestamp, sizeof(current_timestamp), "%H:%M:%S", tm_info);
}

void print_with_timestamp(const char* format, ...) {
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "[%Y-%m-%d %H:%M:%S]", tm_info);

    printf("%s ", timestamp);

    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

void detect_tls_version(const unsigned char* payload, size_t len, char* version_out) {
    if (len < 3) {
        strcpy(version_out, "Unknown");
        return;
    }
    
    unsigned char major = payload[1];
    unsigned char minor = payload[2];
    unsigned char handshake_type = (len > 5) ? payload[5] : 0;

    // Check for TLS 1.3 specific indicators in ClientHello
    if (handshake_type == 0x01) { // ClientHello
        // Look for supported_versions extension (0x002b) - RFC 8446
        for (size_t i = 0; i < len - 8; i++) {
            if (payload[i] == 0x00 && payload[i+1] == 0x2b) {
                unsigned short ext_len = (payload[i+2] << 8) | payload[i+3];
                if (i + 4 + ext_len <= len && ext_len >= 3) {
                    // supported_versions format: versions_length(1) + ProtocolVersion[]
                    unsigned char versions_len = payload[i+4];
                    if (versions_len + 1 == ext_len) {
                        // Check each supported version (2 bytes each)
                        for (int j = 0; j < versions_len; j += 2) {
                            if (i + 5 + j + 1 < len) {
                                unsigned short version = (payload[i+5+j] << 8) | payload[i+5+j+1];
                                if (version == 0x0304) { // TLS 1.3 version code
                                    strcpy(version_out, "TLS 1.3");
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    if (handshake_type == 0x02) { // ServerHello
        // Check cipher suite for TLS 1.3
        if (len > 44) {
            unsigned char session_id_len = payload[43];
            size_t cipher_offset = 44 + session_id_len;
            if (cipher_offset + 1 < len) {
                unsigned short cipher = (payload[cipher_offset] << 8) | payload[cipher_offset + 1];
                if (cipher == 0x1301 || cipher == 0x1302 || cipher == 0x1303) {
                    strcpy(version_out, "TLS 1.3");
                    return;
                }
            }
        }
    }
    
    // Fallback to record layer version
    if (major == 0x03) {
        switch (minor) {
            case 0x01: strcpy(version_out, "TLS 1.0"); break;
            case 0x02: strcpy(version_out, "TLS 1.1"); break;
            case 0x03: strcpy(version_out, "TLS 1.2"); break;
            case 0x04: strcpy(version_out, "TLS 1.3"); break;
            default: sprintf(version_out, "TLS %d.%d", major, minor); break;
        }
    } else {
        sprintf(version_out, "Unknown (0x%02x%02x)", major, minor);
    }
}

void extract_sni(const unsigned char* payload, size_t len, char* sni_out) {
    strcpy(sni_out, "");
    
    if (len < 6 || payload[5] != 0x01) return; // Not ClientHello
    
    // Find SNI extension (0x0000)
    for (size_t i = 0; i < len - 9; i++) {
        if (payload[i] == 0x00 && payload[i+1] == 0x00) {
            size_t ext_len = (payload[i+2] << 8) | payload[i+3];
            if (i + 4 + ext_len <= len && ext_len > 5) {
                size_t name_list_len = (payload[i+4] << 8) | payload[i+5];
                if (name_list_len > 3 && i + 6 + name_list_len <= len) {
                    unsigned char name_type = payload[i+6];
                    if (name_type == 0x00) { // hostname
                        size_t hostname_len = (payload[i+7] << 8) | payload[i+8];
                        if (hostname_len > 0 && i + 9 + hostname_len <= len && hostname_len < 255) {
                            memcpy(sni_out, &payload[i+9], hostname_len);
                            sni_out[hostname_len] = '\0';
                            return;
                        }
                    }
                }
            }
        }
    }
}

void extract_cipher_suite(const unsigned char* payload, size_t len, char* cipher_out) {
    strcpy(cipher_out, "");
    
    if (len < 6 || payload[5] != 0x02) return; // Not ServerHello
    
    if (len >= 44) {
        unsigned char session_id_len = payload[43];
        size_t cipher_offset = 44 + session_id_len;
        if (cipher_offset + 1 < len) {
            unsigned short cipher_code = (payload[cipher_offset] << 8) | payload[cipher_offset + 1];
            strcpy(cipher_out, get_cipher_suite_name(cipher_code));
        }
    }
}

void extract_signature_algorithm(const unsigned char* payload, size_t len, char* sig_out) {
    strcpy(sig_out, "");
    
    if (len < 6 || payload[5] != 0x0f) return; // Not CertificateVerify
    
    if (len >= 11) {
        unsigned short sig_code = (payload[9] << 8) | payload[10];
        strcpy(sig_out, get_signature_algorithm_name(sig_code));
    }
}

void extract_key_exchange(const unsigned char* payload, size_t len, char* kex_out) {
    strcpy(kex_out, "");
    
    // Look for KeyShare extension (0x0033) in TLS 1.3 handshake
    for (size_t i = 0; i < len - 8; i++) {
        if (payload[i] == 0x00 && payload[i+1] == 0x33) {
            unsigned short ext_len = (payload[i+2] << 8) | payload[i+3];
            if (i + 4 + ext_len <= len && ext_len >= 4) {
                // KeyShare extension structure: length(2) + key_exchange_entry...
                size_t pos = i + 4;
                
                if (payload[5] == 0x01) { // ClientHello - contains multiple key shares
                    // ClientKeyShare: client_shares_length(2) + KeyShareEntry[]
                    unsigned short client_shares_len = (payload[pos] << 8) | payload[pos + 1];
                    pos += 2;
                    
                    // Extract first key share entry: group(2) + key_exchange_length(2) + key_exchange
                    if (pos + 4 <= i + 4 + ext_len) {
                        unsigned short group_code = (payload[pos] << 8) | payload[pos + 1];
                        strcpy(kex_out, get_key_exchange_name(group_code));
                        return;
                    }
                } else if (payload[5] == 0x02) { // ServerHello - contains single key share
                    // ServerKeyShare: KeyShareEntry (group(2) + key_exchange_length(2) + key_exchange)
                    if (pos + 4 <= i + 4 + ext_len) {
                        unsigned short group_code = (payload[pos] << 8) | payload[pos + 1];
                        strcpy(kex_out, get_key_exchange_name(group_code));
                        return;
                    }
                }
            }
        }
    }
}

void analyze_certificate(const unsigned char* payload, size_t len,
                        char* pubkey_out, char* subject_out,
                        char* issuer_out, char* expiry_out,
                        const char* sni, tls_session_analysis* session) {
  
   strcpy(pubkey_out, "");
   strcpy(subject_out, "");
   strcpy(issuer_out, "");
   strcpy(expiry_out, "");

   if (len < 6 || payload[5] != 0x0b) return;

   // Public key algorithm detection using OpenSSL parsing
   if (len > 100) { // Certificate must be large enough
       const unsigned char* cert_ptr = payload + 9; // Skip TLS handshake header
       
       // Extract certificate length (3 bytes)
       if (len > 12) {
           int cert_len = (payload[9] << 16) | (payload[10] << 8) | payload[11];
           cert_ptr = payload + 12; // Start of certificate data
           
           if (cert_len > 0 && cert_len < len - 12) {
               // Parse certificate with OpenSSL
               X509* cert = d2i_X509(NULL, &cert_ptr, cert_len);
               if (cert) {
                   EVP_PKEY* pkey = X509_get_pubkey(cert);
                   if (pkey) {
                       int key_type = EVP_PKEY_base_id(pkey);
                       switch (key_type) {
                           case EVP_PKEY_RSA:
                               strcpy(pubkey_out, "RSA");
                               break;
                           case EVP_PKEY_EC:
                               strcpy(pubkey_out, "ECDSA");
                               break;
                           case EVP_PKEY_ED25519:
                               strcpy(pubkey_out, "Ed25519");
                               break;
                           case EVP_PKEY_ED448:
                               strcpy(pubkey_out, "Ed448");
                               break;
                           default:
                               strcpy(pubkey_out, "Unknown");
                               break;
                       }
                       EVP_PKEY_free(pkey);
                   } else {
                       strcpy(pubkey_out, "Extract_Failed");
                   }
                   X509_free(cert);
               } else {
                   // Fallback to pattern matching method
                   if (memmem(payload, len, "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01", 12)) {
                       strcpy(pubkey_out, "RSA");
                   } else if (memmem(payload, len, "\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01", 11)) {
                       strcpy(pubkey_out, "ECDSA");
                   } else {
                       strcpy(pubkey_out, "Unknown");
                   }
               }
           } else {
               strcpy(pubkey_out, "Invalid_Cert");
           }
       } else {
           strcpy(pubkey_out, "Too_Short");
       }
   } else {
       strcpy(pubkey_out, "Packet_Too_Small");
   }

   // Extract issuer CN (first occurrence - usually issuer)
   const unsigned char* cn_oid = (const unsigned char*)"\x06\x03\x55\x04\x03";
   const unsigned char* first_cn_pos = memmem(payload, len, cn_oid, 5);
   if (first_cn_pos && first_cn_pos + 7 < payload + len) {
       unsigned char cn_len = first_cn_pos[6];
       if (cn_len > 0 && cn_len < 64 && first_cn_pos + 7 + cn_len <= payload + len) {
           memcpy(issuer_out, first_cn_pos + 7, cn_len);
           issuer_out[cn_len] = '\0';
       }
   }

   // Extract subject CN (second occurrence - usually subject)
   const unsigned char* subject_seq = (const unsigned char*)"\x30\x82";
   const unsigned char* subject_pos = memmem(payload, len, subject_seq, 2);
   if (subject_pos) {
       const unsigned char* second_cn_pos = memmem(subject_pos, len - (subject_pos - payload), cn_oid, 5);
       if (second_cn_pos && second_cn_pos + 7 < payload + len) {
           unsigned char cn_len = second_cn_pos[6];
           if (cn_len > 0 && cn_len < 64 && second_cn_pos + 7 + cn_len <= payload + len) {
               memcpy(subject_out, second_cn_pos + 7, cn_len);
               subject_out[cn_len] = '\0';
           }
       }
   }

   // Expiry date extraction
   if (!extract_cert_expiry_date(payload, len, expiry_out)) {
       strcpy(expiry_out, "unknown");
   }

   // If packet-based extraction failed or incomplete, try SNI-based extraction
   if ((strlen(issuer_out) == 0 || strcmp(issuer_out, "unknown") == 0) ||
       (strlen(expiry_out) == 0 || strcmp(expiry_out, "unknown") == 0)) {
       if (session) {
           analyze_certificate_from_sni(sni, session);
           
           if (strlen(session->cert_issuer) > 0 && strcmp(session->cert_issuer, "Unknown") != 0) {
               strncpy(issuer_out, session->cert_issuer, 255);
               issuer_out[255] = '\0';
           }
           if (strlen(session->cert_expiry_date) > 0 && strcmp(session->cert_expiry_date, "Unknown") != 0) {
               strncpy(expiry_out, session->cert_expiry_date, 63);
               expiry_out[63] = '\0';
           }
       }
   }
}

void analyze_certificate_from_sni(const char* hostname, tls_session_analysis* session) {
    static int winsock_initialized = 0;
    if (!winsock_initialized) {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            strcpy(session->cert_issuer, "Winsock Init Failed");
            strcpy(session->cert_expiry_date, "Winsock Init Failed");
            return;
        }
        winsock_initialized = 1;
    }

    if (!hostname || strlen(hostname) == 0) {
        strcpy(session->cert_issuer, "Invalid Hostname");
        strcpy(session->cert_expiry_date, "Unknown");
        return;
    }

    // Static cache to avoid repeated failed connections
    static char failed_hosts[200][256]; 
    static time_t failed_times[200]; 
    static int failed_count = 0;
    static time_t last_cleanup = 0;

    time_t now = time(NULL);
    if (now - last_cleanup > 180) {
        int new_count = 0;
        for (int i = 0; i < failed_count; i++) {
            if (now - failed_times[i] < 300) {
                if (new_count != i) {
                    strcpy(failed_hosts[new_count], failed_hosts[i]);
                    failed_times[new_count] = failed_times[i];
                }
                new_count++;
            }
        }
        failed_count = new_count;
        last_cleanup = now;
    }

    // Check if this host recently failed
    for (int i = 0; i < failed_count && i < 100; i++) {
        if (strcmp(failed_hosts[i], hostname) == 0) {
            strcpy(session->cert_issuer, "Previous Connection Failed");
            strcpy(session->cert_expiry_date, "Cached Failure");
            return;
        }
    }

    SSL_CTX* ctx = NULL;
    SSL* ssl = NULL;
    X509* cert = NULL;
    SOCKET sockfd = INVALID_SOCKET;
    struct sockaddr_in server_addr;
    struct hostent* host_entry;

    // Initialize default failure state
    strcpy(session->cert_issuer, "Connection Failed");
    strcpy(session->cert_expiry_date, "Connection Failed");

    // OpenSSL initialization (one-time)
    static int ssl_initialized = 0;
    if (!ssl_initialized) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        ssl_initialized = 1;
    }

    // Create SSL context - use older method for better compatibility
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx) {
        strcpy(session->cert_issuer, "SSL Context Failed");
        goto add_to_cache_and_return;
    }

    // Set SSL context options
    SSL_CTX_set_timeout(ctx, 10);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);

    // Create SSL object
    ssl = SSL_new(ctx);
    if (!ssl) {
        strcpy(session->cert_issuer, "SSL Create Failed");
        goto add_to_cache_and_cleanup;
    }

    // DNS resolution
    host_entry = gethostbyname(hostname);
    if (!host_entry) {
        strcpy(session->cert_issuer, "DNS Failed");
        strcpy(session->cert_expiry_date, "DNS Failed");
        goto add_to_cache_and_cleanup;
    }

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == INVALID_SOCKET) {
        strcpy(session->cert_issuer, "Socket Failed");
        strcpy(session->cert_expiry_date, "Socket Failed");
        goto add_to_cache_and_cleanup;
    }

    // Set socket timeout (Windows style)
    DWORD timeout_ms = 10000; // 10 seconds
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));

    // Prepare server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    
    if (strcmp(hostname, "localhost") == 0) {
        server_addr.sin_port = htons(4450);
        server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    } else {
        server_addr.sin_port = htons(443);
        memcpy(&server_addr.sin_addr, host_entry->h_addr_list[0], host_entry->h_length);
    }

    // Connect to server
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
        int error = WSAGetLastError();
        switch (error) {
            case WSAECONNREFUSED:
                strcpy(session->cert_issuer, "Connection Refused");
                strcpy(session->cert_expiry_date, "Connection Refused");
                break;
            case WSAETIMEDOUT:
                strcpy(session->cert_issuer, "Connection Timeout");
                strcpy(session->cert_expiry_date, "Connection Timeout");
                break;
            case WSAEHOSTUNREACH:
                strcpy(session->cert_issuer, "Host Unreachable");
                strcpy(session->cert_expiry_date, "Host Unreachable");
                break;
            default:
                strcpy(session->cert_issuer, "Connect Failed");
                strcpy(session->cert_expiry_date, "Connect Failed");
                break;
        }
        goto add_to_cache_and_cleanup;
    }

    // Set up SSL connection
    SSL_set_fd(ssl, (int)sockfd);
    SSL_set_tlsext_host_name(ssl, hostname);

    // Perform SSL handshake
    int ssl_result = SSL_connect(ssl);
    if (ssl_result <= 0) {
        int ssl_error = SSL_get_error(ssl, ssl_result);
        
        switch (ssl_error) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                strcpy(session->cert_issuer, "SSL Handshake Timeout");
                strcpy(session->cert_expiry_date, "SSL Handshake Timeout");
                break;
            case SSL_ERROR_SYSCALL:
                strcpy(session->cert_issuer, "SSL System Error");
                strcpy(session->cert_expiry_date, "SSL System Error");
                break;
            case SSL_ERROR_SSL:
                strcpy(session->cert_issuer, "SSL Protocol Error");
                strcpy(session->cert_expiry_date, "SSL Protocol Error");
                break;
            default:
                strcpy(session->cert_issuer, "SSL Handshake Failed");
                strcpy(session->cert_expiry_date, "SSL Handshake Failed");
                break;
        }
        goto add_to_cache_and_cleanup;
    }

    // Get certificate
    cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        strcpy(session->cert_issuer, "No Certificate");
        strcpy(session->cert_expiry_date, "No Certificate");
        goto cleanup;
    }

    // Extract public key information
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (pkey) {
        int key_type = EVP_PKEY_base_id(pkey);
    
        switch (key_type) {
            case EVP_PKEY_RSA: {
                strcpy(session->public_key_algo, "RSA");
                int key_size = EVP_PKEY_bits(pkey);
                break;
            }
            case EVP_PKEY_EC: {
                strcpy(session->public_key_algo, "ECDSA");
                break;
            }
            case EVP_PKEY_ED25519: {
                strcpy(session->public_key_algo, "Ed25519");
                break;
            }
            case EVP_PKEY_ED448: {
                strcpy(session->public_key_algo, "Ed448");
                break;
            }
            default: {
                char key_type_str[32];
                snprintf(key_type_str, sizeof(key_type_str), "Type_%d", key_type);
                strcpy(session->public_key_algo, key_type_str);
                break;
            }
        }
        EVP_PKEY_free(pkey);
    } else {
        strcpy(session->public_key_algo, "Extract_Failed");
    }

    // Extract issuer information (simplified but reliable approach)
    X509_NAME* issuer_name = X509_get_issuer_name(cert);
    if (issuer_name) {
        // Try CN first
        char temp_issuer[256];
        int cn_len = X509_NAME_get_text_by_NID(issuer_name, NID_commonName, temp_issuer, sizeof(temp_issuer) - 1);
        if (cn_len > 0) {
            temp_issuer[cn_len] = '\0';
            strncpy(session->cert_issuer, temp_issuer, sizeof(session->cert_issuer) - 1);
            session->cert_issuer[sizeof(session->cert_issuer) - 1] = '\0';
        } else {
            // Try Organization as fallback
            int org_len = X509_NAME_get_text_by_NID(issuer_name, NID_organizationName, temp_issuer, sizeof(temp_issuer) - 1);
            if (org_len > 0) {
                temp_issuer[org_len] = '\0';
                strncpy(session->cert_issuer, temp_issuer, sizeof(session->cert_issuer) - 1);
                session->cert_issuer[sizeof(session->cert_issuer) - 1] = '\0';
            } else {
                strcpy(session->cert_issuer, "Unknown Issuer");
            }
        }
    } else {
        strcpy(session->cert_issuer, "No Issuer Info");
    }

    // Extract expiry date
    ASN1_TIME* not_after = X509_get0_notAfter(cert);
    if (not_after) {
        struct tm tm_time;
        if (ASN1_TIME_to_tm(not_after, &tm_time)) {
            char formatted_date[20];
            strftime(formatted_date, sizeof(formatted_date), "%Y-%m-%d", &tm_time);
            strncpy(session->cert_expiry_date, formatted_date, sizeof(session->cert_expiry_date) - 1);
            session->cert_expiry_date[sizeof(session->cert_expiry_date) - 1] = '\0';
        } else {
            strcpy(session->cert_expiry_date, "Parse Failed");
        }
    } else {
        strcpy(session->cert_expiry_date, "No Expiry Info");
    }

    // Success - don't add to failed cache
    goto cleanup;

add_to_cache_and_cleanup:
    // Add to cache only on failure
    if (failed_count < 100) {
        strncpy(failed_hosts[failed_count], hostname, 255);
        failed_hosts[failed_count][255] = '\0';
        failed_count++;
    }
    goto cleanup;

add_to_cache_and_return:
    // Add to cache and return without cleanup
    if (failed_count < 100) {
        strncpy(failed_hosts[failed_count], hostname, 255);
        failed_hosts[failed_count][255] = '\0';
        failed_count++;
    }
    if (ctx) SSL_CTX_free(ctx);
    return;

cleanup:
    if (cert) X509_free(cert);
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (sockfd != INVALID_SOCKET) closesocket(sockfd);
    if (ctx) SSL_CTX_free(ctx);
}

const char* get_handshake_type_name(unsigned char type) {
    switch (type) {
        case 0x00: return "HelloRequest";          // Server requests renegotiation (TLS 1.0-1.2 only)
        case 0x01: return "ClientHello";           // Client initiates handshake, sends supported protocols/ciphers
        case 0x02: return "ServerHello";           // Server responds with selected protocol/cipher
        case 0x03: return "HelloVerifyRequest";    // DTLS DoS protection mechanism
        case 0x04: return "NewSessionTicket";      // Session resumption ticket (TLS 1.3)
        case 0x05: return "CertificateStatus";     // OCSP stapling response for certificate validation
        case 0x08: return "EncryptedExtensions";   // TLS 1.3 encrypted extension data
        case 0x0b: return "Certificate";           // Server/client certificate chain transmission
        case 0x0c: return "ServerKeyExchange";     // Server key exchange for DHE/ECDHE
        case 0x0d: return "CertificateRequest";    // Server requests client certificate
        case 0x0e: return "ServerHelloDone";       // Server indicates end of hello message phase
        case 0x0f: return "CertificateVerify";     // Proves certificate private key ownership
        case 0x10: return "ClientKeyExchange";     // Client key exchange material
        case 0x14: return "Finished";              // Handshake completion verification message
        case 0x15: return "KeyUpdate";             // TLS 1.3 key rotation during session
        case 0x16: return "NextProtocol";          // NPN protocol negotiation (deprecated)
        case 0x17: return "MessageHash";           // TLS 1.3 message hash for transcript
        default: return "Unknown";                 // Unrecognized handshake type
    }
}

void print_header(void) {
    printf("\n");
    printf("================================================================\n");
    printf("            TLS Packet Analyzer for Windows\n");
    printf("           With Quantum Vulnerability Analysis\n");
    printf("                    C Version 1.0\n");
    printf("================================================================\n\n");

    printf("[INFO] Key Features:\n");
    printf("       - Live TLS traffic capture & offline PCAP analysis\n");
    printf("       - Multiple keyword SNI filtering for targeted analysis\n");
    printf("       - Interactive network interface selection\n");
    printf("       - TLS 1.0-1.3 version detection & cipher suite analysis\n");
    printf("       - Quantum vulnerability assessment & post-quantum readiness\n");
    printf("       - Real-time handshake message tracking\n");
    printf("       - Automated vulnerability reporting with recommendations\n");
    printf("       - Automatic vulnerability report generation\n\n");
    

    printf("[INFO] Quantum Vulnerable Algorithms:\n");
    printf("       - RSA: Shor's algorithm can factor large numbers\n");
    printf("       - ECDSA/ECDHE: Shor's algorithm can solve discrete log\n");
    printf("       - DH/DHE: Vulnerable to quantum discrete log attacks\n");
    printf("       - AES-128: Security reduced to 64-bit by Grover's algorithm\n");
    printf("       - SHA-224: Reduced to 112-bit security\n");
    printf("       - SHA-256: Reduced to 128-bit security\n\n");

    printf("[INFO] Quantum Resistant:\n");
    printf("       - AES-256: Recommended (AES-128 reduced security)\n");
    printf("       - SHA-384/512: Recommended (SHA-256 reduced security)\n");
    printf("       - ChaCha20: Symmetric ciphers with sufficient key lengths\n\n");
    
    printf("[INFO] Quick Start:\n");
    printf("       - Live capture mode: windows_tls_capture.exe\n");
    printf("       - Offline PCAP analysis mode: windows_tls_capture.exe example.pcapng\n");
    printf("       - Generate traffic: open https://localhost:4450 in browser\n");
    printf("       - Stop and see analysis results: Ctrl+C\n\n");


}


void prompt_sni_filtering_option() {
    char response[16];

    printf("\n============================================================\n");
    printf("        SNI filtering mode? (yes / no)\n");
    printf("============================================================\n");
    printf("> ");
    scanf("%15s", response);

    if (strcmp(response, "yes") == 0) {
        enable_sni_filtering = 1;

        printf("\n============================================================\n");
        printf("        Enter SNI keywords to filter.\n\n");
        printf("        Input example:\n");
        printf("        > \"google\" \"amazon\" \"etc\"\n\n");
        printf("        Guide:\n");
        printf("        Enter \"google\" for all related TLS communication\n");
        printf("        or \"www.google.com\" for specific TLS communication\n");
        printf("============================================================\n");
        printf("> ");

        getchar();

        char input_line[1024];
        fgets(input_line, sizeof(input_line), stdin);

        const char* ptr = input_line;
        while ((ptr = strchr(ptr, '"')) != NULL) {
            ptr++;
            const char* end = strchr(ptr, '"');
            if (!end) break;

            int len = end - ptr;
            if (len > 0 && len < 128 && keyword_count < 10) {
                strncpy(custom_sni_keywords[keyword_count], ptr, len);
                custom_sni_keywords[keyword_count][len] = '\0';
                keyword_count++;
            }
            ptr = end + 1;
        }

        printf("\n[INFO] SNI filtering enabled. %d keyword(s) loaded.\n\n", keyword_count);
    } else {
        enable_sni_filtering = 0;
        printf("\n[INFO] SNI filtering disabled. All TLS sessions will be analyzed.\n\n");
    }

    if (enable_sni_filtering && keyword_count > 0) {
        sni_filter_status[0] = '\0';
        for (int i = 0; i < keyword_count; i++) {
            strcat(sni_filter_status, custom_sni_keywords[i]);
            if (i < keyword_count - 1) strcat(sni_filter_status, ", ");
        }
    } else {
        strcpy(sni_filter_status, "(all sessions analyzed)");
    }
}

void print_analysis_start_info(const char* mode_filename) {
    printf("\n============================================================\n");
    printf("                           Check\n");
    printf("============================================================\n");

    if (mode_filename != NULL) {
        printf("[INFO] Mode: Offline PCAP file analysis (%s)\n", mode_filename);
    } else {
        printf("[INFO] Mode: Real-time packet capture\n");
    }

    printf("[INFO] Target SNI: %s\n", sni_filter_status);
    printf("[INFO] Press Ctrl+C to stop capture and see analysis results\n\n");
}

void print_session_summary() {
    printf("\n================================================================\n");
    printf("                    TLS ANALYSIS RESULTS\n");
    printf("================================================================\n");
    printf("Total packets: %d\n", total_packets);
    printf("TLS sessions: %d\n", session_mgr.count);
    printf("Vulnerable sessions: %d\n", vulnerable_count);
    printf("SNI Filter: %s\n", sni_filter_status);
    printf("================================================================\n");

    if (session_mgr.count == 0) {
        printf("No TLS sessions captured.\n\n");
        return;
    }

    // First table - TLS information with increased SNI and Field widths
    printf("\n+-----------+---------------------------------------+---------------+-----------+--------------------------------------------------+---------------+---------------+\n");
    printf("| Session # | SNI                                   | TLS ver       | TLS Level | Cipher suite                                     | Field         | Cipher Level  |\n");
    printf("+-----------+---------------------------------------+---------------+-----------+--------------------------------------------------+---------------+---------------+\n");

    for (int i = 0; i < session_mgr.count; i++) {
        tls_session_analysis* s = &session_mgr.sessions[i];

        const char* tls_level = get_tls_level(s->tls_version, 1);
        const char* cipher_level = get_cipher_level(s->vulnerable_field, 1);
        
        // Increased truncation limits for SNI and Field
        char sni_display[38];
        char cipher_display[49];
        char field_display[14];
        
        strncpy(sni_display, (s->sni && strlen(s->sni) > 0) ? s->sni : "-", 37);
        sni_display[37] = '\0';
        
        strncpy(cipher_display, (s->cipher_suite && strlen(s->cipher_suite) > 0) ? s->cipher_suite : "-", 48);
        cipher_display[48] = '\0';
        
        strncpy(field_display, (s->vulnerable_field && strlen(s->vulnerable_field) > 0) ? s->vulnerable_field : "X", 13);
        field_display[13] = '\0';

        printf("| %-9d | %-37s | %-13s | %-9s | %-48s | %-13s | %-13s |\n",
            i + 1,
            sni_display,
            s->tls_version,
            tls_level,
            cipher_display,
            field_display,
            cipher_level
        );
    }

    printf("+-----------+---------------------------------------+---------------+-----------+--------------------------------------------------+---------------+---------------+\n\n");


    // Second table - Certificate information with Public Key column added
    printf("+-----------+---------------------------------------+--------------------------------------------------+---------------+---------------+---------------------+\n");
    printf("| Session # | SNI                                   | Issuer                                           | Public Key    | Expiry Date   | Migration Required  |\n");
    printf("+-----------+---------------------------------------+--------------------------------------------------+---------------+---------------+---------------------+\n");

    for (int i = 0; i < session_mgr.count; i++) {
        tls_session_analysis* s = &session_mgr.sessions[i];
    
        char sni_display[38];
        char issuer_display[49];
        char pubkey_display[14];
        char expiry_display[14];
    
        strncpy(sni_display, (s->sni && strlen(s->sni) > 0) ? s->sni : "-", 37);
        sni_display[37] = '\0';
    
        strncpy(issuer_display, (s->cert_issuer && strlen(s->cert_issuer) > 0) ? s->cert_issuer : "Unknown", 48);
        issuer_display[48] = '\0';
    
        strncpy(pubkey_display, (s->public_key_algo && strlen(s->public_key_algo) > 0) ? s->public_key_algo : "Unknown", 13);
        pubkey_display[13] = '\0';
    
        strncpy(expiry_display, s->cert_expiry_date, 13);
        expiry_display[13] = '\0';

        printf("| %-9d | %-37s | %-48s | %-13s | %-13s | %-19s |\n",
            i + 1,
            sni_display,
            issuer_display,
            pubkey_display,
            expiry_display,
            (is_migration_required(s->cert_expiry_date) ? "T" : "F")
        );
    }

    printf("+-----------+---------------------------------------+--------------------------------------------------+---------------+---------------+---------------------+\n\n");

}

const char* get_tls_level(const char* version, int short_format) {
    const char* level;
    if (strstr(version, "1.3") != NULL) level = "HIGH";
    else if (strstr(version, "1.2") != NULL) level = "MID";
    else level = "LOW"; // Legacy TLS
    
    if (short_format) {
        return (level[0] == 'H') ? "H" : (level[0] == 'M') ? "M" : "L";
    }
    return level;
}

const char* get_cipher_level(const char* field, int short_format) {
   const char* level;
   if (field == NULL || strlen(field) == 0 || strcmp(field, "X") == 0) {
       level = "HIGH"; // No vulnerability
   } 
   // HIGH level 
   else if (strcmp(field, "AES_256") == 0 || strcmp(field, "ChaCha20") == 0 || strcmp(field, "SHA_384") == 0) {
       level = "HIGH";
   }
   // MID level  
   else if (strcmp(field, "AES_128") == 0 || strcmp(field, "SHA_256") == 0) {
       level = "MID";
   }
   // LOW level
   else if (strcmp(field, "RSA") == 0 || strcmp(field, "CBC") == 0 || strcmp(field, "ECDSA") == 0 || strcmp(field, "ECC") == 0 || strcmp(field, "ECDHE") == 0) {
       level = "LOW";
   }
   else {
       level = "MID"; // Default fallback
   }
   
   if (short_format) {
       return (level[0] == 'H') ? "H" : (level[0] == 'M') ? "M" : "L";
   }
   return level;
}

int is_migration_required(const char* expiry_date_str) {
    if (!expiry_date_str || strlen(expiry_date_str) == 0) {
        return 0; // Unknown expiry date
    }
    
    // Skip if expiry date is error message
    if (strstr(expiry_date_str, "Failed") || 
        strstr(expiry_date_str, "Unknown") || 
        strstr(expiry_date_str, "unknown") ||
        strcmp(expiry_date_str, "X") == 0) {
        return 0;
    }

    struct tm expiry = {0};
    int year, month, day;

    // Format: "YYYY-MM-DD" (standardized format)
    if (sscanf(expiry_date_str, "%d-%d-%d", &year, &month, &day) == 3) {
        expiry.tm_year = year - 1900;
        expiry.tm_mon = month - 1;
        expiry.tm_mday = day;
    } else {
        return 0; // Parse failed
    }

    // Validate parsed date
    if (year < 2025 || year > 2035 || month < 1 || month > 12 || day < 1 || day > 31) {
        return 0;
    }

    time_t now = time(NULL);
    time_t expiry_time = mktime(&expiry);
    
    if (expiry_time == -1) {
        return 0; // mktime failed
    }

    double days_left = difftime(expiry_time, now) / 86400.0;
    
    // Debug output (can be removed later)
    // printf("[DEBUG] Expiry: %s, Days left: %.1f\n", expiry_date_str, days_left);

    return (days_left < 90.0 && days_left > 0) ? 1 : 0;
}

void save_report_to_xlsx() {
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);

    char filename[128];
    snprintf(filename, sizeof(filename), "TLS_Quantum_Vulnerability_Report_%s.xlsx", timestamp);

    lxw_workbook  *workbook  = workbook_new(filename);
    lxw_worksheet *worksheet = workbook_add_worksheet(workbook, NULL);

    worksheet_merge_range(worksheet, 0, 0, 0, 4, "", NULL);
    worksheet_write_string(worksheet, 0, 0, "==================================================================", NULL);

    worksheet_merge_range(worksheet, 11, 0, 11, 3, "", NULL);
    worksheet_write_string(worksheet, 11, 0, "==================================================================", NULL);
    
    lxw_format *header_fmt = workbook_add_format(workbook);
    format_set_bold(header_fmt);
    format_set_border(header_fmt, LXW_BORDER_THIN);
    format_set_bg_color(header_fmt, LXW_COLOR_GRAY);
    format_set_align(header_fmt, LXW_ALIGN_CENTER);
    format_set_align(header_fmt, LXW_ALIGN_VERTICAL_CENTER);

    lxw_format *data_fmt = workbook_add_format(workbook);
    format_set_border(data_fmt, LXW_BORDER_THIN);

    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

    worksheet_write_string(worksheet, 1, 1, "TLS QUANTUM VULNERABILITY ANALYSIS REPORT", NULL);
    worksheet_write_string(worksheet, 4, 1, "Report Generated:", NULL);
    worksheet_write_string(worksheet, 4, 2, time_str, NULL);
    worksheet_write_string(worksheet, 5, 1, "Analysis Tool:", NULL);
    worksheet_write_string(worksheet, 5, 2, "TLS Packet Analyzer for Windows", NULL);

    char buf[256];
    snprintf(buf, sizeof(buf), "- Total packets: %d", total_packets);
    worksheet_write_string(worksheet, 7, 1, buf, NULL);
    snprintf(buf, sizeof(buf), "- TLS sessions: %d", session_mgr.count);
    worksheet_write_string(worksheet, 8, 1, buf, NULL);
    snprintf(buf, sizeof(buf), "- Vulnerable sessions: %d", vulnerable_count);
    worksheet_write_string(worksheet, 9, 1, buf, NULL);
    snprintf(buf, sizeof(buf), "- SNI Filter: %s", sni_filter_status);
    worksheet_write_string(worksheet, 10, 1, buf, NULL);

    worksheet_merge_range(worksheet, 14, 0, 14, 1, "Session", header_fmt);
    worksheet_merge_range(worksheet, 14, 2, 14, 3, "TLS", header_fmt);
    worksheet_merge_range(worksheet, 14, 4, 14, 6, "Quantum Vulnerable", header_fmt);


    worksheet_merge_range(worksheet, 14, 7, 14, 9, "CA", header_fmt);
    worksheet_write_string(worksheet, 14, 10, "Migration", header_fmt);
    worksheet_write_string(worksheet, 14, 11, "Total", header_fmt);

    const char* field_names[] = {
        "Session #", "SNI", "TLS ver", "level",
        "Cipher suite", "Field", "level",
        "Issuer", "Public Key", "Expiry Date", "Required", "level"
    };
    for (int i = 0; i < 12; i++) {
        worksheet_write_string(worksheet, 15, i, field_names[i], header_fmt);
        worksheet_set_column(worksheet, i, i, 20, NULL);
    }

    for (int i = 0; i < session_mgr.count; i++) {
        tls_session_analysis* s = &session_mgr.sessions[i];
        int row = 16 + i;
        int migrate = is_migration_required(s->cert_expiry_date);

        const char* tls_level = get_tls_level(s->tls_version, 1);        
        const char* cipher_level = get_cipher_level(s->vulnerable_field, 1);

        char total_level[32];
        const char* tls_short = get_tls_level(s->tls_version, 1);       // 1 = "H/M/L"
        const char* cipher_short = get_cipher_level(s->vulnerable_field, 1);   // 1 = "H/M/L"
        const char* ca_level = migrate ? "L" : "H";
        
        snprintf(total_level, sizeof(total_level), "TLS_%s_CS_%s_CA_%s", tls_short, cipher_short, ca_level);

        worksheet_write_number(worksheet, row, 0, i + 1, data_fmt);
        worksheet_write_string(worksheet, row, 1, s->sni, data_fmt);

        char tls_version_short[16];
        if (strncmp(s->tls_version, "TLS ", 4) == 0) {
            strcpy(tls_version_short, s->tls_version + 4);
        } else {
            strcpy(tls_version_short, s->tls_version);  
        }
        worksheet_write_string(worksheet, row, 2, tls_version_short, data_fmt);

        worksheet_write_string(worksheet, row, 3, tls_level, data_fmt); 
    
        char cipher_suite_short[64];
        if (strncmp(s->cipher_suite, "TLS_", 4) == 0) {
            strcpy(cipher_suite_short, s->cipher_suite + 4); 
        } else {
            strcpy(cipher_suite_short, s->cipher_suite);    
        }
        worksheet_write_string(worksheet, row, 4, cipher_suite_short, data_fmt);

        worksheet_write_string(worksheet, row, 5, s->vulnerable_field, data_fmt);
        worksheet_write_string(worksheet, row, 6, cipher_level, data_fmt);  
        worksheet_write_string(worksheet, row, 7, s->cert_issuer, data_fmt);
        worksheet_write_string(worksheet, row, 8, (s->public_key_algo && strlen(s->public_key_algo) > 0) ? s->public_key_algo : "Unknown", data_fmt);
        worksheet_write_string(worksheet, row, 9, s->cert_expiry_date, data_fmt);
        worksheet_write_string(worksheet, row, 10, migrate ? "T" : "F", data_fmt);
        worksheet_write_string(worksheet, row, 11, total_level, data_fmt);
    }

    workbook_close(workbook);
    printf("[INFO] Analysis report saved to \"%s\"\n", filename);
}

void analyze_tls_session(const unsigned char* payload, size_t payload_len,
                        const char* src_ip, const char* dst_ip,
                        unsigned short src_port, unsigned short dst_port) {
    
    if (payload_len < 6 || payload[0] != 0x16) {
        return; // Not TLS handshake
    }
    
    tls_packets++;
    unsigned char handshake_type = payload[5];

    static char last_sni[256] = "";
    static char last_src_ip[16] = "";
    static char last_dst_ip[16] = "";
    static unsigned short last_src_port = 0;
    static unsigned short last_dst_port = 0;
    char current_sni[256] = "";

    // Static variables to store session data for later saving
    static char saved_tls_version[32] = "";
    static char saved_cipher_suite[64] = "";
    static char saved_pubkey[32] = "";
    static char saved_subject[64] = "";
    static char saved_issuer[64] = "";
    static int session_data_ready = 0;  // Flag to indicate if session tracking is active
    
    if (handshake_type == 0x01) {
        extract_sni(payload, payload_len, current_sni);
    
        // Always track connections, apply SNI filter during display/storage phase
        int should_track = 1;
        if (enable_sni_filtering && strlen(current_sni) > 0) {
            should_track = is_custom_sni_match(current_sni);
        } else if (enable_sni_filtering && strlen(current_sni) == 0) {
            should_track = 0;  // Skip empty SNI when filtering is enabled
        }

        if (should_track) {
            char current_conn_key[128];
            snprintf(current_conn_key, sizeof(current_conn_key), "%s:%d->%s:%d:%s", 
                     src_ip, src_port, dst_ip, dst_port, current_sni);
            static char last_conn_key[128] = "";
            if (strcmp(current_conn_key, last_conn_key) != 0) {
                connection_counter++;
                strcpy(last_sni, current_sni);
                strcpy(last_src_ip, src_ip);
                strcpy(last_dst_ip, dst_ip);
                last_src_port = src_port;
                last_dst_port = dst_port;
                strcpy(last_conn_key, current_conn_key);
                session_data_ready = 1;  // Start session tracking

                update_current_timestamp();

                printf("\n[%s] TLS Connection #%d\n", current_timestamp, connection_counter);
                printf("[+] %s:%d -> %s:%d\n", src_ip, src_port, dst_ip, dst_port);
                printf("Server Name (SNI): %s\n", strlen(current_sni) > 0 ? current_sni : "(empty)");

                char client_tls_version[32];
                detect_tls_version(payload, payload_len, client_tls_version);
                printf("Client TLS Version: %s\n", client_tls_version);
                printf("Supported: TLS 1.3, TLS 1.2\n");
                printf("    ClientHello detected\n");

                // Enhanced PQC algorithm detection from ClientHello extensions
                char supported_groups[512] = "";
                char signature_algs[512] = "";
                char supported_versions[64] = "";
                
                // Parse ClientHello structure to find extensions
                if (payload_len > 43) {
                    unsigned char session_id_len = payload[43];
                    size_t pos = 44 + session_id_len;
                    
                    // Skip cipher suites
                    if (pos + 2 < payload_len) {
                        unsigned short cipher_suites_len = (payload[pos] << 8) | payload[pos + 1];
                        pos += 2 + cipher_suites_len;
                        
                        // Skip compression methods
                        if (pos + 1 < payload_len) {
                            unsigned char compression_len = payload[pos];
                            pos += 1 + compression_len;
                            
                            // Parse extensions for PQC algorithms
                            if (pos + 2 < payload_len) {
                                parse_tls_extensions(payload, payload_len, pos, 
                                                   supported_groups, signature_algs, supported_versions);
                                
                                // Check for Post-Quantum Key Exchange algorithms
                                if (strlen(supported_groups) > 0) {
                                    printf("Supported Groups: %s\n", supported_groups);
                                    if (strstr(supported_groups, "ML-KEM") || 
                                    strstr(supported_groups, "Kyber") ||
                                    strstr(supported_groups, "BIKE") ||
                                    strstr(supported_groups, "X25519Kyber") ||
                                    strstr(supported_groups, "X25519MLKEM")) {
                                        printf("    [PQC DETECTED] Post-Quantum Key Exchange algorithms found!\n");
                                        printf("    -> Client supports quantum-resistant key exchange\n");
                                    }
                                }
                                
                                // Check for Post-Quantum Digital Signature algorithms
                                if (strlen(signature_algs) > 0) {
                                    printf("Signature Algorithms: %s\n", signature_algs);
                                    if (strstr(signature_algs, "ML-DSA") || 
                                        strstr(signature_algs, "Falcon") ||
                                        strstr(signature_algs, "SPHINCS")) {
                                        printf("    [PQC DETECTED] Post-Quantum Signature algorithms found!\n");
                                        printf("    -> Client supports quantum-resistant digital signatures\n");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            if (enable_sni_filtering && strlen(current_sni) > 0) {
                session_data_ready = 0;
            }
        }
    }

    else if (handshake_type == 0x02) {
        if (session_data_ready && strlen(last_sni) > 0) {
            update_current_timestamp();
            printf("\n[%s] TLS Connection #%d\n", current_timestamp, connection_counter);
            printf("[+] %s:%d -> %s:%d\n", dst_ip, dst_port, src_ip, src_port);

            char negotiated_version[32];
            char cipher_suite[64];
            detect_tls_version(payload, payload_len, negotiated_version);
            extract_cipher_suite(payload, payload_len, cipher_suite);
            
            // Save data for session storage
            strcpy(saved_tls_version, negotiated_version);
            strcpy(saved_cipher_suite, cipher_suite);

            printf("Negotiated TLS Version: %s\n", negotiated_version);
            printf("Cipher Suite: %s\n", cipher_suite);
            printf("    ServerHello detected\n");

            printf("\nQuantum Computer Vulnerability Analysis:\n");

            if (strstr(cipher_suite, "TLS_AES") || strstr(negotiated_version, "TLS 1.3")) {
                printf("    [Protocol] TLS 1.3: POST-QUANTUM READY\n");
                printf("        -> Uses modern cryptographic primitives\n");
                printf("        -> Forward secrecy built-in\n");
                printf("    [Encryption] AES-128: RESISTANT\n");
                printf("        -> Grover algorithm reduces to 64-bit but still strong\n");
                printf("\nOverall Quantum Vulnerability: SAFE\n");
                printf("    Relatively safe against quantum computer attacks.\n");
            } else {
                if (strstr(cipher_suite, "ECDHE")) {
                    printf("    [Key Exchange] ECDHE: VULNERABLE\n");
                    printf("        -> Shor algorithm can solve elliptic curve discrete log\n");
                }
                if (strstr(cipher_suite, "RSA")) {
                    printf("    [Authentication] RSA: VULNERABLE\n");
                    printf("        -> Shor algorithm can factor large numbers\n");
                }
                if (strstr(cipher_suite, "AES_128")) {
                    printf("    [Encryption] AES-128: RESISTANT\n");
                    printf("        -> Grover algorithm reduces to 64-bit but still strong\n");
                }
                printf("\nOverall Quantum Vulnerability: VULNERABLE\n");
                printf("    This connection is vulnerable to quantum computer attacks!\n");
            }

            // Store session data immediately after ServerHello analysis
            // Enhanced session uniqueness check using connection-specific identifier
            int session_exists = 0;

            // Check if this SNI was already displayed for session storage
            int sni_already_displayed = is_sni_already_displayed(last_sni);
            if (sni_already_displayed) {
                session_exists = 1; // Skip session storage but continue processing
            } else {
                // Mark this SNI as displayed
                mark_sni_as_displayed(last_sni);
                
                char current_connection_id[128];
                snprintf(current_connection_id, sizeof(current_connection_id), "%s:%d->%s:%d:%s", 
                         last_src_ip, last_src_port, last_dst_ip, last_dst_port, last_sni);

                for (int i = 0; i < session_mgr.count; i++) {
                    char existing_connection_id[128];
                    snprintf(existing_connection_id, sizeof(existing_connection_id), "%s:%d->%s:%d:%s",
                             session_mgr.sessions[i].src_ip, session_mgr.sessions[i].src_port,
                             session_mgr.sessions[i].dst_ip, session_mgr.sessions[i].dst_port,
                             session_mgr.sessions[i].sni);
    
                    if (strcmp(existing_connection_id, current_connection_id) == 0) {
                        session_exists = 1;
                        break;
                    }
                }
            }

            // Store new session if it doesn't exist
            if (!session_exists && session_mgr.count < session_mgr.capacity) {
                tls_session_analysis* session = &session_mgr.sessions[session_mgr.count];
    
                // Basic session information
                time_t now = time(NULL);
                struct tm *tm_info = localtime(&now);
                strftime(session->timestamp, sizeof(session->timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
                strcpy(session->src_ip, last_src_ip);
                strcpy(session->dst_ip, last_dst_ip);
                session->src_port = last_src_port;
                session->dst_port = last_dst_port;
                strcpy(session->sni, last_sni);
    
                // Copy TLS information (use current data, not saved static variables)
                strcpy(session->tls_version, negotiated_version);
                strcpy(session->cipher_suite, cipher_suite);
                strcpy(session->cert_subject, "");
                strcpy(session->signature_algo, "");
                strcpy(session->key_exchange, "");
                strcpy(session->handshake_types, "ClientHello,ServerHello");
    
                // Vulnerability analysis
                session->vulnerability_count = 0;
                strcpy(session->vulnerabilities, "");
                strcpy(session->detailed_vulnerabilities, "");
    
                // Check TLS version vulnerability
                if (strstr(negotiated_version, "1.0") || strstr(negotiated_version, "1.1") || 
                    strstr(negotiated_version, "1.2")) {
                    session->vulnerability_count++;
                    strcat(session->vulnerabilities, "TLSVersion");
                    strcat(session->detailed_vulnerabilities, negotiated_version);
                }
    
                // Check cipher suite vulnerability
                if (strlen(cipher_suite) > 0) {
                    int cipher_vulnerable = 0;
                    char cipher_details[256] = "";
                    strcpy(session->vulnerable_field, "");
        
                    if (strstr(cipher_suite, "RSA_WITH")) {
                        cipher_vulnerable = 1;
                        strcat(cipher_details, "RSA-KeyExchange");
                    }
                    if (strstr(cipher_suite, "ECDHE_RSA")) {
                        cipher_vulnerable = 1;
                        if (strlen(cipher_details) > 0) strcat(cipher_details, "+");
                        strcat(cipher_details, "ECDHE+RSA");
                    }
                    if (strstr(cipher_suite, "ECDHE_ECDSA")) {
                        cipher_vulnerable = 1;
                        if (strlen(cipher_details) > 0) strcat(cipher_details, "+");
                        strcat(cipher_details, "ECDHE+ECDSA");
                    }
                    if (strstr(cipher_suite, "CBC")) {
                        cipher_vulnerable = 1;
                        if (strlen(cipher_details) > 0) strcat(cipher_details, "+");
                        strcat(cipher_details, "CBC-Mode");
                    }
                    if (strstr(cipher_suite, "SHA1") || strstr(cipher_suite, "MD5")) {
                        cipher_vulnerable = 1;
                        if (strlen(cipher_details) > 0) strcat(cipher_details, "+");
                        strcat(cipher_details, "Weak-Hash");
                    }
                    
                    if (strstr(cipher_suite, "RSA")) {
                        strcpy(session->vulnerable_field, "RSA");
                    } else if (strstr(cipher_suite, "CBC")) {
                        strcpy(session->vulnerable_field, "CBC");
                    } else if (strstr(cipher_suite, "AES_128")) {
                        strcpy(session->vulnerable_field, "AES_128");
                    } else if (strstr(cipher_suite, "ChaCha20")) {
                        strcpy(session->vulnerable_field, "ChaCha20");
                    } else if (strstr(cipher_suite, "ECDSA")) {
                        strcpy(session->vulnerable_field, "ECDSA");
                    } else {
                        strcpy(session->vulnerable_field, "X");
                    }
                    
                    if (cipher_vulnerable) {
                        session->vulnerability_count++;
                        if (strlen(session->vulnerabilities) > 0) strcat(session->vulnerabilities, ",");
                        strcat(session->vulnerabilities, "Cipher");
                        if (strlen(session->detailed_vulnerabilities) > 0) strcat(session->detailed_vulnerabilities, ", ");
                        strcat(session->detailed_vulnerabilities, cipher_details);
                    }
                }
                
                session_mgr.count++;

                if (session->vulnerability_count > 0) {
                    vulnerable_count++;
                }

                if (strlen(last_sni) > 0) {
                    analyze_certificate_from_sni(last_sni, session);
                }
            }
        }
    }

    else if (handshake_type == 0x0b) {
        if (session_data_ready && strlen(last_sni) > 0) {
            char pubkey_algo[32];
            char subject[64];
            char issuer[64];
            char expiry[20];

            tls_session_analysis* session = NULL;

            if (session_mgr.count > 0) {
                session = &session_mgr.sessions[session_mgr.count - 1];
            }

            size_t len = payload_len;

            analyze_certificate(payload, len, 
                 pubkey_algo,  // pubkey_algo → pubkey_out
                 subject,      // subject     → subject_out
                 issuer,       // issuer      → issuer_out
                 expiry,       // expiry      → expiry_out
                 last_sni,     // sni
                 session);     // session struct

            printf("Certificate Subject: %s\n", strlen(subject) > 0 ? subject : (session ? session->subject_cn : "Unknown"));
            printf("Certificate Issuer: %s\n", strlen(issuer) > 0 ? issuer : (session ? session->cert_issuer : "Unknown"));
            printf("Public Key: %s\n", strlen(pubkey_algo) > 0 ? pubkey_algo : (session ? session->pubkey_type : "Unknown"));

            
            if (strlen(pubkey_algo) > 0) {
                if (strcmp(pubkey_algo, "RSA") == 0) {
                    printf("    Quantum Vulnerable: Shor algorithm can factor large numbers\n");
                } else if (strcmp(pubkey_algo, "ECDSA") == 0) {
                    printf("    Quantum Vulnerable: Shor algorithm can solve discrete log\n");
                }
            }
            printf("    Certificate detected\n");
            
            // Update existing session with certificate information
            for (int i = 0; i < session_mgr.count; i++) {
                if (strcmp(session_mgr.sessions[i].sni, last_sni) == 0 && 
                    strcmp(session_mgr.sessions[i].dst_ip, last_dst_ip) == 0 &&
                    session_mgr.sessions[i].dst_port == last_dst_port) {
                        
                    // Update public key information
                    strcpy(session_mgr.sessions[i].public_key_algo, pubkey_algo);
                    strcpy(session_mgr.sessions[i].cert_subject, subject);
                    strcpy(session_mgr.sessions[i].cert_issuer, issuer);
                    strcpy(session_mgr.sessions[i].cert_expiry_date, expiry);
                        
                    // Add public key vulnerability if RSA or ECDSA
                    if (strcmp(pubkey_algo, "RSA") == 0) {
                        session_mgr.sessions[i].vulnerability_count++;
                        if (strlen(session_mgr.sessions[i].vulnerabilities) > 0) strcat(session_mgr.sessions[i].vulnerabilities, ",");
                        strcat(session_mgr.sessions[i].vulnerabilities, "PubKey");
                        if (strlen(session_mgr.sessions[i].detailed_vulnerabilities) > 0) strcat(session_mgr.sessions[i].detailed_vulnerabilities, ", ");
                        strcat(session_mgr.sessions[i].detailed_vulnerabilities, "RSA-PublicKey");
                    } else if (strcmp(pubkey_algo, "ECDSA") == 0) {
                        session_mgr.sessions[i].vulnerability_count++;
                        if (strlen(session_mgr.sessions[i].vulnerabilities) > 0) strcat(session_mgr.sessions[i].vulnerabilities, ",");
                        strcat(session_mgr.sessions[i].vulnerabilities, "PubKey");
                        if (strlen(session_mgr.sessions[i].detailed_vulnerabilities) > 0) strcat(session_mgr.sessions[i].detailed_vulnerabilities, ", ");
                        strcat(session_mgr.sessions[i].detailed_vulnerabilities, "ECDSA-PublicKey");
                    }
                    break;
                }
            }
        }
    }

    else if (handshake_type == 0x14) {
        if (session_data_ready && strlen(last_sni) > 0) {
            printf("    Finished detected\n");
        }
    }

    else {
        if (session_data_ready && strlen(last_sni) > 0) {
            const char* handshake_name = get_handshake_type_name(handshake_type);
            printf("    %s detected\n", handshake_name);
        }
    }
}

void packet_handler(unsigned char* args, const struct pcap_pkthdr* header, const unsigned char* packet) {
    total_packets++;
    
    if (header->caplen < sizeof(ethernet_header) + sizeof(ip_header) + sizeof(tcp_header)) {
        return;
    }
    
    ethernet_header* eth = (ethernet_header*)packet;
    
    if (ntohs(eth->ether_type) != 0x0800) {
        return; // Not IP
    }
    
    ip_header* ip = (ip_header*)(packet + sizeof(ethernet_header));
    
    if (ip->protocol != 6) {
        return; // Not TCP
    }
    
    unsigned char ip_header_len = (ip->version_ihl & 0x0F) * 4;
    tcp_header* tcp = (tcp_header*)((unsigned char*)ip + ip_header_len);
    unsigned char tcp_header_len = ((tcp->data_offset >> 4) & 0x0F) * 4;
    
    const unsigned char* payload = (unsigned char*)tcp + tcp_header_len;
    size_t payload_len = header->caplen - (sizeof(ethernet_header) + ip_header_len + tcp_header_len);
    
    char* src_ip = format_ip(ntohl(ip->src_addr));
    char* dst_ip = format_ip(ntohl(ip->dest_addr));
        
    analyze_tls_session(payload, payload_len, src_ip, dst_ip,
                    ntohs(tcp->src_port), ntohs(tcp->dest_port));
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

// Helper function for memmem (not available in all Windows environments)
void* memmem(const void* haystack, size_t haystacklen, const void* needle, size_t needlelen) {
    if (!haystack || !needle || haystacklen < needlelen) return NULL;
    
    const unsigned char* h = (const unsigned char*)haystack;
    const unsigned char* n = (const unsigned char*)needle;
    
    for (size_t i = 0; i <= haystacklen - needlelen; i++) {
        if (memcmp(h + i, n, needlelen) == 0) {
            return (void*)(h + i);
        }
    }
    return NULL;
}

BOOL WINAPI console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT) {
        printf("\n[CTRL+C] Stopping packet capture...\n");
        if (global_handle) {
            pcap_breakloop(global_handle); 
        }
        return TRUE;
    }
    return FALSE;
}

// Parse TLS extensions to extract cryptographic algorithm information
int parse_tls_extensions(const unsigned char* payload, size_t len, size_t extensions_start,
                        char* supported_groups, char* signature_algs, char* supported_versions) {
    // Ensure we have at least the extensions length field
    if (extensions_start + 2 >= len) return 0;
    
    // Read total extensions length (2 bytes)
    size_t extensions_len = (payload[extensions_start] << 8) | payload[extensions_start + 1];
    size_t pos = extensions_start + 2;
    size_t end = pos + extensions_len;
    
    // Validate extensions length doesn't exceed packet boundary
    if (end > len) return 0;
    
    // Parse each extension: type(2) + length(2) + data(length)
    while (pos + 4 <= end) {
        unsigned short ext_type = (payload[pos] << 8) | payload[pos + 1];
        unsigned short ext_len = (payload[pos + 2] << 8) | payload[pos + 3];
        pos += 4;
        
        // Validate extension length doesn't exceed remaining data
        if (pos + ext_len > end) break;
        
        switch (ext_type) {
            case 0x000A: // supported_groups extension - key exchange algorithms
                extract_supported_groups_ext(payload + pos, ext_len, supported_groups);
                break;
            case 0x000D: // signature_algorithms extension
                extract_signature_algorithms_ext(payload + pos, ext_len, signature_algs);
                break;
            case 0x002B: // supported_versions extension - TLS version negotiation
                if (ext_len >= 1) {
                    unsigned char versions_len = payload[pos];
                    if (versions_len + 1 <= ext_len) {
                        // Check each supported version (2 bytes each)
                        for (int i = 1; i < versions_len; i += 2) {
                            if (pos + i + 1 < end) {
                                unsigned short version = (payload[pos + i] << 8) | payload[pos + i + 1];
                                if (version == 0x0304) { // TLS 1.3
                                    strcpy(supported_versions, "TLS 1.3");
                                    break;
                                }
                            }
                        }
                    }
                }
                break;
            case 0x0033: // key_share extension (handled separately in extract_key_exchange)
                break;
        }
        
        pos += ext_len;
    }
    
    return 1;
}

// Extract and parse supported groups (named groups) for key exchange
void extract_supported_groups_ext(const unsigned char* payload, size_t len, char* groups_out) {
    strcpy(groups_out, "");
    if (len < 2) return;
    
    // Read supported groups list length (2 bytes)
    unsigned short groups_len = (payload[0] << 8) | payload[1];
    if (groups_len + 2 > len) return;
    
    char temp[512] = "";
    // Parse each group (2 bytes each)
    for (size_t i = 2; i + 1 < groups_len + 2; i += 2) {
        unsigned short group_code = (payload[i] << 8) | payload[i + 1];
        const char* group_name = get_key_exchange_name(group_code);
        
        // Only include recognized algorithms
        if (strcmp(group_name, "Unknown") != 0) {
            if (strlen(temp) > 0) strcat(temp, ",");
            strcat(temp, group_name);
        }
    }
    
    strncpy(groups_out, temp, 255);
    groups_out[255] = '\0';
}

// Extract and parse signature algorithms extension
void extract_signature_algorithms_ext(const unsigned char* payload, size_t len, char* sig_out) {
    strcpy(sig_out, "");
    if (len < 2) return;
    
    // Read signature algorithms list length (2 bytes)
    unsigned short sig_len = (payload[0] << 8) | payload[1];
    if (sig_len + 2 > len) return;
    
    char temp[512] = "";
    // Parse each signature algorithm (2 bytes each)
    for (size_t i = 2; i + 1 < sig_len + 2; i += 2) {
        unsigned short sig_code = (payload[i] << 8) | payload[i + 1];
        const char* sig_name = get_signature_algorithm_name(sig_code);
        
        // Only include recognized algorithms
        if (strcmp(sig_name, "Unknown") != 0) {
            if (strlen(temp) > 0) strcat(temp, ",");
            strcat(temp, sig_name);
        }
    }
    
    strncpy(sig_out, temp, 255);
    sig_out[255] = '\0';
}

int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    setlocale(LC_ALL, "");

    session_mgr.capacity = 1000;
    session_mgr.sessions = (tls_session_analysis*)malloc(session_mgr.capacity * sizeof(tls_session_analysis));
    session_mgr.count = 0;
    
    if (session_mgr.sessions == NULL) {
        printf("Error: Failed to allocate memory for sessions\n");
        return 1;
    }

    SetConsoleCtrlHandler(console_handler, TRUE);
    
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("Error: Winsock initialization failed\n");
        return 1;
    }
    
    print_header();

    prompt_sni_filtering_option();
    
    pcap_if_t* alldevs;
    pcap_if_t* device;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    
    if (argc > 1) {
        // PCAP file analysis mode
        printf("[INFO] Mode: Offline PCAP file analysis %s\n\n", argv[1]);
        
        handle = pcap_open_offline(argv[1], errbuf);
        global_handle = handle;
        if (handle == NULL) {
            printf("Error: Failed to open PCAP file '%s': %s\n", argv[1], errbuf);
            WSACleanup();
            return 1;
        }
        
        printf("[INFO] Analyzing PCAP file for quantum-vulnerable crypto...\n");
        printf("[INFO] Target SNI: %s\n", sni_filter_status);
        printf("\n");
        
    } else {
        // Live capture mode
        printf("[INFO] Mode: Real-time packet capture \n\n");
        
        // Find all network interfaces
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            printf("Error: Failed to find network interfaces: %s\n", errbuf);
            printf("Make sure Npcap is installed and you have administrator privileges.\n");
            WSACleanup();
            return 1;
        }
        
        // Display available interfaces
        printf("Available network interfaces:\n");
        int i = 0;

        for (device = alldevs; device != NULL; device = device->next) {
            char ip_str[INET_ADDRSTRLEN] = "(no IPv4)";
            for (pcap_addr_t* addr = device->addresses; addr != NULL; addr = addr->next) {
                if (addr->addr && addr->addr->sa_family == AF_INET) {
                    struct sockaddr_in* ipv4 = (struct sockaddr_in*)addr->addr;
                    strcpy(ip_str, inet_ntoa(ipv4->sin_addr));
                    break;
                }
            }
            
            printf("%d. %-30s [%s]\n", ++i, device->description ? device->description : "(No description)", ip_str);
            printf("   %s\n", device->name);
        }
        
        if (i == 0) {
            printf("Error: No network interfaces found.\n");
            printf("Make sure Npcap is installed and you have administrator privileges.\n");
            pcap_freealldevs(alldevs);
            WSACleanup();
            return 1;
        }
        
        // User selects interface
        int choice;
        printf("\nSelect interface number (1-%d): ", i);
        if (scanf("%d", &choice) != 1 || choice < 1 || choice > i) {
            printf("Error: Invalid selection.\n");
            pcap_freealldevs(alldevs);
            WSACleanup();
            return 1;
        }
        
        // Find selected interface
        device = alldevs;
        for (int j = 1; j < choice; j++) {
            device = device->next;
        }
        
        // Open interface for live capture
        handle = pcap_open_live(device->name, 65536, 1, 1000, errbuf);
        global_handle = handle;
        if (handle == NULL) {
            printf("Error: Failed to open interface '%s': %s\n", device->name, errbuf);
            pcap_freealldevs(alldevs);
            WSACleanup();
            return 1;
        }
        
        printf("[INFO] Starting packet capture on interface: %s\n", device->name);
        printf("[INFO] Target SNI: %s\n", sni_filter_status);
        
        pcap_freealldevs(alldevs);

        struct bpf_program filter;
        char filter_str[] = "tcp port 443 or tcp port 8443 or tcp port 4450";
        if (pcap_compile(handle, &filter, filter_str, 0, 0) == -1) {
            printf("Warning: Failed to compile BPF filter: %s\n", pcap_geterr(handle));
        } else if (pcap_setfilter(handle, &filter) == -1) {
            printf("Warning: Failed to set BPF filter: %s\n", pcap_geterr(handle));
        } else {
            printf("[INFO] BPF filter applied: HTTPS ports only\n");
        }

    }
    
    print_analysis_start_info((argc > 1) ? argv[1] : NULL);
    printf("=== TLS Packet Analysis Started ===\n\n");
    
    // Start packet capture loop
    int result = pcap_loop(handle, 0, packet_handler, NULL);
    
    if (result == -1) {
        printf("Error: Packet capture failed: %s\n", pcap_geterr(handle));
    } else if (result == -2) {
        printf("\n[INFO] Packet capture stopped by user.\n");
    } else {
        printf("\n[INFO] Packet capture completed.\n");
    }
    
    // Clean up
    pcap_close(handle);
    
    // Display results
    print_session_summary();
    
    // Save report if vulnerabilities found
    if (session_mgr.count > 0) {
        save_report_to_xlsx();
    }
        
    // Clean up memory
    if (session_mgr.sessions) {
        free(session_mgr.sessions);
    }
    
    // Clean up Winsock
    WSACleanup();
    
    printf("\nPress Enter to exit...");
    getchar();
    getchar(); // Handle any remaining newline
    
    return 0;
}
