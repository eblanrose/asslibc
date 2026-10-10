#ifndef SSL_H
#define SSL_H

#include "asslibc.h"
#include "x509.h"

/* Protocol versions */
#define SSL3_VERSION    0x0300
#define TLS10_VERSION   0x0301
#define TLS11_VERSION   0x0302
#define TLS12_VERSION   0x0303
#define TLS13_VERSION   0x0304

#define SSL3_CT_CHANGE_CIPHER_SPEC  20
#define SSL3_CT_ALERT              21
#define SSL3_CT_HANDSHAKE          22
#define SSL3_CT_APPLICATION_DATA   23

#define SSL3_HS_CLIENT_HELLO        1
#define SSL3_HS_SERVER_HELLO        2
#define SSL3_HS_NEW_SESSION_TICKET  4
#define SSL3_HS_CERTIFICATE        11
#define SSL3_HS_SERVER_KEY_EXCHANGE 12
#define SSL3_HS_CERTIFICATE_REQUEST 13
#define SSL3_HS_SERVER_DONE        14
#define SSL3_HS_CLIENT_KEY_EXCHANGE 16
#define SSL3_HS_FINISHED           20
#define SSL3_HS_CERTIFICATE_STATUS 22
#define SSL3_HS_ENCRYPTED_EXTENSIONS 8
#define SSL3_HS_CERTIFICATE_VERIFY 15
#define SSL3_HS_KEY_UPDATE         24

#define TLS13_HS_CLIENT_HELLO       1
#define TLS13_HS_SERVER_HELLO       2
#define TLS13_HS_ENCRYPTED_EXT     8
#define TLS13_HS_CERTIFICATE       11
#define TLS13_HS_CERT_VERIFY       15
#define TLS13_HS_FINISHED          20
#define TLS13_HS_KEY_UPDATE        24

#define SSL3_ALERT_WARNING          1
#define SSL3_ALERT_FATAL            2

#define SSL3_ALERT_CLOSE_NOTIFY     0
#define SSL3_ALERT_UNEXPECTED_MSG  10
#define SSL3_ALERT_DECRYPT_ERROR  51
#define SSL3_ALERT_BAD_RECORD_MAC  20
#define SSL3_ALERT_DECOMPRESSION_FAIL 30
#define SSL3_ALERT_HANDSHAKE_FAILURE 40
#define SSL3_ALERT_DECODE_ERROR     50
#define SSL3_ALERT_INTERNAL_ERROR   80
#define SSL3_ALERT_USER_CANCELED    90
#define SSL3_ALERT_MISSING_EXTENSION 109
#define SSL3_ALERT_UNSUPPORTED_EXTENSION 110
#define SSL3_ALERT_UNRECOGNIZED_NAME  112
#define SSL3_ALERT_ILLEGAL_PARAMETER  47
#define SSL3_ALERT_PROTOCOL_VERSION   70
#define SSL3_ALERT_UNKNOWN_CA       48
#define SSL3_ALERT_ACCESS_DENIED    49

#define SSL3_CK_RSA_WITH_NULL_MD5             0x0001
#define SSL3_CK_RSA_WITH_RC4_128_MD5          0x0004
#define SSL3_CK_RSA_WITH_RC4_128_SHA1         0x0005
#define SSL3_CK_RSA_WITH_AES_128_CBC_SHA      0x002F
#define SSL3_CK_RSA_WITH_AES_256_CBC_SHA      0x0035
#define TLS12_CK_RSA_WITH_AES_128_CBC_SHA256  0x003C
#define TLS12_CK_RSA_WITH_AES_256_CBC_SHA256  0x003D
#define TLS12_CK_RSA_WITH_AES_128_GCM_SHA256  0x009C
#define TLS12_CK_RSA_WITH_AES_256_GCM_SHA384  0x009D
#define TLS12_CK_RSA_WITH_AES_128_CCM_SHA256  0x009F
#define TLS12_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256  0xC02F
#define TLS12_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384  0xC030
#define TLS12_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 0xCCA8

#define TLS13_CK_AES_128_GCM_SHA256           0x1301
#define TLS13_CK_AES_256_GCM_SHA384           0x1302
#define TLS13_CK_CHACHA20_POLY1305_SHA256     0x1303
#define TLS13_CK_AES_128_CCM_SHA256           0x1304
#define TLS13_CK_AES_128_CCM_8_SHA256         0x1305

#define SSL3_MAX_RECORD_LEN    16384
#define SSL3_HEADER_LEN        5       /* type(1) + version(2) + length(2) */
#define SSL3_VERIFY_DATA_LEN   12
#define SSL3_RANDOM_LEN        32

#define SSL3_RECORD_EOF        (-2)

#define SSL3_EXT_SERVER_NAME           0
#define SSL3_EXT_STATUS_REQUEST        5
#define SSL3_EXT_SUPPORTED_GROUPS      10
#define SSL3_EXT_EC_POINT_FORMATS      11
#define SSL3_EXT_SIGNATURE_ALGORITHMS  13
#define SSL3_EXT_ALPN                  16
#define SSL3_EXT_EXTENDED_MASTER_SECRET 23
#define SSL3_EXT_SESSION_TICKET        35
#define SSL3_EXT_PRE_SHARED_KEY        41
#define SSL3_EXT_EARLY_DATA            42
#define SSL3_EXT_SUPPORTED_VERSIONS    43
#define SSL3_EXT_COOKIE                44
#define SSL3_EXT_PSK_KEY_EXCHANGE_MODES 45
#define SSL3_EXT_KEY_SHARE             51

#define SSL3_GROUP_SECP256R1 0x0017
#define SSL3_GROUP_SECP384R1 0x0018
#define SSL3_GROUP_SECP521R1 0x0019
#define SSL3_GROUP_X25519    0x001D

#define SSL3_ALERT_INAPPROPRIATE_FALLBACK 86
#define SSL3_ALERT_INSUFFICIENT_SECURITY 71

#define TLS13_MAX_RECORD_LEN   16384
#define TLS13_HANDSHAKE_PREFIX  16  /* content_type(1) + legacy_record_version(2) + length(2) = 5
                                       inner content type is 1 extra byte in the inner plaintext */

typedef enum {
    SSL3_STATE_INIT = 0,
    SSL3_STATE_CLIENT_HELLO_SENT,
    SSL3_STATE_SERVER_HELLO_RECEIVED,
    SSL3_STATE_CERTIFICATE_RECEIVED,
    SSL3_STATE_KEY_EXCHANGE_DONE,
    SSL3_STATE_CHANGE_CIPHER_SENT,
    SSL3_STATE_FINISHED_SENT,
    SSL3_STATE_CONNECTED,
    SSL3_STATE_ERROR
} ssl3_handshake_state;

typedef struct {
    uint16_t cipher_suite;
    assl_hash_t mac_algo;       
    unsigned mac_key_len;       
    unsigned key_len;           
    unsigned iv_len;            
    unsigned block_size;        
    int is_stream;              
    int is_aead;                
    int is_tls13;               
    assl_hash_t prf_hash;       
} ssl3_cipher_spec;

typedef struct {
    int is_client;

    uint16_t version;

    ssl3_handshake_state state;
    int error_code;

    uint8_t client_random[SSL3_RANDOM_LEN];
    uint8_t server_random[SSL3_RANDOM_LEN];

    uint8_t master_secret[48];

    uint8_t handshake_secret[48];
    uint8_t master_secret_13[48];
    uint8_t client_handshake_traffic_secret[48];
    uint8_t server_handshake_traffic_secret[48];
    uint8_t client_application_traffic_secret[48];
    uint8_t server_application_traffic_secret[48];
    int tls13_handshake_secret_set;

    ssl3_cipher_spec cipher;
    int read_cipher_active;   
    int write_cipher_active;  

    uint8_t client_mac_secret[32];
    uint8_t server_mac_secret[32];

    uint8_t client_write_key[32];
    uint8_t server_write_key[32];

    uint8_t client_write_iv[16];
    uint8_t server_write_iv[16];

    assl_aes_ctx write_ctx;
    assl_aes_ctx read_ctx;
    uint8_t write_iv_current[16];   
    uint8_t read_iv_current[16];    

    int write_explicit_iv_used;
    int read_explicit_iv_used;

    uint64_t write_seq_num;
    uint64_t read_seq_num;

    assl_sha1_ctx hs_digest;
    assl_md5_ctx hs_md5_digest;
    uint8_t hs_messages[16384];  
    size_t hs_messages_len;

    assl_sha256_ctx hs_sha256_digest;
    int hs_sha256_active;

    uint8_t rbuf[SSL3_MAX_RECORD_LEN + SSL3_HEADER_LEN + 256]; 
    size_t rbuf_len;
    uint8_t rbuf_record_type;
    size_t rbuf_record_len;

    const uint8_t *cert_der;
    size_t cert_der_len;
    assl_rsa_key rsa_key;
    int have_cert;

    assl_rsa_key peer_rsa_key;
    int have_peer_key;

    uint8_t ecdh_priv[32];       
    uint8_t ecdh_peer_pub[64];   
    uint8_t ecdh_local_pub[64];  

    uint8_t client_session_id[32];
    uint8_t client_session_id_len;

    uint16_t client_suites[16];
    size_t client_suites_count;

    int verify_peer;                 
    char verify_hostname[256];       
    int verify_hostname_len;
    assl_x509_trust_store trust_store;

    char sni_hostname[256];
    int sni_hostname_len;
    char server_name[256];
    size_t server_name_len;

    uint8_t alpn_protos[64];
    size_t alpn_protos_len;
    uint8_t peer_alpn_protos[64];
    size_t peer_alpn_protos_len;
    uint8_t negotiated_alpn[64];
    size_t negotiated_alpn_len;

    int ems_offered;
    int ems_negotiated;

    int hrr_done;
    uint16_t selected_group;

    uint8_t wbuf[SSL3_MAX_RECORD_LEN + SSL3_HEADER_LEN + 256];
    size_t wbuf_len;

    uint8_t app_buf[SSL3_MAX_RECORD_LEN + 256];
    size_t app_len;
    size_t app_off;
    int close_notify_received;
} assl_ssl;

void assl_ssl_init(assl_ssl *ssl, int is_client);

void assl_ssl_set_version(assl_ssl *ssl, uint16_t version);

void assl_ssl_set_cert(assl_ssl *ssl, const uint8_t *der, size_t der_len,
                       const assl_rsa_key *key);

int assl_ssl_set_verify(assl_ssl *ssl, int enable, const char *hostname);

int assl_ssl_add_trust(assl_ssl *ssl, const uint8_t *der, size_t len);

int assl_ssl_set_servername(assl_ssl *ssl, const char *hostname);

int assl_ssl_set_alpn(assl_ssl *ssl, const uint8_t *protos, size_t len);

const char *assl_ssl_get_negotiated_alpn(const assl_ssl *ssl);

const char *assl_ssl_get_server_name(const assl_ssl *ssl);

uint16_t assl_ssl_get_group(const assl_ssl *ssl);


int assl_ssl_handshake(assl_ssl *ssl, int in_fd, int out_fd);

int assl_ssl_read(assl_ssl *ssl, int fd, void *buf, size_t len);

int assl_ssl_key_update(assl_ssl *ssl, int fd, int request);

int assl_ssl_write(assl_ssl *ssl, int fd, const void *buf, size_t len);

void assl_ssl_shutdown(assl_ssl *ssl, int fd);

uint16_t assl_ssl_get_cipher(const assl_ssl *ssl);

uint16_t assl_ssl_get_version(const assl_ssl *ssl);

#endif
