#ifndef X509_H
#define X509_H

#include "asslibc.h"
#include "asn1.h"

typedef enum {
    ASSL_X509_SIG_UNKNOWN = 0,
    ASSL_X509_SIG_SHA1_RSA,
    ASSL_X509_SIG_SHA256_RSA,
    ASSL_X509_SIG_SHA384_RSA,
    ASSL_X509_SIG_SHA512_RSA,
} assl_x509_sigalgo_t;

#define ASSL_X509_KU_DIGITAL_SIGNATURE  (1u << 0)
#define ASSL_X509_KU_KEY_ENCIPHERMENT    (1u << 2)
#define ASSL_X509_KU_KEY_CERT_SIGN       (1u << 5)
#define ASSL_X509_KU_CRL_SIGN            (1u << 6)

typedef enum {
    ASSL_X509_PK_UNKNOWN = 0,
    ASSL_X509_PK_RSA,
    ASSL_X509_PK_EC,
} assl_x509_pkalgo_t;

typedef enum {
    ASSL_X509_DN_UNKNOWN = 0,
    ASSL_X509_DN_CN,           
    ASSL_X509_DN_O,            
    ASSL_X509_DN_OU,           
    ASSL_X509_DN_EMAIL,        
} assl_x509_dn_attr_t;

typedef struct {
    assl_x509_dn_attr_t attr;
    const uint8_t *value;
    size_t value_len;
} assl_x509_dn_pair;

typedef struct {
    const assl_x509_dn_pair *attrs;
    size_t count;
    const uint8_t *raw;
    size_t raw_len;
} assl_x509_dn;

typedef struct {
    int year, month, day, hour, min, sec;
} assl_x509_time;

typedef struct {
    assl_x509_time not_before;
    assl_x509_time not_after;
} assl_x509_validity;

typedef struct {
    assl_bn n;
    assl_bn e;
    int bits;
} assl_x509_rsa_pubkey;

typedef struct {
    const uint8_t *der;
    size_t der_len;

    const uint8_t *tbs;
    size_t tbs_len;

    int version;

    uint8_t serial[20];
    size_t serial_len;

    assl_x509_sigalgo_t sig_algo;
    assl_hash_t hash_algo;

    assl_x509_dn issuer;
    assl_x509_dn subject;

    assl_x509_validity validity;

    assl_x509_pkalgo_t pk_algo;
    assl_x509_rsa_pubkey pubkey;

    const uint8_t *signature;
    size_t sig_len;

    assl_x509_dn_pair issuer_attrs[8];
    size_t issuer_attr_count;
    assl_x509_dn_pair subject_attrs[8];
    size_t subject_attr_count;

    int has_auth_key_id;
    uint8_t auth_key_id[20];

    int has_basic_constraints;
    int is_ca;
    int has_pathlen;
    int pathlen;

    int key_usage;

    int has_san;
    const uint8_t *san_dns[8];
    size_t san_dns_len[8];
    size_t san_dns_count;
    const uint8_t *san_ip[8];
    size_t san_ip_len[8];
    size_t san_ip_count;
} assl_x509_cert;

int assl_x509_parse(assl_x509_cert *cert, const uint8_t *der, size_t len);

void assl_x509_free(assl_x509_cert *cert);

int assl_x509_verify(const assl_x509_cert *cert, const assl_rsa_key *issuer_key);

int assl_x509_verify_self(const assl_x509_cert *cert);


int assl_x509_dn_raw_eq(const assl_x509_dn *a, const assl_x509_dn *b);

int assl_x509_time_in_validity(const assl_x509_cert *cert, int64_t now);

int assl_x509_check_hostname(const assl_x509_cert *cert, const char *hostname);

typedef struct {
    const uint8_t *der[8];
    size_t len[8];
    size_t count;
    int strict; 
} assl_x509_trust_store;

#define ASSL_X509_MAX_CHAIN 8

int assl_x509_verify_chain(const uint8_t *const *chain, const size_t *chain_len,
                           size_t chain_cnt, const assl_x509_trust_store *store,
                           const char *hostname, int64_t now);


typedef struct {
    const assl_x509_dn_pair *subject_attrs;
    size_t subject_attr_count;

    const assl_x509_dn_pair *issuer_attrs;
    size_t issuer_attr_count;

    const uint8_t *serial;
    size_t serial_len;

    assl_x509_validity validity;

    const assl_rsa_key *subject_key;

    const assl_rsa_key *issuer_key;

    assl_x509_sigalgo_t sig_algo;

    int is_ca;
} assl_x509_params;

int assl_x509_generate(const assl_x509_params *params,
                       uint8_t **out_der, size_t *out_len);

int assl_x509_generate_self_signed(const assl_x509_params *params,
                                   uint8_t **out_der, size_t *out_len);

#endif
