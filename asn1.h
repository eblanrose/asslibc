#ifndef ASN1_H
#define ASN1_H

#include "asslibc.h"

#define ASN1_CLASS_UNIVERSAL   0
#define ASN1_CLASS_CONTEXT     2
#define ASN1_CLASS_PRIVATE     3

#define ASN1_TAG_BOOLEAN       0x01
#define ASN1_TAG_INTEGER       0x02
#define ASN1_TAG_BIT_STRING    0x03
#define ASN1_TAG_OCTET_STRING  0x04
#define ASN1_TAG_NULL          0x05
#define ASN1_TAG_OID           0x06
#define ASN1_TAG_UTF8STRING    0x0C
#define ASN1_TAG_SEQUENCE      0x30
#define ASN1_TAG_SET           0x31
#define ASN1_TAG_UTCTIME       0x17
#define ASN1_TAG_GENERALIZED   0x18

#define ASN1_TAG_CTX0          0xA0
#define ASN1_TAG_CTX1          0xA1
#define ASN1_TAG_CTX2          0xA2
#define ASN1_TAG_CTX3          0xA3

typedef struct {
    uint8_t tag;
    const uint8_t *value;
    size_t len;            
    const uint8_t *raw;    
    const uint8_t *end;    
} asn1_node;

int asn1_parse(const uint8_t *der, size_t total, asn1_node *out);

int asn1_next(const asn1_node *cur, size_t remain, asn1_node *out);

int asn1_find(const asn1_node *parent, uint8_t tag, asn1_node *out);

const uint8_t *asn1_end(const asn1_node *cur);

int asn1_read_int(const asn1_node *n, uint8_t *buf, size_t buflen);

int asn1_read_oid(const asn1_node *n, uint32_t *oids, size_t max_oids);

#endif
