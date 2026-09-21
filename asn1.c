#include "asn1.h"

static size_t read_der_length(const uint8_t *p, size_t total, size_t *out) {
    if (total < 1) return 0;
    if (p[0] < 0x80) { *out = p[0]; return 1; }
    size_t nbytes = p[0] & 0x7f;
    if (nbytes == 0 || nbytes > 4 || 1 + nbytes > total) return 0;
    size_t len = 0;
    for (size_t i = 0; i < nbytes; i++) len = (len << 8) | p[1 + i];
    *out = len;
    return 1 + nbytes;
}

int asn1_parse(const uint8_t *der, size_t total, asn1_node *out) {
    if (!der || !out || total < 2) return -1;
    out->tag = der[0];
    out->raw = der;
    size_t hdr = 1;
    size_t dlen = 0;
    size_t lbytes = read_der_length(der + 1, total - 1, &dlen);
    if (lbytes == 0) return -1;
    hdr += lbytes;
    if (hdr + dlen > total) return -1;
    out->value = der + hdr;
    out->len = dlen;
    out->end = der + hdr + dlen;
    return 0;
}

int asn1_next(const asn1_node *cur, size_t remain, asn1_node *out) {
    if (!cur || !out || !cur->end || remain == 0) return -1;
    const uint8_t *p = cur->end;
    return asn1_parse(p, remain, out);
}

int asn1_find(const asn1_node *parent, uint8_t tag, asn1_node *out) {
    if (!parent || !out) return -1;
    const uint8_t *p = parent->value;
    const uint8_t *end = parent->value + parent->len;
    while (p < end) {
        asn1_node tmp;
        if (asn1_parse(p, (size_t)(end - p), &tmp) < 0) return -1;
        if (tmp.tag == tag) { *out = tmp; return 0; }
        p = tmp.end;
    }
    return -1;
}

const uint8_t *asn1_end(const asn1_node *cur) {
    return cur ? cur->end : NULL;
}

int asn1_read_int(const asn1_node *n, uint8_t *buf, size_t buflen) {
    if (!n || n->tag != ASN1_TAG_INTEGER || !buf) return -1;
    size_t len = n->len;
    const uint8_t *p = n->value;
    while (len > 1 && p[0] == 0x00) { p++; len--; }
    if (len > buflen) return -1;
    memcpy(buf, p, len);
    return (int)len;
}

int asn1_read_oid(const asn1_node *n, uint32_t *oids, size_t max_oids) {
    if (!n || n->tag != ASN1_TAG_OID || !oids) return -1;
    const uint8_t *p = n->value;
    const uint8_t *end = n->value + n->len;
    size_t count = 0;
    if (p >= end) return -1;
    uint32_t val = 0;
    if (*p < 40) { oids[count++] = 0; oids[count++] = *p; }
    else if (*p < 80) { oids[count++] = 1; oids[count++] = *p - 40; }
    else { oids[count++] = 2; oids[count++] = *p - 80; }
    p++;
    val = 0;
    int first = 1;
    while (p < end) {
        val = (val << 7) | (*p & 0x7f);
        if (!(*p & 0x80)) {
            if (count < max_oids) oids[count++] = val;
            val = 0;
            first = 1;
        } else {
            first = 0;
        }
        p++;
    }
    if (!first && count < max_oids) oids[count++] = val;
    return (int)count;
}
