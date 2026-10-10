#include "x509.h"

static const uint32_t oid_sha1_rsa[]      = {1, 2, 840, 113549, 1, 1, 5};
static const uint32_t oid_sha256_rsa[]    = {1, 2, 840, 113549, 1, 1, 11};
static const uint32_t oid_sha384_rsa[]    = {1, 2, 840, 113549, 1, 1, 12};
static const uint32_t oid_sha512_rsa[]    = {1, 2, 840, 113549, 1, 1, 13};
static const uint32_t oid_rsa_enc[]       = {1, 2, 840, 113549, 1, 1, 1};
static const uint32_t oid_cn[]            = {2, 5, 4, 3};
static const uint32_t oid_o[]             = {2, 5, 4, 10};
static const uint32_t oid_ou[]            = {2, 5, 4, 11};
static const uint32_t oid_email[]         = {1, 2, 840, 113549, 1, 9, 1};
static const uint32_t oid_auth_key_id[]   = {2, 5, 29, 35};
static const uint32_t oid_basic_constraints[] = {2, 5, 29, 19};
static const uint32_t oid_key_usage[]     = {2, 5, 29, 15};
static const uint32_t oid_subject_alt_name[] = {2, 5, 29, 17};

static int oid_eq(const uint32_t *a, size_t alen, const uint32_t *b, size_t blen) {
    if (alen != blen) return 0;
    for (size_t i = 0; i < alen; i++) if (a[i] != b[i]) return 0;
    return 1;
}

static assl_x509_sigalgo_t match_sigalgo(const uint32_t *oids, size_t count) {
    if (oid_eq(oids, count, oid_sha1_rsa, 7))   return ASSL_X509_SIG_SHA1_RSA;
    if (oid_eq(oids, count, oid_sha256_rsa, 7)) return ASSL_X509_SIG_SHA256_RSA;
    if (oid_eq(oids, count, oid_sha384_rsa, 7)) return ASSL_X509_SIG_SHA384_RSA;
    if (oid_eq(oids, count, oid_sha512_rsa, 7)) return ASSL_X509_SIG_SHA512_RSA;
    return ASSL_X509_SIG_UNKNOWN;
}

static assl_hash_t sigalgo_to_hash(assl_x509_sigalgo_t sa) {
    switch (sa) {
        case ASSL_X509_SIG_SHA1_RSA:   return ASSL_H_SHA1;
        case ASSL_X509_SIG_SHA256_RSA: return ASSL_H_SHA256;
        case ASSL_X509_SIG_SHA384_RSA: return ASSL_H_SHA384;
        case ASSL_X509_SIG_SHA512_RSA: return ASSL_H_SHA512;
        default: return ASSL_H_SHA256;
    }
}

static assl_x509_dn_attr_t match_dn_attr(const uint32_t *oids, size_t count) {
    if (oid_eq(oids, count, oid_cn, 4))    return ASSL_X509_DN_CN;
    if (oid_eq(oids, count, oid_o, 4))     return ASSL_X509_DN_O;
    if (oid_eq(oids, count, oid_ou, 4))    return ASSL_X509_DN_OU;
    if (oid_eq(oids, count, oid_email, 7)) return ASSL_X509_DN_EMAIL;
    return ASSL_X509_DN_UNKNOWN;
}

static int parse_time(const asn1_node *n, assl_x509_time *t) {
    if (!n || !t) return -1;
    const char *s = (const char *)n->value;
    size_t len = n->len;
    memset(t, 0, sizeof *t);
    if (len < 13 || s[len-1] != 'Z') return -1;
    const char *p;
    if (n->tag == ASN1_TAG_UTCTIME) {
        t->year = (s[0]-'0')*10 + (s[1]-'0');
        t->year += (t->year < 50) ? 2000 : 1900;
        p = s + 2; 
    } else if (n->tag == ASN1_TAG_GENERALIZED) {
        t->year = (s[0]-'0')*1000 + (s[1]-'0')*100 + (s[2]-'0')*10 + (s[3]-'0');
        p = s + 4; 
    } else return -1;
    t->month = (p[0]-'0')*10 + (p[1]-'0');
    t->day   = (p[2]-'0')*10 + (p[3]-'0');
    t->hour  = (p[4]-'0')*10 + (p[5]-'0');
    t->min   = (p[6]-'0')*10 + (p[7]-'0');
    t->sec   = (p[8]-'0')*10 + (p[9]-'0');
    if (t->month < 1 || t->month > 12 || t->day < 1 || t->day > 31) return -1;
    return 0;
}

static size_t parse_rdn(const asn1_node *rdn_set, assl_x509_dn_pair *attrs, size_t max) {
    size_t count = 0;
    asn1_node rdn_seq;
    if (asn1_find(rdn_set, ASN1_TAG_SEQUENCE, &rdn_seq) < 0) return 0;
    const uint8_t *p = rdn_seq.value;
    const uint8_t *end = rdn_seq.value + rdn_seq.len;
    asn1_node items[4];
    int nitems = 0;
    while (p < end && nitems < 4) {
        if (asn1_parse(p, (size_t)(end - p), &items[nitems]) < 0) break;
        p = items[nitems].end;
        nitems++;
    }
    if (nitems >= 2 && items[0].tag == ASN1_TAG_OID) {
        uint32_t oids[8];
        int nc = asn1_read_oid(&items[0], oids, 8);
        if (nc > 0 && count < max) {
            attrs[count].attr = match_dn_attr(oids, (size_t)nc);
            attrs[count].value = items[1].value;
            attrs[count].value_len = items[1].len;
            count++;
        }
    }
    return count;
}

static void parse_dn(const asn1_node *dn_seq, assl_x509_dn_pair *attrs,
                     size_t *attr_count, size_t max, assl_x509_dn *dn) {
    *attr_count = 0;
    dn->attrs = attrs;
    dn->count = 0;
    dn->raw = dn_seq->value;
    dn->raw_len = dn_seq->len;
    const uint8_t *p = dn_seq->value;
    const uint8_t *end = dn_seq->value + dn_seq->len;
    while (p < end && *attr_count < max) {
        asn1_node set;
        if (asn1_parse(p, (size_t)(end - p), &set) < 0) break;
        if (set.tag != ASN1_TAG_SET) break;
        size_t n = parse_rdn(&set, attrs + *attr_count, max - *attr_count);
        *attr_count += n;
        p = set.end;
    }
    dn->count = *attr_count;
}

static int parse_pubkey(const asn1_node *spki, assl_x509_cert *cert) {
    asn1_node algo_seq, bitstr;
    if (asn1_find(spki, ASN1_TAG_SEQUENCE, &algo_seq) < 0) return -1;
    if (asn1_find(spki, ASN1_TAG_BIT_STRING, &bitstr) < 0) return -1;
    asn1_node algo_oid;
    if (asn1_find(&algo_seq, ASN1_TAG_OID, &algo_oid) < 0) return -1;
    uint32_t oids[8];
    int nc = asn1_read_oid(&algo_oid, oids, 8);
    if (nc <= 0) return -1;
    if (oid_eq(oids, (size_t)nc, oid_rsa_enc, 7)) {
        cert->pk_algo = ASSL_X509_PK_RSA;
    } else {
        cert->pk_algo = ASSL_X509_PK_UNKNOWN;
        return -1;
    }
    const uint8_t *p = bitstr.value;
    size_t blen = bitstr.len;
    if (blen < 1 || p[0] != 0x00) return -1;
    p++; blen--;
    asn1_node key_seq;
    if (asn1_parse(p, blen, &key_seq) < 0) return -1;
    if (key_seq.tag != ASN1_TAG_SEQUENCE) return -1;
    const uint8_t *kp = key_seq.value;
    const uint8_t *kend = key_seq.value + key_seq.len;
    asn1_node n_node = {0}, e_node = {0};
    int found = 0;
    while (kp < kend && found < 2) {
        asn1_node tmp;
        if (asn1_parse(kp, (size_t)(kend - kp), &tmp) < 0) break;
        if (tmp.tag == ASN1_TAG_INTEGER) {
            if (found == 0) n_node = tmp; else e_node = tmp;
            found++;
        }
        kp = tmp.end;
    }
    if (found < 2) return -1;
    assl_bn_init(&cert->pubkey.n);
    assl_bn_init(&cert->pubkey.e);
    uint8_t buf[512];
    int nlen = asn1_read_int(&n_node, buf, sizeof buf);
    if (nlen <= 0) return -1;
    if (assl_bn_from_bin(&cert->pubkey.n, buf, (size_t)nlen)) return -1;
    int elen = asn1_read_int(&e_node, buf, sizeof buf);
    if (elen <= 0) return -1;
    if (assl_bn_from_bin(&cert->pubkey.e, buf, (size_t)elen)) return -1;
    cert->pubkey.bits = (int)assl_bn_bitlen(&cert->pubkey.n);
    return 0;
}

static void parse_basic_constraints(const asn1_node *ext_value, assl_x509_cert *cert) {
    asn1_node bc_seq;
    if (asn1_parse(ext_value->value, ext_value->len, &bc_seq) < 0) return;
    if (bc_seq.tag != ASN1_TAG_SEQUENCE) return;
    cert->has_basic_constraints = 1;
    cert->is_ca = 0;
    const uint8_t *p = bc_seq.value;
    const uint8_t *end = bc_seq.value + bc_seq.len;
    if (p < end) {
        asn1_node b;
        if (asn1_parse(p, (size_t)(end - p), &b) == 0 && b.tag == ASN1_TAG_BOOLEAN) {
            cert->is_ca = (b.len > 0 && b.value[0] != 0);
            p = b.end;
        }
    }
    if (p < end) {
        asn1_node i;
        if (asn1_parse(p, (size_t)(end - p), &i) == 0 && i.tag == ASN1_TAG_INTEGER) {
            uint8_t vbuf[4];
            int vlen = asn1_read_int(&i, vbuf, sizeof vbuf);
            if (vlen > 0) {
                cert->has_pathlen = 1;
                cert->pathlen = 0;
                for (int j = 0; j < vlen; j++) cert->pathlen = (cert->pathlen << 8) | vbuf[j];
            }
        }
    }
}

static void parse_key_usage(const asn1_node *ext_value, assl_x509_cert *cert) {
    asn1_node bs;
    if (asn1_parse(ext_value->value, ext_value->len, &bs) < 0) return;
    if (bs.tag != ASN1_TAG_BIT_STRING) return;
    if (bs.len < 1) return;
    unsigned unused = bs.value[0];
    if (unused > 7) return;
    int bits = 0;
    for (size_t i = 1; i < bs.len && i <= 2; i++) {
        for (int bit = 0; bit < 8; bit++) {
            if (i == bs.len - 1 && 8 - bit <= unused) break;
            if (bs.value[i] & (0x80 >> bit))
                bits |= 1u << ((int)i - 1) * 8 + bit;
        }
    }
    cert->key_usage = bits;
}

static void parse_subject_alt_name(const asn1_node *ext_value, assl_x509_cert *cert) {
    asn1_node san;
    if (asn1_parse(ext_value->value, ext_value->len, &san) < 0) return;
    if (san.tag != ASN1_TAG_SEQUENCE) return;
    cert->has_san = 1;
    const uint8_t *p = san.value;
    const uint8_t *end = san.value + san.len;
    while (p < end) {
        asn1_node gn;
        if (asn1_parse(p, (size_t)(end - p), &gn) < 0) break;
        if ((gn.tag & 0x1f) == 0x02 && cert->san_dns_count < 8) {
            cert->san_dns[cert->san_dns_count] = gn.value;
            cert->san_dns_len[cert->san_dns_count] = gn.len;
            cert->san_dns_count++;
        } else if ((gn.tag & 0x1f) == 0x07 && cert->san_ip_count < 8) {
            cert->san_ip[cert->san_ip_count] = gn.value;
            cert->san_ip_len[cert->san_ip_count] = gn.len;
            cert->san_ip_count++;
        }
        p = gn.end;
    }
}

static void parse_extensions(const asn1_node *exts, assl_x509_cert *cert) {
    asn1_node extseq;
    if (asn1_find(exts, ASN1_TAG_SEQUENCE, &extseq) < 0) return;
    const uint8_t *ep = extseq.value;
    const uint8_t *eend = extseq.value + extseq.len;
    while (ep < eend) {
        asn1_node ext_entry;
        if (asn1_parse(ep, (size_t)(eend - ep), &ext_entry) < 0) break;
        if (ext_entry.tag != ASN1_TAG_SEQUENCE) break;
        asn1_node ext_oid;
        if (asn1_find(&ext_entry, ASN1_TAG_OID, &ext_oid) == 0) {
            uint32_t eoids[8];
            int enc = asn1_read_oid(&ext_oid, eoids, 8);
            if (enc > 0) {
                int is_critical = 0;
                const uint8_t *p = ext_entry.value;
                const uint8_t *pend = ext_entry.value + ext_entry.len;
                asn1_node tmp;
                if (asn1_parse(p, (size_t)(pend - p), &tmp) == 0 && tmp.tag == ASN1_TAG_OID) {
                    p = tmp.end;
                    if (p < pend) {
                        if (asn1_parse(p, (size_t)(pend - p), &tmp) == 0 && tmp.tag == ASN1_TAG_BOOLEAN) {
                            is_critical = (tmp.len > 0 && tmp.value[0] != 0);
                            p = tmp.end;
                        }
                    }
                }
                asn1_node ext_val;
                if (asn1_find(&ext_entry, ASN1_TAG_OCTET_STRING, &ext_val) == 0) {
                    if (oid_eq(eoids, (size_t)enc, oid_auth_key_id, 4)) {
                        cert->has_auth_key_id = 1;
                        asn1_node aki_seq;
                        if (asn1_parse(ext_val.value, ext_val.len, &aki_seq) == 0 &&
                            aki_seq.tag == ASN1_TAG_SEQUENCE) {
                            asn1_node keyid;
                            if (asn1_find(&aki_seq, ASN1_TAG_CTX0, &keyid) == 0) {
                                size_t klen = keyid.len < 20 ? keyid.len : 20;
                                memcpy(cert->auth_key_id, keyid.value, klen);
                                memset(cert->auth_key_id + klen, 0, 20 - klen);
                            }
                        }
                    } else if (oid_eq(eoids, (size_t)enc, oid_basic_constraints, 4)) {
                        parse_basic_constraints(&ext_val, cert);
                    } else if (oid_eq(eoids, (size_t)enc, oid_key_usage, 4)) {
                        parse_key_usage(&ext_val, cert);
                    } else if (oid_eq(eoids, (size_t)enc, oid_subject_alt_name, 4)) {
                        parse_subject_alt_name(&ext_val, cert);
                    } else if (is_critical) {
                        cert->has_unknown_critical = 1;
                    }
                }
            }
        }
        ep = ext_entry.end;
    }
}

int assl_x509_parse(assl_x509_cert *cert, const uint8_t *der, size_t len) {
    if (!cert || !der || len < 20) return -1;
    memset(cert, 0, sizeof *cert);
    cert->der = der;
    cert->der_len = len;

    asn1_node outer;
    if (asn1_parse(der, len, &outer) < 0) return -1;
    if (outer.tag != ASN1_TAG_SEQUENCE) return -1;
    const uint8_t *p = outer.value;
    const uint8_t *end = outer.value + outer.len;

    asn1_node tbs;
    if (asn1_parse(p, (size_t)(end - p), &tbs) < 0) return -1;
    cert->tbs = tbs.raw;
    cert->tbs_len = (size_t)(tbs.end - tbs.raw);
    p = tbs.end;

    if (tbs.tag != ASN1_TAG_SEQUENCE) return -1;
    const uint8_t *tp = tbs.value;
    const uint8_t *tend = tbs.value + tbs.len;

    asn1_node ver;
    if (asn1_parse(tp, (size_t)(tend - tp), &ver) < 0) return -1;
    if (ver.tag == ASN1_TAG_CTX0) {
        asn1_node ver_int;
        if (asn1_find(&ver, ASN1_TAG_INTEGER, &ver_int) < 0) return -1;
        uint8_t vbuf[4];
        int vlen = asn1_read_int(&ver_int, vbuf, sizeof vbuf);
        if (vlen <= 0) return -1;
        cert->version = 0;
        for (int i = 0; i < vlen; i++) cert->version = (cert->version << 8) | vbuf[i];
        cert->version += 1; 
        tp = ver.end;
    } else {
        cert->version = 1; 
    }

    asn1_node serial;
    if (asn1_parse(tp, (size_t)(tend - tp), &serial) < 0) return -1;
    if (serial.tag != ASN1_TAG_INTEGER) return -1;
    int slen = asn1_read_int(&serial, cert->serial, sizeof cert->serial);
    if (slen <= 0) return -1;
    cert->serial_len = (size_t)slen;
    tp = serial.end;

    asn1_node sigalgo;
    if (asn1_parse(tp, (size_t)(tend - tp), &sigalgo) < 0) return -1;
    if (sigalgo.tag != ASN1_TAG_SEQUENCE) return -1;
    asn1_node sigalgo_oid;
    if (asn1_find(&sigalgo, ASN1_TAG_OID, &sigalgo_oid) < 0) return -1;
    uint32_t soids[8];
    int snc = asn1_read_oid(&sigalgo_oid, soids, 8);
    cert->sig_algo = match_sigalgo(soids, (size_t)snc);
    cert->hash_algo = sigalgo_to_hash(cert->sig_algo);
    tp = sigalgo.end;

    asn1_node issuer;
    if (asn1_parse(tp, (size_t)(tend - tp), &issuer) < 0) return -1;
    if (issuer.tag != ASN1_TAG_SEQUENCE) return -1;
    parse_dn(&issuer, cert->issuer_attrs, &cert->issuer_attr_count, 8, &cert->issuer);
    tp = issuer.end;

    asn1_node validity;
    if (asn1_parse(tp, (size_t)(tend - tp), &validity) < 0) return -1;
    if (validity.tag != ASN1_TAG_SEQUENCE) return -1;
    {
        asn1_node nb, na;
        const uint8_t *vp = validity.value;
        const uint8_t *vend = validity.value + validity.len;
        if (asn1_parse(vp, (size_t)(vend - vp), &nb) < 0) return -1;
        if (nb.tag != ASN1_TAG_UTCTIME && nb.tag != ASN1_TAG_GENERALIZED) return -1;
        if (parse_time(&nb, &cert->validity.not_before) < 0) return -1;
        vp = nb.end;
        if (asn1_parse(vp, (size_t)(vend - vp), &na) < 0) return -1;
        if (na.tag != ASN1_TAG_UTCTIME && na.tag != ASN1_TAG_GENERALIZED) return -1;
        if (parse_time(&na, &cert->validity.not_after) < 0) return -1;
    }
    tp = validity.end;

    asn1_node subject;
    if (asn1_parse(tp, (size_t)(tend - tp), &subject) < 0) return -1;
    if (subject.tag != ASN1_TAG_SEQUENCE) return -1;
    parse_dn(&subject, cert->subject_attrs, &cert->subject_attr_count, 8, &cert->subject);
    tp = subject.end;

    asn1_node spki;
    if (asn1_parse(tp, (size_t)(tend - tp), &spki) < 0) return -1;
    if (spki.tag != ASN1_TAG_SEQUENCE) return -1;
    if (parse_pubkey(&spki, cert) < 0) return -1;
    tp = spki.end;

    if (tp < tend) {
        asn1_node exts;
        if (asn1_parse(tp, (size_t)(tend - tp), &exts) == 0 && exts.tag == ASN1_TAG_CTX3) {
            parse_extensions(&exts, cert);
        }
    }

    asn1_node sigalgo2;
    if (asn1_parse(p, (size_t)(end - p), &sigalgo2) < 0) return -1;
    if (sigalgo2.tag != ASN1_TAG_SEQUENCE) return -1;
    p = sigalgo2.end;

    asn1_node sigbit;
    if (asn1_parse(p, (size_t)(end - p), &sigbit) < 0) return -1;
    if (sigbit.tag != ASN1_TAG_BIT_STRING) return -1;
    if (sigbit.len < 1 || sigbit.value[0] != 0x00) return -1;
    cert->signature = sigbit.value + 1;
    cert->sig_len = sigbit.len - 1;

    return 0;
}

void assl_x509_free(assl_x509_cert *cert) {
    if (!cert) return;
    if (cert->pk_algo == ASSL_X509_PK_RSA) {
        assl_bn_free(&cert->pubkey.n);
        assl_bn_free(&cert->pubkey.e);
    }
}

static int assl_x509_time_to_ts(const assl_x509_time *t, int64_t *out);

int assl_x509_crl_parse(assl_x509_crl *crl, const uint8_t *der, size_t len) {
    if (!crl || !der || len < 16) return -1;
    memset(crl, 0, sizeof *crl);
    crl->der = der;
    crl->der_len = len;

    asn1_node outer, tbs, sigalg, sigval;
    if (asn1_parse(der, len, &outer) < 0) return -1;
    if (outer.tag != ASN1_TAG_SEQUENCE) return -1;
    const uint8_t *p = outer.value;
    if (asn1_parse(p, outer.len, &tbs) < 0 || tbs.tag != ASN1_TAG_SEQUENCE) return -1;
    p = tbs.end;
    if (asn1_parse(p, (size_t)(outer.end - p), &sigalg) < 0 ||
        sigalg.tag != ASN1_TAG_SEQUENCE) return -1;
    p = sigalg.end;
    if (asn1_parse(p, (size_t)(outer.end - p), &sigval) < 0 ||
        sigval.tag != ASN1_TAG_BIT_STRING) return -1;
    if (outer.end != sigval.end) return -1;

    crl->tbs = tbs.raw;
    crl->tbs_len = (size_t)(tbs.end - tbs.raw);
    if (sigval.len < 1) return -1;
    unsigned unused_bits = sigval.value[0];
    if (unused_bits > 7) return -1;
    crl->signature = sigval.value + 1;
    crl->sig_len = sigval.len - 1;

    {
        uint32_t oids[8];
        asn1_node oidn;
        if (asn1_find(&sigalg, ASN1_TAG_OID, &oidn) < 0) return -1;
        int enc = asn1_read_oid(&oidn, oids, 8);
        if (enc <= 0) return -1;
        crl->sig_algo = match_sigalgo(oids, (size_t)enc);
        if (crl->sig_algo == ASSL_X509_SIG_UNKNOWN) return -1;
        crl->hash_algo = sigalgo_to_hash(crl->sig_algo);
    }

    asn1_node f;
    if (asn1_parse(tbs.value, tbs.len, &f) < 0) return -1;

    if (f.tag == ASN1_TAG_INTEGER) {
        uint8_t vb[4];
        int vl = asn1_read_int(&f, vb, sizeof vb);
        if (vl < 0) return -1;
        int ver = 0;
        for (int i = 0; i < vl; i++) ver = (ver << 8) | vb[i];
        if (ver > 1) return -1;
        if (asn1_next(&f, (size_t)(tbs.end - f.end), &f) < 0) return -1;
    }

    if (f.tag != ASN1_TAG_SEQUENCE) return -1;
    if (asn1_next(&f, (size_t)(tbs.end - f.end), &f) < 0) return -1;
    if (f.tag != ASN1_TAG_SEQUENCE) return -1;
    crl->issuer.raw = f.value;
    crl->issuer.raw_len = f.len;

    if (asn1_next(&f, (size_t)(tbs.end - f.end), &f) < 0) return -1;
    {
        assl_x509_time t;
        if (parse_time(&f, &t) < 0) return -1;
        if (assl_x509_time_to_ts(&t, &crl->this_update) < 0) return -1;
    }

    if (asn1_next(&f, (size_t)(tbs.end - f.end), &f) < 0) return -1;
    if (f.tag == ASN1_TAG_UTCTIME || f.tag == ASN1_TAG_GENERALIZED) {
        assl_x509_time t;
        if (parse_time(&f, &t) < 0) return -1;
        if (assl_x509_time_to_ts(&t, &crl->next_update) < 0) return -1;
        crl->has_next_update = 1;
        if (asn1_next(&f, (size_t)(tbs.end - f.end), &f) < 0) f.tag = 0;
    }

    if (f.tag == ASN1_TAG_SEQUENCE) {
        const uint8_t *rp = f.value;
        const uint8_t *rend = f.value + f.len;
        while (rp < rend) {
            asn1_node entry;
            if (asn1_parse(rp, (size_t)(rend - rp), &entry) < 0) return -1;
            if (entry.tag != ASN1_TAG_SEQUENCE) return -1;
            asn1_node ser;
            if (asn1_parse(entry.value, entry.len, &ser) < 0) return -1;
            if (ser.tag != ASN1_TAG_INTEGER) return -1;
            uint8_t sb[24];
            int sl = asn1_read_int(&ser, sb, sizeof sb);
            if (sl < 0 || sl > 20) return -1;
            if (crl->revoked_count < ASSL_X509_MAX_REVOKED) {
                assl_x509_revoked *e = &crl->revoked[crl->revoked_count++];
                if (sl > 0) memcpy(e->serial, sb, (size_t)sl);
                e->serial_len = (size_t)sl;
            } else {
                crl->revoked_truncated = 1;
            }
            rp = entry.end;
        }
        if (asn1_next(&f, (size_t)(tbs.end - f.end), &f) < 0) f.tag = 0;
    }

    if (f.tag == ASN1_TAG_CTX0) {
        if (asn1_next(&f, (size_t)(tbs.end - f.end), &f) < 0) f.tag = 0;
    }
    return (f.tag == 0) ? 0 : -1;
}

int assl_x509_crl_check(const assl_x509_crl *crl,
                        const assl_rsa_key *issuer_key,
                        const assl_x509_dn *expected_issuer,
                        int64_t now) {
    if (!crl || !issuer_key || !expected_issuer) return -1;
    if (crl->sig_algo == ASSL_X509_SIG_UNKNOWN || crl->tbs_len == 0) return -1;

    if (assl_x509_dn_raw_eq(&crl->issuer, expected_issuer) == 0) return -1;

    uint8_t digest[64];
    assl_hash_one(crl->hash_algo, crl->tbs, crl->tbs_len, digest);
    if (assl_rsa_verify(issuer_key, crl->hash_algo, digest,
                        crl->signature, crl->sig_len) < 0)
        return -1;

    if (now < 0) now = (int64_t)time(NULL);
    if (now < crl->this_update) return -1;
    if (!crl->has_next_update) return -1;
    if (now > crl->next_update) return -1;
    return 0;
}

int assl_x509_crl_is_revoked(const assl_x509_crl *crl, const assl_x509_cert *cert) {
    if (!crl || !cert) return -1;
    if (crl->revoked_truncated) return -1;
    for (size_t i = 0; i < crl->revoked_count; i++) {
        if (crl->revoked[i].serial_len != cert->serial_len) continue;
        if (memcmp(crl->revoked[i].serial, cert->serial, cert->serial_len) == 0)
            return 1;
    }
    return 0;
}

int assl_x509_verify(const assl_x509_cert *cert, const assl_rsa_key *issuer_key) {
    if (!cert || !issuer_key || !cert->tbs || cert->tbs_len == 0) return -1;
    if (cert->sig_algo == ASSL_X509_SIG_UNKNOWN) return -1;
    uint8_t digest[64];
    assl_hash_one(cert->hash_algo, cert->tbs, cert->tbs_len, digest);
    return assl_rsa_verify(issuer_key, cert->hash_algo, digest,
                           cert->signature, cert->sig_len);
}

int assl_x509_verify_self(const assl_x509_cert *cert) {
    if (!cert) return -1;
    assl_rsa_key k;
    assl_rsa_init(&k);
    assl_bn_init(&k.n);
    assl_bn_init(&k.e);
    assl_bn_copy(&k.n, &cert->pubkey.n);
    assl_bn_copy(&k.e, &cert->pubkey.e);
    k.have_priv = 0;
    int rv = assl_x509_verify(cert, &k);
    assl_bn_free(&k.n);
    assl_bn_free(&k.e);
    return rv;
}


int assl_x509_dn_raw_eq(const assl_x509_dn *a, const assl_x509_dn *b) {
    if (!a || !b || !a->raw || !b->raw) return 0;
    if (a->raw_len != b->raw_len) return 0;
    return memcmp(a->raw, b->raw, a->raw_len) == 0;
}

static int assl_x509_time_to_ts(const assl_x509_time *t, int64_t *out) {
    if (!t || !out) return -1;
    static const int mdays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int y = t->year;
    int m = t->month;
    if (m < 1 || m > 12) return -1;
    int leap = (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0));
    long long days = 365LL * (y - 1970) + (y - 1970 + 1) / 4 - (y - 1970 - 1) / 100 + (y - 1970 - 1) / 400;
    for (int i = 0; i < m - 1; i++) days += mdays[i];
    if (m > 2 && leap) days += 1;
    days += t->day - 1;
    *out = days * 86400LL + t->hour * 3600LL + t->min * 60LL + t->sec;
    return 0;
}

int assl_x509_time_in_validity(const assl_x509_cert *cert, int64_t now) {
    int64_t nb, na;
    if (!cert) return 0;
    if (assl_x509_time_to_ts(&cert->validity.not_before, &nb) < 0) return 0;
    if (assl_x509_time_to_ts(&cert->validity.not_after, &na) < 0) return 0;
    if (now < 0) now = (int64_t)time(NULL);
    return now >= nb && now <= na;
}

static int dns_label_match(const char *pattern, size_t plen, const char *host, size_t hlen) {
    if (plen >= 2 && pattern[0] == '*' && pattern[1] == '.') {
        const char *dot = (const char *)memchr(host, '.', hlen);
        if (!dot) return 0;
        size_t right_host = hlen - (size_t)(dot - host);
        return right_host == plen - 1 &&
               strncasecmp(pattern + 1, dot, plen - 1) == 0;
    }
    if (plen != hlen) return 0;
    return strncasecmp(pattern, host, hlen) == 0;
}

int assl_x509_check_hostname(const assl_x509_cert *cert, const char *hostname) {
    if (!cert || !hostname || !*hostname) return -1;
    size_t hlen = strlen(hostname);
    if (hlen > 255) return -1;

    if (cert->has_san) {
        for (size_t i = 0; i < cert->san_dns_count; i++) {
            if (dns_label_match((const char *)cert->san_dns[i],
                                cert->san_dns_len[i], hostname, hlen) == 1)
                return 0;
        }
        return -1;
    }
    for (size_t i = 0; i < cert->subject.count; i++) {
        const assl_x509_dn_pair *a = &cert->subject.attrs[i];
        if (a->attr == ASSL_X509_DN_CN) {
            return dns_label_match((const char *)a->value, a->value_len,
                                   hostname, hlen) == 1 ? 0 : -1;
        }
    }
    return -1;
}

static int verify_cert_sig(const assl_x509_cert *child, const assl_x509_cert *parent) {
    assl_rsa_key k;
    assl_rsa_init(&k);
    assl_bn_init(&k.n);
    assl_bn_init(&k.e);
    if (assl_bn_copy(&k.n, &parent->pubkey.n) ||
        assl_bn_copy(&k.e, &parent->pubkey.e)) {
        assl_bn_free(&k.n); assl_bn_free(&k.e); assl_bn_free(&k.d);
        return -1;
    }
    k.have_priv = 0;
    int rv = assl_x509_verify(child, &k);
    assl_bn_free(&k.n); assl_bn_free(&k.e);
    return rv;
}

static int pubkey_from_cert(const assl_x509_cert *c, assl_rsa_key *k) {
    if (!c || !k || c->pk_algo != ASSL_X509_PK_RSA) return -1;
    assl_rsa_init(k);
    assl_bn_init(&k->n);
    assl_bn_init(&k->e);
    if (assl_bn_copy(&k->n, &c->pubkey.n) || assl_bn_copy(&k->e, &c->pubkey.e)) {
        assl_bn_free(&k->n);
        assl_bn_free(&k->e);
        return -1;
    }
    k->have_priv = 0;
    return 0;
}

int assl_x509_verify_chain(const uint8_t *const *chain, const size_t *chain_len,
                           size_t chain_cnt, const assl_x509_trust_store *store,
                           const char *hostname, int64_t now) {
    if (!chain || !chain_len || chain_cnt == 0 || chain_cnt > ASSL_X509_MAX_CHAIN)
        return -1;
    if (!store || store->count == 0) return -1;

    assl_x509_cert certs[ASSL_X509_MAX_CHAIN];
    memset(certs, 0, sizeof certs);
    int ok = -1;

    assl_rsa_key anchor_key;
    assl_bn_init(&anchor_key.n);
    assl_bn_init(&anchor_key.e);
    int have_anchor_key = 0;

    for (size_t i = 0; i < chain_cnt; i++) {
        if (assl_x509_parse(&certs[i], chain[i], chain_len[i]) < 0) goto out;
        if (!assl_x509_time_in_validity(&certs[i], now)) goto out;
    }

    const assl_x509_cert *leaf = &certs[0];

    size_t parent_i;
    for (parent_i = 1; parent_i < chain_cnt; parent_i++) {
        assl_x509_cert *child = &certs[parent_i - 1];
        assl_x509_cert *parent = &certs[parent_i];
        if (!assl_x509_dn_raw_eq(&child->issuer, &parent->subject)) goto out;
        if (verify_cert_sig(child, parent) < 0) goto out;
        if (parent->has_basic_constraints && !parent->is_ca) goto out;
        if (parent->has_unknown_critical) goto out;
        if (store->strict) {
            if (parent->key_usage >= 0 &&
                !(parent->key_usage & ASSL_X509_KU_KEY_CERT_SIGN)) goto out;
        }
    }

    if (leaf->has_unknown_critical) goto out;

    if (store->strict) {
        int max_path_length = ASSL_X509_MAX_CHAIN;
        for (size_t i = 0; i + 1 < chain_cnt; i++) {
            const assl_x509_cert *ca = &certs[i];
            if (!assl_x509_dn_raw_eq(&ca->issuer, &ca->subject))
                max_path_length--;
            if (ca->has_pathlen && ca->pathlen < max_path_length)
                max_path_length = ca->pathlen;
            if (max_path_length < 0) goto out;
        }
    }

    const assl_x509_cert *top = &certs[chain_cnt - 1];
    int anchored = 0;
    int anchor_in_chain = 0;
    for (size_t i = 0; i < store->count && !anchored; i++) {
        assl_x509_cert anc;
        if (assl_x509_parse(&anc, store->der[i], store->len[i]) < 0) continue;
        if (assl_x509_dn_raw_eq(&top->issuer, &anc.subject) == 0) {
            assl_x509_free(&anc);
            continue;
        }
        if (verify_cert_sig(top, &anc) < 0) {
            assl_x509_free(&anc);
            continue;
        }
        if (anc.has_unknown_critical) {
            assl_x509_free(&anc);
            continue;
        }
        if (store->strict) {
            if (assl_x509_verify_self(&anc) != 0) {
                assl_x509_free(&anc);
                continue;
            }
        }
        if (assl_x509_time_in_validity(&anc, now)) {
            anchored = 1;
            if (assl_x509_dn_raw_eq(&certs[chain_cnt - 1].subject, &anc.subject) != 0)
                anchor_in_chain = 1;
            if (pubkey_from_cert(&anc, &anchor_key) == 0) have_anchor_key = 1;
        }
        assl_x509_free(&anc);
    }
    if (!anchored) goto out;

    if (store->check_revocation) {
        size_t ncheck = chain_cnt - (anchor_in_chain ? 1u : 0u);
        int revoked = 0, uncovered = 0, borked = 0;
        for (size_t i = 0; i < ncheck && !borked; i++) {
            assl_rsa_key issuer;
            assl_bn_init(&issuer.n);
            assl_bn_init(&issuer.e);
            int got = 0;
            if (i + 1 < chain_cnt) {
                got = (pubkey_from_cert(&certs[i + 1], &issuer) == 0);
            } else if (have_anchor_key) {
                got = (assl_bn_copy(&issuer.n, &anchor_key.n) == 0 &&
                       assl_bn_copy(&issuer.e, &anchor_key.e) == 0);
            }
            if (!got) {
                assl_bn_free(&issuer.n);
                assl_bn_free(&issuer.e);
                borked = 1;
                break;
            }

            int covered = 0;
            for (size_t j = 0; j < store->crl_count && !covered; j++) {
                assl_x509_crl crl;
                if (assl_x509_crl_parse(&crl, store->crl_der[j], store->crl_len[j]) < 0)
                    continue;
                if (assl_x509_crl_check(&crl, &issuer, &certs[i].issuer, now) < 0)
                    continue;
                int r = assl_x509_crl_is_revoked(&crl, &certs[i]);
                if (r < 0) continue;
                if (r == 1) { revoked = 1; break; }
                covered = 1;
            }

            assl_bn_free(&issuer.n);
            assl_bn_free(&issuer.e);
            if (!covered && !revoked) uncovered = 1;
        }
        if (revoked || uncovered || borked) goto out;
    }

    if (hostname && assl_x509_check_hostname(leaf, hostname) < 0) goto out;

    ok = 0;
out:
    for (size_t i = 0; i < chain_cnt; i++) assl_x509_free(&certs[i]);
    assl_bn_free(&anchor_key.n);
    assl_bn_free(&anchor_key.e);
    return ok;
}


typedef struct {
    uint8_t *buf;
    size_t len;
    size_t cap;
} der_buf;

static int der_init(der_buf *b, size_t cap) {
    b->buf = malloc(cap);
    if (!b->buf) return -1;
    b->len = 0;
    b->cap = cap;
    return 0;
}

static int der_ensure(der_buf *b, size_t need) {
    if (b->len + need <= b->cap) return 0;
    size_t ncap = b->cap * 2;
    while (ncap < b->len + need) ncap *= 2;
    uint8_t *p = realloc(b->buf, ncap);
    if (!p) return -1;
    b->buf = p;
    b->cap = ncap;
    return 0;
}

static int der_write(der_buf *b, const void *data, size_t len) {
    if (der_ensure(b, len)) return -1;
    memcpy(b->buf + b->len, data, len);
    b->len += len;
    return 0;
}

static int der_write_u8(der_buf *b, uint8_t v) {
    return der_write(b, &v, 1);
}

static void der_write_tag_len(der_buf *b, uint8_t tag, size_t len) {
    der_write_u8(b, tag);
    if (len < 0x80) {
        der_write_u8(b, (uint8_t)len);
    } else if (len < 0x100) {
        der_write_u8(b, 0x81);
        der_write_u8(b, (uint8_t)len);
    } else if (len < 0x10000) {
        der_write_u8(b, 0x82);
        der_write_u8(b, (uint8_t)(len >> 8));
        der_write_u8(b, (uint8_t)len);
    } else {
        der_write_u8(b, 0x83);
        der_write_u8(b, (uint8_t)(len >> 16));
        der_write_u8(b, (uint8_t)(len >> 8));
        der_write_u8(b, (uint8_t)len);
    }
}

static int der_write_integer(der_buf *b, const uint8_t *data, size_t len) {
    while (len > 1 && data[0] == 0) { data++; len--; }
    int need_pad = (len > 0 && (data[0] & 0x80));
    der_write_tag_len(b, ASN1_TAG_INTEGER, len + need_pad);
    if (need_pad) der_write_u8(b, 0);
    return der_write(b, data, len);
}

static int der_write_integer_u32(der_buf *b, uint32_t v) {
    if (v == 0) {
        uint8_t zero = 0;
        return der_write_integer(b, &zero, 1);
    }
    uint8_t buf[4];
    int len = 0;
    uint32_t tmp = v;
    for (int i = 3; i >= 0; i--) { buf[i] = (uint8_t)tmp; tmp >>= 8; if (tmp == 0 && len == 0) len = 4 - i; }
    return der_write_integer(b, buf + (4 - len), (size_t)len);
}

static int der_write_oid(der_buf *b, const uint32_t *oids, size_t count) {
    if (count < 2) return -1;
    size_t elen = 0;
    uint32_t first = oids[0] * 40 + oids[1];
    if (first < 0x80) { elen++; }
    else if (first < 0x4000) { elen += 2; }
    else { elen += 3; }
    for (size_t i = 2; i < count; i++) {
        uint32_t v = oids[i];
        if (v < 0x80) elen++;
        else if (v < 0x4000) elen += 2;
        else if (v < 0x200000) elen += 3;
        else if (v < 0x10000000) elen += 4;
        else elen += 5;
    }
    der_write_tag_len(b, ASN1_TAG_OID, elen);
    uint32_t first2 = oids[0] * 40 + oids[1];
    if (first2 < 0x80) { der_write_u8(b, (uint8_t)first2); }
    else if (first2 < 0x4000) { der_write_u8(b, (uint8_t)(0x80 | (first2 >> 7))); der_write_u8(b, (uint8_t)(first2 & 0x7F)); }
    else { der_write_u8(b, (uint8_t)(0x80 | (first2 >> 14))); der_write_u8(b, (uint8_t)(0x80 | ((first2 >> 7) & 0x7F))); der_write_u8(b, (uint8_t)(first2 & 0x7F)); }
    for (size_t i = 2; i < count; i++) {
        uint32_t v = oids[i];
        uint8_t tmp[5];
        int n = 0;
        tmp[n++] = (uint8_t)(v & 0x7F); v >>= 7;
        while (v > 0) { tmp[n++] = (uint8_t)(0x80 | (v & 0x7F)); v >>= 7; }
        for (int j = n - 1; j >= 0; j--) der_write_u8(b, tmp[j]);
    }
    return 0;
}

static int der_write_utf8string(der_buf *b, const uint8_t *str, size_t len) {
    der_write_tag_len(b, ASN1_TAG_UTF8STRING, len);
    return der_write(b, str, len);
}

static int der_write_utctime(der_buf *b, const assl_x509_time *t) {
    char buf[16];
    int yy = t->year % 100;
    snprintf(buf, sizeof buf, "%02d%02d%02d%02d%02d%02dZ",
             yy, t->month, t->day, t->hour, t->min, t->sec);
    der_write_tag_len(b, ASN1_TAG_UTCTIME, 13);
    return der_write(b, buf, 13);
}

static int der_write_null(der_buf *b) {
    der_write_u8(b, ASN1_TAG_NULL);
    der_write_u8(b, 0);
    return 0;
}

static int der_build_dn(der_buf *b, const assl_x509_dn_pair *attrs, size_t count) {
    for (size_t i = 0; i < count; i++) {
        const uint32_t *oid = NULL;
        size_t oid_count = 0;
        switch (attrs[i].attr) {
            case ASSL_X509_DN_CN:     oid = oid_cn; oid_count = 4; break;
            case ASSL_X509_DN_O:      oid = oid_o;  oid_count = 4; break;
            case ASSL_X509_DN_OU:     oid = oid_ou; oid_count = 4; break;
            case ASSL_X509_DN_EMAIL:  oid = oid_email; oid_count = 7; break;
            default: return -1;
        }

        der_buf seq_buf;
        if (der_init(&seq_buf, 64)) return -1;
        der_write_oid(&seq_buf, oid, oid_count);
        der_write_utf8string(&seq_buf, attrs[i].value, attrs[i].value_len);

        der_buf set_buf;
        if (der_init(&set_buf, 128)) { free(seq_buf.buf); return -1; }
        der_write_tag_len(&set_buf, ASN1_TAG_SET, 0);
        size_t set_content_start = set_buf.len;
        der_write_tag_len(&set_buf, ASN1_TAG_SEQUENCE, seq_buf.len);
        der_write(&set_buf, seq_buf.buf, seq_buf.len);
        free(seq_buf.buf);
        size_t set_content_len = set_buf.len - set_content_start;
        if (set_content_len < 0x80) {
            set_buf.buf[set_content_start - 1] = (uint8_t)set_content_len;
        }

        der_write(b, set_buf.buf, set_buf.len);
        free(set_buf.buf);
    }
    return 0;
}

static int der_build_spki(der_buf *b, const assl_rsa_key *key) {
    der_buf algo_buf;
    if (der_init(&algo_buf, 64)) return -1;
    der_write_oid(&algo_buf, oid_rsa_enc, 7);
    der_write_null(&algo_buf);

    der_buf key_buf;
    if (der_init(&key_buf, 512)) { free(algo_buf.buf); return -1; }
    uint8_t nbuf[512], ebuf[64];
    size_t nlen = assl_bn_bytes(&key->n);
    size_t elen = assl_bn_bytes(&key->e);
    assl_bn_to_bin(&key->n, nbuf, nlen);
    assl_bn_to_bin(&key->e, ebuf, elen);
    der_write_integer(&key_buf, nbuf, nlen);
    der_write_integer(&key_buf, ebuf, elen);

    der_buf key_seq;
    if (der_init(&key_seq, 512 + 5)) { free(key_buf.buf); free(algo_buf.buf); return -1; }
    der_write_tag_len(&key_seq, ASN1_TAG_SEQUENCE, key_buf.len);
    der_write(&key_seq, key_buf.buf, key_buf.len);
    free(key_buf.buf);

    der_buf bitstr_buf;
    if (der_init(&bitstr_buf, 512 + 10)) { free(key_seq.buf); free(algo_buf.buf); return -1; }
    der_write_tag_len(&bitstr_buf, ASN1_TAG_BIT_STRING, key_seq.len + 1);
    der_write_u8(&bitstr_buf, 0); 
    der_write(&bitstr_buf, key_seq.buf, key_seq.len);
    free(key_seq.buf);

    der_buf algo_seq;
    if (der_init(&algo_seq, algo_buf.len + 8)) { free(algo_buf.buf); return -1; }
    der_write_tag_len(&algo_seq, ASN1_TAG_SEQUENCE, algo_buf.len);
    der_write(&algo_seq, algo_buf.buf, algo_buf.len);
    free(algo_buf.buf);

    der_write_tag_len(b, ASN1_TAG_SEQUENCE, algo_seq.len + bitstr_buf.len);
    der_write(b, algo_seq.buf, algo_seq.len);
    der_write(b, bitstr_buf.buf, bitstr_buf.len);
    free(algo_seq.buf);
    free(bitstr_buf.buf);
    return 0;
}

static int der_build_sigalgo(der_buf *b, assl_x509_sigalgo_t algo) {
    const uint32_t *oid = NULL;
    switch (algo) {
        case ASSL_X509_SIG_SHA1_RSA:   oid = oid_sha1_rsa; break;
        case ASSL_X509_SIG_SHA256_RSA: oid = oid_sha256_rsa; break;
        case ASSL_X509_SIG_SHA384_RSA: oid = oid_sha384_rsa; break;
        case ASSL_X509_SIG_SHA512_RSA: oid = oid_sha512_rsa; break;
        default: oid = oid_sha256_rsa; break;
    }
    der_buf algo_buf;
    if (der_init(&algo_buf, 64)) return -1;
    der_write_oid(&algo_buf, oid, 7);
    der_write_null(&algo_buf);
    der_write_tag_len(b, ASN1_TAG_SEQUENCE, algo_buf.len);
    der_write(b, algo_buf.buf, algo_buf.len);
    free(algo_buf.buf);
    return 0;
}

static int der_build_validity(der_buf *b, const assl_x509_validity *v) {
    der_buf nb, na;
    if (der_init(&nb, 20)) return -1;
    if (der_init(&na, 20)) { free(nb.buf); return -1; }
    der_write_utctime(&nb, &v->not_before);
    der_write_utctime(&na, &v->not_after);
    der_write_tag_len(b, ASN1_TAG_SEQUENCE, nb.len + na.len);
    der_write(b, nb.buf, nb.len);
    der_write(b, na.buf, na.len);
    free(nb.buf);
    free(na.buf);
    return 0;
}

static int der_build_tbs(der_buf *b, const assl_x509_params *params,
                         const uint8_t *tbs_hash, size_t tbs_hash_len) {
    (void)tbs_hash; (void)tbs_hash_len;

    der_buf ver_buf;
    if (der_init(&ver_buf, 8)) return -1;
    der_write_integer_u32(&ver_buf, 2); 
    der_buf ver_ctx;
    if (der_init(&ver_ctx, 16)) { free(ver_buf.buf); return -1; }
    der_write_tag_len(&ver_ctx, ASN1_TAG_CTX0, ver_buf.len);
    der_write(&ver_ctx, ver_buf.buf, ver_buf.len);
    free(ver_buf.buf);

    der_buf serial_buf;
    if (der_init(&serial_buf, 32)) { free(ver_ctx.buf); return -1; }
    der_write_integer(&serial_buf, params->serial, params->serial_len);

    der_buf sigalgo_buf;
    if (der_init(&sigalgo_buf, 64)) { free(serial_buf.buf); free(ver_ctx.buf); return -1; }
    der_build_sigalgo(&sigalgo_buf, params->sig_algo);

    der_buf issuer_buf;
    if (der_init(&issuer_buf, 256)) { free(sigalgo_buf.buf); free(serial_buf.buf); free(ver_ctx.buf); return -1; }
    if (der_build_dn(&issuer_buf, params->issuer_attrs, params->issuer_attr_count)) {
        free(issuer_buf.buf); free(sigalgo_buf.buf); free(serial_buf.buf); free(ver_ctx.buf); return -1;
    }
    der_buf issuer_seq;
    if (der_init(&issuer_seq, issuer_buf.len + 8)) { free(issuer_buf.buf); free(sigalgo_buf.buf); free(serial_buf.buf); free(ver_ctx.buf); return -1; }
    der_write_tag_len(&issuer_seq, ASN1_TAG_SEQUENCE, issuer_buf.len);
    der_write(&issuer_seq, issuer_buf.buf, issuer_buf.len);
    free(issuer_buf.buf);

    der_buf validity_buf;
    if (der_init(&validity_buf, 40)) { free(sigalgo_buf.buf); free(serial_buf.buf); free(ver_ctx.buf); return -1; }
    der_build_validity(&validity_buf, &params->validity);

    der_buf subject_buf;
    if (der_init(&subject_buf, 256)) { free(issuer_seq.buf); free(validity_buf.buf); free(sigalgo_buf.buf); free(serial_buf.buf); free(ver_ctx.buf); return -1; }
    if (der_build_dn(&subject_buf, params->subject_attrs, params->subject_attr_count)) {
        free(subject_buf.buf); free(issuer_seq.buf); free(validity_buf.buf); free(sigalgo_buf.buf); free(serial_buf.buf); free(ver_ctx.buf); return -1;
    }
    der_buf subject_seq;
    if (der_init(&subject_seq, subject_buf.len + 8)) { free(subject_buf.buf); free(issuer_seq.buf); free(validity_buf.buf); free(sigalgo_buf.buf); free(serial_buf.buf); free(ver_ctx.buf); return -1; }
    der_write_tag_len(&subject_seq, ASN1_TAG_SEQUENCE, subject_buf.len);
    der_write(&subject_seq, subject_buf.buf, subject_buf.len);
    free(subject_buf.buf);

    der_buf spki_buf;
    if (der_init(&spki_buf, 1024)) { free(subject_seq.buf); free(validity_buf.buf); free(issuer_seq.buf); free(sigalgo_buf.buf); free(serial_buf.buf); free(ver_ctx.buf); return -1; }
    der_build_spki(&spki_buf, params->subject_key);

    der_buf exts_buf;
    if (der_init(&exts_buf, 128)) { free(spki_buf.buf); free(subject_seq.buf); free(validity_buf.buf); free(issuer_seq.buf); free(sigalgo_buf.buf); free(serial_buf.buf); free(ver_ctx.buf); return -1; }

    der_buf bc_val;
    if (der_init(&bc_val, 32)) { free(exts_buf.buf); free(spki_buf.buf); free(subject_seq.buf); free(validity_buf.buf); free(issuer_seq.buf); free(sigalgo_buf.buf); free(serial_buf.buf); free(ver_ctx.buf); return -1; }
    der_buf bc_seq;
    if (der_init(&bc_seq, 32)) { free(bc_val.buf); free(exts_buf.buf); free(spki_buf.buf); free(subject_seq.buf); free(validity_buf.buf); free(issuer_seq.buf); free(sigalgo_buf.buf); free(serial_buf.buf); free(ver_ctx.buf); return -1; }
    der_write_tag_len(&bc_seq, 0x01, 1);
    der_write_u8(&bc_seq, params->is_ca ? 0xFF : 0x00);
    if (params->is_ca) {
        der_write_integer_u32(&bc_seq, 0);
    }

    der_write_tag_len(&bc_val, ASN1_TAG_SEQUENCE, bc_seq.len);
    der_write(&bc_val, bc_seq.buf, bc_seq.len);
    free(bc_seq.buf);

    der_buf ext_entry;
    if (der_init(&ext_entry, 64)) { free(bc_val.buf); free(exts_buf.buf); free(spki_buf.buf); free(subject_seq.buf); free(validity_buf.buf); free(issuer_seq.buf); free(sigalgo_buf.buf); free(serial_buf.buf); free(ver_ctx.buf); return -1; }
    der_buf ext_fields;
    if (der_init(&ext_fields, 64)) { free(ext_entry.buf); free(bc_val.buf); free(exts_buf.buf); free(spki_buf.buf); free(subject_seq.buf); free(validity_buf.buf); free(issuer_seq.buf); free(sigalgo_buf.buf); free(serial_buf.buf); free(ver_ctx.buf); return -1; }
    der_write_oid(&ext_fields, oid_basic_constraints, 4);
    der_write_tag_len(&ext_fields, ASN1_TAG_OCTET_STRING, bc_val.len);
    der_write(&ext_fields, bc_val.buf, bc_val.len);
    free(bc_val.buf);
    der_write_tag_len(&ext_entry, ASN1_TAG_SEQUENCE, ext_fields.len);
    der_write(&ext_entry, ext_fields.buf, ext_fields.len);
    free(ext_fields.buf);

    der_write_tag_len(&exts_buf, ASN1_TAG_SEQUENCE, ext_entry.len);
    der_write(&exts_buf, ext_entry.buf, ext_entry.len);
    free(ext_entry.buf);

    der_buf exts_ctx;
    if (der_init(&exts_ctx, exts_buf.len + 8)) { free(exts_buf.buf); free(spki_buf.buf); free(subject_seq.buf); free(validity_buf.buf); free(issuer_seq.buf); free(sigalgo_buf.buf); free(serial_buf.buf); free(ver_ctx.buf); return -1; }
    der_write_tag_len(&exts_ctx, ASN1_TAG_CTX3, exts_buf.len);
    der_write(&exts_ctx, exts_buf.buf, exts_buf.len);
    free(exts_buf.buf);

    size_t total = ver_ctx.len + serial_buf.len + sigalgo_buf.len +
                   issuer_seq.len + validity_buf.len + subject_seq.len +
                   spki_buf.len + exts_ctx.len;
    der_write_tag_len(b, ASN1_TAG_SEQUENCE, total);
    der_write(b, ver_ctx.buf, ver_ctx.len);
    der_write(b, serial_buf.buf, serial_buf.len);
    der_write(b, sigalgo_buf.buf, sigalgo_buf.len);
    der_write(b, issuer_seq.buf, issuer_seq.len);
    der_write(b, validity_buf.buf, validity_buf.len);
    der_write(b, subject_seq.buf, subject_seq.len);
    der_write(b, spki_buf.buf, spki_buf.len);
    der_write(b, exts_ctx.buf, exts_ctx.len);

    free(ver_ctx.buf);
    free(serial_buf.buf);
    free(sigalgo_buf.buf);
    free(issuer_seq.buf);
    free(validity_buf.buf);
    free(subject_seq.buf);
    free(spki_buf.buf);
    free(exts_ctx.buf);
    return 0;
}

int assl_x509_generate(const assl_x509_params *params,
                       uint8_t **out_der, size_t *out_len) {
    if (!params || !out_der || !out_len) return -1;
    if (!params->subject_attrs || params->subject_attr_count == 0) return -1;
    if (!params->subject_key) return -1;
    if (!params->serial || params->serial_len == 0) return -1;

    const assl_rsa_key *signing_key = params->issuer_key ? params->issuer_key : params->subject_key;
    assl_x509_params p = *params;
    if (!p.issuer_attrs || p.issuer_attr_count == 0) {
        p.issuer_attrs = p.subject_attrs;
        p.issuer_attr_count = p.subject_attr_count;
    }
    assl_x509_sigalgo_t sigalgo = params->sig_algo;
    if (sigalgo == ASSL_X509_SIG_UNKNOWN) sigalgo = ASSL_X509_SIG_SHA256_RSA;
    assl_hash_t hash = sigalgo_to_hash(sigalgo);

    der_buf tbs_buf;
    if (der_init(&tbs_buf, 2048)) return -1;
    if (der_build_tbs(&tbs_buf, &p, NULL, 0)) {
        free(tbs_buf.buf);
        return -1;
    }

    uint8_t digest[64];
    assl_hash_one(hash, tbs_buf.buf, tbs_buf.len, digest);
    size_t siglen = assl_rsa_key_size(signing_key);
    if (siglen == 0 || siglen > 512) {
        free(tbs_buf.buf);
        return -1;
    }
    uint8_t sig[512];
    if (assl_rsa_sign(signing_key, hash, digest, sig) < 0) {
        free(tbs_buf.buf);
        return -1;
    }

    der_buf sigalgo_buf;
    if (der_init(&sigalgo_buf, 64)) { free(tbs_buf.buf); return -1; }
    der_build_sigalgo(&sigalgo_buf, sigalgo);

    der_buf sigbit_buf;
    if (der_init(&sigbit_buf, siglen + 10)) { free(sigalgo_buf.buf); free(tbs_buf.buf); return -1; }
    der_write_tag_len(&sigbit_buf, ASN1_TAG_BIT_STRING, siglen + 1);
    der_write_u8(&sigbit_buf, 0); 
    der_write(&sigbit_buf, sig, siglen);

    size_t cert_total = tbs_buf.len + sigalgo_buf.len + sigbit_buf.len;
    der_buf cert_buf;
    if (der_init(&cert_buf, cert_total + 16)) {
        free(sigbit_buf.buf); free(sigalgo_buf.buf); free(tbs_buf.buf);
        return -1;
    }
    der_write_tag_len(&cert_buf, ASN1_TAG_SEQUENCE, cert_total);
    der_write(&cert_buf, tbs_buf.buf, tbs_buf.len);
    der_write(&cert_buf, sigalgo_buf.buf, sigalgo_buf.len);
    der_write(&cert_buf, sigbit_buf.buf, sigbit_buf.len);

    free(sigbit_buf.buf);
    free(sigalgo_buf.buf);
    free(tbs_buf.buf);

    *out_der = cert_buf.buf;
    *out_len = cert_buf.len;
    return 0;
}

int assl_x509_generate_self_signed(const assl_x509_params *params,
                                   uint8_t **out_der, size_t *out_len) {
    if (!params) return -1;
    assl_x509_params p = *params;
    if (!p.issuer_attrs || p.issuer_attr_count == 0) {
        p.issuer_attrs = p.subject_attrs;
        p.issuer_attr_count = p.subject_attr_count;
    }
    if (!p.issuer_key) {
        p.issuer_key = p.subject_key;
    }
    return assl_x509_generate(&p, out_der, out_len);
}
