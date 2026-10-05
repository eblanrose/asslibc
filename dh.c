#include "asslibc.h"

static const char dh_p2048[] =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF95"
    "19B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB"
    "5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3"
    "AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E8603"
    "9B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFF"
    "FFFFFFFFFFFF"
;
static const char dh_p3072[] =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF95"
    "19B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB"
    "5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3"
    "AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E8603"
    "9B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33"
    "170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E0"
    "4A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD9"
    "46E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
;

static int dh_set(const char *hexstr, assl_bn *p, assl_bn *g) {
    assl_bn tu;
    int rv = -1;
    assl_bn_init(&tu);
    if (assl_bn_from_hex(p, hexstr)) goto out;
    if (assl_bn_set_u32(&tu, 2)) goto out;
    if (assl_bn_copy(g, &tu)) goto out;
    rv = 0;
out:
    assl_bn_free(&tu);
    return rv;
}

int assl_dh_group(int group, assl_bn *p, assl_bn *g) {
    const char *h = group == ASSL_DH_FFDHE2048 ? dh_p2048 :
                    group == ASSL_DH_FFDHE3072 ? dh_p3072 : NULL;
    return h ? dh_set(h, p, g) : -1;
}

int assl_dh_pub(const assl_bn *p, const assl_bn *g, const assl_bn *priv, assl_bn *pub) {
    if (!p || !g || !priv || !pub) return -1;
    return assl_bn_modpow_ct(g, priv, p, pub);
}

int assl_dh_keygen(const assl_bn *p, const assl_bn *g, assl_bn *priv, assl_bn *pub) {
    uint8_t buf[512];
    size_t nb = (assl_bn_bitlen(p) + 7) / 8;
    if (!p || !g || !priv || !pub || nb > sizeof buf) return -1;
    if (!assl_rng_is_secure()) return -1;
    do {
        if (assl_rng_bytes_checked(buf, nb)) return -1;
        if (assl_bn_from_bin(priv, buf, nb)) return -1;
        if (assl_bn_is_zero(priv) || assl_bn_is_one(priv)) continue;
        if (assl_bn_cmp(priv, p) >= 0) continue;
        if (assl_dh_pub(p, g, priv, pub)) return -1;
        if (assl_bn_is_one(pub) || assl_bn_is_zero(pub)) continue;
        return 0;
    } while (1);
}

int assl_dh_shared(const assl_bn *p, const assl_bn *priv, const assl_bn *peer_pub, assl_bn *shared) {
    if (!p || !priv || !peer_pub || !shared) return -1;
    return assl_bn_modpow_ct(peer_pub, priv, p, shared);
}
