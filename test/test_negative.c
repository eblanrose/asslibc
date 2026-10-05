#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include "utest.h"
#include "asslibc.h"
#include "ssl.h"
#include "rsa_keygen.h"


typedef struct {
    int fd;
    assl_rsa_key *key;
    uint16_t version;
    int hs_result;
    int echo;
} peer_arg;

static void echo_loop(assl_ssl *s, int fd) {
    uint8_t buf[4096];
    for (;;) {
        int n = assl_ssl_read(s, fd, buf, sizeof buf);
        if (n < 0) break;
        if (n == 0) {
            assl_ssl_shutdown(s, fd);
            break;
        }
        if (assl_ssl_write(s, fd, buf, (size_t)n) < 0) break;
    }
}

static void *good_server(void *a) {
    peer_arg *p = a;
    assl_ssl s;
        assl_ssl_init(&s, 0);
    assl_ssl_set_verify(&s, 0, NULL);
    assl_ssl_set_version(&s, p->version);
    assl_ssl_set_cert(&s, (const uint8_t *)"dummy", 5, p->key);
    p->hs_result = assl_ssl_handshake(&s, p->fd, p->fd);
    if (p->hs_result == 0 && p->echo) echo_loop(&s, p->fd);
    assl_rsa_free(p->key);
    p->key = NULL;
    close(p->fd);
    return NULL;
}

typedef struct {
    int in, out;
    int corrupt_record;
    int flipped;
    int rewrite_ccs;
    uint8_t ccs_byte;
    int tamper_ch;
} relay_arg;

static void *relay_thread(void *a) {
    relay_arg *r = a;
    uint8_t hdr[5];
    int idx = 0;
    for (;;) {
        size_t h = 0;
        while (h < 5) {
            ssize_t k = read(r->in, hdr + h, 5 - h);
            if (k <= 0) goto done;
            h += (size_t)k;
        }
        size_t n = ((size_t)hdr[3] << 8) | hdr[4];
        if (n > 65536) break;
        uint8_t *body = malloc(n ? n : 1);
        if (!body) break;
        size_t got = 0;
        while (got < n) {
            ssize_t k = read(r->in, body + got, n - got);
            if (k <= 0) { free(body); goto done; }
            got += (size_t)k;
        }
        idx++;
        if (r->corrupt_record && idx == r->corrupt_record && n > 0) {
            body[n - 1] ^= 0x40;
            r->flipped = 1;
        }
        if (r->rewrite_ccs && hdr[0] == SSL3_CT_CHANGE_CIPHER_SPEC && n == 1) {
            body[0] = r->ccs_byte;
            r->flipped = 1;
        }
        if (r->tamper_ch && idx == 1 && hdr[0] == SSL3_CT_HANDSHAKE &&
            body[0] == SSL3_HS_CLIENT_HELLO && n > 8) {
            body[n - 1] ^= 0x01;
            r->flipped = 1;
        }
        if (write(r->out, hdr, 5) != 5) { free(body); break; }
        if (n && write(r->out, body, n) != (ssize_t)n) { free(body); break; }
        free(body);
    }
done:
    shutdown(r->out, SHUT_WR);
    return NULL;
}

static void drain(int fd, int max_bytes) {
    uint8_t junk[4096];
    int total = 0;
    while (total < max_bytes) {
        ssize_t r = read(fd, junk, sizeof junk);
        if (r <= 0) break;
        total += (int)r;
    }
}

static int write_raw(int fd, uint8_t type, const uint8_t *body, size_t len) {
    uint8_t hdr[5] = { type, 3, 3, (uint8_t)(len >> 8), (uint8_t)len };
    if (write(fd, hdr, 5) != 5) return -1;
    if (len && write(fd, body, len) != (ssize_t)len) return -1;
    return 0;
}

static size_t hs_msg(uint8_t *out, uint8_t type, const uint8_t *payload, size_t plen) {
    out[0] = type;
    out[1] = (uint8_t)(plen >> 16);
    out[2] = (uint8_t)(plen >> 8);
    out[3] = (uint8_t)plen;
    memcpy(out + 4, payload, plen);
    return 4 + plen;
}


static int server_rejects(const uint8_t *ch_body, size_t ch_len) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -1;

    assl_rsa_key *k = malloc(sizeof *k);
    assl_rsa_init(k);
    if (assl_rsa_keygen(k, 2048) < 0) { free(k); close(sv[0]); close(sv[1]); return -1; }

    peer_arg pa = { .fd = sv[0], .key = k, .version = TLS12_VERSION, .hs_result = -99 };
    pthread_t th;
    pthread_create(&th, NULL, good_server, &pa);

    if (write_raw(sv[1], SSL3_CT_HANDSHAKE, ch_body, ch_len) < 0) {
        pthread_join(th, NULL);
        assl_rsa_free(k); free(k);
        close(sv[0]); close(sv[1]);
        return -1;
    }
    shutdown(sv[1], SHUT_WR);

    drain(sv[1], 1 << 20);
    pthread_join(th, NULL);
    close(sv[1]);

    int rejected = (pa.hs_result < 0);
    assl_rsa_free(k);
    free(k);
    return rejected;
}

static size_t ch_prefix(uint8_t *b) {
    size_t p = 0;
    b[p++] = 3; b[p++] = 3;
    memset(b + p, 0xAB, 32); p += 32;
    b[p++] = 0;
    b[p++] = 0; b[p++] = 2;
    b[p++] = 0xC0; b[p++] = 0x2F;
    b[p++] = 1; b[p++] = 0;
    return p;
}

static void test_ch_truncated(void) {
    utest_begin("ch-truncated");
    uint8_t body[256], msg[300];

    body[0] = SSL3_HS_CLIENT_HELLO;
    size_t n = hs_msg(msg, SSL3_HS_CLIENT_HELLO, body, 0);
    utest_bool(server_rejects(msg, n) == 1, "empty ClientHello rejected");

    msg[0] = SSL3_HS_CLIENT_HELLO;
    msg[1] = 0; msg[2] = 0; msg[3] = 64;
    utest_bool(server_rejects(msg, 4) == 1, "declared body missing rejected");

    uint8_t b[64];
    size_t p = 0;
    b[p++] = 3; b[p++] = 3;
    n = hs_msg(msg, SSL3_HS_CLIENT_HELLO, b, p);
    utest_bool(server_rejects(msg, n) == 1, "version-only ClientHello rejected");

    p = 0;
    b[p++] = 3; b[p++] = 3;
    memset(b + p, 0, 32); p += 32;
    b[p++] = 32;
    n = hs_msg(msg, SSL3_HS_CLIENT_HELLO, b, p);
    utest_bool(server_rejects(msg, n) == 1, "oversized session_id rejected");

    utest_end();
}

static void test_ch_bad_lengths(void) {
    utest_begin("ch-bad-lengths");
    uint8_t b[512], msg[600];

    size_t p = ch_prefix(b);
    b[p - 4] = 0xFF; b[p - 3] = 0xFF;
    p = 0;
    b[p++] = 3; b[p++] = 3;
    memset(b + p, 0, 32); p += 32;
    b[p++] = 0;
    b[p++] = 0xFF; b[p++] = 0xFF;
    b[p++] = 0xC0; b[p++] = 0x2F;
    b[p++] = 1; b[p++] = 0;
    size_t n = hs_msg(msg, SSL3_HS_CLIENT_HELLO, b, p);
    utest_bool(server_rejects(msg, n) == 1, "huge cipher_suites len rejected");

    p = 0;
    b[p++] = 3; b[p++] = 3;
    memset(b + p, 0, 32); p += 32;
    b[p++] = 0;
    b[p++] = 0; b[p++] = 3;
    b[p++] = 0xC0; b[p++] = 0x2F; b[p++] = 0x30;
    b[p++] = 1; b[p++] = 0;
    n = hs_msg(msg, SSL3_HS_CLIENT_HELLO, b, p);
    utest_bool(server_rejects(msg, n) == 1, "odd cipher_suites len rejected");

    p = ch_prefix(b);
    b[p++] = 0xFF; b[p++] = 0xFF;
    b[p++] = 0x00; b[p++] = 0x33;
    b[p++] = 0x00; b[p++] = 0x04;
    b[p++] = 0x00; b[p++] = 0x81;
    memset(b + p, 0, 64); p += 64;
    n = hs_msg(msg, SSL3_HS_CLIENT_HELLO, b, p);
    utest_bool(server_rejects(msg, n) == 1, "oversized extension block rejected");

    p = 0;
    b[p++] = 3; b[p++] = 3;
    memset(b + p, 0, 32); p += 32;
    b[p++] = 0;
    b[p++] = 0; b[p++] = 2;
    b[p++] = 0xC0; b[p++] = 0x2F;
    b[p++] = 1; b[p++] = 1;
    n = hs_msg(msg, SSL3_HS_CLIENT_HELLO, b, p);
    utest_bool(server_rejects(msg, n) == 1, "non-null compression rejected");

    p = 0;
    b[p++] = 3; b[p++] = 3;
    memset(b + p, 0, 32); p += 32;
    b[p++] = 0;
    b[p++] = 0; b[p++] = 2;
    b[p++] = 0xFF; b[p++] = 0xFF;
    b[p++] = 1; b[p++] = 0;
    n = hs_msg(msg, SSL3_HS_CLIENT_HELLO, b, p);
    utest_bool(server_rejects(msg, n) == 1, "no shared suite rejected");

    utest_end();
}

static void test_ch_wrong_type(void) {
    utest_begin("ch-wrong-type");
    uint8_t b[256], msg[300];

    size_t p = ch_prefix(b);
    size_t n = hs_msg(msg, SSL3_HS_SERVER_HELLO, b, p);
    utest_bool(server_rejects(msg, n) == 1, "ServerHello as first msg rejected");

    p = ch_prefix(b);
    n = hs_msg(msg, SSL3_HS_CLIENT_HELLO, b, p);
    (void)n;
    {
        int sv[2];
        utest_bool(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
        assl_rsa_key *k = malloc(sizeof *k);
        assl_rsa_init(k);
        if (assl_rsa_keygen(k, 2048) == 0) {
            peer_arg pa = { .fd = sv[0], .key = k, .version = TLS12_VERSION, .hs_result = -99 };
            pthread_t th;
            pthread_create(&th, NULL, good_server, &pa);
            p = ch_prefix(b);
            n = hs_msg(msg, SSL3_HS_CLIENT_HELLO, b, p);
            write_raw(sv[1], SSL3_CT_APPLICATION_DATA, msg, n);
            shutdown(sv[1], SHUT_WR);
            pthread_join(th, NULL);
            utest_bool(pa.hs_result < 0, "app-data record rejected as ClientHello");
            assl_rsa_free(k);
            free(k);
        }
        close(sv[0]); close(sv[1]);
    }

    utest_end();
}


static void test_record_framing(void) {
    utest_begin("record-framing");
    int sv[2];
    utest_bool(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    assl_rsa_key *k = malloc(sizeof *k);
    assl_rsa_init(k);
    if (assl_rsa_keygen(k, 2048) < 0) { utest_end(); return; }

    peer_arg pa = { .fd = sv[0], .key = k, .version = TLS12_VERSION, .hs_result = -99 };
    pthread_t th;
    pthread_create(&th, NULL, good_server, &pa);

    uint8_t hdr[5] = { SSL3_CT_HANDSHAKE, 3, 3, 0xFF, 0xFF };
    ssize_t w = write(sv[1], hdr, 5);
    utest_bool(w == 5, "wrote oversized header");
    pthread_join(th, NULL);
    utest_bool(pa.hs_result < 0, "oversized record length rejected");

    close(sv[0]); close(sv[1]);
    assl_rsa_free(k); free(k);
    utest_end();
}

static void test_read_semantics(void) {
    utest_begin("read-semantics");
    int sv[2];
    utest_bool(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    assl_rsa_key *k = malloc(sizeof *k);
    assl_rsa_init(k);
    if (assl_rsa_keygen(k, 2048) < 0) { utest_end(); return; }

    peer_arg pa = { .fd = sv[0], .key = k, .version = TLS12_VERSION, .hs_result = -99, .echo = 1 };
    pthread_t th;
    pthread_create(&th, NULL, good_server, &pa);

    assl_ssl c;
        assl_ssl_init(&c, 1);
    assl_ssl_set_verify(&c, 0, NULL);
    assl_ssl_set_version(&c, TLS12_VERSION);
    assl_ssl_set_cert(&c, (const uint8_t *)"dummy", 5, k);
    int cr = assl_ssl_handshake(&c, sv[1], sv[1]);
    utest_bool(cr == 0, "handshake for read tests");

    if (cr == 0) {
        uint8_t dummy;
        int z = assl_ssl_read(&c, sv[1], &dummy, 0);
        utest_bool(z == 0, "zero-length read returns 0");

        size_t big = 40000;
        uint8_t *buf = malloc(big);
        uint8_t *out = malloc(big + 64);
        for (size_t i = 0; i < big; i++) buf[i] = (uint8_t)(i * 7 + (i >> 8));
        int w = assl_ssl_write(&c, sv[1], buf, big);
        utest_bool(w == (int)big, "40k write returns full count");

        size_t got = 0;
        int loops = 0;
        while (got < big && loops++ < 200) {
            int n = assl_ssl_read(&c, sv[1], out + got, 1000);
            if (n <= 0) break;
            got += (size_t)n;
        }
        utest_bool(got == big, "all 40k echo bytes returned");
        utest_bool(got == big && memcmp(out, buf, big) == 0, "echo data matches");

        assl_ssl_shutdown(&c, sv[1]);
        int eof = -1;
        for (int i = 0; i < 64; i++) {
            eof = assl_ssl_read(&c, sv[1], out, 1000);
            if (eof <= 0) break;
        }
        utest_bool(eof == 0, "close_notify reported as clean EOF");
        utest_bool(assl_ssl_read(&c, sv[1], out, 16) == 0,
                   "read after close_notify still clean");

        free(out);
        free(buf);
    }

    pthread_join(th, NULL);
    close(sv[0]); close(sv[1]);
    assl_rsa_free(k); free(k);
    utest_end();
}


static void test_aead_tag_rejected(void) {
    utest_begin("aead-tag-rejected");
    uint8_t key[32], nonce[12], aad[13], pt[64], ct[64], tag[16], out[64];
    memset(key, 0x11, sizeof key);
    memset(nonce, 0x22, sizeof nonce);
    memset(aad, 0x33, sizeof aad);
    memset(pt, 0x44, sizeof pt);

    assl_gcm_seal(key, 256, nonce, 12, aad, sizeof aad, pt, sizeof pt, ct, tag);
    int rc = assl_gcm_open(key, 256, nonce, 12, aad, sizeof aad, ct, sizeof pt, tag, out);
    utest_bool(rc == 0, "valid GCM tag accepted");

    for (int byte = 0; byte < 16; byte++) {
        uint8_t bad[16];
        memcpy(bad, tag, 16);
        bad[byte] ^= 0x01;
        rc = assl_gcm_open(key, 256, nonce, 12, aad, sizeof aad, ct, sizeof pt, bad, out);
        utest_bool(rc < 0, "flipped tag byte rejected");
    }

    uint8_t badct[64];
    memcpy(badct, ct, sizeof ct);
    badct[0] ^= 0x80;
    rc = assl_gcm_open(key, 256, nonce, 12, aad, sizeof aad, badct, sizeof pt, tag, out);
    utest_bool(rc < 0, "tampered ciphertext rejected");

    uint8_t badaad[13];
    memcpy(badaad, aad, sizeof aad);
    badaad[0] ^= 0x01;
    rc = assl_gcm_open(key, 256, nonce, 12, badaad, sizeof aad, ct, sizeof pt, tag, out);
    utest_bool(rc < 0, "tampered AAD rejected");

    uint8_t badkey[32];
    memcpy(badkey, key, sizeof key);
    badkey[31] ^= 0x01;
    rc = assl_gcm_open(badkey, 256, nonce, 12, aad, sizeof aad, ct, sizeof pt, tag, out);
    utest_bool(rc < 0, "wrong key rejected");

    utest_end();
}


static void test_finished_verified(void) {
    utest_begin("finished-verified");

    {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
            assl_rsa_key *k = malloc(sizeof *k);
            assl_rsa_init(k);
            if (assl_rsa_keygen(k, 2048) == 0) {
                peer_arg pa = { .fd = sv[0], .key = k, .version = TLS12_VERSION, .hs_result = -99 };
                pthread_t th;
                pthread_create(&th, NULL, good_server, &pa);

                assl_ssl c;
                                assl_ssl_init(&c, 1);
                assl_ssl_set_verify(&c, 0, NULL);
                assl_ssl_set_version(&c, TLS12_VERSION);
                assl_ssl_set_cert(&c, (const uint8_t *)"dummy", 5, k);
                int cr = assl_ssl_handshake(&c, sv[1], sv[1]);
                utest_bool(cr == 0, "client handshake succeeds");

                pthread_join(th, NULL);
                utest_bool(pa.hs_result == 0, "server accepted valid handshake");
            }
            assl_rsa_free(k);
            free(k);
            close(sv[0]); close(sv[1]);
        }
    }

    for (int dir = 0; dir < 2; dir++) {
        int c2s[2], s2c[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, c2s) != 0) break;
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, s2c) != 0) {
            close(c2s[0]); close(c2s[1]); break;
        }

        assl_rsa_key *k = malloc(sizeof *k);
        assl_rsa_init(k);
        if (assl_rsa_keygen(k, 2048) != 0) { free(k); break; }

        peer_arg pa = { .fd = s2c[0], .key = k, .version = TLS12_VERSION, .hs_result = -99 };
        pthread_t th;
        pthread_create(&th, NULL, good_server, &pa);

        int up_idx   = dir == 0 ? 4 : 0;
        int down_idx = dir == 0 ? 0 : 6;
        relay_arg up   = { .in = c2s[1], .out = s2c[1], .corrupt_record = up_idx, .flipped = 0 };
        relay_arg down = { .in = s2c[1], .out = c2s[1], .corrupt_record = down_idx, .flipped = 0 };
        pthread_t tup, tdown;
        pthread_create(&tup, NULL, relay_thread, &up);
        pthread_create(&tdown, NULL, relay_thread, &down);

        assl_ssl c;
                assl_ssl_init(&c, 1);
        assl_ssl_set_verify(&c, 0, NULL);
        assl_ssl_set_version(&c, TLS12_VERSION);
        assl_ssl_set_cert(&c, (const uint8_t *)"dummy", 5, k);
        int cr = assl_ssl_handshake(&c, c2s[0], c2s[0]);
        if (dir == 0) {
            utest_bool(up.flipped == 1, "relay corrupted the client Finished");
            utest_bool(pa.hs_result < 0, "server rejected a corrupted Finished");
        } else {
            utest_bool(down.flipped == 1, "relay corrupted the server Finished");
            utest_bool(cr < 0, "client rejected a corrupted Finished");
        }
        close(c2s[0]);


        pthread_join(tup, NULL);
        pthread_join(tdown, NULL);
        pthread_join(th, NULL);

        close(c2s[1]); close(s2c[0]); close(s2c[1]);
        assl_rsa_free(k);
        free(k);
    }

    {
        int c2s[2], s2c[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, c2s) == 0 &&
            socketpair(AF_UNIX, SOCK_STREAM, 0, s2c) == 0) {

            assl_rsa_key *k = malloc(sizeof *k);
            assl_rsa_init(k);
            if (assl_rsa_keygen(k, 2048) == 0) {
                peer_arg pa = { .fd = s2c[0], .key = k, .version = TLS12_VERSION, .hs_result = -99 };
                pthread_t th;
                pthread_create(&th, NULL, good_server, &pa);

                relay_arg up   = { .in = c2s[1], .out = s2c[1], .tamper_ch = 1 };
                relay_arg down = { .in = s2c[1], .out = c2s[1] };
                pthread_t tup, tdown;
                pthread_create(&tup, NULL, relay_thread, &up);
                pthread_create(&tdown, NULL, relay_thread, &down);

                assl_ssl c;
                                assl_ssl_init(&c, 1);
                assl_ssl_set_verify(&c, 0, NULL);
                assl_ssl_set_version(&c, TLS12_VERSION);
                assl_ssl_set_cert(&c, (const uint8_t *)"dummy", 5, k);
                int cr = assl_ssl_handshake(&c, c2s[0], c2s[0]);
                close(c2s[0]);

                pthread_join(tup, NULL);
                pthread_join(tdown, NULL);
                pthread_join(th, NULL);

                utest_bool(up.flipped == 1, "relay altered the ClientHello");
                utest_bool(pa.hs_result != 0,
                           "server did not accept a tampered transcript");
                utest_bool(cr != 0,
                           "client did not accept a tampered transcript");

                close(c2s[1]); close(s2c[0]); close(s2c[1]);
            }
            assl_rsa_free(k);
            free(k);
        }
    }

    utest_end();
}


static void test_ccs_validated(void) {
    utest_begin("ccs-validated");

    for (int dir = 0; dir < 2; dir++) {
        int c2s[2], s2c[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, c2s) != 0) break;
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, s2c) != 0) {
            close(c2s[0]); close(c2s[1]); break;
        }

        assl_rsa_key *k = malloc(sizeof *k);
        assl_rsa_init(k);
        if (assl_rsa_keygen(k, 2048) != 0) { free(k); break; }

        peer_arg pa = { .fd = s2c[0], .key = k, .version = TLS12_VERSION, .hs_result = -99 };
        pthread_t th;
        pthread_create(&th, NULL, good_server, &pa);

        relay_arg up   = { .in = c2s[1], .out = s2c[1], .corrupt_record = 0, .flipped = 0,
                           .rewrite_ccs = dir == 0, .ccs_byte = 0x02 };
        relay_arg down = { .in = s2c[1], .out = c2s[1], .corrupt_record = 0, .flipped = 0,
                           .rewrite_ccs = dir == 1, .ccs_byte = 0x02 };
        pthread_t tup, tdown;
        pthread_create(&tup, NULL, relay_thread, &up);
        pthread_create(&tdown, NULL, relay_thread, &down);

        assl_ssl c;
                assl_ssl_init(&c, 1);
        assl_ssl_set_verify(&c, 0, NULL);
        assl_ssl_set_version(&c, TLS12_VERSION);
        assl_ssl_set_cert(&c, (const uint8_t *)"dummy", 5, k);
        int cr = assl_ssl_handshake(&c, c2s[0], c2s[0]);
        close(c2s[0]);
        pthread_join(tup, NULL);
        pthread_join(tdown, NULL);
        pthread_join(th, NULL);

        if (dir == 0) {
            utest_bool(up.flipped == 1, "relay rewrote the client CCS");
            utest_bool(pa.hs_result < 0, "server rejected a malformed CCS");
        } else {
            utest_bool(down.flipped == 1, "relay rewrote the server CCS");
            utest_bool(cr < 0, "client rejected a malformed CCS");
        }

        close(c2s[1]); close(s2c[0]); close(s2c[1]);
        assl_rsa_free(k);
        free(k);
    }

    utest_end();
}


int main(void) {
    signal(SIGPIPE, SIG_IGN);

    if (!utest_need_rng()) {
        printf("SKIP: no /dev/urandom\n");
        return 0;
    }

    test_ch_truncated();
    test_ch_bad_lengths();
    test_ch_wrong_type();
    test_record_framing();
    test_read_semantics();
    test_aead_tag_rejected();
    test_finished_verified();
    test_ccs_validated();

    return utest_finish("NEGATIVE");
}
