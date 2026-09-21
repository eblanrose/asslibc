#define _GNU_SOURCE
#include "asslibc.h"

/* ---- OS entropy sources ----
 * getrandom(2) on Linux, getentropy(3) on macOS, fallback /dev/urandom.
 * Returns 0 on success, -1 when no OS entropy source is available. */
static int os_entropy(uint8_t *out, size_t len) {
#if defined(__linux__)
    {
        size_t got = 0;
        while (got < len) {
            ssize_t r = getrandom(out + got, len - got, 0);
            if (r < 0) {
                if (errno == EINTR) continue;
                break;
            }
            got += (size_t)r;
        }
        if (got == len) return 0;
    }
#elif defined(__APPLE__)
    if (len <= 256 && getentropy(out, len) == 0) return 0;
#endif
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) fd = open("/dev/random", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t got = 0;
    ssize_t r;
    while (got < len) {
        r = read(fd, out + got, len - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (r == 0) {
            close(fd);
            return -1;
        }
        got += (size_t)r;
    }
    close(fd);
    return 0;
}

#define ASSL_RNG_KEY_LEN    32
#define ASSL_RNG_NONCE_LEN  12
#define ASSL_RNG_BLOCK_LEN  64
#define ASSL_RNG_RESEED_BYTES ((uint32_t)1u << 20)  /* 1 MiB */

static uint8_t  rng_key[ASSL_RNG_KEY_LEN];
static uint8_t  rng_nonce[ASSL_RNG_NONCE_LEN];
static uint32_t rng_counter;
static int      rng_ready;
static int      rng_secure;      
static uint32_t rng_generated;   

static void rng_init_from_os(void) {
    uint8_t seed[ASSL_RNG_KEY_LEN + ASSL_RNG_NONCE_LEN];
    if (os_entropy(seed, sizeof seed)) return;
    memcpy(rng_key, seed, ASSL_RNG_KEY_LEN);
    memcpy(rng_nonce, seed + ASSL_RNG_KEY_LEN, ASSL_RNG_NONCE_LEN);
    rng_counter = 0;
    rng_ready = 1;
    rng_secure = 1;
    rng_generated = 0;
}

static void rng_reseed_os(void) {
    uint8_t seed[ASSL_RNG_KEY_LEN + ASSL_RNG_NONCE_LEN];
    if (os_entropy(seed, sizeof seed)) return;
    for (size_t i = 0; i < ASSL_RNG_KEY_LEN; i++) rng_key[i] ^= seed[i];
    for (size_t i = 0; i < ASSL_RNG_NONCE_LEN; i++) rng_nonce[i] ^= seed[ASSL_RNG_KEY_LEN + i];
    rng_counter = 0;
    rng_generated = 0;
}

static void rng_ensure(void) {
    if (rng_ready && rng_generated >= ASSL_RNG_RESEED_BYTES) {
        rng_reseed_os();
    } else if (!rng_ready) {
        rng_init_from_os();
    }
    if (!rng_ready) {
        static uint64_t lcg = 0x0ddc0ffee9c0c00fULL;
        lcg = lcg * 0x5851f42d4c957f2dULL + 0x14057b7ef767814fULL;
        for (size_t i = 0; i < ASSL_RNG_KEY_LEN; i++) {
            rng_key[i] = (uint8_t)((lcg >> (8 * (i & 7))));
            if (i == 15) lcg = lcg * 0x9e3779b97f4a7c15ULL + 1;
        }
        for (size_t i = 0; i < ASSL_RNG_NONCE_LEN; i++)
            rng_nonce[i] = (uint8_t)((lcg >> (8 * (i & 7))));
        rng_counter = (uint32_t)lcg;
        rng_ready = 1;
        rng_secure = 0;
        rng_generated = 0;
    }
    if (!rng_secure && rng_counter >= ASSL_RNG_RESEED_BYTES / ASSL_RNG_BLOCK_LEN)
        rng_init_from_os();
}

int assl_rng_is_secure(void) {
    rng_ensure();
    return rng_secure;
}

void assl_rng_bytes(uint8_t *out, size_t len) {
    if (!out) return;
    rng_ensure();
    while (len) {
        if (!rng_secure && rng_counter >= ASSL_RNG_RESEED_BYTES / ASSL_RNG_BLOCK_LEN)
            rng_init_from_os();
        uint8_t blk[ASSL_RNG_BLOCK_LEN];
        assl_chacha20_block(rng_key, rng_nonce, rng_counter++, blk);
        size_t t = len < ASSL_RNG_BLOCK_LEN ? len : ASSL_RNG_BLOCK_LEN;
        memcpy(out, blk, t);
        out += t;
        len -= t;
        rng_generated += (uint32_t)t;
    }
}

uint64_t assl_rng_next(void) {
    uint64_t v;
    assl_rng_bytes((uint8_t *)&v, sizeof v);
    return v;
}

void assl_rng_bytes_nonzero(uint8_t *out, size_t len) {
    uint8_t b;
    while (len) {
        do {
            assl_rng_bytes(&b, 1);
        } while (b == 0);
        *out++ = b;
        len--;
    }
}

void assl_rng_seed(uint64_t seed) {
    uint64_t z = seed + 0x9e3779b97f4a7c15ULL;
    size_t i = 0;
    for (i = 0; i < ASSL_RNG_KEY_LEN; i += 4) {
        z += 0x9e3779b97f4a7c15ULL;
        uint64_t x = z;
        x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
        x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
        uint32_t w = (uint32_t)(x ^ (x >> 31));
        rng_key[i + 0] = (uint8_t)(w >> 24);
        rng_key[i + 1] = (uint8_t)(w >> 16);
        rng_key[i + 2] = (uint8_t)(w >> 8);
        rng_key[i + 3] = (uint8_t)w;
    }
    for (i = 0; i < ASSL_RNG_NONCE_LEN; i += 4) {
        z += 0x9e3779b97f4a7c15ULL;
        uint64_t x = z;
        x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
        x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
        uint32_t w = (uint32_t)(x ^ (x >> 31));
        rng_nonce[i + 0] = (uint8_t)(w >> 24);
        rng_nonce[i + 1] = (uint8_t)(w >> 16);
        rng_nonce[i + 2] = (uint8_t)(w >> 8);
        rng_nonce[i + 3] = (uint8_t)w;
    }
    rng_counter = 0;
    rng_ready = 1;
    rng_secure = 0;
    rng_generated = 0;
}