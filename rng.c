#include "asslibc.h"
#include <pthread.h>

/* ---- OS entropy sources ----
 * Uses POSIX getentropy() where available, then falls back to reading
 * /dev/urandom (and /dev/random as a last resort).  Returns 0 on success,
 * -1 when no OS entropy source is available. */
static int os_entropy(uint8_t *out, size_t len) {
#if ASSL_HAVE_GETENTROPY
    {
        size_t got = 0;
        while (got < len) {
            size_t chunk = len - got;
            if (chunk > 256) chunk = 256;
            if (getentropy(out + got, chunk) != 0) break;
            got += chunk;
        }
        if (got == len) return 0;
    }
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

static pthread_mutex_t rng_lock = PTHREAD_MUTEX_INITIALIZER;

static int rng_init_from_os(void) {
    uint8_t seed[ASSL_RNG_KEY_LEN + ASSL_RNG_NONCE_LEN];
    if (os_entropy(seed, sizeof seed)) {
        rng_secure = 0;
        return -1;
    }
    if (rng_ready) {
        for (size_t i = 0; i < ASSL_RNG_KEY_LEN; i++) rng_key[i] ^= seed[i];
        for (size_t i = 0; i < ASSL_RNG_NONCE_LEN; i++) rng_nonce[i] ^= seed[ASSL_RNG_KEY_LEN + i];
    } else {
        memcpy(rng_key, seed, ASSL_RNG_KEY_LEN);
        memcpy(rng_nonce, seed + ASSL_RNG_KEY_LEN, ASSL_RNG_NONCE_LEN);
    }
    assl_memzero(seed, sizeof seed);
    rng_counter = 0;
    rng_ready = 1;
    rng_secure = 1;
    rng_generated = 0;
    return 0;
}

static void rng_ensure(void) {
    if (!rng_ready) {
        rng_init_from_os();
        return;
    }
    if (!rng_secure) {
        rng_init_from_os();
        return;
    }
    if (rng_generated >= ASSL_RNG_RESEED_BYTES)
        rng_init_from_os();
}

static int rng_usable(void) {
    rng_ensure();
    return rng_secure;
}

int assl_rng_is_secure(void) {
    pthread_mutex_lock(&rng_lock);
    int s = rng_usable();
    pthread_mutex_unlock(&rng_lock);
    return s;
}

int assl_rng_bytes_checked(uint8_t *out, size_t len) {
    if (!out) return -1;
    pthread_mutex_lock(&rng_lock);
    if (!rng_usable()) {
        memset(out, 0, len);
        pthread_mutex_unlock(&rng_lock);
        return -1;
    }
    while (len) {
        uint8_t blk[ASSL_RNG_BLOCK_LEN];
        assl_chacha20_block(rng_key, rng_nonce, rng_counter++, blk);
        size_t t = len < ASSL_RNG_BLOCK_LEN ? len : ASSL_RNG_BLOCK_LEN;
        memcpy(out, blk, t);
        out += t;
        len -= t;
        rng_generated += (uint32_t)t;
        assl_memzero(blk, sizeof blk);
    }
    pthread_mutex_unlock(&rng_lock);
    return 0;
}

void assl_rng_bytes(uint8_t *out, size_t len) {
    (void)assl_rng_bytes_checked(out, len);
}

uint64_t assl_rng_next(void) {
    uint64_t v;
    assl_rng_bytes((uint8_t *)&v, sizeof v);
    return v;
}

int assl_rng_bytes_nonzero(uint8_t *out, size_t len) {
    if (!out) return -1;
    uint8_t b;
    while (len) {
        do {
            if (assl_rng_bytes_checked(&b, 1)) { memset(out, 0, len); return -1; }
        } while (b == 0);
        *out++ = b;
        len--;
    }
    return 0;
}

void assl_rng_seed(uint64_t seed) {
    pthread_mutex_lock(&rng_lock);
    uint8_t kseed[ASSL_RNG_KEY_LEN + ASSL_RNG_NONCE_LEN];
    uint64_t z = seed + 0x9e3779b97f4a7c15ULL;
    size_t i = 0;
    for (i = 0; i < ASSL_RNG_KEY_LEN; i += 4) {
        z += 0x9e3779b97f4a7c15ULL;
        uint64_t x = z;
        x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
        x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
        uint32_t w = (uint32_t)(x ^ (x >> 31));
        kseed[i + 0] = (uint8_t)(w >> 24);
        kseed[i + 1] = (uint8_t)(w >> 16);
        kseed[i + 2] = (uint8_t)(w >> 8);
        kseed[i + 3] = (uint8_t)w;
    }
    for (i = 0; i < ASSL_RNG_NONCE_LEN; i += 4) {
        z += 0x9e3779b97f4a7c15ULL;
        uint64_t x = z;
        x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
        x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
        uint32_t w = (uint32_t)(x ^ (x >> 31));
        kseed[ASSL_RNG_KEY_LEN + i + 0] = (uint8_t)(w >> 24);
        kseed[ASSL_RNG_KEY_LEN + i + 1] = (uint8_t)(w >> 16);
        kseed[ASSL_RNG_KEY_LEN + i + 2] = (uint8_t)(w >> 8);
        kseed[ASSL_RNG_KEY_LEN + i + 3] = (uint8_t)w;
    }
    if (rng_ready) {
        for (i = 0; i < ASSL_RNG_KEY_LEN; i++) rng_key[i] ^= kseed[i];
        for (i = 0; i < ASSL_RNG_NONCE_LEN; i++) rng_nonce[i] ^= kseed[ASSL_RNG_KEY_LEN + i];
    } else {
        memcpy(rng_key, kseed, ASSL_RNG_KEY_LEN);
        memcpy(rng_nonce, kseed + ASSL_RNG_KEY_LEN, ASSL_RNG_NONCE_LEN);
        rng_ready = 1;
    }
    assl_memzero(kseed, sizeof kseed);
    rng_counter = 0;
    rng_generated = 0;
    /* Immediately (re)establish security from the OS.  If no OS entropy is
     * available the generator stays un-secure and rng_ensure() keeps retrying,
     * so a seeded generator never remains permanently insecure. */
    rng_init_from_os();
    pthread_mutex_unlock(&rng_lock);
}