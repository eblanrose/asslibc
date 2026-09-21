
#include "x509.h"

#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    size_t cap = size;
    if (cap > 65536) cap = 65536;
    assl_x509_cert cert;
    if (assl_x509_parse(&cert, data, cap)) return 0;
    assl_x509_verify_self(&cert);
    assl_x509_dn_raw_eq(&cert.subject, &cert.issuer);
    assl_x509_check_hostname(&cert, "");
    assl_x509_free(&cert);
    return 0;
}

#ifdef ASSL_FUZZ_STANDALONE
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s FILE [FILE...]\n", argv[0]);
        return 2;
    }
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) { perror(argv[i]); return 2; }
        static uint8_t buf[1 << 20];
        size_t got = fread(buf, 1, sizeof buf, f);
        fclose(f);
        LLVMFuzzerTestOneInput(buf, got);
        printf("ok: %s\n", argv[i]);
    }
    return 0;
}
#endif