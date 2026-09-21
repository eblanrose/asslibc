#ifndef RSA_KEYGEN_H
#define RSA_KEYGEN_H

#include "asslibc.h"

int assl_bn_is_prime(const assl_bn *n, int confidence);

int assl_rsa_keygen(assl_rsa_key *k, unsigned bits);

#endif
