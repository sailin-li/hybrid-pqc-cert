#ifndef HYBRID_PQC_COMPOSITE_KEY_H
#define HYBRID_PQC_COMPOSITE_KEY_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/evp.h>

#include "dilithium_wrapper.h"

#define SM2_UNCOMPRESSED_PUBLIC_KEY_BYTES 65u
#define COMPOSITE_PUBLIC_KEY_BYTES \
    (DILITHIUM_PUBLIC_KEY_BYTES + SM2_UNCOMPRESSED_PUBLIC_KEY_BYTES)

typedef struct {
    EVP_PKEY *sm2_private_key;
    uint8_t dilithium_secret_key[DILITHIUM_SECRET_KEY_BYTES];
} HYBRID_PRIVATE_KEY;

typedef struct {
    EVP_PKEY *sm2_public_key;
    uint8_t dilithium_public_key[DILITHIUM_PUBLIC_KEY_BYTES];
} HYBRID_PUBLIC_KEY;

void hybrid_private_key_init(HYBRID_PRIVATE_KEY *key);
void hybrid_private_key_cleanup(HYBRID_PRIVATE_KEY *key);
void hybrid_public_key_init(HYBRID_PUBLIC_KEY *key);
void hybrid_public_key_cleanup(HYBRID_PUBLIC_KEY *key);

int composite_key_generate(HYBRID_PRIVATE_KEY *private_key,
                           HYBRID_PUBLIC_KEY *public_key);

int composite_serialize_public_key(const HYBRID_PUBLIC_KEY *key,
                                   uint8_t **serialized,
                                   size_t *serialized_len);

int composite_parse_public_key(const uint8_t *serialized,
                               size_t serialized_len,
                               HYBRID_PUBLIC_KEY *key);

int composite_get_sm2_public_key_octets(
    const HYBRID_PUBLIC_KEY *key,
    uint8_t output[SM2_UNCOMPRESSED_PUBLIC_KEY_BYTES]);

#endif
