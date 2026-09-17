#ifndef HYBRID_PQC_HYBRID_SIGN_H
#define HYBRID_PQC_HYBRID_SIGN_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/evp.h>

typedef struct {
    unsigned char *sm2_signature;
    size_t sm2_signature_len;
    uint8_t *dilithium_signature;
    size_t dilithium_signature_len;
} HYBRID_SIGNATURE;

void hybrid_signature_init(HYBRID_SIGNATURE *signature);
void hybrid_signature_cleanup(HYBRID_SIGNATURE *signature);

int hybrid_sign(EVP_PKEY *sm2_private_key,
                const uint8_t *dilithium_secret_key,
                size_t dilithium_secret_key_len,
                const unsigned char *message, size_t message_len,
                HYBRID_SIGNATURE *signature);

int hybrid_verify(EVP_PKEY *sm2_public_key,
                  const uint8_t *dilithium_public_key,
                  size_t dilithium_public_key_len,
                  const unsigned char *message, size_t message_len,
                  const HYBRID_SIGNATURE *signature);

#endif
