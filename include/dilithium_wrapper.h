#ifndef HYBRID_PQC_DILITHIUM_WRAPPER_H
#define HYBRID_PQC_DILITHIUM_WRAPPER_H

#include <stddef.h>
#include <stdint.h>

#define DILITHIUM_PUBLIC_KEY_BYTES 1312u
#define DILITHIUM_SECRET_KEY_BYTES 2560u
#define DILITHIUM_SIGNATURE_BYTES 2420u

const char *dilithium_algorithm_name(void);

int dilithium_generate_keypair(uint8_t *public_key, size_t public_key_capacity,
                               uint8_t *secret_key, size_t secret_key_capacity);

int dilithium_sign(const uint8_t *secret_key, size_t secret_key_len,
                   const uint8_t *message, size_t message_len,
                   uint8_t **signature, size_t *signature_len);

int dilithium_verify(const uint8_t *public_key, size_t public_key_len,
                     const uint8_t *message, size_t message_len,
                     const uint8_t *signature, size_t signature_len);

void dilithium_clear_secret_key(uint8_t *secret_key, size_t secret_key_len);

#endif
