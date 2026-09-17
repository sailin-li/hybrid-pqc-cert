#ifndef HYBRID_PQC_SM2_WRAPPER_H
#define HYBRID_PQC_SM2_WRAPPER_H

#include <stddef.h>

#include <openssl/evp.h>

#define SM2_DEFAULT_USER_ID "1234567812345678"

EVP_PKEY *sm2_generate_keypair(void);

int sm2_sign(EVP_PKEY *private_key,
             const unsigned char *message, size_t message_len,
             unsigned char **signature, size_t *signature_len);

int sm2_verify(EVP_PKEY *public_key,
               const unsigned char *message, size_t message_len,
               const unsigned char *signature, size_t signature_len);

#endif
