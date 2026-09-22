#ifndef HYBRID_PQC_HYBRID_KEY_STORE_H
#define HYBRID_PQC_HYBRID_KEY_STORE_H

#include "composite_key.h"

#define HYBRID_SM2_PRIVATE_KEY_FILE "sm2_private.pem"
#define HYBRID_DILITHIUM_PRIVATE_KEY_FILE "dilithium2_private.enc"
#define HYBRID_KEY_STORE_PASSPHRASE_ENV "HYBRID_KEY_PASSPHRASE"

typedef enum {
    HYBRID_KEY_STORE_INCOMPLETE = -1,
    HYBRID_KEY_STORE_MISSING = 0,
    HYBRID_KEY_STORE_COMPLETE = 1
} HYBRID_KEY_STORE_STATUS;

HYBRID_KEY_STORE_STATUS hybrid_key_store_status(const char *directory);
HYBRID_KEY_STORE_STATUS hybrid_sm2_key_store_status(const char *directory);

int hybrid_key_store_save(const char *directory,
                          const HYBRID_PRIVATE_KEY *private_key,
                          const HYBRID_PUBLIC_KEY *public_key,
                          const char *passphrase);

int hybrid_key_store_load(const char *directory,
                          const char *passphrase,
                          HYBRID_PRIVATE_KEY *private_key,
                          HYBRID_PUBLIC_KEY *public_key);

int hybrid_sm2_key_store_save(const char *directory,
                              EVP_PKEY *private_key,
                              const char *passphrase);
EVP_PKEY *hybrid_sm2_key_store_load(const char *directory,
                                    const char *passphrase);

int composite_public_keys_equal(const HYBRID_PUBLIC_KEY *left,
                                const HYBRID_PUBLIC_KEY *right);

#endif
