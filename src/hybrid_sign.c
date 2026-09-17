#include "hybrid_sign.h"

#include "dilithium_wrapper.h"
#include "sm2_wrapper.h"

#include <openssl/crypto.h>

#include <stdlib.h>
#include <string.h>

void hybrid_signature_init(HYBRID_SIGNATURE *signature)
{
    if (signature != NULL) {
        memset(signature, 0, sizeof(*signature));
    }
}

void hybrid_signature_cleanup(HYBRID_SIGNATURE *signature)
{
    if (signature == NULL) {
        return;
    }
    OPENSSL_free(signature->sm2_signature);
    free(signature->dilithium_signature);
    hybrid_signature_init(signature);
}

int hybrid_sign(EVP_PKEY *sm2_private_key,
                const uint8_t *dilithium_secret_key,
                size_t dilithium_secret_key_len,
                const unsigned char *message, size_t message_len,
                HYBRID_SIGNATURE *signature)
{
    if (signature == NULL) {
        return 0;
    }
    hybrid_signature_cleanup(signature);
    if (!sm2_sign(sm2_private_key, message, message_len,
                  &signature->sm2_signature,
                  &signature->sm2_signature_len) ||
        !dilithium_sign(dilithium_secret_key, dilithium_secret_key_len,
                        message, message_len,
                        &signature->dilithium_signature,
                        &signature->dilithium_signature_len)) {
        hybrid_signature_cleanup(signature);
        return 0;
    }
    return 1;
}

int hybrid_verify(EVP_PKEY *sm2_public_key,
                  const uint8_t *dilithium_public_key,
                  size_t dilithium_public_key_len,
                  const unsigned char *message, size_t message_len,
                  const HYBRID_SIGNATURE *signature)
{
    int sm2_valid;
    int dilithium_valid;

    if (signature == NULL) {
        return 0;
    }
    sm2_valid = sm2_verify(sm2_public_key, message, message_len,
                           signature->sm2_signature,
                           signature->sm2_signature_len);
    dilithium_valid = dilithium_verify(dilithium_public_key,
                                       dilithium_public_key_len,
                                       message, message_len,
                                       signature->dilithium_signature,
                                       signature->dilithium_signature_len);
    return sm2_valid && dilithium_valid;
}
