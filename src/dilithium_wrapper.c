#include "dilithium_wrapper.h"

#include <openssl/crypto.h>

#include <stdlib.h>

#include "api.h"

_Static_assert(DILITHIUM_PUBLIC_KEY_BYTES == pqcrystals_dilithium2_ref_PUBLICKEYBYTES,
               "Dilithium2 public key size mismatch");
_Static_assert(DILITHIUM_SECRET_KEY_BYTES == pqcrystals_dilithium2_ref_SECRETKEYBYTES,
               "Dilithium2 secret key size mismatch");
_Static_assert(DILITHIUM_SIGNATURE_BYTES == pqcrystals_dilithium2_ref_BYTES,
               "Dilithium2 signature size mismatch");

const char *dilithium_algorithm_name(void)
{
    return "CRYSTALS-Dilithium2";
}

int dilithium_generate_keypair(uint8_t *public_key, size_t public_key_capacity,
                               uint8_t *secret_key, size_t secret_key_capacity)
{
    if (public_key == NULL || secret_key == NULL ||
        public_key_capacity < DILITHIUM_PUBLIC_KEY_BYTES ||
        secret_key_capacity < DILITHIUM_SECRET_KEY_BYTES) {
        return 0;
    }
    return pqcrystals_dilithium2_ref_keypair(public_key, secret_key) == 0;
}

int dilithium_sign(const uint8_t *secret_key, size_t secret_key_len,
                   const uint8_t *message, size_t message_len,
                   uint8_t **signature, size_t *signature_len)
{
    uint8_t *output;
    size_t output_len = 0;

    if (signature == NULL || signature_len == NULL) {
        return 0;
    }
    *signature = NULL;
    *signature_len = 0;
    if (secret_key == NULL || secret_key_len != DILITHIUM_SECRET_KEY_BYTES ||
        (message == NULL && message_len != 0)) {
        return 0;
    }

    output = malloc(DILITHIUM_SIGNATURE_BYTES);
    if (output == NULL) {
        return 0;
    }
    if (pqcrystals_dilithium2_ref_signature(output, &output_len,
                                             message, message_len,
                                             NULL, 0, secret_key) != 0 ||
        output_len != DILITHIUM_SIGNATURE_BYTES) {
        free(output);
        return 0;
    }
    *signature = output;
    *signature_len = output_len;
    return 1;
}

int dilithium_verify(const uint8_t *public_key, size_t public_key_len,
                     const uint8_t *message, size_t message_len,
                     const uint8_t *signature, size_t signature_len)
{
    if (public_key == NULL || public_key_len != DILITHIUM_PUBLIC_KEY_BYTES ||
        signature == NULL || signature_len != DILITHIUM_SIGNATURE_BYTES ||
        (message == NULL && message_len != 0)) {
        return 0;
    }
    return pqcrystals_dilithium2_ref_verify(signature, signature_len,
                                             message, message_len,
                                             NULL, 0, public_key) == 0;
}

void dilithium_clear_secret_key(uint8_t *secret_key, size_t secret_key_len)
{
    if (secret_key != NULL) {
        OPENSSL_cleanse(secret_key, secret_key_len);
    }
}
