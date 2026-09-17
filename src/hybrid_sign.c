#include "hybrid_sign.h"

#include "composite_key.h"
#include "composite_sig.h"
#include "dilithium_wrapper.h"

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
    HYBRID_PRIVATE_KEY key;
    uint8_t *serialized = NULL;
    size_t serialized_len = 0;
    const uint8_t *dilithium_component = NULL;
    size_t dilithium_component_len = 0;
    const uint8_t *sm2_component = NULL;
    size_t sm2_component_len = 0;

    if (signature == NULL) {
        return 0;
    }
    hybrid_signature_cleanup(signature);
    hybrid_private_key_init(&key);
    if (sm2_private_key == NULL || dilithium_secret_key == NULL ||
        dilithium_secret_key_len != sizeof(key.dilithium_secret_key)) {
        goto error;
    }
    key.sm2_private_key = sm2_private_key;
    memcpy(key.dilithium_secret_key, dilithium_secret_key,
           sizeof(key.dilithium_secret_key));
    if (!composite_sign(&key, message, message_len, NULL, 0,
                        &serialized, &serialized_len) ||
        !composite_parse_signature(serialized, serialized_len,
                                   &dilithium_component,
                                   &dilithium_component_len,
                                   &sm2_component, &sm2_component_len)) {
        goto error;
    }
    signature->dilithium_signature = malloc(dilithium_component_len);
    signature->sm2_signature = OPENSSL_malloc(sm2_component_len);
    if (signature->dilithium_signature == NULL ||
        signature->sm2_signature == NULL) {
        goto error;
    }
    memcpy(signature->dilithium_signature, dilithium_component,
           dilithium_component_len);
    memcpy(signature->sm2_signature, sm2_component, sm2_component_len);
    signature->dilithium_signature_len = dilithium_component_len;
    signature->sm2_signature_len = sm2_component_len;
    OPENSSL_cleanse(key.dilithium_secret_key,
                    sizeof(key.dilithium_secret_key));
    OPENSSL_free(serialized);
    return 1;

error:
    OPENSSL_cleanse(key.dilithium_secret_key,
                    sizeof(key.dilithium_secret_key));
    OPENSSL_free(serialized);
    hybrid_signature_cleanup(signature);
    return 0;
}

int hybrid_verify(EVP_PKEY *sm2_public_key,
                  const uint8_t *dilithium_public_key,
                  size_t dilithium_public_key_len,
                  const unsigned char *message, size_t message_len,
                  const HYBRID_SIGNATURE *signature)
{
    HYBRID_PUBLIC_KEY key;
    uint8_t *serialized = NULL;
    size_t serialized_len = 0;
    int valid = 0;

    if (signature == NULL || sm2_public_key == NULL ||
        dilithium_public_key == NULL ||
        dilithium_public_key_len != DILITHIUM_PUBLIC_KEY_BYTES) {
        return 0;
    }
    hybrid_public_key_init(&key);
    key.sm2_public_key = sm2_public_key;
    memcpy(key.dilithium_public_key, dilithium_public_key,
           sizeof(key.dilithium_public_key));
    if (composite_serialize_signature(signature->dilithium_signature,
                                      signature->dilithium_signature_len,
                                      signature->sm2_signature,
                                      signature->sm2_signature_len,
                                      &serialized, &serialized_len)) {
        valid = composite_verify(&key, message, message_len, NULL, 0,
                                 serialized, serialized_len);
    }
    OPENSSL_free(serialized);
    return valid;
}
