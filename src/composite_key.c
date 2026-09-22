#include "composite_key.h"

#include "sm2_wrapper.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>

#include <string.h>

void hybrid_private_key_init(HYBRID_PRIVATE_KEY *key)
{
    if (key != NULL) {
        memset(key, 0, sizeof(*key));
    }
}

void hybrid_private_key_cleanup(HYBRID_PRIVATE_KEY *key)
{
    if (key == NULL) {
        return;
    }
    EVP_PKEY_free(key->sm2_private_key);
    dilithium_clear_secret_key(key->dilithium_secret_key,
                               sizeof(key->dilithium_secret_key));
    hybrid_private_key_init(key);
}

void hybrid_public_key_init(HYBRID_PUBLIC_KEY *key)
{
    if (key != NULL) {
        memset(key, 0, sizeof(*key));
    }
}

void hybrid_public_key_cleanup(HYBRID_PUBLIC_KEY *key)
{
    if (key == NULL) {
        return;
    }
    EVP_PKEY_free(key->sm2_public_key);
    hybrid_public_key_init(key);
}

int composite_key_generate(HYBRID_PRIVATE_KEY *private_key,
                           HYBRID_PUBLIC_KEY *public_key)
{
    HYBRID_PRIVATE_KEY generated_private;
    HYBRID_PUBLIC_KEY generated_public;

    if (private_key == NULL || public_key == NULL) {
        return 0;
    }
    hybrid_private_key_init(&generated_private);
    hybrid_public_key_init(&generated_public);
    generated_private.sm2_private_key = hybrid_sm2_generate_keypair();
    if (generated_private.sm2_private_key == NULL ||
        !EVP_PKEY_up_ref(generated_private.sm2_private_key)) {
        goto error;
    }
    generated_public.sm2_public_key = generated_private.sm2_private_key;
    if (!dilithium_generate_keypair(generated_public.dilithium_public_key,
                                    sizeof(generated_public.dilithium_public_key),
                                    generated_private.dilithium_secret_key,
                                    sizeof(generated_private.dilithium_secret_key))) {
        goto error;
    }
    hybrid_private_key_cleanup(private_key);
    hybrid_public_key_cleanup(public_key);
    *private_key = generated_private;
    *public_key = generated_public;
    return 1;

error:
    hybrid_private_key_cleanup(&generated_private);
    hybrid_public_key_cleanup(&generated_public);
    return 0;
}

static int serialize_sm2_public_key(EVP_PKEY *key,
                                    uint8_t output[SM2_UNCOMPRESSED_PUBLIC_KEY_BYTES])
{
    size_t output_len = SM2_UNCOMPRESSED_PUBLIC_KEY_BYTES;

    if (key == NULL || !EVP_PKEY_is_a(key, "SM2") ||
        EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
                                        output, output_len,
                                        &output_len) <= 0 ||
        output_len != SM2_UNCOMPRESSED_PUBLIC_KEY_BYTES || output[0] != 0x04) {
        return 0;
    }
    return 1;
}

int composite_serialize_public_key(const HYBRID_PUBLIC_KEY *key,
                                   uint8_t **serialized,
                                   size_t *serialized_len)
{
    uint8_t *output;

    if (serialized == NULL || serialized_len == NULL) {
        return 0;
    }
    *serialized = NULL;
    *serialized_len = 0;
    if (key == NULL || key->sm2_public_key == NULL) {
        return 0;
    }
    output = OPENSSL_malloc(COMPOSITE_PUBLIC_KEY_BYTES);
    if (output == NULL) {
        return 0;
    }
    memcpy(output, key->dilithium_public_key, DILITHIUM_PUBLIC_KEY_BYTES);
    if (!serialize_sm2_public_key(key->sm2_public_key,
                                 output + DILITHIUM_PUBLIC_KEY_BYTES)) {
        OPENSSL_free(output);
        return 0;
    }
    *serialized = output;
    *serialized_len = COMPOSITE_PUBLIC_KEY_BYTES;
    return 1;
}

static EVP_PKEY *parse_sm2_public_key(const uint8_t *encoded,
                                      size_t encoded_len)
{
    EVP_PKEY_CTX *context = NULL;
    EVP_PKEY_CTX *check_context = NULL;
    EVP_PKEY *key = NULL;
    char group_name[] = "SM2";
    OSSL_PARAM params[3];

    if (encoded == NULL || encoded_len != SM2_UNCOMPRESSED_PUBLIC_KEY_BYTES ||
        encoded[0] != 0x04) {
        return NULL;
    }
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                  group_name, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                   (void *)encoded,
                                                   encoded_len);
    params[2] = OSSL_PARAM_construct_end();
    context = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
    if (context == NULL || EVP_PKEY_fromdata_init(context) <= 0 ||
        EVP_PKEY_fromdata(context, &key, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
        goto done;
    }
    check_context = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (check_context == NULL || EVP_PKEY_public_check(check_context) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }

done:
    EVP_PKEY_CTX_free(check_context);
    EVP_PKEY_CTX_free(context);
    return key;
}

int composite_parse_public_key(const uint8_t *serialized,
                               size_t serialized_len,
                               HYBRID_PUBLIC_KEY *key)
{
    HYBRID_PUBLIC_KEY parsed;

    if (serialized == NULL || key == NULL ||
        serialized_len != COMPOSITE_PUBLIC_KEY_BYTES) {
        return 0;
    }
    hybrid_public_key_init(&parsed);
    parsed.sm2_public_key =
        parse_sm2_public_key(serialized + DILITHIUM_PUBLIC_KEY_BYTES,
                             SM2_UNCOMPRESSED_PUBLIC_KEY_BYTES);
    if (parsed.sm2_public_key == NULL) {
        return 0;
    }
    memcpy(parsed.dilithium_public_key, serialized,
           DILITHIUM_PUBLIC_KEY_BYTES);
    hybrid_public_key_cleanup(key);
    *key = parsed;
    return 1;
}

int composite_get_sm2_public_key_octets(
    const HYBRID_PUBLIC_KEY *key,
    uint8_t output[SM2_UNCOMPRESSED_PUBLIC_KEY_BYTES])
{
    if (key == NULL || output == NULL) {
        return 0;
    }
    return serialize_sm2_public_key(key->sm2_public_key, output);
}
