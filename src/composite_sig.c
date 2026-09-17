#include "composite_sig.h"

#include "dilithium_wrapper.h"
#include "sm2_wrapper.h"

#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static int sm2_signature_der_is_valid(const uint8_t *der, size_t der_len)
{
    ECDSA_SIG *signature = NULL;
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;
    const unsigned char *cursor = der;
    unsigned char *canonical = NULL;
    int canonical_len;
    int valid = 0;

    if (der == NULL || der_len == 0 || der_len > LONG_MAX) {
        return 0;
    }
    signature = d2i_ECDSA_SIG(NULL, &cursor, (long)der_len);
    if (signature == NULL || cursor != der + der_len) {
        goto done;
    }
    ECDSA_SIG_get0(signature, &r, &s);
    if (r == NULL || s == NULL || BN_is_negative(r) || BN_is_zero(r) ||
        BN_is_negative(s) || BN_is_zero(s)) {
        goto done;
    }
    canonical_len = i2d_ECDSA_SIG(signature, &canonical);
    if (canonical_len <= 0 || (size_t)canonical_len != der_len ||
        CRYPTO_memcmp(canonical, der, der_len) != 0) {
        goto done;
    }
    valid = 1;

done:
    OPENSSL_free(canonical);
    ECDSA_SIG_free(signature);
    return valid;
}

int composite_build_message(const uint8_t *message, size_t message_len,
                            const uint8_t *ctx, size_t ctx_len,
                            uint8_t **m_prime, size_t *m_prime_len)
{
    static const uint8_t prefix[] = COMPOSITE_SIGNATURE_PREFIX;
    static const uint8_t label[] = COMPOSITE_SIGNATURE_LABEL;
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    uint8_t *output = NULL;
    size_t output_len;
    size_t offset = 0;

    if (m_prime == NULL || m_prime_len == NULL) {
        return 0;
    }
    *m_prime = NULL;
    *m_prime_len = 0;
    if ((message == NULL && message_len != 0) ||
        (ctx == NULL && ctx_len != 0) || ctx_len > COMPOSITE_MAX_CONTEXT_BYTES) {
        return 0;
    }
    if (!EVP_Digest(message, message_len, digest, &digest_len,
                    EVP_sm3(), NULL) || digest_len != 32u) {
        return 0;
    }
    if (ctx_len > SIZE_MAX - (sizeof(prefix) - 1u) - (sizeof(label) - 1u) -
                      1u - digest_len) {
        OPENSSL_cleanse(digest, sizeof(digest));
        return 0;
    }
    output_len = (sizeof(prefix) - 1u) + (sizeof(label) - 1u) + 1u +
                 ctx_len + digest_len;
    output = OPENSSL_malloc(output_len);
    if (output == NULL) {
        OPENSSL_cleanse(digest, sizeof(digest));
        return 0;
    }
    memcpy(output + offset, prefix, sizeof(prefix) - 1u);
    offset += sizeof(prefix) - 1u;
    memcpy(output + offset, label, sizeof(label) - 1u);
    offset += sizeof(label) - 1u;
    output[offset++] = (uint8_t)ctx_len;
    if (ctx_len != 0) {
        memcpy(output + offset, ctx, ctx_len);
        offset += ctx_len;
    }
    memcpy(output + offset, digest, digest_len);
    offset += digest_len;
    OPENSSL_cleanse(digest, sizeof(digest));
    if (offset != output_len) {
        OPENSSL_free(output);
        return 0;
    }
    *m_prime = output;
    *m_prime_len = output_len;
    return 1;
}

int composite_serialize_signature(const uint8_t *dilithium_signature,
                                  size_t dilithium_signature_len,
                                  const uint8_t *sm2_signature_der,
                                  size_t sm2_signature_der_len,
                                  uint8_t **signature,
                                  size_t *signature_len)
{
    uint8_t *output;

    if (signature == NULL || signature_len == NULL) {
        return 0;
    }
    *signature = NULL;
    *signature_len = 0;
    if (dilithium_signature == NULL ||
        dilithium_signature_len != DILITHIUM_SIGNATURE_BYTES ||
        !sm2_signature_der_is_valid(sm2_signature_der, sm2_signature_der_len) ||
        sm2_signature_der_len > SIZE_MAX - DILITHIUM_SIGNATURE_BYTES) {
        return 0;
    }
    output = OPENSSL_malloc(DILITHIUM_SIGNATURE_BYTES + sm2_signature_der_len);
    if (output == NULL) {
        return 0;
    }
    memcpy(output, dilithium_signature, DILITHIUM_SIGNATURE_BYTES);
    memcpy(output + DILITHIUM_SIGNATURE_BYTES, sm2_signature_der,
           sm2_signature_der_len);
    *signature = output;
    *signature_len = DILITHIUM_SIGNATURE_BYTES + sm2_signature_der_len;
    return 1;
}

int composite_parse_signature(const uint8_t *signature, size_t signature_len,
                              const uint8_t **dilithium_signature,
                              size_t *dilithium_signature_len,
                              const uint8_t **sm2_signature_der,
                              size_t *sm2_signature_der_len)
{
    size_t sm2_len;

    if (dilithium_signature == NULL || dilithium_signature_len == NULL ||
        sm2_signature_der == NULL || sm2_signature_der_len == NULL) {
        return 0;
    }
    *dilithium_signature = NULL;
    *dilithium_signature_len = 0;
    *sm2_signature_der = NULL;
    *sm2_signature_der_len = 0;
    if (signature == NULL || signature_len <= DILITHIUM_SIGNATURE_BYTES) {
        return 0;
    }
    sm2_len = signature_len - DILITHIUM_SIGNATURE_BYTES;
    if (!sm2_signature_der_is_valid(signature + DILITHIUM_SIGNATURE_BYTES,
                                    sm2_len)) {
        return 0;
    }
    *dilithium_signature = signature;
    *dilithium_signature_len = DILITHIUM_SIGNATURE_BYTES;
    *sm2_signature_der = signature + DILITHIUM_SIGNATURE_BYTES;
    *sm2_signature_der_len = sm2_len;
    return 1;
}

int composite_sign(const HYBRID_PRIVATE_KEY *key,
                   const uint8_t *message, size_t message_len,
                   const uint8_t *ctx, size_t ctx_len,
                   uint8_t **signature, size_t *signature_len)
{
    uint8_t *m_prime = NULL;
    size_t m_prime_len = 0;
    uint8_t *dilithium_signature = NULL;
    size_t dilithium_signature_len = 0;
    unsigned char *sm2_signature = NULL;
    size_t sm2_signature_len = 0;
    int ok = 0;

    if (signature == NULL || signature_len == NULL) {
        return 0;
    }
    *signature = NULL;
    *signature_len = 0;
    if (key == NULL || key->sm2_private_key == NULL ||
        !composite_build_message(message, message_len, ctx, ctx_len,
                                 &m_prime, &m_prime_len) ||
        !dilithium_sign(key->dilithium_secret_key,
                        sizeof(key->dilithium_secret_key),
                        m_prime, m_prime_len,
                        &dilithium_signature, &dilithium_signature_len) ||
        !sm2_sign(key->sm2_private_key, m_prime, m_prime_len,
                  &sm2_signature, &sm2_signature_len) ||
        !composite_serialize_signature(dilithium_signature,
                                       dilithium_signature_len,
                                       sm2_signature, sm2_signature_len,
                                       signature, signature_len)) {
        goto done;
    }
    ok = 1;

done:
    OPENSSL_clear_free(m_prime, m_prime_len);
    free(dilithium_signature);
    OPENSSL_free(sm2_signature);
    return ok;
}

int composite_verify_detailed(const HYBRID_PUBLIC_KEY *key,
                              const uint8_t *message, size_t message_len,
                              const uint8_t *ctx, size_t ctx_len,
                              const uint8_t *signature, size_t signature_len,
                              COMPOSITE_VERIFY_RESULT *result)
{
    COMPOSITE_VERIFY_RESULT local = {0};
    const uint8_t *dilithium_signature = NULL;
    size_t dilithium_signature_len = 0;
    const uint8_t *sm2_signature = NULL;
    size_t sm2_signature_len = 0;
    uint8_t *m_prime = NULL;
    size_t m_prime_len = 0;

    if (key == NULL || key->sm2_public_key == NULL ||
        !composite_parse_signature(signature, signature_len,
                                   &dilithium_signature,
                                   &dilithium_signature_len,
                                   &sm2_signature, &sm2_signature_len)) {
        goto done;
    }
    local.format_valid = 1;
    if (!composite_build_message(message, message_len, ctx, ctx_len,
                                 &m_prime, &m_prime_len)) {
        goto done;
    }
    local.dilithium_valid =
        dilithium_verify(key->dilithium_public_key,
                         sizeof(key->dilithium_public_key),
                         m_prime, m_prime_len,
                         dilithium_signature, dilithium_signature_len);
    local.sm2_valid = sm2_verify(key->sm2_public_key, m_prime, m_prime_len,
                                 sm2_signature, sm2_signature_len);
    local.composite_valid = local.dilithium_valid && local.sm2_valid;

done:
    OPENSSL_clear_free(m_prime, m_prime_len);
    if (result != NULL) {
        *result = local;
    }
    return local.composite_valid;
}

int composite_verify(const HYBRID_PUBLIC_KEY *key,
                     const uint8_t *message, size_t message_len,
                     const uint8_t *ctx, size_t ctx_len,
                     const uint8_t *signature, size_t signature_len)
{
    return composite_verify_detailed(key, message, message_len, ctx, ctx_len,
                                     signature, signature_len, NULL);
}
