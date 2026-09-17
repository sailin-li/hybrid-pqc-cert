#include "hybrid_asn1.h"

#include "dilithium_wrapper.h"

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crypto.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    ASN1_INTEGER *version;
    ASN1_OCTET_STRING *sm2_signature;
    ASN1_OCTET_STRING *dilithium_signature;
} HYBRID_SIGNATURE_ASN1;

ASN1_SEQUENCE(HYBRID_SIGNATURE_ASN1) = {
    ASN1_SIMPLE(HYBRID_SIGNATURE_ASN1, version, ASN1_INTEGER),
    ASN1_SIMPLE(HYBRID_SIGNATURE_ASN1, sm2_signature, ASN1_OCTET_STRING),
    ASN1_SIMPLE(HYBRID_SIGNATURE_ASN1, dilithium_signature, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(HYBRID_SIGNATURE_ASN1)

IMPLEMENT_ASN1_FUNCTIONS(HYBRID_SIGNATURE_ASN1)

int hybrid_signature_encode_der(const HYBRID_SIGNATURE *signature,
                                unsigned char **der, size_t *der_len)
{
    HYBRID_SIGNATURE_ASN1 *value = NULL;
    unsigned char *output = NULL;
    int encoded_len;
    int ok = 0;

    if (der == NULL || der_len == NULL) {
        return 0;
    }
    *der = NULL;
    *der_len = 0;
    if (signature == NULL || signature->sm2_signature == NULL ||
        signature->sm2_signature_len == 0 ||
        signature->sm2_signature_len > INT_MAX ||
        signature->dilithium_signature == NULL ||
        signature->dilithium_signature_len != DILITHIUM_SIGNATURE_BYTES) {
        return 0;
    }

    value = HYBRID_SIGNATURE_ASN1_new();
    if (value == NULL ||
        !ASN1_INTEGER_set(value->version, HYBRID_SIGNATURE_VERSION) ||
        !ASN1_OCTET_STRING_set(value->sm2_signature,
                               signature->sm2_signature,
                               (int)signature->sm2_signature_len) ||
        !ASN1_OCTET_STRING_set(value->dilithium_signature,
                               signature->dilithium_signature,
                               (int)signature->dilithium_signature_len)) {
        goto done;
    }
    encoded_len = i2d_HYBRID_SIGNATURE_ASN1(value, &output);
    if (encoded_len <= 0) {
        goto done;
    }
    *der = output;
    *der_len = (size_t)encoded_len;
    output = NULL;
    ok = 1;

done:
    OPENSSL_free(output);
    HYBRID_SIGNATURE_ASN1_free(value);
    return ok;
}

int hybrid_signature_decode_der(const unsigned char *der, size_t der_len,
                                HYBRID_SIGNATURE *signature)
{
    HYBRID_SIGNATURE_ASN1 *value = NULL;
    HYBRID_SIGNATURE decoded;
    const unsigned char *cursor = der;
    int sm2_len;
    int dilithium_len;
    int ok = 0;

    if (der == NULL || der_len == 0 || der_len > LONG_MAX || signature == NULL) {
        return 0;
    }
    hybrid_signature_init(&decoded);
    value = d2i_HYBRID_SIGNATURE_ASN1(NULL, &cursor, (long)der_len);
    if (value == NULL || cursor != der + der_len ||
        ASN1_INTEGER_get(value->version) != HYBRID_SIGNATURE_VERSION) {
        goto done;
    }
    sm2_len = ASN1_STRING_length(value->sm2_signature);
    dilithium_len = ASN1_STRING_length(value->dilithium_signature);
    if (sm2_len <= 0 || dilithium_len != (int)DILITHIUM_SIGNATURE_BYTES) {
        goto done;
    }
    decoded.sm2_signature = OPENSSL_malloc((size_t)sm2_len);
    decoded.dilithium_signature = malloc((size_t)dilithium_len);
    if (decoded.sm2_signature == NULL || decoded.dilithium_signature == NULL) {
        goto done;
    }
    memcpy(decoded.sm2_signature,
           ASN1_STRING_get0_data(value->sm2_signature), (size_t)sm2_len);
    memcpy(decoded.dilithium_signature,
           ASN1_STRING_get0_data(value->dilithium_signature),
           (size_t)dilithium_len);
    decoded.sm2_signature_len = (size_t)sm2_len;
    decoded.dilithium_signature_len = (size_t)dilithium_len;

    hybrid_signature_cleanup(signature);
    *signature = decoded;
    hybrid_signature_init(&decoded);
    ok = 1;

done:
    hybrid_signature_cleanup(&decoded);
    HYBRID_SIGNATURE_ASN1_free(value);
    return ok;
}
