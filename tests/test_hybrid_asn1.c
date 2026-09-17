#include "dilithium_wrapper.h"
#include "hybrid_asn1.h"
#include "hybrid_sign.h"
#include "sm2_wrapper.h"

#include <openssl/crypto.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition, text) do { \
    if (!(condition)) { fprintf(stderr, "FAIL: %s\n", text); goto done; } \
} while (0)

static int decode_must_fail(const unsigned char *der, size_t der_len)
{
    HYBRID_SIGNATURE decoded;
    int rejected;

    hybrid_signature_init(&decoded);
    rejected = !hybrid_signature_decode_der(der, der_len, &decoded);
    hybrid_signature_cleanup(&decoded);
    return rejected;
}

int main(void)
{
    static const unsigned char message[] = "hybrid ASN.1 round trip";
    uint8_t public_key[DILITHIUM_PUBLIC_KEY_BYTES];
    uint8_t secret_key[DILITHIUM_SECRET_KEY_BYTES];
    HYBRID_SIGNATURE signature;
    HYBRID_SIGNATURE decoded;
    EVP_PKEY *sm2_key = NULL;
    unsigned char *der1 = NULL;
    unsigned char *der2 = NULL;
    unsigned char *malformed = NULL;
    size_t der1_len = 0;
    size_t der2_len = 0;
    int ok = EXIT_FAILURE;

    hybrid_signature_init(&signature);
    hybrid_signature_init(&decoded);
    CHECK((sm2_key = sm2_generate_keypair()) != NULL, "SM2 keypair");
    CHECK(dilithium_generate_keypair(public_key, sizeof(public_key),
                                     secret_key, sizeof(secret_key)),
          "Dilithium keypair");
    CHECK(hybrid_sign(sm2_key, secret_key, sizeof(secret_key), message,
                      sizeof(message) - 1, &signature), "hybrid sign");
    CHECK(hybrid_signature_encode_der(&signature, &der1, &der1_len), "encode");
    CHECK(hybrid_signature_decode_der(der1, der1_len, &decoded), "decode");
    CHECK(hybrid_signature_encode_der(&decoded, &der2, &der2_len), "re-encode");
    CHECK(der1_len == der2_len && memcmp(der1, der2, der1_len) == 0,
          "DER round trip differs");
    CHECK(hybrid_verify(sm2_key, public_key, sizeof(public_key), message,
                        sizeof(message) - 1, &decoded), "decoded signature invalid");

    CHECK(decode_must_fail(der1, der1_len - 1), "truncated DER accepted");
    malformed = OPENSSL_malloc(der1_len + 1);
    CHECK(malformed != NULL, "malformed allocation");
    memcpy(malformed, der1, der1_len);
    malformed[der1_len] = 0;
    CHECK(decode_must_fail(malformed, der1_len + 1), "trailing byte accepted");
    memcpy(malformed, der1, der1_len);
    malformed[0] = 0x31;
    CHECK(decode_must_fail(malformed, der1_len), "wrong tag accepted");
    memcpy(malformed, der1, der1_len);
    malformed[1] = 0xff;
    CHECK(decode_must_fail(malformed, der1_len), "wrong length accepted");

    puts("PASS: HybridSignature DER is canonical and malformed DER is rejected");
    ok = EXIT_SUCCESS;

done:
    OPENSSL_free(malformed);
    OPENSSL_free(der2);
    OPENSSL_free(der1);
    hybrid_signature_cleanup(&decoded);
    hybrid_signature_cleanup(&signature);
    dilithium_clear_secret_key(secret_key, sizeof(secret_key));
    EVP_PKEY_free(sm2_key);
    return ok;
}
