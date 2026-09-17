#include "dilithium_wrapper.h"
#include "hybrid_sign.h"
#include "sm2_wrapper.h"

#include <stdio.h>
#include <stdlib.h>

#define CHECK(condition, text) do { \
    if (!(condition)) { fprintf(stderr, "FAIL: %s\n", text); goto done; } \
} while (0)

int main(void)
{
    static const unsigned char message[] = "same bytes for SM2 and Dilithium";
    uint8_t public_key[DILITHIUM_PUBLIC_KEY_BYTES];
    uint8_t secret_key[DILITHIUM_SECRET_KEY_BYTES];
    HYBRID_SIGNATURE signature;
    EVP_PKEY *sm2_key = NULL;
    int ok = EXIT_FAILURE;

    hybrid_signature_init(&signature);
    CHECK((sm2_key = sm2_generate_keypair()) != NULL, "SM2 keypair");
    CHECK(dilithium_generate_keypair(public_key, sizeof(public_key),
                                     secret_key, sizeof(secret_key)),
          "Dilithium keypair");
    CHECK(hybrid_sign(sm2_key, secret_key, sizeof(secret_key),
                      message, sizeof(message) - 1, &signature), "hybrid sign");
    CHECK(hybrid_verify(sm2_key, public_key, sizeof(public_key), message,
                        sizeof(message) - 1, &signature), "both valid");

    signature.sm2_signature[0] ^= 1u;
    CHECK(!hybrid_verify(sm2_key, public_key, sizeof(public_key), message,
                         sizeof(message) - 1, &signature), "SM2 fail + PQC OK");
    signature.sm2_signature[0] ^= 1u;
    signature.dilithium_signature[0] ^= 1u;
    CHECK(!hybrid_verify(sm2_key, public_key, sizeof(public_key), message,
                         sizeof(message) - 1, &signature), "SM2 OK + PQC fail");
    signature.sm2_signature[0] ^= 1u;
    CHECK(!hybrid_verify(sm2_key, public_key, sizeof(public_key), message,
                         sizeof(message) - 1, &signature), "both fail");
    puts("PASS: hybrid validity is strictly SM2Valid && DilithiumValid");
    ok = EXIT_SUCCESS;

done:
    hybrid_signature_cleanup(&signature);
    dilithium_clear_secret_key(secret_key, sizeof(secret_key));
    EVP_PKEY_free(sm2_key);
    return ok;
}
