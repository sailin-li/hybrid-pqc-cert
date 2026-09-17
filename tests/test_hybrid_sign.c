#include "composite_key.h"
#include "composite_sig.h"
#include "dilithium_wrapper.h"

#include <openssl/crypto.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition, text) do { \
    if (!(condition)) { fprintf(stderr, "FAIL: %s\n", text); goto done; } \
} while (0)

int main(void)
{
    static const uint8_t message[] = "hello composite signature";
    uint8_t changed_message[sizeof(message) - 1u];
    HYBRID_PRIVATE_KEY private_key;
    HYBRID_PUBLIC_KEY public_key;
    uint8_t *signature = NULL;
    uint8_t *changed_signature = NULL;
    size_t signature_len = 0;
    COMPOSITE_VERIFY_RESULT result;
    int ok = EXIT_FAILURE;

    hybrid_private_key_init(&private_key);
    hybrid_public_key_init(&public_key);
    CHECK(composite_key_generate(&private_key, &public_key), "key generation");
    CHECK(composite_sign(&private_key, message, sizeof(message) - 1u,
                         NULL, 0, &signature, &signature_len), "sign");
    CHECK(signature_len > DILITHIUM_SIGNATURE_BYTES,
          "composite signature length");
    CHECK(composite_verify(&public_key, message, sizeof(message) - 1u,
                           NULL, 0, signature, signature_len),
          "1: original message");
    puts("PASS 1: original message -> VALID");

    memcpy(changed_message, message, sizeof(changed_message));
    changed_message[0] ^= 1u;
    CHECK(!composite_verify(&public_key, changed_message,
                            sizeof(changed_message), NULL, 0,
                            signature, signature_len),
          "2: changed message accepted");
    puts("PASS 2: changed message byte -> INVALID");

    changed_signature = OPENSSL_memdup(signature, signature_len);
    CHECK(changed_signature != NULL, "signature copy");
    changed_signature[0] ^= 1u;
    CHECK(!composite_verify_detailed(&public_key, message,
                                     sizeof(message) - 1u, NULL, 0,
                                     changed_signature, signature_len,
                                     &result) &&
          !result.dilithium_valid && result.sm2_valid,
          "3: changed Dilithium component accepted");
    puts("PASS 3: changed Dilithium signature byte -> INVALID");

    memcpy(changed_signature, signature, signature_len);
    changed_signature[signature_len - 1u] ^= 1u;
    CHECK(!composite_verify(&public_key, message, sizeof(message) - 1u,
                            NULL, 0, changed_signature, signature_len),
          "4: changed SM2 component accepted");
    puts("PASS 4: changed SM2 signature byte -> INVALID");

    CHECK(!composite_verify(&public_key, message, sizeof(message) - 1u,
                            NULL, 0, signature, signature_len - 1u),
          "5: truncated signature accepted");
    puts("PASS 5: truncated composite signature -> INVALID");

    puts("PASS: Composite Signature Core uses strict Dilithium && SM2");
    ok = EXIT_SUCCESS;

done:
    OPENSSL_free(changed_signature);
    OPENSSL_free(signature);
    hybrid_public_key_cleanup(&public_key);
    hybrid_private_key_cleanup(&private_key);
    return ok;
}
