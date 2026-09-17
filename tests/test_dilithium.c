#include "dilithium_wrapper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition, text) do { \
    if (!(condition)) { fprintf(stderr, "FAIL: %s\n", text); goto done; } \
} while (0)

int main(void)
{
    static const uint8_t message[] = "standalone Dilithium wrapper test";
    uint8_t public_key[DILITHIUM_PUBLIC_KEY_BYTES];
    uint8_t secret_key[DILITHIUM_SECRET_KEY_BYTES];
    uint8_t wrong_public_key[DILITHIUM_PUBLIC_KEY_BYTES];
    uint8_t wrong_secret_key[DILITHIUM_SECRET_KEY_BYTES];
    uint8_t changed_message[sizeof(message)];
    uint8_t *signature = NULL;
    size_t signature_len = 0;
    int ok = EXIT_FAILURE;

    CHECK(dilithium_generate_keypair(public_key, sizeof(public_key),
                                     secret_key, sizeof(secret_key)), "keypair");
    CHECK(dilithium_generate_keypair(wrong_public_key, sizeof(wrong_public_key),
                                     wrong_secret_key, sizeof(wrong_secret_key)),
          "wrong keypair");
    CHECK(dilithium_sign(secret_key, sizeof(secret_key), message,
                         sizeof(message) - 1, &signature, &signature_len), "sign");
    CHECK(dilithium_verify(public_key, sizeof(public_key), message,
                           sizeof(message) - 1, signature, signature_len),
          "valid signature rejected");

    memcpy(changed_message, message, sizeof(message));
    changed_message[0] ^= 1u;
    CHECK(!dilithium_verify(public_key, sizeof(public_key), changed_message,
                            sizeof(message) - 1, signature, signature_len),
          "modified message accepted");
    signature[0] ^= 1u;
    CHECK(!dilithium_verify(public_key, sizeof(public_key), message,
                            sizeof(message) - 1, signature, signature_len),
          "modified signature accepted");
    signature[0] ^= 1u;
    CHECK(!dilithium_verify(wrong_public_key, sizeof(wrong_public_key), message,
                            sizeof(message) - 1, signature, signature_len),
          "wrong public key accepted");
    printf("PASS: standalone %s sign/verify and negative tests\n",
           dilithium_algorithm_name());
    ok = EXIT_SUCCESS;

done:
    free(signature);
    dilithium_clear_secret_key(secret_key, sizeof(secret_key));
    dilithium_clear_secret_key(wrong_secret_key, sizeof(wrong_secret_key));
    return ok;
}
