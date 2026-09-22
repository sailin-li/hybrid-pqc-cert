#include "sm2_wrapper.h"

#include <openssl/crypto.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition, text) do { \
    if (!(condition)) { fprintf(stderr, "FAIL: %s\n", text); goto done; } \
} while (0)

int main(void)
{
    static const unsigned char message[] = "standalone SM2 wrapper test";
    unsigned char changed_message[sizeof(message)];
    EVP_PKEY *key = NULL;
    EVP_PKEY *wrong_key = NULL;
    unsigned char *signature = NULL;
    size_t signature_len = 0;
    int ok = EXIT_FAILURE;

    CHECK((key = hybrid_sm2_generate_keypair()) != NULL, "keypair");
    CHECK((wrong_key = hybrid_sm2_generate_keypair()) != NULL, "wrong keypair");
    CHECK(hybrid_sm2_sign(key, message, sizeof(message) - 1,
                          &signature, &signature_len), "sign");
    CHECK(hybrid_sm2_verify(key, message, sizeof(message) - 1,
                            signature, signature_len), "valid signature rejected");
    memcpy(changed_message, message, sizeof(message));
    changed_message[0] ^= 1u;
    CHECK(!hybrid_sm2_verify(key, changed_message, sizeof(message) - 1,
                             signature, signature_len), "modified message accepted");
    signature[signature_len - 1] ^= 1u;
    CHECK(!hybrid_sm2_verify(key, message, sizeof(message) - 1,
                             signature, signature_len), "modified signature accepted");
    signature[signature_len - 1] ^= 1u;
    CHECK(!hybrid_sm2_verify(wrong_key, message, sizeof(message) - 1,
                             signature, signature_len), "wrong public key accepted");
    puts("PASS: standalone OpenSSL EVP SM2 sign/verify and negative tests");
    ok = EXIT_SUCCESS;

done:
    OPENSSL_free(signature);
    EVP_PKEY_free(wrong_key);
    EVP_PKEY_free(key);
    return ok;
}
