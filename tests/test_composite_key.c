#include "composite_key.h"
#include "composite_sig.h"

#include <openssl/crypto.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition, text) do { \
    if (!(condition)) { fprintf(stderr, "FAIL: %s\n", text); goto done; } \
} while (0)

int main(void)
{
    static const uint8_t message[] = "composite key round trip";
    HYBRID_PRIVATE_KEY private_key;
    HYBRID_PUBLIC_KEY public_key;
    HYBRID_PUBLIC_KEY parsed_key;
    uint8_t *serialized = NULL;
    uint8_t *signature = NULL;
    size_t serialized_len = 0;
    size_t signature_len = 0;
    int ok = EXIT_FAILURE;

    hybrid_private_key_init(&private_key);
    hybrid_public_key_init(&public_key);
    hybrid_public_key_init(&parsed_key);
    CHECK(composite_key_generate(&private_key, &public_key), "key generation");
    CHECK(composite_serialize_public_key(&public_key,
                                         &serialized, &serialized_len),
          "public key serialization");
    CHECK(serialized_len == COMPOSITE_PUBLIC_KEY_BYTES,
          "serialized public key length");
    CHECK(serialized[DILITHIUM_PUBLIC_KEY_BYTES] == 0x04,
          "SM2 point is not uncompressed");
    CHECK(memcmp(serialized, public_key.dilithium_public_key,
                 DILITHIUM_PUBLIC_KEY_BYTES) == 0,
          "Dilithium component is not first");
    CHECK(composite_parse_public_key(serialized, serialized_len, &parsed_key),
          "public key parse");
    CHECK(composite_sign(&private_key, message, sizeof(message) - 1u,
                         NULL, 0, &signature, &signature_len), "sign");
    CHECK(composite_verify(&parsed_key, message, sizeof(message) - 1u,
                           NULL, 0, signature, signature_len),
          "parsed key verification");

    serialized[DILITHIUM_PUBLIC_KEY_BYTES] = 0x02;
    CHECK(!composite_parse_public_key(serialized, serialized_len, &parsed_key),
          "compressed SM2 point accepted");
    serialized[DILITHIUM_PUBLIC_KEY_BYTES] = 0x04;
    memset(serialized + DILITHIUM_PUBLIC_KEY_BYTES + 1u, 0,
           SM2_UNCOMPRESSED_PUBLIC_KEY_BYTES - 1u);
    CHECK(!composite_parse_public_key(serialized, serialized_len, &parsed_key),
          "off-curve SM2 point accepted");
    CHECK(!composite_parse_public_key(serialized, serialized_len - 1u,
                                      &parsed_key),
          "short composite key accepted");

    puts("PASS: CompositePublicKey = Dilithium2 PK || validated SM2 point");
    ok = EXIT_SUCCESS;

done:
    OPENSSL_free(signature);
    OPENSSL_free(serialized);
    hybrid_public_key_cleanup(&parsed_key);
    hybrid_public_key_cleanup(&public_key);
    hybrid_private_key_cleanup(&private_key);
    return ok;
}
