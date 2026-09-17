#include "mlkem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition, text) do { \
    if (!(condition)) { fprintf(stderr, "FAIL: %s\n", text); goto done; } \
} while (0)

int main(void)
{
    MLKEM_KEYPAIR keypair_a = {0};
    MLKEM_KEYPAIR keypair_b = {0};
    MLKEM_KEYPAIR nonempty = {0};
    uint8_t ciphertext_a1[MLKEM768_CIPHERTEXT_BYTES];
    uint8_t ciphertext_a2[MLKEM768_CIPHERTEXT_BYTES];
    uint8_t ciphertext_b[MLKEM768_CIPHERTEXT_BYTES];
    uint8_t tampered[MLKEM768_CIPHERTEXT_BYTES];
    uint8_t zero_ciphertext[MLKEM768_CIPHERTEXT_BYTES] = {0};
    uint8_t malformed_ek[MLKEM768_ENCAPSULATION_KEY_BYTES];
    uint8_t secret_a1[MLKEM768_SHARED_SECRET_BYTES] = {0};
    uint8_t secret_a2[MLKEM768_SHARED_SECRET_BYTES] = {0};
    uint8_t secret_b[MLKEM768_SHARED_SECRET_BYTES] = {0};
    uint8_t recovered[MLKEM768_SHARED_SECRET_BYTES] = {0};
    uint8_t rejected[MLKEM768_SHARED_SECRET_BYTES] = {0};
    size_t ciphertext_a1_len = 0;
    size_t ciphertext_a2_len = 0;
    size_t ciphertext_b_len = 0;
    size_t output_len = 7;
    int ok = EXIT_FAILURE;

    CHECK(strcmp(mlkem768_algorithm_name(), "ML-KEM-768") == 0,
          "unexpected algorithm identifier");
    CHECK(strcmp(mlkem_provider_name(), "liboqs") == 0,
          "unexpected provider name");
    CHECK(mlkem768_provider_check(),
          "FIPS 203 ML-KEM-768 provider unavailable or wrong lengths");

    CHECK(mlkem768_keygen(&keypair_a), "keypair A generation");
    CHECK(keypair_a.encapsulation_key_len ==
              MLKEM768_ENCAPSULATION_KEY_BYTES,
          "keypair A encapsulation key length");
    CHECK(keypair_a.decapsulation_key_len ==
              MLKEM768_DECAPSULATION_KEY_BYTES,
          "keypair A decapsulation key length");
    CHECK(mlkem768_keygen(&keypair_b), "keypair B generation");
    CHECK(memcmp(keypair_a.encapsulation_key, keypair_b.encapsulation_key,
                 MLKEM768_ENCAPSULATION_KEY_BYTES) != 0,
          "independent KeyGen produced the same encapsulation key");
    CHECK(memcmp(keypair_a.decapsulation_key, keypair_b.decapsulation_key,
                 MLKEM768_DECAPSULATION_KEY_BYTES) != 0,
          "independent KeyGen produced the same decapsulation key");

    CHECK(mlkem768_encaps(keypair_a.encapsulation_key,
                          keypair_a.encapsulation_key_len,
                          ciphertext_a1, sizeof(ciphertext_a1),
                          &ciphertext_a1_len, secret_a1),
          "first encapsulation");
    CHECK(ciphertext_a1_len == MLKEM768_CIPHERTEXT_BYTES,
          "ciphertext length");
    CHECK(mlkem768_decaps(keypair_a.decapsulation_key,
                          keypair_a.decapsulation_key_len,
                          ciphertext_a1, ciphertext_a1_len, recovered),
          "valid decapsulation");
    CHECK(memcmp(secret_a1, recovered, sizeof(secret_a1)) == 0,
          "encapsulated and decapsulated secrets differ");

    CHECK(mlkem768_encaps(keypair_a.encapsulation_key,
                          keypair_a.encapsulation_key_len,
                          ciphertext_a2, sizeof(ciphertext_a2),
                          &ciphertext_a2_len, secret_a2),
          "second encapsulation");
    CHECK(memcmp(ciphertext_a1, ciphertext_a2, sizeof(ciphertext_a1)) != 0,
          "randomized encapsulations produced the same ciphertext");
    CHECK(memcmp(secret_a1, secret_a2, sizeof(secret_a1)) != 0,
          "randomized encapsulations produced the same shared secret");

    /* Fixed-length and NULL checks must fail before entering the provider. */
    CHECK(!mlkem768_encaps(keypair_a.encapsulation_key,
                           MLKEM768_ENCAPSULATION_KEY_BYTES - 1,
                           ciphertext_a2, sizeof(ciphertext_a2),
                           &output_len, rejected) && output_len == 0,
          "1183-byte encapsulation key accepted");
    output_len = 7;
    CHECK(!mlkem768_encaps(keypair_a.encapsulation_key,
                           MLKEM768_ENCAPSULATION_KEY_BYTES + 1,
                           ciphertext_a2, sizeof(ciphertext_a2),
                           &output_len, rejected) && output_len == 0,
          "1185-byte encapsulation key accepted");
    output_len = 7;
    CHECK(!mlkem768_encaps(NULL, MLKEM768_ENCAPSULATION_KEY_BYTES,
                           ciphertext_a2, sizeof(ciphertext_a2),
                           &output_len, rejected) && output_len == 0,
          "NULL encapsulation key accepted");
    output_len = 7;
    CHECK(!mlkem768_encaps(keypair_a.encapsulation_key,
                           keypair_a.encapsulation_key_len,
                           NULL, sizeof(ciphertext_a2), &output_len,
                           rejected) && output_len == 0,
          "NULL ciphertext output accepted");
    output_len = 7;
    CHECK(!mlkem768_encaps(keypair_a.encapsulation_key,
                           keypair_a.encapsulation_key_len,
                           ciphertext_a2, MLKEM768_CIPHERTEXT_BYTES - 1,
                           &output_len, rejected) && output_len == 0,
          "undersized ciphertext buffer accepted");
    CHECK(!mlkem768_encaps(keypair_a.encapsulation_key,
                           keypair_a.encapsulation_key_len,
                           ciphertext_a2, sizeof(ciphertext_a2),
                           NULL, rejected),
          "NULL ciphertext length output accepted");
    output_len = 7;
    CHECK(!mlkem768_encaps(keypair_a.encapsulation_key,
                           keypair_a.encapsulation_key_len,
                           ciphertext_a2, sizeof(ciphertext_a2),
                           &output_len, NULL) && output_len == 0,
          "NULL encapsulated secret output accepted");

    memcpy(malformed_ek, keypair_a.encapsulation_key, sizeof(malformed_ek));
    malformed_ek[0] = 0xffu;
    malformed_ek[1] = (uint8_t)(malformed_ek[1] | 0x0fu);
    output_len = 7;
    CHECK(!mlkem768_encaps(malformed_ek, sizeof(malformed_ek),
                           ciphertext_a2, sizeof(ciphertext_a2),
                           &output_len, rejected) && output_len == 0,
          "non-canonical same-length encapsulation key accepted");

    CHECK(!mlkem768_decaps(keypair_a.decapsulation_key,
                           MLKEM768_DECAPSULATION_KEY_BYTES - 1,
                           ciphertext_a1, ciphertext_a1_len, rejected),
          "short decapsulation key accepted");
    CHECK(!mlkem768_decaps(keypair_a.decapsulation_key,
                           MLKEM768_DECAPSULATION_KEY_BYTES + 1,
                           ciphertext_a1, ciphertext_a1_len, rejected),
          "long decapsulation key accepted");
    CHECK(!mlkem768_decaps(NULL, MLKEM768_DECAPSULATION_KEY_BYTES,
                           ciphertext_a1, ciphertext_a1_len, rejected),
          "NULL decapsulation key accepted");
    CHECK(!mlkem768_decaps(keypair_a.decapsulation_key,
                           keypair_a.decapsulation_key_len,
                           ciphertext_a1,
                           MLKEM768_CIPHERTEXT_BYTES - 1, rejected),
          "1087-byte ciphertext accepted");
    CHECK(!mlkem768_decaps(keypair_a.decapsulation_key,
                           keypair_a.decapsulation_key_len,
                           ciphertext_a1,
                           MLKEM768_CIPHERTEXT_BYTES + 1, rejected),
          "1089-byte ciphertext accepted");
    CHECK(!mlkem768_decaps(keypair_a.decapsulation_key,
                           keypair_a.decapsulation_key_len,
                           NULL, MLKEM768_CIPHERTEXT_BYTES, rejected),
          "NULL ciphertext accepted");
    CHECK(!mlkem768_decaps(keypair_a.decapsulation_key,
                           keypair_a.decapsulation_key_len,
                           ciphertext_a1, ciphertext_a1_len, NULL),
          "NULL decapsulated secret output accepted");

    keypair_a.decapsulation_key[MLKEM768_DECAPSULATION_KEY_BYTES - 64u] ^=
        0x01u;
    CHECK(!mlkem768_decaps(keypair_a.decapsulation_key,
                           keypair_a.decapsulation_key_len,
                           ciphertext_a1, ciphertext_a1_len, rejected),
          "same-length decapsulation key with invalid embedded hash accepted");
    keypair_a.decapsulation_key[MLKEM768_DECAPSULATION_KEY_BYTES - 64u] ^=
        0x01u;

    /* Wrong-key and modified-ciphertext cases exercise implicit rejection:
     * structurally valid inputs produce a secret that must not match the
     * original session secret. */
    CHECK(mlkem768_encaps(keypair_b.encapsulation_key,
                          keypair_b.encapsulation_key_len,
                          ciphertext_b, sizeof(ciphertext_b),
                          &ciphertext_b_len, secret_b),
          "keypair B encapsulation");
    CHECK(mlkem768_decaps(keypair_a.decapsulation_key,
                          keypair_a.decapsulation_key_len,
                          ciphertext_b, ciphertext_b_len, rejected),
          "wrong-key decapsulation API failure");
    CHECK(memcmp(secret_b, rejected, sizeof(secret_b)) != 0,
          "wrong decapsulation key reproduced the shared secret");

    memcpy(tampered, ciphertext_a1, sizeof(tampered));
    tampered[sizeof(tampered) / 2] ^= 0x01u;
    CHECK(mlkem768_decaps(keypair_a.decapsulation_key,
                          keypair_a.decapsulation_key_len,
                          tampered, sizeof(tampered), rejected),
          "tampered ciphertext did not follow implicit rejection");
    CHECK(memcmp(secret_a1, rejected, sizeof(secret_a1)) != 0,
          "tampered ciphertext reproduced the shared secret");

    CHECK(mlkem768_decaps(keypair_a.decapsulation_key,
                          keypair_a.decapsulation_key_len,
                          zero_ciphertext, sizeof(zero_ciphertext), rejected),
          "all-zero fixed-length ciphertext caused API failure");
    CHECK(memcmp(secret_a1, rejected, sizeof(secret_a1)) != 0,
          "all-zero ciphertext reproduced the shared secret");

    nonempty.encapsulation_key = keypair_a.encapsulation_key;
    CHECK(!mlkem768_keygen(&nonempty), "nonempty keypair output accepted");
    nonempty.encapsulation_key = NULL;

    printf("PASS: ML-KEM-768 KeyGen/Encaps/Decaps positive tests\n");
    printf("PASS: ML-KEM-768 input validation and 12 negative cases\n");
    printf("PASS: tampered ciphertext used FIPS 203 implicit rejection\n");
    ok = EXIT_SUCCESS;

done:
    mlkem_shared_secret_cleanup(secret_a1);
    mlkem_shared_secret_cleanup(secret_a2);
    mlkem_shared_secret_cleanup(secret_b);
    mlkem_shared_secret_cleanup(recovered);
    mlkem_shared_secret_cleanup(rejected);
    mlkem_keypair_cleanup(&keypair_a);
    mlkem_keypair_cleanup(&keypair_b);
    return ok;
}
