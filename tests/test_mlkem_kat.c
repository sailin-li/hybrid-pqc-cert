#include "mlkem.h"

#include <oqs/oqs.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mlkem768_acvp_vectors.h"

#define MLKEM768_KEYGEN_SEED_BYTES 64u
#define MLKEM768_ENCAPS_SEED_BYTES 32u

#define CHECK(condition, text) do { \
    if (!(condition)) { fprintf(stderr, "FAIL: %s\n", text); goto done; } \
} while (0)

_Static_assert(sizeof(MLKEM_ACVP_KG_D) == 32u, "ACVP d size mismatch");
_Static_assert(sizeof(MLKEM_ACVP_KG_Z) == 32u, "ACVP z size mismatch");
_Static_assert(sizeof(MLKEM_ACVP_KG_EK) == MLKEM768_ENCAPSULATION_KEY_BYTES,
               "ACVP KeyGen ek size mismatch");
_Static_assert(sizeof(MLKEM_ACVP_KG_DK) == MLKEM768_DECAPSULATION_KEY_BYTES,
               "ACVP KeyGen dk size mismatch");
_Static_assert(sizeof(MLKEM_ACVP_ENCAP_M) == MLKEM768_ENCAPS_SEED_BYTES,
               "ACVP encapsulation randomness size mismatch");
_Static_assert(sizeof(MLKEM_ACVP_ENCAP_EK) ==
                   MLKEM768_ENCAPSULATION_KEY_BYTES,
               "ACVP Encaps ek size mismatch");
_Static_assert(sizeof(MLKEM_ACVP_ENCAP_DK) ==
                   MLKEM768_DECAPSULATION_KEY_BYTES,
               "ACVP Decaps dk size mismatch");
_Static_assert(sizeof(MLKEM_ACVP_ENCAP_C) == MLKEM768_CIPHERTEXT_BYTES,
               "ACVP ciphertext size mismatch");
_Static_assert(sizeof(MLKEM_ACVP_ENCAP_K) == MLKEM768_SHARED_SECRET_BYTES,
               "ACVP shared secret size mismatch");

int main(void)
{
    OQS_KEM *kem = NULL;
    uint8_t seed[MLKEM768_KEYGEN_SEED_BYTES];
    uint8_t actual_ek[MLKEM768_ENCAPSULATION_KEY_BYTES];
    uint8_t actual_dk[MLKEM768_DECAPSULATION_KEY_BYTES];
    uint8_t actual_c[MLKEM768_CIPHERTEXT_BYTES];
    uint8_t actual_k[MLKEM768_SHARED_SECRET_BYTES];
    uint8_t decaps_k[MLKEM768_SHARED_SECRET_BYTES];
    int ok = EXIT_FAILURE;

    CHECK(mlkem768_provider_check(), "ML-KEM-768 provider check");
    kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    CHECK(kem != NULL, "create test-only ML-KEM-768 provider object");

    memcpy(seed, MLKEM_ACVP_KG_D, sizeof(MLKEM_ACVP_KG_D));
    memcpy(seed + sizeof(MLKEM_ACVP_KG_D), MLKEM_ACVP_KG_Z,
           sizeof(MLKEM_ACVP_KG_Z));
    CHECK(OQS_KEM_keypair_derand(kem, actual_ek, actual_dk, seed) ==
              OQS_SUCCESS,
          "ACVP deterministic KeyGen");
    CHECK(memcmp(actual_ek, MLKEM_ACVP_KG_EK, sizeof(actual_ek)) == 0,
          "ACVP KeyGen encapsulation key mismatch");
    CHECK(memcmp(actual_dk, MLKEM_ACVP_KG_DK, sizeof(actual_dk)) == 0,
          "ACVP KeyGen decapsulation key mismatch");

    memcpy(seed, MLKEM_ACVP_ENCAP_M, sizeof(MLKEM_ACVP_ENCAP_M));
    CHECK(OQS_KEM_encaps_derand(kem, actual_c, actual_k,
                                MLKEM_ACVP_ENCAP_EK, seed) == OQS_SUCCESS,
          "ACVP deterministic Encaps");
    CHECK(memcmp(actual_c, MLKEM_ACVP_ENCAP_C, sizeof(actual_c)) == 0,
          "ACVP Encaps ciphertext mismatch");
    CHECK(memcmp(actual_k, MLKEM_ACVP_ENCAP_K, sizeof(actual_k)) == 0,
          "ACVP Encaps shared secret mismatch");
    CHECK(OQS_KEM_decaps(kem, decaps_k, MLKEM_ACVP_ENCAP_C,
                         MLKEM_ACVP_ENCAP_DK) == OQS_SUCCESS,
          "ACVP Decaps");
    CHECK(memcmp(decaps_k, MLKEM_ACVP_ENCAP_K, sizeof(decaps_k)) == 0,
          "ACVP Decaps shared secret mismatch");

    printf("PASS: NIST ACVP FIPS203 ML-KEM-768 KeyGen tgId 2 tcId 26\n");
    printf("PASS: NIST ACVP FIPS203 ML-KEM-768 Encaps/Decaps "
           "tgId 2 tcId 26\n");
    ok = EXIT_SUCCESS;

done:
    OQS_MEM_cleanse(seed, sizeof(seed));
    OQS_MEM_cleanse(actual_dk, sizeof(actual_dk));
    OQS_MEM_cleanse(actual_k, sizeof(actual_k));
    OQS_MEM_cleanse(decaps_k, sizeof(decaps_k));
    OQS_KEM_free(kem);
    return ok;
}
