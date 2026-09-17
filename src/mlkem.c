#include "mlkem.h"

#include <oqs/oqs.h>

#include <stdlib.h>
#include <string.h>

_Static_assert(MLKEM768_ENCAPSULATION_KEY_BYTES ==
                   OQS_KEM_ml_kem_768_length_public_key,
               "ML-KEM-768 encapsulation key size mismatch");
_Static_assert(MLKEM768_DECAPSULATION_KEY_BYTES ==
                   OQS_KEM_ml_kem_768_length_secret_key,
               "ML-KEM-768 decapsulation key size mismatch");
_Static_assert(MLKEM768_CIPHERTEXT_BYTES ==
                   OQS_KEM_ml_kem_768_length_ciphertext,
               "ML-KEM-768 ciphertext size mismatch");
_Static_assert(MLKEM768_SHARED_SECRET_BYTES ==
                   OQS_KEM_ml_kem_768_length_shared_secret,
               "ML-KEM-768 shared secret size mismatch");

static OQS_KEM *mlkem768_new_checked(void)
{
    OQS_KEM *kem;

    if (!OQS_KEM_alg_is_enabled(OQS_KEM_alg_ml_kem_768)) {
        return NULL;
    }
    kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        return NULL;
    }
    if (kem->method_name == NULL || kem->alg_version == NULL ||
        strcmp(kem->method_name, OQS_KEM_alg_ml_kem_768) != 0 ||
        strcmp(kem->alg_version, "FIPS203") != 0 ||
        kem->length_public_key != MLKEM768_ENCAPSULATION_KEY_BYTES ||
        kem->length_secret_key != MLKEM768_DECAPSULATION_KEY_BYTES ||
        kem->length_ciphertext != MLKEM768_CIPHERTEXT_BYTES ||
        kem->length_shared_secret != MLKEM768_SHARED_SECRET_BYTES) {
        OQS_KEM_free(kem);
        return NULL;
    }
    return kem;
}

const char *mlkem768_algorithm_name(void)
{
    return "ML-KEM-768";
}

const char *mlkem_provider_name(void)
{
    return "liboqs";
}

const char *mlkem_provider_version(void)
{
    return OQS_version();
}

int mlkem768_provider_check(void)
{
    OQS_KEM *kem = mlkem768_new_checked();

    if (kem == NULL) {
        return 0;
    }
    OQS_KEM_free(kem);
    return 1;
}

int mlkem768_keygen(MLKEM_KEYPAIR *keypair)
{
    OQS_KEM *kem = NULL;
    uint8_t *ek = NULL;
    uint8_t *dk = NULL;
    int ok = 0;

    if (keypair == NULL || keypair->encapsulation_key != NULL ||
        keypair->decapsulation_key != NULL ||
        keypair->encapsulation_key_len != 0 ||
        keypair->decapsulation_key_len != 0) {
        return 0;
    }
    kem = mlkem768_new_checked();
    if (kem == NULL) {
        return 0;
    }
    ek = OQS_MEM_malloc(MLKEM768_ENCAPSULATION_KEY_BYTES);
    dk = OQS_MEM_malloc(MLKEM768_DECAPSULATION_KEY_BYTES);
    if (ek == NULL || dk == NULL) {
        goto done;
    }
    if (OQS_KEM_keypair(kem, ek, dk) != OQS_SUCCESS) {
        goto done;
    }

    keypair->encapsulation_key = ek;
    keypair->encapsulation_key_len = MLKEM768_ENCAPSULATION_KEY_BYTES;
    keypair->decapsulation_key = dk;
    keypair->decapsulation_key_len = MLKEM768_DECAPSULATION_KEY_BYTES;
    ek = NULL;
    dk = NULL;
    ok = 1;

done:
    OQS_MEM_insecure_free(ek);
    OQS_MEM_secure_free(dk, MLKEM768_DECAPSULATION_KEY_BYTES);
    OQS_KEM_free(kem);
    return ok;
}

int mlkem768_encaps(const uint8_t *encapsulation_key,
                    size_t encapsulation_key_len,
                    uint8_t *ciphertext,
                    size_t ciphertext_capacity,
                    size_t *ciphertext_len,
                    uint8_t shared_secret[MLKEM768_SHARED_SECRET_BYTES])
{
    OQS_KEM *kem;
    int ok;

    if (ciphertext_len != NULL) {
        *ciphertext_len = 0;
    }
    if (shared_secret != NULL) {
        OQS_MEM_cleanse(shared_secret, MLKEM768_SHARED_SECRET_BYTES);
    }
    if (encapsulation_key == NULL ||
        encapsulation_key_len != MLKEM768_ENCAPSULATION_KEY_BYTES ||
        ciphertext == NULL ||
        ciphertext_capacity < MLKEM768_CIPHERTEXT_BYTES ||
        ciphertext_len == NULL || shared_secret == NULL) {
        return 0;
    }

    kem = mlkem768_new_checked();
    if (kem == NULL) {
        OQS_MEM_cleanse(shared_secret, MLKEM768_SHARED_SECRET_BYTES);
        return 0;
    }
    ok = OQS_KEM_encaps(kem, ciphertext, shared_secret,
                        encapsulation_key) == OQS_SUCCESS;
    OQS_KEM_free(kem);
    if (!ok) {
        OQS_MEM_cleanse(ciphertext, MLKEM768_CIPHERTEXT_BYTES);
        OQS_MEM_cleanse(shared_secret, MLKEM768_SHARED_SECRET_BYTES);
        return 0;
    }
    *ciphertext_len = MLKEM768_CIPHERTEXT_BYTES;
    return 1;
}

int mlkem768_decaps(const uint8_t *decapsulation_key,
                    size_t decapsulation_key_len,
                    const uint8_t *ciphertext,
                    size_t ciphertext_len,
                    uint8_t shared_secret[MLKEM768_SHARED_SECRET_BYTES])
{
    OQS_KEM *kem;
    int ok;

    if (decapsulation_key == NULL ||
        decapsulation_key_len != MLKEM768_DECAPSULATION_KEY_BYTES ||
        ciphertext == NULL || ciphertext_len != MLKEM768_CIPHERTEXT_BYTES ||
        shared_secret == NULL) {
        if (shared_secret != NULL) {
            OQS_MEM_cleanse(shared_secret, MLKEM768_SHARED_SECRET_BYTES);
        }
        return 0;
    }

    OQS_MEM_cleanse(shared_secret, MLKEM768_SHARED_SECRET_BYTES);

    kem = mlkem768_new_checked();
    if (kem == NULL) {
        OQS_MEM_cleanse(shared_secret, MLKEM768_SHARED_SECRET_BYTES);
        return 0;
    }
    ok = OQS_KEM_decaps(kem, shared_secret, ciphertext,
                        decapsulation_key) == OQS_SUCCESS;
    OQS_KEM_free(kem);
    if (!ok) {
        OQS_MEM_cleanse(shared_secret, MLKEM768_SHARED_SECRET_BYTES);
        return 0;
    }
    return 1;
}

void mlkem_keypair_cleanup(MLKEM_KEYPAIR *keypair)
{
    if (keypair == NULL) {
        return;
    }
    OQS_MEM_insecure_free(keypair->encapsulation_key);
    OQS_MEM_secure_free(keypair->decapsulation_key,
                        MLKEM768_DECAPSULATION_KEY_BYTES);
    keypair->encapsulation_key = NULL;
    keypair->encapsulation_key_len = 0;
    keypair->decapsulation_key = NULL;
    keypair->decapsulation_key_len = 0;
}

void mlkem_shared_secret_cleanup(
    uint8_t shared_secret[MLKEM768_SHARED_SECRET_BYTES])
{
    if (shared_secret != NULL) {
        OQS_MEM_cleanse(shared_secret, MLKEM768_SHARED_SECRET_BYTES);
    }
}
