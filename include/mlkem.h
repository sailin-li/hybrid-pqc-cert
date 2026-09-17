#ifndef HYBRID_PQC_MLKEM_H
#define HYBRID_PQC_MLKEM_H

#include <stddef.h>
#include <stdint.h>

#define MLKEM768_ENCAPSULATION_KEY_BYTES 1184u
#define MLKEM768_DECAPSULATION_KEY_BYTES 2400u
#define MLKEM768_CIPHERTEXT_BYTES 1088u
#define MLKEM768_SHARED_SECRET_BYTES 32u

typedef struct {
    uint8_t *encapsulation_key;
    size_t encapsulation_key_len;
    uint8_t *decapsulation_key;
    size_t decapsulation_key_len;
} MLKEM_KEYPAIR;

const char *mlkem768_algorithm_name(void);
const char *mlkem_provider_name(void);
const char *mlkem_provider_version(void);

/* Verifies that the configured provider exposes FIPS 203 ML-KEM-768 with the
 * exact parameter lengths above. */
int mlkem768_provider_check(void);

int mlkem768_keygen(MLKEM_KEYPAIR *keypair);

int mlkem768_encaps(const uint8_t *encapsulation_key,
                    size_t encapsulation_key_len,
                    uint8_t *ciphertext,
                    size_t ciphertext_capacity,
                    size_t *ciphertext_len,
                    uint8_t shared_secret[MLKEM768_SHARED_SECRET_BYTES]);

int mlkem768_decaps(const uint8_t *decapsulation_key,
                    size_t decapsulation_key_len,
                    const uint8_t *ciphertext,
                    size_t ciphertext_len,
                    uint8_t shared_secret[MLKEM768_SHARED_SECRET_BYTES]);

void mlkem_keypair_cleanup(MLKEM_KEYPAIR *keypair);
void mlkem_shared_secret_cleanup(
    uint8_t shared_secret[MLKEM768_SHARED_SECRET_BYTES]);

#endif
