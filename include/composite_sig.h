#ifndef HYBRID_PQC_COMPOSITE_SIG_H
#define HYBRID_PQC_COMPOSITE_SIG_H

#include <stddef.h>
#include <stdint.h>

#include "composite_key.h"

#define COMPOSITE_SIGNATURE_PREFIX "CompositeAlgorithmSignatures2025"
#define COMPOSITE_SIGNATURE_LABEL "COMPSIG-DILITHIUM2-SM2-SM3"
#define COMPOSITE_PREHASH_NAME "SM3"
#define COMPOSITE_MAX_CONTEXT_BYTES 255u

typedef struct {
    int format_valid;
    int dilithium_valid;
    int sm2_valid;
    int composite_valid;
} COMPOSITE_VERIFY_RESULT;

int composite_build_message(const uint8_t *message, size_t message_len,
                            const uint8_t *ctx, size_t ctx_len,
                            uint8_t **m_prime, size_t *m_prime_len);

int composite_serialize_signature(const uint8_t *dilithium_signature,
                                  size_t dilithium_signature_len,
                                  const uint8_t *sm2_signature_der,
                                  size_t sm2_signature_der_len,
                                  uint8_t **signature,
                                  size_t *signature_len);

int composite_parse_signature(const uint8_t *signature, size_t signature_len,
                              const uint8_t **dilithium_signature,
                              size_t *dilithium_signature_len,
                              const uint8_t **sm2_signature_der,
                              size_t *sm2_signature_der_len);

int composite_sign(const HYBRID_PRIVATE_KEY *key,
                   const uint8_t *message, size_t message_len,
                   const uint8_t *ctx, size_t ctx_len,
                   uint8_t **signature, size_t *signature_len);

int composite_verify_detailed(const HYBRID_PUBLIC_KEY *key,
                              const uint8_t *message, size_t message_len,
                              const uint8_t *ctx, size_t ctx_len,
                              const uint8_t *signature, size_t signature_len,
                              COMPOSITE_VERIFY_RESULT *result);

int composite_verify(const HYBRID_PUBLIC_KEY *key,
                     const uint8_t *message, size_t message_len,
                     const uint8_t *ctx, size_t ctx_len,
                     const uint8_t *signature, size_t signature_len);

#endif
