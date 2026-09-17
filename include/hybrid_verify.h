#ifndef HYBRID_PQC_HYBRID_VERIFY_H
#define HYBRID_PQC_HYBRID_VERIFY_H

#include <openssl/x509.h>

typedef enum {
    HYBRID_VERIFY_STRICT = 0,
    HYBRID_VERIFY_CLASSICAL_COMPAT = 1
} HYBRID_VERIFY_MODE;

typedef struct {
    int sm2_valid;
    int pqc_extension_present;
    int pqc_info_valid;
    int pqc_algorithm_known;
    int dilithium_valid;
    int hybrid_valid;
} HYBRID_VERIFY_RESULT;

int hybrid_cert_verify(X509 *certificate, HYBRID_VERIFY_MODE mode,
                       HYBRID_VERIFY_RESULT *result);

int hybrid_cert_verify_strict(X509 *certificate);

#endif
