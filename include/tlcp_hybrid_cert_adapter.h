#ifndef HYBRID_PQC_TLCP_HYBRID_CERT_ADAPTER_H
#define HYBRID_PQC_TLCP_HYBRID_CERT_ADAPTER_H

#include <stddef.h>
#include <stdint.h>

#include "composite_key.h"
#include "hybrid_chain.h"

typedef enum {
    TLCP_HYBRID_CERT_INVALID = -1,
    TLCP_HYBRID_CERT_NOT_APPLICABLE = 0,
    TLCP_HYBRID_CERT_VALID = 1
} TLCP_HYBRID_CERT_RESULT;

typedef struct {
    int recognized_composite;
    int oid_ok;
    int pqc_marker_ok;
    int issuer_subject_ok;
    int validity_ok;
    int constraints_ok;
    int key_usage_ok;
    int hostname_ok;
    int dilithium_ok;
    int sm2_ok;
    int composite_ok;
    int encryption_subject_spki_sm2_ok;
    int encryption_oid_ok;
    int encryption_pqc_marker_ok;
    int encryption_dilithium_ok;
    int encryption_sm2_ok;
    int encryption_composite_ok;
    int encryption_certificate_ok;
    int tlcp_dual_identity_ok;
    int tlcp_dual_certificate_ok;
    HYBRID_CHAIN_VERIFY_RESULT chain;
    HYBRID_CERT_VERIFY_RESULT encryption;
} TLCP_HYBRID_CERT_VERIFY_REPORT;

typedef struct {
    const uint8_t *trust_anchor_der;
    size_t trust_anchor_der_len;
    const char *expected_hostname;
    TLCP_HYBRID_CERT_VERIFY_REPORT *last_report;
} TLCP_HYBRID_CERT_ADAPTER_CONFIG;

TLCP_HYBRID_CERT_RESULT tlcp_hybrid_cert_verify_der(
    const uint8_t *signing_cert_der, size_t signing_cert_der_len,
    const uint8_t *trust_anchor_der, size_t trust_anchor_der_len,
    const char *expected_hostname,
    uint8_t sm2_public_key[SM2_UNCOMPRESSED_PUBLIC_KEY_BYTES],
    TLCP_HYBRID_CERT_VERIFY_REPORT *report);

int tlcp_hybrid_cert_get_sm2_sign_public_key(
    const uint8_t *cert_der, size_t cert_der_len,
    uint8_t sm2_public_key[SM2_UNCOMPRESSED_PUBLIC_KEY_BYTES]);

void tlcp_hybrid_cert_report_print(
    const TLCP_HYBRID_CERT_VERIFY_REPORT *report);

int tlcp_hybrid_cert_gmssl_verify_callback(
    const uint8_t *cert_chain_der, size_t cert_chain_der_len,
    uint8_t sm2_public_key[SM2_UNCOMPRESSED_PUBLIC_KEY_BYTES],
    void *arg, int verbose);

#endif
