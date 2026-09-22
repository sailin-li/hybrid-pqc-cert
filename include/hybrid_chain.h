#ifndef HYBRID_PQC_HYBRID_CHAIN_H
#define HYBRID_PQC_HYBRID_CHAIN_H

#include <openssl/x509.h>

typedef struct {
    int issuer_subject_link_valid;
    int validity_valid;
    int issuer_ca_constraints_valid;
    int subject_constraints_valid;
    int eku_valid;
    int san_valid;
    int key_identifiers_valid;
    int pqc_extension_present;
    int composite_oids_valid;
    int subject_public_key_composite;
    int subject_public_key_sm2;
    int composite_public_key_valid;
    int signature_format_valid;
    int dilithium_valid;
    int sm2_valid;
    int composite_valid;
    int certificate_valid;
} HYBRID_CERT_VERIFY_RESULT;

typedef struct {
    int trust_anchor_configured;
    HYBRID_CERT_VERIFY_RESULT root;
    HYBRID_CERT_VERIFY_RESULT server;
    int chain_valid;
} HYBRID_CHAIN_VERIFY_RESULT;

int hybrid_verify_root_self_signature(X509 *root,
                                      HYBRID_CERT_VERIFY_RESULT *result);

int hybrid_verify_certificate(X509 *certificate, X509 *issuer_certificate,
                              HYBRID_CERT_VERIFY_RESULT *result);

int hybrid_verify_encryption_certificate(
    X509 *certificate, X509 *issuer_certificate,
    HYBRID_CERT_VERIFY_RESULT *result);

int hybrid_verify_chain(X509 *root, X509 *server,
                        HYBRID_CHAIN_VERIFY_RESULT *result);

#endif
