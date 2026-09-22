#include "tlcp_hybrid_cert_adapter.h"

#include "hybrid_x509.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <limits.h>
#include <stdio.h>
#include <string.h>

static const uint8_t composite_oid_der[] = {
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
    0x01, 0x81, 0xfd, 0x59, 0x01, 0x01
};

static int contains_composite_oid(const uint8_t *der, size_t der_len)
{
    size_t i;

    if (der == NULL || der_len < sizeof(composite_oid_der)) {
        return 0;
    }
    for (i = 0; i <= der_len - sizeof(composite_oid_der); ++i) {
        if (memcmp(der + i, composite_oid_der,
                   sizeof(composite_oid_der)) == 0) {
            return 1;
        }
    }
    return 0;
}

static X509 *decode_der_strict(const uint8_t *der, size_t der_len)
{
    const unsigned char *cursor = der;
    X509 *certificate;

    if (der == NULL || der_len == 0 || der_len > LONG_MAX) {
        return NULL;
    }
    certificate = d2i_X509(NULL, &cursor, (long)der_len);
    if (certificate == NULL || cursor != der + der_len) {
        X509_free(certificate);
        return NULL;
    }
    return certificate;
}

static X509 *decode_next_certificate(const uint8_t **der, size_t *der_len)
{
    const unsigned char *cursor;
    const unsigned char *start;
    X509 *certificate;

    if (der == NULL || *der == NULL || der_len == NULL || *der_len == 0 ||
        *der_len > LONG_MAX) {
        return NULL;
    }
    start = *der;
    cursor = start;
    certificate = d2i_X509(NULL, &cursor, (long)*der_len);
    if (certificate == NULL || cursor <= start ||
        (size_t)(cursor - start) > *der_len) {
        X509_free(certificate);
        return NULL;
    }
    *der_len -= (size_t)(cursor - start);
    *der = cursor;
    return certificate;
}

static int certificate_mentions_composite(const X509 *certificate)
{
    const X509_ALGOR *outer = NULL;
    const X509_ALGOR *inner;
    const ASN1_OBJECT *outer_object = NULL;
    const ASN1_OBJECT *inner_object = NULL;
    ASN1_OBJECT *composite = NULL;
    int recognized = 0;

    if (certificate == NULL) {
        return 0;
    }
    X509_get0_signature(NULL, &outer, certificate);
    inner = X509_get0_tbs_sigalg(certificate);
    if (outer != NULL) {
        X509_ALGOR_get0(&outer_object, NULL, NULL, outer);
    }
    if (inner != NULL) {
        X509_ALGOR_get0(&inner_object, NULL, NULL, inner);
    }
    composite = OBJ_txt2obj(COMPOSITE_SM2_DILITHIUM_EXPERIMENTAL_OID, 1);
    if (composite != NULL &&
        ((outer_object != NULL && OBJ_cmp(outer_object, composite) == 0) ||
         (inner_object != NULL && OBJ_cmp(inner_object, composite) == 0))) {
        recognized = 1;
    }
    ASN1_OBJECT_free(composite);
    return recognized;
}

int tlcp_hybrid_cert_get_sm2_sign_public_key(
    const uint8_t *cert_der, size_t cert_der_len,
    uint8_t sm2_public_key[SM2_UNCOMPRESSED_PUBLIC_KEY_BYTES])
{
    X509 *certificate = NULL;
    HYBRID_PUBLIC_KEY public_key;
    int ok = 0;

    hybrid_public_key_init(&public_key);
    certificate = decode_der_strict(cert_der, cert_der_len);
    if (certificate != NULL &&
        hybrid_x509_composite_algorithms_valid(certificate) &&
        hybrid_x509_get_composite_public_key(certificate, &public_key) &&
        composite_get_sm2_public_key_octets(&public_key, sm2_public_key)) {
        ok = 1;
    }
    hybrid_public_key_cleanup(&public_key);
    X509_free(certificate);
    return ok;
}

TLCP_HYBRID_CERT_RESULT tlcp_hybrid_cert_verify_der(
    const uint8_t *signing_cert_der, size_t signing_cert_der_len,
    const uint8_t *trust_anchor_der, size_t trust_anchor_der_len,
    const char *expected_hostname,
    uint8_t sm2_public_key[SM2_UNCOMPRESSED_PUBLIC_KEY_BYTES],
    TLCP_HYBRID_CERT_VERIFY_REPORT *report)
{
    TLCP_HYBRID_CERT_VERIFY_REPORT local;
    X509 *signing = NULL;
    X509 *root = NULL;
    int chain_ok = 0;

    memset(&local, 0, sizeof(local));
    if (sm2_public_key != NULL) {
        memset(sm2_public_key, 0, SM2_UNCOMPRESSED_PUBLIC_KEY_BYTES);
    }
    signing = decode_der_strict(signing_cert_der, signing_cert_der_len);
    if (signing == NULL) {
        local.recognized_composite =
            contains_composite_oid(signing_cert_der, signing_cert_der_len);
        goto done;
    }
    local.recognized_composite = certificate_mentions_composite(signing);
    if (!local.recognized_composite) {
        goto done;
    }

    local.oid_ok = hybrid_x509_composite_algorithms_valid(signing);
    local.pqc_marker_ok = hybrid_x509_has_pqc_extension(signing);
    root = decode_der_strict(trust_anchor_der, trust_anchor_der_len);
    if (root != NULL) {
        chain_ok = hybrid_verify_chain(root, signing, &local.chain);
    }
    local.issuer_subject_ok =
        local.chain.server.issuer_subject_link_valid;
    local.validity_ok = local.chain.root.validity_valid &&
                        local.chain.server.validity_valid;
    local.constraints_ok =
        local.chain.server.issuer_ca_constraints_valid &&
        local.chain.server.subject_constraints_valid;
    local.key_usage_ok = local.chain.server.subject_constraints_valid;
    local.dilithium_ok = local.chain.server.dilithium_valid;
    local.sm2_ok = local.chain.server.sm2_valid;
    local.composite_ok = local.chain.server.composite_valid;
    local.hostname_ok = expected_hostname == NULL ||
                        expected_hostname[0] == '\0' ||
                        X509_check_host(signing, expected_hostname, 0, 0,
                                        NULL) == 1;

    if (!local.oid_ok || !local.pqc_marker_ok || !chain_ok ||
        !local.hostname_ok || sm2_public_key == NULL ||
        !tlcp_hybrid_cert_get_sm2_sign_public_key(
            signing_cert_der, signing_cert_der_len, sm2_public_key)) {
        chain_ok = 0;
    }

done:
    X509_free(root);
    X509_free(signing);
    if (report != NULL) {
        *report = local;
    }
    if (!local.recognized_composite) {
        return TLCP_HYBRID_CERT_NOT_APPLICABLE;
    }
    return chain_ok ? TLCP_HYBRID_CERT_VALID : TLCP_HYBRID_CERT_INVALID;
}

void tlcp_hybrid_cert_report_print(
    const TLCP_HYBRID_CERT_VERIFY_REPORT *report)
{
    if (report == NULL) {
        return;
    }
    fprintf(stderr, "[Hybrid Cert] Composite OID: %s\n",
            report->oid_ok ? "PASS" : "FAIL");
    fprintf(stderr, "[Hybrid Cert] PQC marker: %s\n",
            report->pqc_marker_ok ? "PASS" : "FAIL");
    fprintf(stderr, "[Hybrid Cert] issuer/subject: %s\n",
            report->issuer_subject_ok ? "PASS" : "FAIL");
    fprintf(stderr, "[Hybrid Cert] validity: %s\n",
            report->validity_ok ? "PASS" : "FAIL");
    fprintf(stderr, "[Hybrid Cert] constraints: %s\n",
            report->constraints_ok ? "PASS" : "FAIL");
    fprintf(stderr, "[Hybrid Cert] hostname: %s\n",
            report->hostname_ok ? "PASS" : "FAIL");
    fprintf(stderr, "[Hybrid Cert] Dilithium2: %s\n",
            report->dilithium_ok ? "PASS" : "FAIL");
    fprintf(stderr, "[Hybrid Cert] SM2: %s\n",
            report->sm2_ok ? "PASS" : "FAIL");
    fprintf(stderr, "[Hybrid Cert] Composite AND: %s\n",
            report->composite_ok ? "PASS" : "FAIL");
    fprintf(stderr, "[Hybrid Cert] Encryption SPKI is SM2: %s\n",
            report->encryption_subject_spki_sm2_ok ? "PASS" : "FAIL");
    fprintf(stderr, "[Hybrid Cert] Encryption Composite OID: %s\n",
            report->encryption_oid_ok ? "PASS" : "FAIL");
    fprintf(stderr, "[Hybrid Cert] Encryption PQC marker: %s\n",
            report->encryption_pqc_marker_ok ? "PASS" : "FAIL");
    fprintf(stderr, "[Hybrid Cert] Encryption Dilithium2: %s\n",
            report->encryption_dilithium_ok ? "PASS" : "FAIL");
    fprintf(stderr, "[Hybrid Cert] Encryption SM2: %s\n",
            report->encryption_sm2_ok ? "PASS" : "FAIL");
    fprintf(stderr, "[Hybrid Cert] Encryption Composite AND: %s\n",
            report->encryption_composite_ok ? "PASS" : "FAIL");
    fprintf(stderr, "[Hybrid Cert] Encryption certificate overall: %s\n",
            report->encryption_certificate_ok ? "PASS" : "FAIL");
    fprintf(stderr, "[Hybrid Cert] TLCP dual identity: %s\n",
            report->tlcp_dual_identity_ok ? "PASS" : "FAIL");
    fprintf(stderr, "[Hybrid Cert] TLCP dual certificate overall: %s\n",
            report->tlcp_dual_certificate_ok ? "PASS" : "FAIL");
}

int tlcp_hybrid_cert_gmssl_verify_callback(
    const uint8_t *cert_chain_der, size_t cert_chain_der_len,
    uint8_t sm2_public_key[SM2_UNCOMPRESSED_PUBLIC_KEY_BYTES],
    void *arg, int verbose)
{
    TLCP_HYBRID_CERT_ADAPTER_CONFIG *config = arg;
    TLCP_HYBRID_CERT_VERIFY_REPORT local;
    TLCP_HYBRID_CERT_RESULT result;
    const uint8_t *cursor = cert_chain_der;
    size_t remaining = cert_chain_der_len;
    const uint8_t *signing_der;
    size_t signing_der_len;
    X509 *signing = NULL;
    X509 *encryption = NULL;
    X509 *root = NULL;

    if (config == NULL) {
        return TLCP_HYBRID_CERT_INVALID;
    }
    signing_der = cursor;
    signing = decode_next_certificate(&cursor, &remaining);
    signing_der_len = signing != NULL ? (size_t)(cursor - signing_der) : 0;
    encryption = decode_next_certificate(&cursor, &remaining);
    result = tlcp_hybrid_cert_verify_der(
        signing_der, signing_der_len,
        config->trust_anchor_der, config->trust_anchor_der_len,
        config->expected_hostname, sm2_public_key, &local);
    if (result == TLCP_HYBRID_CERT_VALID) {
        root = decode_der_strict(config->trust_anchor_der,
                                 config->trust_anchor_der_len);
        local.encryption_certificate_ok =
            hybrid_verify_encryption_certificate(
                encryption, root, &local.encryption);
        local.encryption_subject_spki_sm2_ok =
            local.encryption.subject_public_key_sm2;
        local.encryption_oid_ok = local.encryption.composite_oids_valid;
        local.encryption_pqc_marker_ok =
            local.encryption.pqc_extension_present;
        local.encryption_dilithium_ok = local.encryption.dilithium_valid;
        local.encryption_sm2_ok = local.encryption.sm2_valid;
        local.encryption_composite_ok = local.encryption.composite_valid;
        local.tlcp_dual_identity_ok = signing != NULL && encryption != NULL &&
            X509_NAME_cmp(X509_get_subject_name(signing),
                          X509_get_subject_name(encryption)) == 0 &&
            X509_NAME_cmp(X509_get_issuer_name(signing),
                          X509_get_issuer_name(encryption)) == 0;
        local.tlcp_dual_certificate_ok =
            local.composite_ok && local.encryption_certificate_ok &&
            local.tlcp_dual_identity_ok;
        if (!local.tlcp_dual_certificate_ok) {
            result = TLCP_HYBRID_CERT_INVALID;
        }
    }
    if (config->last_report != NULL) {
        *config->last_report = local;
    }
    if (verbose && result != TLCP_HYBRID_CERT_NOT_APPLICABLE) {
        tlcp_hybrid_cert_report_print(&local);
    }
    X509_free(encryption);
    X509_free(signing);
    X509_free(root);
    return result;
}
