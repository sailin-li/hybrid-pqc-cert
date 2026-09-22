#include "hybrid_chain.h"

#include "composite_key.h"
#include "composite_sig.h"
#include "hybrid_x509.h"

#include <openssl/crypto.h>
#include <openssl/x509v3.h>

#include <string.h>

static int certificate_time_valid(const X509 *certificate)
{
    int before;
    int after;

    if (certificate == NULL) {
        return 0;
    }
    before = X509_cmp_current_time(X509_get0_notBefore(certificate));
    after = X509_cmp_current_time(X509_get0_notAfter(certificate));
    return before < 0 && after > 0;
}

static int certificate_constraints_valid(const X509 *certificate, int is_ca)
{
    BASIC_CONSTRAINTS *constraints = NULL;
    ASN1_BIT_STRING *usage = NULL;
    int critical = -1;
    int basic_valid = 0;
    int usage_valid = 0;

    constraints = X509_get_ext_d2i(certificate, NID_basic_constraints,
                                   &critical, NULL);
    if (constraints != NULL && critical == 1 &&
        (!!constraints->ca == !!is_ca)) {
        basic_valid = 1;
    }
    BASIC_CONSTRAINTS_free(constraints);
    critical = -1;
    usage = X509_get_ext_d2i(certificate, NID_key_usage, &critical, NULL);
    if (usage != NULL && critical == 1) {
        if (is_ca) {
            usage_valid = ASN1_BIT_STRING_get_bit(usage, 5) &&
                          ASN1_BIT_STRING_get_bit(usage, 6) &&
                          !ASN1_BIT_STRING_get_bit(usage, 0) &&
                          !ASN1_BIT_STRING_get_bit(usage, 2) &&
                          !ASN1_BIT_STRING_get_bit(usage, 3) &&
                          !ASN1_BIT_STRING_get_bit(usage, 4);
        } else {
            usage_valid = ASN1_BIT_STRING_get_bit(usage, 0) &&
                          !ASN1_BIT_STRING_get_bit(usage, 2) &&
                          !ASN1_BIT_STRING_get_bit(usage, 3) &&
                          !ASN1_BIT_STRING_get_bit(usage, 4) &&
                          !ASN1_BIT_STRING_get_bit(usage, 5) &&
                          !ASN1_BIT_STRING_get_bit(usage, 6);
        }
    }
    ASN1_BIT_STRING_free(usage);
    return basic_valid && usage_valid;
}

static int encryption_certificate_constraints_valid(
    const X509 *certificate)
{
    BASIC_CONSTRAINTS *constraints = NULL;
    ASN1_BIT_STRING *usage = NULL;
    int critical = -1;
    int basic_valid = 0;
    int usage_valid = 0;

    constraints = X509_get_ext_d2i(certificate, NID_basic_constraints,
                                   &critical, NULL);
    if (constraints != NULL && critical == 1 && !constraints->ca) {
        basic_valid = 1;
    }
    BASIC_CONSTRAINTS_free(constraints);
    critical = -1;
    usage = X509_get_ext_d2i(certificate, NID_key_usage, &critical, NULL);
    if (usage != NULL && critical == 1) {
        usage_valid = !ASN1_BIT_STRING_get_bit(usage, 0) &&
                      ASN1_BIT_STRING_get_bit(usage, 2) &&
                      ASN1_BIT_STRING_get_bit(usage, 4) &&
                      !ASN1_BIT_STRING_get_bit(usage, 5) &&
                      !ASN1_BIT_STRING_get_bit(usage, 6);
    }
    ASN1_BIT_STRING_free(usage);
    return basic_valid && usage_valid;
}

static int server_eku_valid(const X509 *certificate)
{
    EXTENDED_KEY_USAGE *usage = NULL;
    int i;
    int valid = 0;

    usage = X509_get_ext_d2i(certificate, NID_ext_key_usage, NULL, NULL);
    if (usage == NULL) {
        return 0;
    }
    for (i = 0; i < sk_ASN1_OBJECT_num(usage); ++i) {
        if (OBJ_obj2nid(sk_ASN1_OBJECT_value(usage, i)) == NID_server_auth) {
            valid = 1;
            break;
        }
    }
    EXTENDED_KEY_USAGE_free(usage);
    return valid;
}

static int server_san_valid(const X509 *certificate)
{
    GENERAL_NAMES *names = NULL;
    int i;
    int valid = 0;

    names = X509_get_ext_d2i(certificate, NID_subject_alt_name, NULL, NULL);
    if (names == NULL) {
        return 0;
    }
    for (i = 0; i < sk_GENERAL_NAME_num(names); ++i) {
        const GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);
        if (name->type == GEN_DNS && name->d.dNSName != NULL &&
            ASN1_STRING_length(name->d.dNSName) > 0) {
            valid = 1;
            break;
        }
    }
    GENERAL_NAMES_free(names);
    return valid;
}

static int subject_key_identifier_present(const X509 *certificate)
{
    ASN1_OCTET_STRING *identifier =
        X509_get_ext_d2i(certificate, NID_subject_key_identifier,
                         NULL, NULL);
    int valid = identifier != NULL && ASN1_STRING_length(identifier) > 0;

    ASN1_OCTET_STRING_free(identifier);
    return valid;
}

static int server_key_identifiers_valid(const X509 *certificate,
                                        const X509 *issuer)
{
    ASN1_OCTET_STRING *subject_identifier = NULL;
    ASN1_OCTET_STRING *issuer_identifier = NULL;
    AUTHORITY_KEYID *authority = NULL;
    int valid = 0;

    subject_identifier =
        X509_get_ext_d2i(certificate, NID_subject_key_identifier,
                         NULL, NULL);
    issuer_identifier =
        X509_get_ext_d2i(issuer, NID_subject_key_identifier, NULL, NULL);
    authority = X509_get_ext_d2i(certificate, NID_authority_key_identifier,
                                 NULL, NULL);
    if (subject_identifier != NULL &&
        ASN1_STRING_length(subject_identifier) > 0 &&
        issuer_identifier != NULL && authority != NULL &&
        authority->keyid != NULL &&
        ASN1_STRING_length(issuer_identifier) > 0 &&
        ASN1_STRING_length(issuer_identifier) ==
            ASN1_STRING_length(authority->keyid) &&
        CRYPTO_memcmp(ASN1_STRING_get0_data(issuer_identifier),
                      ASN1_STRING_get0_data(authority->keyid),
                      (size_t)ASN1_STRING_length(issuer_identifier)) == 0) {
        valid = 1;
    }
    AUTHORITY_KEYID_free(authority);
    ASN1_OCTET_STRING_free(issuer_identifier);
    ASN1_OCTET_STRING_free(subject_identifier);
    return valid;
}

static int verify_certificate_signature(X509 *certificate,
                                        const HYBRID_PUBLIC_KEY *issuer_key,
                                        HYBRID_CERT_VERIFY_RESULT *result)
{
    uint8_t *tbs_der = NULL;
    size_t tbs_der_len = 0;
    const uint8_t *signature = NULL;
    size_t signature_len = 0;
    COMPOSITE_VERIFY_RESULT composite_result = {0};

    if (!hybrid_x509_get_tbs_der(certificate, &tbs_der, &tbs_der_len) ||
        !hybrid_x509_get_signature(certificate, &signature, &signature_len)) {
        goto done;
    }
    (void)composite_verify_detailed(issuer_key, tbs_der, tbs_der_len,
                                    NULL, 0, signature, signature_len,
                                    &composite_result);
    result->signature_format_valid = composite_result.format_valid;
    result->dilithium_valid = composite_result.dilithium_valid;
    result->sm2_valid = composite_result.sm2_valid;
    result->composite_valid = composite_result.composite_valid;

done:
    OPENSSL_free(tbs_der);
    return result->composite_valid;
}

int hybrid_verify_root_self_signature(X509 *root,
                                      HYBRID_CERT_VERIFY_RESULT *result)
{
    HYBRID_CERT_VERIFY_RESULT local = {0};
    HYBRID_PUBLIC_KEY root_key;

    hybrid_public_key_init(&root_key);
    if (root == NULL) {
        goto done;
    }
    local.issuer_subject_link_valid =
        X509_NAME_cmp(X509_get_issuer_name(root),
                      X509_get_subject_name(root)) == 0;
    local.validity_valid = certificate_time_valid(root);
    local.issuer_ca_constraints_valid =
        certificate_constraints_valid(root, 1);
    local.subject_constraints_valid = local.issuer_ca_constraints_valid;
    local.eku_valid = 1;
    local.san_valid = 1;
    local.key_identifiers_valid = subject_key_identifier_present(root);
    local.pqc_extension_present = hybrid_x509_has_pqc_extension(root);
    local.composite_oids_valid =
        hybrid_x509_composite_signature_algorithms_valid(root);
    local.subject_public_key_composite =
        hybrid_x509_subject_public_key_is_composite(root);
    local.composite_public_key_valid =
        hybrid_x509_get_composite_public_key(root, &root_key);
    if (local.composite_public_key_valid) {
        (void)verify_certificate_signature(root, &root_key, &local);
    }
    local.certificate_valid =
        local.issuer_subject_link_valid && local.validity_valid &&
        local.issuer_ca_constraints_valid && local.pqc_extension_present &&
        local.key_identifiers_valid && local.composite_oids_valid &&
        local.subject_public_key_composite &&
        local.composite_public_key_valid && local.composite_valid;

done:
    hybrid_public_key_cleanup(&root_key);
    if (result != NULL) {
        *result = local;
    }
    return local.certificate_valid;
}

int hybrid_verify_certificate(X509 *certificate, X509 *issuer_certificate,
                              HYBRID_CERT_VERIFY_RESULT *result)
{
    HYBRID_CERT_VERIFY_RESULT local = {0};
    HYBRID_PUBLIC_KEY issuer_key;

    hybrid_public_key_init(&issuer_key);
    if (certificate == NULL || issuer_certificate == NULL) {
        goto done;
    }
    local.issuer_subject_link_valid =
        X509_NAME_cmp(X509_get_issuer_name(certificate),
                      X509_get_subject_name(issuer_certificate)) == 0;
    local.validity_valid = certificate_time_valid(certificate);
    local.issuer_ca_constraints_valid =
        certificate_constraints_valid(issuer_certificate, 1);
    local.subject_constraints_valid =
        certificate_constraints_valid(certificate, 0);
    local.eku_valid = server_eku_valid(certificate);
    local.san_valid = server_san_valid(certificate);
    local.key_identifiers_valid =
        server_key_identifiers_valid(certificate, issuer_certificate);
    local.pqc_extension_present =
        hybrid_x509_has_pqc_extension(certificate);
    local.composite_oids_valid =
        hybrid_x509_composite_signature_algorithms_valid(certificate);
    local.subject_public_key_composite =
        hybrid_x509_subject_public_key_is_composite(certificate);
    local.composite_public_key_valid =
        hybrid_x509_get_composite_public_key(issuer_certificate, &issuer_key);
    if (local.composite_public_key_valid) {
        (void)verify_certificate_signature(certificate, &issuer_key, &local);
    }
    local.certificate_valid =
        local.issuer_subject_link_valid && local.validity_valid &&
        local.issuer_ca_constraints_valid &&
        local.subject_constraints_valid && local.eku_valid && local.san_valid &&
        local.key_identifiers_valid && local.pqc_extension_present &&
        local.composite_oids_valid &&
        local.subject_public_key_composite &&
        local.composite_public_key_valid && local.composite_valid;

done:
    hybrid_public_key_cleanup(&issuer_key);
    if (result != NULL) {
        *result = local;
    }
    return local.certificate_valid;
}

int hybrid_verify_encryption_certificate(
    X509 *certificate, X509 *issuer_certificate,
    HYBRID_CERT_VERIFY_RESULT *result)
{
    HYBRID_CERT_VERIFY_RESULT local = {0};
    HYBRID_PUBLIC_KEY issuer_key;

    hybrid_public_key_init(&issuer_key);
    if (certificate == NULL || issuer_certificate == NULL) {
        goto done;
    }
    local.issuer_subject_link_valid =
        X509_NAME_cmp(X509_get_issuer_name(certificate),
                      X509_get_subject_name(issuer_certificate)) == 0;
    local.validity_valid = certificate_time_valid(certificate);
    local.issuer_ca_constraints_valid =
        certificate_constraints_valid(issuer_certificate, 1);
    local.subject_constraints_valid =
        encryption_certificate_constraints_valid(certificate);
    local.eku_valid = 1;
    local.san_valid = 1;
    local.key_identifiers_valid =
        server_key_identifiers_valid(certificate, issuer_certificate);
    local.pqc_extension_present =
        hybrid_x509_has_pqc_extension(certificate);
    local.composite_oids_valid =
        hybrid_x509_composite_signature_algorithms_valid(certificate);
    local.subject_public_key_sm2 =
        hybrid_x509_subject_public_key_is_sm2(certificate);
    local.composite_public_key_valid =
        hybrid_x509_get_composite_public_key(issuer_certificate, &issuer_key);
    if (local.composite_public_key_valid) {
        (void)verify_certificate_signature(certificate, &issuer_key, &local);
    }
    local.certificate_valid =
        local.issuer_subject_link_valid && local.validity_valid &&
        local.issuer_ca_constraints_valid &&
        local.subject_constraints_valid && local.key_identifiers_valid &&
        local.pqc_extension_present && local.composite_oids_valid &&
        local.subject_public_key_sm2 &&
        local.composite_public_key_valid && local.composite_valid;

done:
    hybrid_public_key_cleanup(&issuer_key);
    if (result != NULL) {
        *result = local;
    }
    return local.certificate_valid;
}

int hybrid_verify_chain(X509 *root, X509 *server,
                        HYBRID_CHAIN_VERIFY_RESULT *result)
{
    HYBRID_CHAIN_VERIFY_RESULT local;

    memset(&local, 0, sizeof(local));
    if (root != NULL) {
        local.trust_anchor_configured = 1;
    }
    (void)hybrid_verify_root_self_signature(root, &local.root);
    (void)hybrid_verify_certificate(server, root, &local.server);
    local.chain_valid = local.trust_anchor_configured &&
                        local.root.certificate_valid &&
                        local.server.certificate_valid;
    if (result != NULL) {
        *result = local;
    }
    return local.chain_valid;
}
