#include "composite_key.h"
#include "composite_sig.h"
#include "hybrid_chain.h"
#include "hybrid_x509.h"
#include "sm2_wrapper.h"
#include "tlcp_hybrid_cert_adapter.h"

#include <openssl/crypto.h>
#include <openssl/x509.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition, text) do { \
    if (!(condition)) { fprintf(stderr, "FAIL: %s\n", text); goto done; } \
} while (0)

static int certificate_to_der(X509 *certificate,
                              uint8_t **der, size_t *der_len)
{
    unsigned char *encoded = NULL;
    int length = i2d_X509(certificate, &encoded);

    if (length <= 0) {
        return 0;
    }
    *der = encoded;
    *der_len = (size_t)length;
    return 1;
}

static int replace_signature(X509 *certificate,
                             const uint8_t *signature, size_t signature_len)
{
    const ASN1_BIT_STRING *current = NULL;
    ASN1_BIT_STRING *mutable;

    if (certificate == NULL || signature == NULL || signature_len > INT_MAX) {
        return 0;
    }
    X509_get0_signature(&current, NULL, certificate);
    mutable = (ASN1_BIT_STRING *)current;
    if (mutable == NULL ||
        !ASN1_BIT_STRING_set(mutable, (unsigned char *)signature,
                             (int)signature_len)) {
        return 0;
    }
    mutable->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    mutable->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    return 1;
}

static int set_tbs_signature_oid(X509 *certificate, const char *oid)
{
    X509_ALGOR *algorithm =
        (X509_ALGOR *)X509_get0_tbs_sigalg(certificate);
    ASN1_OBJECT *object = OBJ_txt2obj(oid, 1);

    if (algorithm == NULL || object == NULL) {
        ASN1_OBJECT_free(object);
        return 0;
    }
    X509_ALGOR_set0(algorithm, object, V_ASN1_UNDEF, NULL);
    return 1;
}

static int remove_pqc_marker(X509 *certificate)
{
    ASN1_OBJECT *object = OBJ_txt2obj(HYBRID_PQC_EXTENSION_OID, 1);
    X509_EXTENSION *extension = NULL;
    int index;
    int found;

    if (object == NULL) {
        return 0;
    }
    index = X509_get_ext_by_OBJ(certificate, object, -1);
    ASN1_OBJECT_free(object);
    if (index < 0) {
        return 0;
    }
    extension = X509_delete_ext(certificate, index);
    found = extension != NULL;
    X509_EXTENSION_free(extension);
    return found;
}

static int make_wrong_sm2_signature(X509 *certificate,
                                    uint8_t **output, size_t *output_len)
{
    const uint8_t *signature = NULL;
    size_t signature_len = 0;
    const uint8_t *dilithium = NULL;
    size_t dilithium_len = 0;
    const uint8_t *sm2 = NULL;
    size_t sm2_len = 0;
    uint8_t *tbs = NULL;
    size_t tbs_len = 0;
    uint8_t *wrong_sm2 = NULL;
    size_t wrong_sm2_len = 0;
    EVP_PKEY *wrong_key = NULL;
    int ok = 0;

    *output = NULL;
    *output_len = 0;
    wrong_key = hybrid_sm2_generate_keypair();
    if (wrong_key == NULL ||
        !hybrid_x509_get_signature(certificate, &signature, &signature_len) ||
        !composite_parse_signature(signature, signature_len,
                                   &dilithium, &dilithium_len,
                                   &sm2, &sm2_len) ||
        !hybrid_x509_get_tbs_der(certificate, &tbs, &tbs_len) ||
        !hybrid_sm2_sign(wrong_key, tbs, tbs_len,
                         &wrong_sm2, &wrong_sm2_len) ||
        !composite_serialize_signature(dilithium, dilithium_len,
                                       wrong_sm2, wrong_sm2_len,
                                       output, output_len)) {
        goto done;
    }
    ok = 1;

done:
    EVP_PKEY_free(wrong_key);
    OPENSSL_free(wrong_sm2);
    OPENSSL_free(tbs);
    return ok;
}

static int make_chain_der(X509 *signing, X509 *encryption,
                          uint8_t **chain, size_t *chain_len)
{
    uint8_t *signing_der = NULL;
    size_t signing_der_len = 0;
    uint8_t *encryption_der = NULL;
    size_t encryption_der_len = 0;
    int ok = 0;

    *chain = NULL;
    *chain_len = 0;
    if (!certificate_to_der(signing, &signing_der, &signing_der_len) ||
        !certificate_to_der(encryption, &encryption_der,
                            &encryption_der_len) ||
        signing_der_len > SIZE_MAX - encryption_der_len) {
        goto done;
    }
    *chain_len = signing_der_len + encryption_der_len;
    *chain = OPENSSL_malloc(*chain_len);
    if (*chain == NULL) {
        *chain_len = 0;
        goto done;
    }
    memcpy(*chain, signing_der, signing_der_len);
    memcpy(*chain + signing_der_len, encryption_der, encryption_der_len);
    ok = 1;

done:
    OPENSSL_free(encryption_der);
    OPENSSL_free(signing_der);
    return ok;
}

static int set_mixed_public_key(HYBRID_PUBLIC_KEY *mixed,
                                EVP_PKEY *sm2_key,
                                const uint8_t dilithium_key[
                                    DILITHIUM_PUBLIC_KEY_BYTES])
{
    hybrid_public_key_init(mixed);
    if (sm2_key == NULL || !EVP_PKEY_up_ref(sm2_key)) {
        return 0;
    }
    mixed->sm2_public_key = sm2_key;
    memcpy(mixed->dilithium_public_key, dilithium_key,
           DILITHIUM_PUBLIC_KEY_BYTES);
    return 1;
}

int main(void)
{
    HYBRID_PRIVATE_KEY ca_private;
    HYBRID_PUBLIC_KEY ca_public;
    HYBRID_PRIVATE_KEY signing_private;
    HYBRID_PUBLIC_KEY signing_public;
    HYBRID_PRIVATE_KEY wrong_private;
    HYBRID_PUBLIC_KEY wrong_public;
    HYBRID_PUBLIC_KEY mixed_public;
    EVP_PKEY *encryption_key = NULL;
    X509 *root = NULL;
    X509 *signing = NULL;
    X509 *encryption = NULL;
    X509 *changed = NULL;
    X509 *wrong_issuer = NULL;
    uint8_t *root_der = NULL;
    size_t root_der_len = 0;
    uint8_t *chain = NULL;
    size_t chain_len = 0;
    const uint8_t *signature = NULL;
    size_t signature_len = 0;
    const uint8_t *dilithium = NULL;
    size_t dilithium_len = 0;
    const uint8_t *sm2 = NULL;
    size_t sm2_len = 0;
    uint8_t *changed_signature = NULL;
    size_t changed_signature_len = 0;
    uint8_t sm2_public_key[SM2_UNCOMPRESSED_PUBLIC_KEY_BYTES];
    HYBRID_CERT_VERIFY_RESULT verify;
    TLCP_HYBRID_CERT_VERIFY_REPORT report;
    TLCP_HYBRID_CERT_ADAPTER_CONFIG config;
    int ok = EXIT_FAILURE;

    hybrid_private_key_init(&ca_private);
    hybrid_public_key_init(&ca_public);
    hybrid_private_key_init(&signing_private);
    hybrid_public_key_init(&signing_public);
    hybrid_private_key_init(&wrong_private);
    hybrid_public_key_init(&wrong_public);
    hybrid_public_key_init(&mixed_public);
    CHECK(composite_key_generate(&ca_private, &ca_public) &&
          composite_key_generate(&signing_private, &signing_public) &&
          composite_key_generate(&wrong_private, &wrong_public), "keys");
    encryption_key = hybrid_sm2_generate_keypair();
    root = hybrid_x509_create_root(&ca_private, &ca_public,
                                   "Root Hybrid CA");
    signing = hybrid_x509_create_server(
        &ca_private, &ca_public, &signing_public, root,
        HYBRID_DEFAULT_SERVER_NAME, HYBRID_DEFAULT_SERVER_NAME);
    encryption = hybrid_x509_create_sm2_encryption(
        &ca_private, &ca_public, encryption_key, root,
        HYBRID_DEFAULT_SERVER_NAME);
    CHECK(root != NULL && signing != NULL && encryption != NULL,
          "certificates");
    CHECK(hybrid_x509_subject_public_key_is_sm2(encryption) &&
          !hybrid_x509_subject_public_key_is_composite(encryption) &&
          hybrid_x509_composite_signature_algorithms_valid(encryption) &&
          hybrid_x509_has_pqc_extension(encryption) &&
          hybrid_x509_sm2_public_key_matches(encryption, encryption_key),
          "encryption certificate fields");
    CHECK(hybrid_x509_get_signature(encryption, &signature, &signature_len) &&
          composite_parse_signature(signature, signature_len,
                                    &dilithium, &dilithium_len,
                                    &sm2, &sm2_len) &&
          signature_len == dilithium_len + sm2_len,
          "encryption Composite signatureValue");
    puts("PASS 1: encryption SPKI=SM2, CertSig=Composite, marker present");

    CHECK(hybrid_verify_encryption_certificate(encryption, root, &verify) &&
          verify.subject_public_key_sm2 && verify.dilithium_valid &&
          verify.sm2_valid && verify.composite_valid,
          "valid encryption certificate");
    puts("PASS 2: encryption Dilithium + SM2 strict AND");

    CHECK(certificate_to_der(root, &root_der, &root_der_len) &&
          make_chain_der(signing, encryption, &chain, &chain_len),
          "dual chain DER");
    memset(&config, 0, sizeof(config));
    config.trust_anchor_der = root_der;
    config.trust_anchor_der_len = root_der_len;
    config.expected_hostname = HYBRID_DEFAULT_SERVER_NAME;
    config.last_report = &report;
    CHECK(tlcp_hybrid_cert_gmssl_verify_callback(
              chain, chain_len, sm2_public_key, &config, 0) ==
              TLCP_HYBRID_CERT_VALID &&
          report.composite_ok && report.encryption_composite_ok &&
          report.tlcp_dual_certificate_ok,
          "valid dual Certificate message");
    puts("PASS 3: signing + encryption Certificate message VALID");
    OPENSSL_free(chain);
    chain = NULL;

    changed = X509_dup(encryption);
    changed_signature = OPENSSL_memdup(signature, signature_len);
    CHECK(changed != NULL && changed_signature != NULL,
          "Dilithium mutation allocation");
    changed_signature[0] ^= 1u;
    CHECK(replace_signature(changed, changed_signature, signature_len) &&
          !hybrid_verify_encryption_certificate(changed, root, &verify) &&
          !verify.dilithium_valid && verify.sm2_valid &&
          !verify.composite_valid,
          "bad encryption Dilithium accepted");
    puts("PASS 4: encryption Dilithium FAIL, SM2 PASS -> INVALID");
    X509_free(changed);
    changed = NULL;
    OPENSSL_free(changed_signature);
    changed_signature = NULL;

    changed = X509_dup(encryption);
    CHECK(changed != NULL &&
          make_wrong_sm2_signature(encryption, &changed_signature,
                                   &changed_signature_len) &&
          replace_signature(changed, changed_signature,
                            changed_signature_len) &&
          !hybrid_verify_encryption_certificate(changed, root, &verify) &&
          verify.dilithium_valid && !verify.sm2_valid &&
          !verify.composite_valid,
          "bad encryption SM2 accepted");
    puts("PASS 5: encryption Dilithium PASS, SM2 FAIL -> INVALID");
    X509_free(changed);
    changed = NULL;
    OPENSSL_free(changed_signature);
    changed_signature = NULL;

    changed = X509_dup(encryption);
    CHECK(changed != NULL && remove_pqc_marker(changed) &&
          !hybrid_verify_encryption_certificate(changed, root, &verify) &&
          !verify.pqc_extension_present,
          "missing encryption marker accepted");
    puts("PASS 6: encryption missing PQC marker -> INVALID");
    X509_free(changed);
    changed = NULL;

    changed = X509_dup(encryption);
    CHECK(changed != NULL && set_tbs_signature_oid(changed, "1.2.3.4") &&
          !hybrid_verify_encryption_certificate(changed, root, &verify) &&
          !verify.composite_oids_valid,
          "encryption OID mismatch accepted");
    puts("PASS 7: encryption inner/outer OID mismatch -> INVALID");
    X509_free(changed);
    changed = NULL;

    CHECK(set_mixed_public_key(&mixed_public, ca_public.sm2_public_key,
                               wrong_public.dilithium_public_key),
          "wrong Dilithium issuer key");
    wrong_issuer = hybrid_x509_create_root(&ca_private, &mixed_public,
                                           "Root Hybrid CA");
    CHECK(wrong_issuer != NULL &&
          !hybrid_verify_encryption_certificate(encryption, wrong_issuer,
                                                &verify) &&
          !verify.dilithium_valid && verify.sm2_valid,
          "wrong issuer Dilithium accepted");
    puts("PASS 8: wrong CA Dilithium key -> INVALID");
    X509_free(wrong_issuer);
    wrong_issuer = NULL;
    hybrid_public_key_cleanup(&mixed_public);

    CHECK(set_mixed_public_key(&mixed_public, wrong_public.sm2_public_key,
                               ca_public.dilithium_public_key),
          "wrong SM2 issuer key");
    wrong_issuer = hybrid_x509_create_root(&ca_private, &mixed_public,
                                           "Root Hybrid CA");
    CHECK(wrong_issuer != NULL &&
          !hybrid_verify_encryption_certificate(encryption, wrong_issuer,
                                                &verify) &&
          verify.dilithium_valid && !verify.sm2_valid,
          "wrong issuer SM2 accepted");
    puts("PASS 9: wrong CA SM2 key -> INVALID");
    X509_free(wrong_issuer);
    wrong_issuer = NULL;
    hybrid_public_key_cleanup(&mixed_public);

    changed = X509_dup(encryption);
    changed_signature = OPENSSL_memdup(signature, signature_len);
    CHECK(changed != NULL && changed_signature != NULL,
          "invalid encryption chain allocation");
    changed_signature[0] ^= 1u;
    CHECK(replace_signature(changed, changed_signature, signature_len) &&
          make_chain_der(signing, changed, &chain, &chain_len) &&
          tlcp_hybrid_cert_gmssl_verify_callback(
              chain, chain_len, sm2_public_key, &config, 0) ==
              TLCP_HYBRID_CERT_INVALID,
          "signing valid/encryption invalid accepted");
    puts("PASS 10: signing VALID + encryption INVALID -> message INVALID");
    OPENSSL_free(chain);
    chain = NULL;
    X509_free(changed);
    changed = NULL;
    OPENSSL_free(changed_signature);
    changed_signature = NULL;

    changed = X509_dup(signing);
    CHECK(changed != NULL &&
          hybrid_x509_get_signature(signing, &signature, &signature_len),
          "signing signature");
    changed_signature = OPENSSL_memdup(signature, signature_len);
    CHECK(changed_signature != NULL, "invalid signing allocation");
    changed_signature[0] ^= 1u;
    CHECK(replace_signature(changed, changed_signature, signature_len) &&
          make_chain_der(changed, encryption, &chain, &chain_len) &&
          tlcp_hybrid_cert_gmssl_verify_callback(
              chain, chain_len, sm2_public_key, &config, 0) ==
              TLCP_HYBRID_CERT_INVALID,
          "signing invalid/encryption valid accepted");
    puts("PASS 11: signing INVALID + encryption VALID -> message INVALID");
    OPENSSL_free(chain);
    chain = NULL;
    X509_free(changed);
    changed = NULL;
    OPENSSL_free(changed_signature);
    changed_signature = NULL;

    changed = X509_dup(encryption);
    CHECK(changed != NULL &&
          X509_sign(changed, ca_private.sm2_private_key, EVP_sm3()) > 0 &&
          !hybrid_verify_encryption_certificate(changed, root, &verify) &&
          !verify.composite_oids_valid &&
          make_chain_der(signing, changed, &chain, &chain_len) &&
          tlcp_hybrid_cert_gmssl_verify_callback(
              chain, chain_len, sm2_public_key, &config, 0) ==
              TLCP_HYBRID_CERT_INVALID,
          "ordinary SM2 CA-signed encryption certificate accepted");
    puts("PASS 12: ordinary SM2 CA-signed encryption cert -> INVALID");

    ok = EXIT_SUCCESS;

done:
    OPENSSL_free(chain);
    OPENSSL_free(changed_signature);
    OPENSSL_free(root_der);
    X509_free(wrong_issuer);
    X509_free(changed);
    X509_free(encryption);
    X509_free(signing);
    X509_free(root);
    EVP_PKEY_free(encryption_key);
    hybrid_public_key_cleanup(&mixed_public);
    hybrid_public_key_cleanup(&wrong_public);
    hybrid_private_key_cleanup(&wrong_private);
    hybrid_public_key_cleanup(&signing_public);
    hybrid_private_key_cleanup(&signing_private);
    hybrid_public_key_cleanup(&ca_public);
    hybrid_private_key_cleanup(&ca_private);
    return ok;
}
