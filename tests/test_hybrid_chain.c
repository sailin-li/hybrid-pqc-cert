#include "composite_key.h"
#include "composite_sig.h"
#include "hybrid_chain.h"
#include "hybrid_x509.h"

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition, text) do { \
    if (!(condition)) { fprintf(stderr, "FAIL: %s\n", text); goto done; } \
} while (0)

static X509 *duplicate_certificate(const X509 *certificate)
{
    return X509_dup(certificate);
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

static int make_bad_but_valid_sm2_signature(const uint8_t *signature,
                                             size_t signature_len,
                                             uint8_t **changed,
                                             size_t *changed_len)
{
    const uint8_t *dilithium = NULL;
    size_t dilithium_len = 0;
    const uint8_t *sm2_der = NULL;
    size_t sm2_der_len = 0;
    const unsigned char *cursor;
    ECDSA_SIG *sm2 = NULL;
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;
    BIGNUM *changed_r = NULL;
    BIGNUM *changed_s = NULL;
    unsigned char *changed_der = NULL;
    int changed_der_len;
    int ok = 0;

    if (changed == NULL || changed_len == NULL) {
        return 0;
    }
    *changed = NULL;
    *changed_len = 0;
    if (!composite_parse_signature(signature, signature_len,
                                   &dilithium, &dilithium_len,
                                   &sm2_der, &sm2_der_len)) {
        goto done;
    }
    cursor = sm2_der;
    sm2 = d2i_ECDSA_SIG(NULL, &cursor, (long)sm2_der_len);
    if (sm2 == NULL || cursor != sm2_der + sm2_der_len) {
        goto done;
    }
    ECDSA_SIG_get0(sm2, &r, &s);
    changed_r = BN_dup(r);
    changed_s = BN_dup(s);
    if (changed_r == NULL || changed_s == NULL ||
        !BN_add_word(changed_r, 1) ||
        !ECDSA_SIG_set0(sm2, changed_r, changed_s)) {
        goto done;
    }
    changed_r = NULL;
    changed_s = NULL;
    changed_der_len = i2d_ECDSA_SIG(sm2, &changed_der);
    if (changed_der_len <= 0 ||
        !composite_serialize_signature(dilithium, dilithium_len,
                                       changed_der,
                                       (size_t)changed_der_len,
                                       changed, changed_len)) {
        goto done;
    }
    ok = 1;

done:
    OPENSSL_free(changed_der);
    BN_free(changed_r);
    BN_free(changed_s);
    ECDSA_SIG_free(sm2);
    return ok;
}

static int remove_pqc_extension(X509 *certificate)
{
    ASN1_OBJECT *object = NULL;
    X509_EXTENSION *extension = NULL;
    int index;

    object = OBJ_txt2obj(HYBRID_PQC_EXTENSION_OID, 1);
    if (object == NULL) {
        return 0;
    }
    index = X509_get_ext_by_OBJ(certificate, object, -1);
    ASN1_OBJECT_free(object);
    if (index < 0) {
        return 0;
    }
    extension = X509_delete_ext(certificate, index);
    if (extension == NULL) {
        return 0;
    }
    X509_EXTENSION_free(extension);
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

int main(void)
{
    HYBRID_PRIVATE_KEY ca_private;
    HYBRID_PUBLIC_KEY ca_public;
    HYBRID_PRIVATE_KEY server_private;
    HYBRID_PUBLIC_KEY server_public;
    HYBRID_PRIVATE_KEY wrong_private;
    HYBRID_PUBLIC_KEY wrong_public;
    HYBRID_PUBLIC_KEY mixed_public;
    X509 *root = NULL;
    X509 *server = NULL;
    X509 *changed = NULL;
    X509 *wrong_issuer = NULL;
    HYBRID_CHAIN_VERIFY_RESULT chain_result;
    HYBRID_CERT_VERIFY_RESULT result;
    const uint8_t *signature = NULL;
    size_t signature_len = 0;
    uint8_t *changed_signature = NULL;
    size_t changed_signature_len = 0;
    X509_NAME *subject;
    int ok = EXIT_FAILURE;

    hybrid_private_key_init(&ca_private);
    hybrid_public_key_init(&ca_public);
    hybrid_private_key_init(&server_private);
    hybrid_public_key_init(&server_public);
    hybrid_private_key_init(&wrong_private);
    hybrid_public_key_init(&wrong_public);
    hybrid_public_key_init(&mixed_public);
    CHECK(composite_key_generate(&ca_private, &ca_public), "CA keys");
    CHECK(composite_key_generate(&server_private, &server_public),
          "server keys");
    CHECK(composite_key_generate(&wrong_private, &wrong_public), "wrong keys");
    CHECK((root = hybrid_x509_create_root(&ca_private, &ca_public,
                                          "Root Hybrid CA")) != NULL,
          "root certificate");
    CHECK((server = hybrid_x509_create_server(
               &ca_private, &ca_public, &server_public, root,
               HYBRID_DEFAULT_SERVER_NAME,
               HYBRID_DEFAULT_SERVER_NAME)) != NULL,
          "server certificate");
    CHECK(hybrid_x509_get_signature(server, &signature, &signature_len),
          "get server signature");

    CHECK(hybrid_verify_chain(root, server, &chain_result),
          "1: valid Root -> Server chain");
    puts("PASS 1: normal Root -> Server -> VALID");

    changed = duplicate_certificate(server);
    changed_signature = OPENSSL_memdup(signature, signature_len);
    CHECK(changed != NULL && changed_signature != NULL,
          "2: duplicate server/signature");
    changed_signature[0] ^= 1u;
    CHECK(replace_signature(changed, changed_signature, signature_len) &&
          !hybrid_verify_certificate(changed, root, &result) &&
          !result.dilithium_valid && result.sm2_valid &&
          !result.composite_valid,
          "2: bad Dilithium signature accepted");
    puts("PASS 2: Dilithium signature byte changed -> Dilithium FAIL, Composite FAIL");
    OPENSSL_free(changed_signature);
    changed_signature = NULL;
    X509_free(changed);
    changed = NULL;

    CHECK(make_bad_but_valid_sm2_signature(signature, signature_len,
                                            &changed_signature,
                                            &changed_signature_len),
          "3: build changed SM2 DER");
    changed = duplicate_certificate(server);
    CHECK(changed != NULL &&
          replace_signature(changed, changed_signature,
                            changed_signature_len) &&
          !hybrid_verify_certificate(changed, root, &result) &&
          result.dilithium_valid && !result.sm2_valid &&
          !result.composite_valid,
          "3: bad SM2 signature accepted");
    puts("PASS 3: SM2 DER signature changed -> SM2 FAIL, Composite FAIL");
    OPENSSL_free(changed_signature);
    changed_signature = NULL;
    X509_free(changed);
    changed = NULL;

    CHECK(EVP_PKEY_up_ref(wrong_public.sm2_public_key), "4: SM2 ref");
    mixed_public.sm2_public_key = wrong_public.sm2_public_key;
    memcpy(mixed_public.dilithium_public_key, ca_public.dilithium_public_key,
           sizeof(mixed_public.dilithium_public_key));
    wrong_issuer = hybrid_x509_create_root(&ca_private, &mixed_public,
                                           "Root Hybrid CA");
    CHECK(wrong_issuer != NULL &&
          !hybrid_verify_certificate(server, wrong_issuer, &result) &&
          result.dilithium_valid && !result.sm2_valid,
          "4: wrong CA SM2 public key accepted");
    puts("PASS 4: wrong CA SM2 public key -> INVALID");
    X509_free(wrong_issuer);
    wrong_issuer = NULL;
    hybrid_public_key_cleanup(&mixed_public);

    CHECK(EVP_PKEY_up_ref(ca_public.sm2_public_key), "5: SM2 ref");
    mixed_public.sm2_public_key = ca_public.sm2_public_key;
    memcpy(mixed_public.dilithium_public_key,
           wrong_public.dilithium_public_key,
           sizeof(mixed_public.dilithium_public_key));
    wrong_issuer = hybrid_x509_create_root(&ca_private, &mixed_public,
                                           "Root Hybrid CA");
    CHECK(wrong_issuer != NULL &&
          !hybrid_verify_certificate(server, wrong_issuer, &result) &&
          !result.dilithium_valid && result.sm2_valid,
          "5: wrong CA Dilithium public key accepted");
    puts("PASS 5: wrong CA Dilithium public key -> INVALID");
    X509_free(wrong_issuer);
    wrong_issuer = NULL;
    hybrid_public_key_cleanup(&mixed_public);

    changed = duplicate_certificate(server);
    subject = changed != NULL ? X509_get_subject_name(changed) : NULL;
    CHECK(subject != NULL &&
          X509_NAME_add_entry_by_txt(subject, "OU", MBSTRING_ASC,
                                     (const unsigned char *)"tampered",
                                     -1, -1, 0) &&
          !hybrid_verify_certificate(changed, root, &result) &&
          !result.composite_valid,
          "6: modified TBS accepted");
    puts("PASS 6: TBSCertificate subject changed without resigning -> INVALID");
    X509_free(changed);
    changed = NULL;

    changed = duplicate_certificate(server);
    CHECK(changed != NULL &&
          replace_signature(changed, signature,
                            DILITHIUM_SIGNATURE_BYTES) &&
          !hybrid_verify_certificate(changed, root, &result) &&
          !result.signature_format_valid,
          "7: missing SM2 component accepted");
    puts("PASS 7: missing signature component -> INVALID");
    X509_free(changed);
    changed = NULL;

    changed = duplicate_certificate(server);
    CHECK(changed != NULL &&
          replace_signature(changed, signature, signature_len - 1u) &&
          !hybrid_verify_certificate(changed, root, &result),
          "8: truncated signature accepted");
    puts("PASS 8: truncated Composite signature -> INVALID");
    X509_free(changed);
    changed = NULL;

    changed = duplicate_certificate(server);
    CHECK(changed != NULL && set_tbs_signature_oid(changed, "1.2.3.4") &&
          !hybrid_verify_certificate(changed, root, &result) &&
          !result.composite_oids_valid,
          "9: mismatched signature OID accepted");
    puts("PASS 9: inner/outer signatureAlgorithm mismatch -> INVALID");
    X509_free(changed);
    changed = NULL;

    changed = duplicate_certificate(server);
    CHECK(changed != NULL && remove_pqc_extension(changed) &&
          !hybrid_verify_certificate(changed, root, &result) &&
          !result.pqc_extension_present,
          "10: missing required PQC marker accepted");
    puts("PASS 10: missing 1.3.6.1.4.1.2.267.7 extension -> INVALID");
    X509_free(changed);
    changed = NULL;

    changed_signature = OPENSSL_memdup(signature, signature_len);
    changed = duplicate_certificate(server);
    CHECK(changed_signature != NULL && changed != NULL,
          "11: duplicate signature");
    changed_signature[0] ^= 1u;
    CHECK(replace_signature(changed, changed_signature, signature_len) &&
          !hybrid_verify_certificate(changed, root, &result) &&
          result.sm2_valid && !result.dilithium_valid &&
          !result.certificate_valid,
          "11: SM2-only acceptance");
    puts("PASS 11: SM2-only success is not accepted");
    OPENSSL_free(changed_signature);
    changed_signature = NULL;
    X509_free(changed);
    changed = NULL;

    CHECK(make_bad_but_valid_sm2_signature(signature, signature_len,
                                            &changed_signature,
                                            &changed_signature_len),
          "12: build changed SM2 DER");
    changed = duplicate_certificate(server);
    CHECK(changed != NULL &&
          replace_signature(changed, changed_signature,
                            changed_signature_len) &&
          !hybrid_verify_certificate(changed, root, &result) &&
          result.dilithium_valid && !result.sm2_valid &&
          !result.certificate_valid,
          "12: Dilithium-only acceptance");
    puts("PASS 12: Dilithium-only success is not accepted");

    puts("PASS: all Root -> Server positive and negative chain tests");
    ok = EXIT_SUCCESS;

done:
    OPENSSL_free(changed_signature);
    X509_free(wrong_issuer);
    X509_free(changed);
    X509_free(server);
    X509_free(root);
    hybrid_public_key_cleanup(&mixed_public);
    hybrid_public_key_cleanup(&wrong_public);
    hybrid_private_key_cleanup(&wrong_private);
    hybrid_public_key_cleanup(&server_public);
    hybrid_private_key_cleanup(&server_private);
    hybrid_public_key_cleanup(&ca_public);
    hybrid_private_key_cleanup(&ca_private);
    return ok;
}
