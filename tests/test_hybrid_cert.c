#include "dilithium_wrapper.h"
#include "hybrid_cert.h"
#include "hybrid_verify.h"
#include "sm2_wrapper.h"

#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
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

static X509 *tamper_outer_signature(const X509 *certificate)
{
    unsigned char *der = NULL;
    unsigned char *cursor;
    const unsigned char *read_cursor;
    X509 *changed = NULL;
    int der_len = i2d_X509(certificate, &der);

    if (der_len <= 0) {
        return NULL;
    }
    der[der_len - 1] ^= 1u;
    read_cursor = der;
    changed = d2i_X509(NULL, &read_cursor, der_len);
    cursor = der;
    OPENSSL_free(cursor);
    return changed;
}

static int replace_with_malformed_extension(X509 *certificate)
{
    static const unsigned char malformed_der[] = {0x30, 0x03, 0x02, 0x01};
    ASN1_OBJECT *object = NULL;
    ASN1_OCTET_STRING *data = NULL;
    X509_EXTENSION *extension = NULL;
    X509_EXTENSION *old = NULL;
    int index;
    int ok = 0;

    object = OBJ_txt2obj(HYBRID_PQC_EXTENSION_OID, 1);
    data = ASN1_OCTET_STRING_new();
    if (object == NULL || data == NULL ||
        !ASN1_OCTET_STRING_set(data, malformed_der,
                               (int)sizeof(malformed_der))) {
        goto done;
    }
    extension = X509_EXTENSION_create_by_OBJ(NULL, object, 0, data);
    index = X509_get_ext_by_OBJ(certificate, object, -1);
    if (extension == NULL || index < 0) {
        goto done;
    }
    old = X509_delete_ext(certificate, index);
    X509_EXTENSION_free(old);
    old = NULL;
    ok = X509_add_ext(certificate, extension, index);

done:
    X509_EXTENSION_free(old);
    X509_EXTENSION_free(extension);
    ASN1_OCTET_STRING_free(data);
    ASN1_OBJECT_free(object);
    return ok;
}

int main(void)
{
    uint8_t public_key[DILITHIUM_PUBLIC_KEY_BYTES];
    uint8_t secret_key[DILITHIUM_SECRET_KEY_BYTES];
    EVP_PKEY *sm2_key = NULL;
    X509 *certificate = NULL;
    X509 *changed = NULL;
    HYBRID_PQC_INFO info;
    HYBRID_VERIFY_RESULT result;
    X509_NAME *subject;
    int ok = EXIT_FAILURE;

    hybrid_pqc_info_init(&info);
    CHECK((sm2_key = sm2_generate_keypair()) != NULL, "SM2 keypair");
    CHECK(dilithium_generate_keypair(public_key, sizeof(public_key),
                                     secret_key, sizeof(secret_key)),
          "Dilithium keypair");
    CHECK((certificate = hybrid_cert_generate(sm2_key, public_key,
                                               sizeof(public_key), secret_key,
                                               sizeof(secret_key),
                                               "Hybrid Certificate Test")) != NULL,
          "certificate generation");

    if (!hybrid_cert_verify(certificate, HYBRID_VERIFY_STRICT, &result)) {
        fprintf(stderr, "baseline details: SM2=%d extension=%d info=%d "
                        "algorithm=%d Dilithium=%d hybrid=%d\n",
                result.sm2_valid, result.pqc_extension_present,
                result.pqc_info_valid, result.pqc_algorithm_known,
                result.dilithium_valid, result.hybrid_valid);
    }
    CHECK(result.sm2_valid && result.dilithium_valid && result.hybrid_valid,
          "1: valid certificate");
    puts("PASS 1: SM2 OK + Dilithium OK -> hybrid PASS");

    changed = tamper_outer_signature(certificate);
    CHECK(changed != NULL &&
          !hybrid_cert_verify(changed, HYBRID_VERIFY_STRICT, &result) &&
          !result.sm2_valid, "2: modified SM2 signature");
    puts("PASS 2: modified outer SM2 signature -> FAIL");
    X509_free(changed);
    changed = NULL;

    changed = duplicate_certificate(certificate);
    CHECK(changed != NULL && hybrid_cert_get_pqc_info(changed, &info),
          "3: read PQC signature");
    info.signature[0] ^= 1u;
    CHECK(hybrid_cert_set_pqc_info(changed, &info) &&
          !hybrid_cert_verify(changed, HYBRID_VERIFY_STRICT, NULL),
          "3: modified PQC signature");
    puts("PASS 3: modified PQC signature -> FAIL");
    hybrid_pqc_info_cleanup(&info);
    X509_free(changed);
    changed = NULL;

    changed = duplicate_certificate(certificate);
    CHECK(changed != NULL && hybrid_cert_get_pqc_info(changed, &info),
          "4: read PQC public key");
    info.public_key[0] ^= 1u;
    CHECK(hybrid_cert_set_pqc_info(changed, &info) &&
          !hybrid_cert_verify(changed, HYBRID_VERIFY_STRICT, NULL),
          "4: modified PQC public key");
    puts("PASS 4: modified Dilithium public key -> FAIL");
    hybrid_pqc_info_cleanup(&info);
    X509_free(changed);
    changed = NULL;

    changed = duplicate_certificate(certificate);
    CHECK(changed != NULL && hybrid_cert_remove_pqc_extension(changed) &&
          hybrid_cert_sign_sm2(changed, sm2_key), "5: remove and re-sign");
    CHECK(!hybrid_cert_verify(changed, HYBRID_VERIFY_STRICT, NULL),
          "5: strict accepted missing extension");
    CHECK(hybrid_cert_verify(changed, HYBRID_VERIFY_CLASSICAL_COMPAT, &result) &&
          result.sm2_valid, "5: compatibility rejected SM2-valid certificate");
    puts("PASS 5: missing PQC extension -> STRICT FAIL, COMPAT PASS");
    X509_free(changed);
    changed = NULL;

    changed = duplicate_certificate(certificate);
    CHECK(changed != NULL && replace_with_malformed_extension(changed) &&
          hybrid_cert_sign_sm2(changed, sm2_key) &&
          !hybrid_cert_verify(changed, HYBRID_VERIFY_STRICT, NULL),
          "6: malformed PQC ASN.1");
    puts("PASS 6: malformed PQC ASN.1 -> safe FAIL");
    X509_free(changed);
    changed = NULL;

    changed = duplicate_certificate(certificate);
    CHECK(changed != NULL && hybrid_cert_get_pqc_info(changed, &info),
          "7: read algorithm");
    memcpy(info.algorithm_oid, "1.3.6.1.4.1.2.267.7.99",
           sizeof("1.3.6.1.4.1.2.267.7.99"));
    CHECK(hybrid_cert_set_pqc_info(changed, &info) &&
          hybrid_cert_sign_sm2(changed, sm2_key) &&
          !hybrid_cert_verify(changed, HYBRID_VERIFY_STRICT, &result) &&
          result.sm2_valid && !result.pqc_algorithm_known,
          "7: unknown PQC algorithm did not fail closed");
    puts("PASS 7: unknown PQC algorithm -> fail closed");
    hybrid_pqc_info_cleanup(&info);
    X509_free(changed);
    changed = NULL;

    changed = duplicate_certificate(certificate);
    subject = changed != NULL ? X509_get_subject_name(changed) : NULL;
    CHECK(subject != NULL &&
          X509_NAME_add_entry_by_txt(subject, "OU", MBSTRING_ASC,
                                     (const unsigned char *)"tampered",
                                     -1, -1, 0) &&
          !hybrid_cert_verify(changed, HYBRID_VERIFY_STRICT, NULL),
          "8: modified subject");
    puts("PASS 8: modified certificate subject -> FAIL");
    X509_free(changed);
    changed = NULL;

    changed = duplicate_certificate(certificate);
    CHECK(changed != NULL && hybrid_cert_get_pqc_info(changed, &info),
          "9: read PQC signature");
    info.signature[0] ^= 1u;
    CHECK(hybrid_cert_set_pqc_info(changed, &info) &&
          hybrid_cert_sign_sm2(changed, sm2_key),
          "9: modify PQC signature and re-sign SM2");
    CHECK(!hybrid_cert_verify(changed, HYBRID_VERIFY_STRICT, &result) &&
          result.sm2_valid && !result.dilithium_valid,
          "9: SM2 passed but hybrid verification did not reject bad PQC");
    puts("PASS 9: re-signed bad PQC -> SM2 PASS, Dilithium/Hybrid FAIL");
    hybrid_pqc_info_cleanup(&info);

    puts("PASS: all hybrid certificate positive and negative tests");
    ok = EXIT_SUCCESS;

done:
    hybrid_pqc_info_cleanup(&info);
    X509_free(changed);
    X509_free(certificate);
    EVP_PKEY_free(sm2_key);
    dilithium_clear_secret_key(secret_key, sizeof(secret_key));
    return ok;
}
