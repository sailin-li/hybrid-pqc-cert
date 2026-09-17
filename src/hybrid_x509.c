#include "hybrid_x509.h"

#include "composite_sig.h"

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <limits.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    ASN1_INTEGER *version;
    ASN1_INTEGER *serial_number;
    X509_ALGOR *signature;
    X509_NAME *issuer;
    X509_VAL *validity;
    X509_NAME *subject;
    X509_PUBKEY *subject_public_key_info;
    ASN1_BIT_STRING *issuer_uid;
    ASN1_BIT_STRING *subject_uid;
    STACK_OF(X509_EXTENSION) *extensions;
} COMPOSITE_TBS_CERTIFICATE;

ASN1_SEQUENCE(COMPOSITE_TBS_CERTIFICATE) = {
    ASN1_EXP_OPT(COMPOSITE_TBS_CERTIFICATE, version, ASN1_INTEGER, 0),
    ASN1_SIMPLE(COMPOSITE_TBS_CERTIFICATE, serial_number, ASN1_INTEGER),
    ASN1_SIMPLE(COMPOSITE_TBS_CERTIFICATE, signature, X509_ALGOR),
    ASN1_SIMPLE(COMPOSITE_TBS_CERTIFICATE, issuer, X509_NAME),
    ASN1_SIMPLE(COMPOSITE_TBS_CERTIFICATE, validity, X509_VAL),
    ASN1_SIMPLE(COMPOSITE_TBS_CERTIFICATE, subject, X509_NAME),
    ASN1_SIMPLE(COMPOSITE_TBS_CERTIFICATE, subject_public_key_info, X509_PUBKEY),
    ASN1_IMP_OPT(COMPOSITE_TBS_CERTIFICATE, issuer_uid, ASN1_BIT_STRING, 1),
    ASN1_IMP_OPT(COMPOSITE_TBS_CERTIFICATE, subject_uid, ASN1_BIT_STRING, 2),
    ASN1_EXP_SEQUENCE_OF_OPT(COMPOSITE_TBS_CERTIFICATE, extensions,
                             X509_EXTENSION, 3)
} ASN1_SEQUENCE_END(COMPOSITE_TBS_CERTIFICATE)

IMPLEMENT_ASN1_FUNCTIONS(COMPOSITE_TBS_CERTIFICATE)

typedef struct {
    COMPOSITE_TBS_CERTIFICATE *tbs_certificate;
    X509_ALGOR *signature_algorithm;
    ASN1_BIT_STRING *signature_value;
} COMPOSITE_CERTIFICATE;

ASN1_SEQUENCE(COMPOSITE_CERTIFICATE) = {
    ASN1_SIMPLE(COMPOSITE_CERTIFICATE, tbs_certificate,
                COMPOSITE_TBS_CERTIFICATE),
    ASN1_SIMPLE(COMPOSITE_CERTIFICATE, signature_algorithm, X509_ALGOR),
    ASN1_SIMPLE(COMPOSITE_CERTIFICATE, signature_value, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(COMPOSITE_CERTIFICATE)

IMPLEMENT_ASN1_FUNCTIONS(COMPOSITE_CERTIFICATE)

static int set_composite_algorithm(X509_ALGOR *algorithm)
{
    ASN1_OBJECT *object;

    if (algorithm == NULL) {
        return 0;
    }
    object = OBJ_txt2obj(COMPOSITE_SM2_DILITHIUM_EXPERIMENTAL_OID, 1);
    if (object == NULL) {
        return 0;
    }
    X509_ALGOR_set0(algorithm, object, V_ASN1_UNDEF, NULL);
    return 1;
}

static X509_NAME *make_name(const char *common_name)
{
    X509_NAME *name = NULL;

    if (common_name == NULL || common_name[0] == '\0') {
        return NULL;
    }
    name = X509_NAME_new();
    if (name == NULL ||
        !X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                                    (const unsigned char *)"CN", -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(
            name, "O", MBSTRING_ASC,
            (const unsigned char *)"Experimental Hybrid PKI", -1, -1, 0) ||
        !X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
                                    (const unsigned char *)common_name,
                                    -1, -1, 0)) {
        X509_NAME_free(name);
        return NULL;
    }
    return name;
}

static int push_extension(STACK_OF(X509_EXTENSION) *extensions,
                          X509_EXTENSION *extension)
{
    if (extensions == NULL || extension == NULL ||
        !sk_X509_EXTENSION_push(extensions, extension)) {
        X509_EXTENSION_free(extension);
        return 0;
    }
    return 1;
}

static int add_conf_extension(STACK_OF(X509_EXTENSION) *extensions,
                              int nid, const char *value)
{
    return push_extension(extensions,
                          X509V3_EXT_conf_nid(NULL, NULL, nid, value));
}

static int add_pqc_marker(STACK_OF(X509_EXTENSION) *extensions)
{
    static const unsigned char der_null[] = {0x05, 0x00};
    ASN1_OBJECT *object = NULL;
    ASN1_OCTET_STRING *value = NULL;
    X509_EXTENSION *extension = NULL;
    int ok = 0;

    object = OBJ_txt2obj(HYBRID_PQC_EXTENSION_OID, 1);
    value = ASN1_OCTET_STRING_new();
    if (object == NULL || value == NULL ||
        !ASN1_OCTET_STRING_set(value, der_null, (int)sizeof(der_null))) {
        goto done;
    }
    extension = X509_EXTENSION_create_by_OBJ(NULL, object, 0, value);
    if (extension == NULL || !sk_X509_EXTENSION_push(extensions, extension)) {
        goto done;
    }
    extension = NULL;
    ok = 1;

done:
    X509_EXTENSION_free(extension);
    ASN1_OCTET_STRING_free(value);
    ASN1_OBJECT_free(object);
    return ok;
}

static int compute_key_identifier(const HYBRID_PUBLIC_KEY *key,
                                  unsigned char digest[32])
{
    uint8_t *serialized = NULL;
    size_t serialized_len = 0;
    unsigned int digest_len = 0;
    int ok = 0;

    if (!composite_serialize_public_key(key, &serialized, &serialized_len) ||
        !EVP_Digest(serialized, serialized_len, digest, &digest_len,
                    EVP_sha256(), NULL) || digest_len != 32u) {
        goto done;
    }
    ok = 1;

done:
    OPENSSL_free(serialized);
    return ok;
}

static int add_subject_key_identifier(STACK_OF(X509_EXTENSION) *extensions,
                                      const HYBRID_PUBLIC_KEY *key)
{
    unsigned char digest[32];
    ASN1_OCTET_STRING *identifier = NULL;
    X509_EXTENSION *extension = NULL;
    int ok = 0;

    if (!compute_key_identifier(key, digest)) {
        return 0;
    }
    identifier = ASN1_OCTET_STRING_new();
    if (identifier == NULL ||
        !ASN1_OCTET_STRING_set(identifier, digest, (int)sizeof(digest))) {
        goto done;
    }
    extension = X509V3_EXT_i2d(NID_subject_key_identifier, 0, identifier);
    if (extension == NULL || !sk_X509_EXTENSION_push(extensions, extension)) {
        goto done;
    }
    extension = NULL;
    ok = 1;

done:
    OPENSSL_cleanse(digest, sizeof(digest));
    X509_EXTENSION_free(extension);
    ASN1_OCTET_STRING_free(identifier);
    return ok;
}

static int add_authority_key_identifier(
    STACK_OF(X509_EXTENSION) *extensions, const HYBRID_PUBLIC_KEY *issuer_key)
{
    unsigned char digest[32];
    AUTHORITY_KEYID *authority = NULL;
    X509_EXTENSION *extension = NULL;
    int ok = 0;

    if (!compute_key_identifier(issuer_key, digest)) {
        return 0;
    }
    authority = AUTHORITY_KEYID_new();
    if (authority == NULL) {
        goto done;
    }
    authority->keyid = ASN1_OCTET_STRING_new();
    if (authority->keyid == NULL ||
        !ASN1_OCTET_STRING_set(authority->keyid, digest,
                               (int)sizeof(digest))) {
        goto done;
    }
    extension = X509V3_EXT_i2d(NID_authority_key_identifier, 0, authority);
    if (extension == NULL || !sk_X509_EXTENSION_push(extensions, extension)) {
        goto done;
    }
    extension = NULL;
    ok = 1;

done:
    OPENSSL_cleanse(digest, sizeof(digest));
    X509_EXTENSION_free(extension);
    AUTHORITY_KEYID_free(authority);
    return ok;
}

static X509_PUBKEY *make_composite_spki(const HYBRID_PUBLIC_KEY *key)
{
    X509_PUBKEY *spki = NULL;
    ASN1_OBJECT *algorithm = NULL;
    uint8_t *serialized = NULL;
    size_t serialized_len = 0;

    if (!composite_serialize_public_key(key, &serialized, &serialized_len) ||
        serialized_len > INT_MAX) {
        goto error;
    }
    spki = X509_PUBKEY_new();
    algorithm = OBJ_txt2obj(COMPOSITE_SM2_DILITHIUM_EXPERIMENTAL_OID, 1);
    if (spki == NULL || algorithm == NULL ||
        !X509_PUBKEY_set0_param(spki, algorithm, V_ASN1_UNDEF, NULL,
                                serialized, (int)serialized_len)) {
        goto error;
    }
    return spki;

error:
    ASN1_OBJECT_free(algorithm);
    OPENSSL_free(serialized);
    X509_PUBKEY_free(spki);
    return NULL;
}

static int build_root_extensions(COMPOSITE_TBS_CERTIFICATE *tbs,
                                 const HYBRID_PUBLIC_KEY *ca_public_key)
{
    tbs->extensions = sk_X509_EXTENSION_new_null();
    return tbs->extensions != NULL &&
           add_conf_extension(tbs->extensions, NID_basic_constraints,
                              "critical,CA:TRUE") &&
           add_conf_extension(tbs->extensions, NID_key_usage,
                              "critical,keyCertSign,cRLSign") &&
           add_subject_key_identifier(tbs->extensions, ca_public_key) &&
           add_pqc_marker(tbs->extensions);
}

static int build_server_extensions(COMPOSITE_TBS_CERTIFICATE *tbs,
                                   const HYBRID_PUBLIC_KEY *ca_public_key,
                                   const HYBRID_PUBLIC_KEY *server_public_key,
                                   const char *dns_name)
{
    char san_value[300];
    int length;

    if (dns_name == NULL || dns_name[0] == '\0') {
        return 0;
    }
    length = snprintf(san_value, sizeof(san_value), "DNS:%s", dns_name);
    if (length <= 0 || (size_t)length >= sizeof(san_value)) {
        return 0;
    }
    tbs->extensions = sk_X509_EXTENSION_new_null();
    return tbs->extensions != NULL &&
           add_conf_extension(tbs->extensions, NID_basic_constraints,
                              "critical,CA:FALSE") &&
           add_conf_extension(tbs->extensions, NID_key_usage,
                              "critical,digitalSignature") &&
           add_conf_extension(tbs->extensions, NID_ext_key_usage,
                              "serverAuth") &&
           add_conf_extension(tbs->extensions, NID_subject_alt_name,
                              san_value) &&
           add_subject_key_identifier(tbs->extensions, server_public_key) &&
           add_authority_key_identifier(tbs->extensions, ca_public_key) &&
           add_pqc_marker(tbs->extensions);
}

static COMPOSITE_TBS_CERTIFICATE *make_tbs(
    const HYBRID_PUBLIC_KEY *subject_key, const X509_NAME *issuer,
    const char *subject_common_name, long serial_number, int is_ca,
    const HYBRID_PUBLIC_KEY *ca_public_key, const char *dns_name)
{
    COMPOSITE_TBS_CERTIFICATE *tbs = NULL;

    tbs = COMPOSITE_TBS_CERTIFICATE_new();
    if (tbs == NULL) {
        return NULL;
    }
    tbs->version = ASN1_INTEGER_new();
    tbs->issuer = X509_NAME_dup(issuer);
    tbs->subject = make_name(subject_common_name);
    tbs->subject_public_key_info = make_composite_spki(subject_key);
    if (tbs->version == NULL || tbs->issuer == NULL || tbs->subject == NULL ||
        tbs->subject_public_key_info == NULL ||
        !ASN1_INTEGER_set(tbs->version, 2) ||
        !ASN1_INTEGER_set(tbs->serial_number, serial_number) ||
        !set_composite_algorithm(tbs->signature) ||
        X509_gmtime_adj(tbs->validity->notBefore, -60) == NULL ||
        X509_gmtime_adj(tbs->validity->notAfter, 31536000L) == NULL ||
        (is_ca ? !build_root_extensions(tbs, subject_key)
               : !build_server_extensions(tbs, ca_public_key, subject_key,
                                          dns_name))) {
        COMPOSITE_TBS_CERTIFICATE_free(tbs);
        return NULL;
    }
    return tbs;
}

static X509 *sign_tbs(COMPOSITE_TBS_CERTIFICATE *tbs,
                      const HYBRID_PRIVATE_KEY *signing_key)
{
    COMPOSITE_CERTIFICATE *certificate = NULL;
    X509 *parsed = NULL;
    uint8_t *tbs_der = NULL;
    int tbs_der_len;
    uint8_t *signature = NULL;
    size_t signature_len = 0;
    unsigned char *certificate_der = NULL;
    int certificate_der_len;
    const unsigned char *cursor;

    if (tbs == NULL || signing_key == NULL) {
        COMPOSITE_TBS_CERTIFICATE_free(tbs);
        return NULL;
    }
    tbs_der_len = i2d_COMPOSITE_TBS_CERTIFICATE(tbs, &tbs_der);
    if (tbs_der_len <= 0 ||
        !composite_sign(signing_key, tbs_der, (size_t)tbs_der_len,
                        NULL, 0, &signature, &signature_len) ||
        signature_len > INT_MAX) {
        goto done;
    }
    certificate = COMPOSITE_CERTIFICATE_new();
    if (certificate == NULL) {
        goto done;
    }
    COMPOSITE_TBS_CERTIFICATE_free(certificate->tbs_certificate);
    certificate->tbs_certificate = tbs;
    tbs = NULL;
    if (!set_composite_algorithm(certificate->signature_algorithm) ||
        !ASN1_BIT_STRING_set(certificate->signature_value,
                             signature, (int)signature_len)) {
        goto done;
    }
    certificate->signature_value->flags &=
        ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    certificate->signature_value->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    certificate_der_len = i2d_COMPOSITE_CERTIFICATE(certificate,
                                                     &certificate_der);
    if (certificate_der_len <= 0) {
        goto done;
    }
    cursor = certificate_der;
    parsed = d2i_X509(NULL, &cursor, certificate_der_len);
    if (parsed == NULL || cursor != certificate_der + certificate_der_len) {
        X509_free(parsed);
        parsed = NULL;
    }

done:
    OPENSSL_free(certificate_der);
    OPENSSL_free(signature);
    OPENSSL_free(tbs_der);
    COMPOSITE_CERTIFICATE_free(certificate);
    COMPOSITE_TBS_CERTIFICATE_free(tbs);
    return parsed;
}

X509 *hybrid_x509_create_root(const HYBRID_PRIVATE_KEY *ca_private_key,
                              const HYBRID_PUBLIC_KEY *ca_public_key,
                              const char *common_name)
{
    X509_NAME *name = make_name(common_name);
    COMPOSITE_TBS_CERTIFICATE *tbs;

    if (name == NULL) {
        return NULL;
    }
    tbs = make_tbs(ca_public_key, name, common_name, 1, 1,
                   ca_public_key, NULL);
    X509_NAME_free(name);
    return sign_tbs(tbs, ca_private_key);
}

X509 *hybrid_x509_create_server(const HYBRID_PRIVATE_KEY *ca_private_key,
                                const HYBRID_PUBLIC_KEY *ca_public_key,
                                const HYBRID_PUBLIC_KEY *server_public_key,
                                const X509 *issuer_certificate,
                                const char *common_name,
                                const char *dns_name)
{
    const X509_NAME *issuer;
    COMPOSITE_TBS_CERTIFICATE *tbs;

    if (issuer_certificate == NULL) {
        return NULL;
    }
    issuer = X509_get_subject_name(issuer_certificate);
    if (issuer == NULL) {
        return NULL;
    }
    tbs = make_tbs(server_public_key, issuer, common_name, 2, 0,
                   ca_public_key, dns_name);
    return sign_tbs(tbs, ca_private_key);
}

int hybrid_x509_get_tbs_der(X509 *certificate,
                            uint8_t **der, size_t *der_len)
{
    unsigned char *output = NULL;
    int output_len;

    if (der == NULL || der_len == NULL) {
        return 0;
    }
    *der = NULL;
    *der_len = 0;
    if (certificate == NULL ||
        (output_len = i2d_re_X509_tbs(certificate, &output)) <= 0) {
        OPENSSL_free(output);
        return 0;
    }
    *der = output;
    *der_len = (size_t)output_len;
    return 1;
}

static int algorithm_is_composite_and_absent(const X509_ALGOR *algorithm)
{
    const ASN1_OBJECT *object = NULL;
    int parameter_type = V_ASN1_UNDEF;
    char oid[128];

    if (algorithm == NULL) {
        return 0;
    }
    X509_ALGOR_get0(&object, &parameter_type, NULL, algorithm);
    return object != NULL && parameter_type == V_ASN1_UNDEF &&
           OBJ_obj2txt(oid, (int)sizeof(oid), object, 1) > 0 &&
           strcmp(oid, COMPOSITE_SM2_DILITHIUM_EXPERIMENTAL_OID) == 0;
}

int hybrid_x509_composite_algorithms_valid(const X509 *certificate)
{
    const ASN1_BIT_STRING *signature = NULL;
    const X509_ALGOR *outer = NULL;
    const X509_ALGOR *tbs;
    X509_PUBKEY *spki;
    X509_ALGOR *spki_algorithm = NULL;

    if (certificate == NULL) {
        return 0;
    }
    X509_get0_signature(&signature, &outer, certificate);
    tbs = X509_get0_tbs_sigalg(certificate);
    spki = X509_get_X509_PUBKEY(certificate);
    if (spki == NULL ||
        !X509_PUBKEY_get0_param(NULL, NULL, NULL, &spki_algorithm, spki)) {
        return 0;
    }
    return signature != NULL &&
           algorithm_is_composite_and_absent(tbs) &&
           algorithm_is_composite_and_absent(outer) &&
           algorithm_is_composite_and_absent(spki_algorithm) &&
           OBJ_cmp(tbs->algorithm, outer->algorithm) == 0;
}

int hybrid_x509_get_composite_public_key(const X509 *certificate,
                                         HYBRID_PUBLIC_KEY *public_key)
{
    X509_PUBKEY *spki;
    ASN1_BIT_STRING *public_key_bits;
    X509_ALGOR *algorithm = NULL;
    const unsigned char *serialized = NULL;
    int serialized_len = 0;

    if (certificate == NULL || public_key == NULL) {
        return 0;
    }
    spki = X509_get_X509_PUBKEY(certificate);
    public_key_bits = X509_get0_pubkey_bitstr(certificate);
    if (spki == NULL || public_key_bits == NULL ||
        (public_key_bits->flags & 0x07) != 0 ||
        !X509_PUBKEY_get0_param(NULL, &serialized, &serialized_len,
                                &algorithm, spki) ||
        !algorithm_is_composite_and_absent(algorithm) ||
        serialized_len <= 0) {
        return 0;
    }
    return composite_parse_public_key(serialized, (size_t)serialized_len,
                                      public_key);
}

int hybrid_x509_public_key_matches(const X509 *certificate,
                                   const HYBRID_PUBLIC_KEY *public_key)
{
    HYBRID_PUBLIC_KEY certificate_key;
    uint8_t *certificate_bytes = NULL;
    uint8_t *loaded_bytes = NULL;
    size_t certificate_len = 0;
    size_t loaded_len = 0;
    int matches = 0;

    hybrid_public_key_init(&certificate_key);
    if (certificate != NULL && public_key != NULL &&
        hybrid_x509_get_composite_public_key(certificate, &certificate_key) &&
        composite_serialize_public_key(&certificate_key,
                                       &certificate_bytes, &certificate_len) &&
        composite_serialize_public_key(public_key, &loaded_bytes, &loaded_len) &&
        certificate_len == loaded_len &&
        CRYPTO_memcmp(certificate_bytes, loaded_bytes, loaded_len) == 0) {
        matches = 1;
    }
    OPENSSL_free(loaded_bytes);
    OPENSSL_free(certificate_bytes);
    hybrid_public_key_cleanup(&certificate_key);
    return matches;
}

int hybrid_x509_get_signature(const X509 *certificate,
                              const uint8_t **signature,
                              size_t *signature_len)
{
    const ASN1_BIT_STRING *value = NULL;

    if (signature == NULL || signature_len == NULL) {
        return 0;
    }
    *signature = NULL;
    *signature_len = 0;
    if (certificate == NULL) {
        return 0;
    }
    X509_get0_signature(&value, NULL, certificate);
    if (value == NULL || (value->flags & 0x07) != 0 ||
        ASN1_STRING_length(value) <= 0) {
        return 0;
    }
    *signature = ASN1_STRING_get0_data(value);
    *signature_len = (size_t)ASN1_STRING_length(value);
    return 1;
}

int hybrid_x509_has_pqc_extension(const X509 *certificate)
{
    static const unsigned char expected_value[] = {0x05, 0x00};
    ASN1_OBJECT *object = NULL;
    X509_EXTENSION *extension;
    const ASN1_OCTET_STRING *data;
    int first;
    int second;

    if (certificate == NULL) {
        return 0;
    }
    object = OBJ_txt2obj(HYBRID_PQC_EXTENSION_OID, 1);
    if (object == NULL) {
        return 0;
    }
    first = X509_get_ext_by_OBJ(certificate, object, -1);
    second = first >= 0 ? X509_get_ext_by_OBJ(certificate, object, first) : -1;
    ASN1_OBJECT_free(object);
    if (first < 0 || second >= 0) {
        return 0;
    }
    extension = X509_get_ext(certificate, first);
    data = extension != NULL ? X509_EXTENSION_get_data(extension) : NULL;
    return extension != NULL && !X509_EXTENSION_get_critical(extension) &&
           data != NULL && ASN1_STRING_length(data) == (int)sizeof(expected_value) &&
           CRYPTO_memcmp(ASN1_STRING_get0_data(data), expected_value,
                         sizeof(expected_value)) == 0;
}

int hybrid_x509_write_files(const X509 *certificate,
                            const char *pem_path, const char *der_path)
{
    FILE *pem_file = NULL;
    FILE *der_file = NULL;
    int ok = 0;

    if (certificate == NULL || pem_path == NULL || der_path == NULL) {
        return 0;
    }
    pem_file = fopen(pem_path, "wb");
    der_file = fopen(der_path, "wb");
    if (pem_file == NULL || der_file == NULL ||
        !PEM_write_X509(pem_file, certificate) ||
        !i2d_X509_fp(der_file, certificate)) {
        goto done;
    }
    ok = 1;

done:
    if (pem_file != NULL) {
        fclose(pem_file);
    }
    if (der_file != NULL) {
        fclose(der_file);
    }
    return ok;
}

X509 *hybrid_x509_read_pem(const char *path)
{
    FILE *input;
    X509 *certificate = NULL;

    if (path == NULL) {
        return NULL;
    }
    input = fopen(path, "rb");
    if (input == NULL) {
        return NULL;
    }
    certificate = PEM_read_X509(input, NULL, NULL, NULL);
    fclose(input);
    return certificate;
}
