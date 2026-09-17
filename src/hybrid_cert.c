#include "hybrid_cert.h"

#include "dilithium_wrapper.h"
#include "sm2_wrapper.h"

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    ASN1_INTEGER *version;
    ASN1_OBJECT *algorithm;
    ASN1_OCTET_STRING *public_key;
    ASN1_OCTET_STRING *signature;
} PQC_INFO_ASN1;

ASN1_SEQUENCE(PQC_INFO_ASN1) = {
    ASN1_SIMPLE(PQC_INFO_ASN1, version, ASN1_INTEGER),
    ASN1_SIMPLE(PQC_INFO_ASN1, algorithm, ASN1_OBJECT),
    ASN1_SIMPLE(PQC_INFO_ASN1, public_key, ASN1_OCTET_STRING),
    ASN1_OPT(PQC_INFO_ASN1, signature, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(PQC_INFO_ASN1)

IMPLEMENT_ASN1_FUNCTIONS(PQC_INFO_ASN1)

void hybrid_pqc_info_init(HYBRID_PQC_INFO *info)
{
    if (info != NULL) {
        memset(info, 0, sizeof(*info));
    }
}

void hybrid_pqc_info_cleanup(HYBRID_PQC_INFO *info)
{
    if (info == NULL) {
        return;
    }
    OPENSSL_free(info->public_key);
    OPENSSL_free(info->signature);
    hybrid_pqc_info_init(info);
}

int hybrid_pqc_info_encode_der(const HYBRID_PQC_INFO *info,
                               unsigned char **der, size_t *der_len)
{
    PQC_INFO_ASN1 *value = NULL;
    ASN1_OBJECT *algorithm = NULL;
    unsigned char *output = NULL;
    int encoded_len;
    int ok = 0;

    if (der == NULL || der_len == NULL) {
        return 0;
    }
    *der = NULL;
    *der_len = 0;
    if (info == NULL || info->version != HYBRID_PQC_INFO_VERSION ||
        info->algorithm_oid[0] == '\0' || info->public_key == NULL ||
        info->public_key_len == 0 || info->public_key_len > INT_MAX ||
        info->signature_len > INT_MAX ||
        (info->signature_len != 0 && info->signature == NULL)) {
        return 0;
    }

    value = PQC_INFO_ASN1_new();
    algorithm = OBJ_txt2obj(info->algorithm_oid, 1);
    if (value == NULL || algorithm == NULL ||
        !ASN1_INTEGER_set(value->version, info->version) ||
        !ASN1_OCTET_STRING_set(value->public_key, info->public_key,
                               (int)info->public_key_len)) {
        goto done;
    }
    ASN1_OBJECT_free(value->algorithm);
    value->algorithm = algorithm;
    algorithm = NULL;
    if (info->signature_len != 0) {
        value->signature = ASN1_OCTET_STRING_new();
        if (value->signature == NULL ||
            !ASN1_OCTET_STRING_set(value->signature, info->signature,
                                   (int)info->signature_len)) {
            goto done;
        }
    }
    encoded_len = i2d_PQC_INFO_ASN1(value, &output);
    if (encoded_len <= 0) {
        goto done;
    }
    *der = output;
    *der_len = (size_t)encoded_len;
    output = NULL;
    ok = 1;

done:
    OPENSSL_free(output);
    ASN1_OBJECT_free(algorithm);
    PQC_INFO_ASN1_free(value);
    return ok;
}

int hybrid_pqc_info_decode_der(const unsigned char *der, size_t der_len,
                               HYBRID_PQC_INFO *info)
{
    PQC_INFO_ASN1 *value = NULL;
    HYBRID_PQC_INFO decoded;
    const unsigned char *cursor = der;
    int public_key_len;
    int signature_len = 0;
    int oid_len;
    int ok = 0;

    if (der == NULL || der_len == 0 || der_len > LONG_MAX || info == NULL) {
        return 0;
    }
    hybrid_pqc_info_init(&decoded);
    value = d2i_PQC_INFO_ASN1(NULL, &cursor, (long)der_len);
    if (value == NULL || cursor != der + der_len ||
        ASN1_INTEGER_get(value->version) != HYBRID_PQC_INFO_VERSION) {
        goto done;
    }
    oid_len = OBJ_obj2txt(decoded.algorithm_oid,
                         (int)sizeof(decoded.algorithm_oid),
                         value->algorithm, 1);
    public_key_len = ASN1_STRING_length(value->public_key);
    if (oid_len <= 0 || oid_len >= (int)sizeof(decoded.algorithm_oid) ||
        public_key_len <= 0) {
        goto done;
    }
    if (value->signature != NULL) {
        signature_len = ASN1_STRING_length(value->signature);
        if (signature_len <= 0) {
            goto done;
        }
    }
    decoded.public_key = OPENSSL_malloc((size_t)public_key_len);
    if (decoded.public_key == NULL) {
        goto done;
    }
    memcpy(decoded.public_key, ASN1_STRING_get0_data(value->public_key),
           (size_t)public_key_len);
    decoded.public_key_len = (size_t)public_key_len;
    if (signature_len != 0) {
        decoded.signature = OPENSSL_malloc((size_t)signature_len);
        if (decoded.signature == NULL) {
            goto done;
        }
        memcpy(decoded.signature, ASN1_STRING_get0_data(value->signature),
               (size_t)signature_len);
        decoded.signature_len = (size_t)signature_len;
    }
    decoded.version = HYBRID_PQC_INFO_VERSION;

    hybrid_pqc_info_cleanup(info);
    *info = decoded;
    hybrid_pqc_info_init(&decoded);
    ok = 1;

done:
    hybrid_pqc_info_cleanup(&decoded);
    PQC_INFO_ASN1_free(value);
    return ok;
}

static int pqc_extension_index(const X509 *certificate)
{
    ASN1_OBJECT *object = NULL;
    int index = -1;

    if (certificate == NULL) {
        return -1;
    }
    object = OBJ_txt2obj(HYBRID_PQC_EXTENSION_OID, 1);
    if (object != NULL) {
        index = X509_get_ext_by_OBJ(certificate, object, -1);
    }
    ASN1_OBJECT_free(object);
    return index;
}

int hybrid_cert_has_pqc_extension(const X509 *certificate)
{
    return pqc_extension_index(certificate) >= 0;
}

int hybrid_cert_get_pqc_info(const X509 *certificate, HYBRID_PQC_INFO *info)
{
    X509_EXTENSION *extension;
    const ASN1_OCTET_STRING *data;
    int index;

    if (certificate == NULL || info == NULL) {
        return 0;
    }
    index = pqc_extension_index(certificate);
    if (index < 0) {
        return 0;
    }
    extension = X509_get_ext(certificate, index);
    data = X509_EXTENSION_get_data(extension);
    if (data == NULL) {
        return 0;
    }
    return hybrid_pqc_info_decode_der(ASN1_STRING_get0_data(data),
                                      (size_t)ASN1_STRING_length(data), info);
}

int hybrid_cert_set_pqc_info(X509 *certificate, const HYBRID_PQC_INFO *info)
{
    ASN1_OBJECT *object = NULL;
    ASN1_OCTET_STRING *data = NULL;
    X509_EXTENSION *extension = NULL;
    X509_EXTENSION *old_extension = NULL;
    unsigned char *der = NULL;
    size_t der_len = 0;
    int index;
    int ok = 0;

    if (certificate == NULL ||
        !hybrid_pqc_info_encode_der(info, &der, &der_len) || der_len > INT_MAX) {
        goto done;
    }
    object = OBJ_txt2obj(HYBRID_PQC_EXTENSION_OID, 1);
    data = ASN1_OCTET_STRING_new();
    if (object == NULL || data == NULL ||
        !ASN1_OCTET_STRING_set(data, der, (int)der_len)) {
        goto done;
    }
    extension = X509_EXTENSION_create_by_OBJ(NULL, object, 0, data);
    if (extension == NULL) {
        goto done;
    }
    index = pqc_extension_index(certificate);
    if (index >= 0) {
        old_extension = X509_delete_ext(certificate, index);
        X509_EXTENSION_free(old_extension);
    }
    if (!X509_add_ext(certificate, extension, index)) {
        goto done;
    }
    ok = 1;

done:
    OPENSSL_free(der);
    X509_EXTENSION_free(extension);
    ASN1_OCTET_STRING_free(data);
    ASN1_OBJECT_free(object);
    return ok;
}

int hybrid_cert_remove_pqc_extension(X509 *certificate)
{
    X509_EXTENSION *extension;
    int index;

    if (certificate == NULL) {
        return 0;
    }
    index = pqc_extension_index(certificate);
    if (index < 0) {
        return 1;
    }
    extension = X509_delete_ext(certificate, index);
    if (extension == NULL) {
        return 0;
    }
    X509_EXTENSION_free(extension);
    return 1;
}

int hybrid_cert_tbs_without_pqc_signature(X509 *certificate,
                                          unsigned char **der,
                                          size_t *der_len)
{
    X509 *base = NULL;
    HYBRID_PQC_INFO info;
    unsigned char *output = NULL;
    int output_len;
    int ok = 0;

    if (der == NULL || der_len == NULL) {
        return 0;
    }
    *der = NULL;
    *der_len = 0;
    hybrid_pqc_info_init(&info);
    if (certificate == NULL ||
        (base = X509_dup(certificate)) == NULL ||
        !hybrid_cert_get_pqc_info(base, &info)) {
        goto done;
    }
    OPENSSL_free(info.signature);
    info.signature = NULL;
    info.signature_len = 0;
    if (!hybrid_cert_set_pqc_info(base, &info)) {
        goto done;
    }
    output_len = i2d_re_X509_tbs(base, &output);
    if (output_len <= 0) {
        goto done;
    }
    *der = output;
    *der_len = (size_t)output_len;
    output = NULL;
    ok = 1;

done:
    OPENSSL_free(output);
    hybrid_pqc_info_cleanup(&info);
    X509_free(base);
    return ok;
}

int hybrid_cert_sign_sm2(X509 *certificate, EVP_PKEY *private_key)
{
    EVP_MD_CTX *context = NULL;
    EVP_PKEY_CTX *pkey_context = NULL;
    ASN1_OCTET_STRING *distinguishing_id = NULL;
    int ok = 0;

    if (certificate == NULL || private_key == NULL) {
        return 0;
    }
    context = EVP_MD_CTX_new();
    distinguishing_id = ASN1_OCTET_STRING_new();
    if (context == NULL || distinguishing_id == NULL ||
        !ASN1_OCTET_STRING_set(distinguishing_id,
                               (const unsigned char *)SM2_DEFAULT_USER_ID,
                               (int)strlen(SM2_DEFAULT_USER_ID))) {
        goto done;
    }
    X509_set0_distinguishing_id(certificate, distinguishing_id);
    distinguishing_id = NULL;
    if (
        EVP_DigestSignInit_ex(context, &pkey_context, "SM3", NULL, NULL,
                              private_key, NULL) <= 0 ||
        EVP_PKEY_CTX_set1_id(pkey_context, SM2_DEFAULT_USER_ID,
                             strlen(SM2_DEFAULT_USER_ID)) <= 0 ||
        X509_sign_ctx(certificate, context) <= 0) {
        goto done;
    }
    ok = 1;

done:
    ASN1_OCTET_STRING_free(distinguishing_id);
    EVP_MD_CTX_free(context);
    return ok;
}

static int add_standard_extension(X509 *certificate, int nid,
                                  const char *value)
{
    X509_EXTENSION *extension = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
    int ok = extension != NULL && X509_add_ext(certificate, extension, -1);

    X509_EXTENSION_free(extension);
    return ok;
}

X509 *hybrid_cert_generate(EVP_PKEY *sm2_private_key,
                           const unsigned char *dilithium_public_key,
                           size_t dilithium_public_key_len,
                           const unsigned char *dilithium_secret_key,
                           size_t dilithium_secret_key_len,
                           const char *common_name)
{
    X509 *certificate = NULL;
    X509_NAME *name;
    HYBRID_PQC_INFO info;
    unsigned char *base_tbs = NULL;
    size_t base_tbs_len = 0;
    unsigned char *pqc_signature = NULL;
    size_t pqc_signature_len = 0;

    hybrid_pqc_info_init(&info);
    if (sm2_private_key == NULL || dilithium_public_key == NULL ||
        dilithium_public_key_len != DILITHIUM_PUBLIC_KEY_BYTES ||
        dilithium_secret_key == NULL ||
        dilithium_secret_key_len != DILITHIUM_SECRET_KEY_BYTES ||
        common_name == NULL) {
        return NULL;
    }
    certificate = X509_new();
    if (certificate == NULL || !X509_set_version(certificate, 2) ||
        !ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1) ||
        X509_gmtime_adj(X509_getm_notBefore(certificate), 0) == NULL ||
        X509_gmtime_adj(X509_getm_notAfter(certificate), 31536000L) == NULL ||
        !X509_set_pubkey(certificate, sm2_private_key)) {
        goto error;
    }
    name = X509_get_subject_name(certificate);
    if (name == NULL ||
        !X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    (const unsigned char *)common_name,
                                    -1, -1, 0) ||
        !X509_set_issuer_name(certificate, name) ||
        !add_standard_extension(certificate, NID_basic_constraints,
                                "critical,CA:TRUE") ||
        !add_standard_extension(certificate, NID_key_usage,
                                "critical,digitalSignature,keyCertSign")) {
        goto error;
    }

    info.version = HYBRID_PQC_INFO_VERSION;
    memcpy(info.algorithm_oid, DILITHIUM2_EXPERIMENTAL_OID,
           sizeof(DILITHIUM2_EXPERIMENTAL_OID));
    info.public_key = OPENSSL_memdup(dilithium_public_key,
                                     dilithium_public_key_len);
    info.public_key_len = dilithium_public_key_len;
    if (info.public_key == NULL ||
        !hybrid_cert_set_pqc_info(certificate, &info) ||
        !hybrid_cert_sign_sm2(certificate, sm2_private_key) ||
        !hybrid_cert_tbs_without_pqc_signature(certificate,
                                               &base_tbs, &base_tbs_len) ||
        !dilithium_sign(dilithium_secret_key, dilithium_secret_key_len,
                        base_tbs, base_tbs_len,
                        &pqc_signature, &pqc_signature_len)) {
        goto error;
    }
    info.signature = OPENSSL_memdup(pqc_signature, pqc_signature_len);
    info.signature_len = pqc_signature_len;
    if (info.signature == NULL ||
        !hybrid_cert_set_pqc_info(certificate, &info) ||
        !hybrid_cert_sign_sm2(certificate, sm2_private_key)) {
        goto error;
    }

    OPENSSL_free(base_tbs);
    free(pqc_signature);
    hybrid_pqc_info_cleanup(&info);
    return certificate;

error:
    OPENSSL_free(base_tbs);
    free(pqc_signature);
    hybrid_pqc_info_cleanup(&info);
    X509_free(certificate);
    return NULL;
}

int hybrid_cert_write_files(const X509 *certificate,
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
