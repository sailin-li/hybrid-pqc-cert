#include "hybrid_verify.h"

#include "dilithium_wrapper.h"
#include "hybrid_cert.h"
#include "sm2_wrapper.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509_vfy.h>

#include <string.h>

static int verify_sm2_certificate(X509 *certificate)
{
    X509_STORE *store = NULL;
    X509_STORE_CTX *context = NULL;
    EVP_PKEY *public_key;
    ASN1_OCTET_STRING *distinguishing_id = NULL;
    int valid = 0;

    if (certificate == NULL) {
        return 0;
    }
    public_key = X509_get0_pubkey(certificate);
    if (public_key == NULL || !EVP_PKEY_is_a(public_key, "SM2")) {
        return 0;
    }
    distinguishing_id = ASN1_OCTET_STRING_new();
    if (distinguishing_id == NULL ||
        !ASN1_OCTET_STRING_set(distinguishing_id,
                               (const unsigned char *)SM2_DEFAULT_USER_ID,
                               (int)strlen(SM2_DEFAULT_USER_ID))) {
        goto done;
    }
    X509_set0_distinguishing_id(certificate, distinguishing_id);
    distinguishing_id = NULL;
    store = X509_STORE_new();
    context = X509_STORE_CTX_new();
    if (store == NULL || context == NULL ||
        !X509_STORE_set_flags(store, X509_V_FLAG_CHECK_SS_SIGNATURE) ||
        !X509_STORE_add_cert(store, certificate) ||
        !X509_STORE_CTX_init(context, store, certificate, NULL)) {
        goto done;
    }
    valid = X509_verify_cert(context) == 1;

done:
    ASN1_OCTET_STRING_free(distinguishing_id);
    X509_STORE_CTX_free(context);
    X509_STORE_free(store);
    return valid;
}

int hybrid_cert_verify(X509 *certificate, HYBRID_VERIFY_MODE mode,
                       HYBRID_VERIFY_RESULT *result)
{
    HYBRID_VERIFY_RESULT local_result = {0};
    HYBRID_PQC_INFO info;
    unsigned char *base_tbs = NULL;
    size_t base_tbs_len = 0;

    hybrid_pqc_info_init(&info);
    if (certificate == NULL ||
        (mode != HYBRID_VERIFY_STRICT &&
         mode != HYBRID_VERIFY_CLASSICAL_COMPAT)) {
        goto done;
    }

    local_result.sm2_valid = verify_sm2_certificate(certificate);
    local_result.pqc_extension_present =
        hybrid_cert_has_pqc_extension(certificate);
    if (mode == HYBRID_VERIFY_CLASSICAL_COMPAT) {
        local_result.hybrid_valid = local_result.sm2_valid;
        goto done;
    }
    if (!local_result.pqc_extension_present ||
        !hybrid_cert_get_pqc_info(certificate, &info)) {
        goto done;
    }
    local_result.pqc_info_valid = 1;
    local_result.pqc_algorithm_known =
        strcmp(info.algorithm_oid, DILITHIUM2_EXPERIMENTAL_OID) == 0;
    if (!local_result.pqc_algorithm_known ||
        info.public_key_len != DILITHIUM_PUBLIC_KEY_BYTES ||
        info.signature_len != DILITHIUM_SIGNATURE_BYTES ||
        !hybrid_cert_tbs_without_pqc_signature(certificate,
                                               &base_tbs, &base_tbs_len)) {
        goto done;
    }
    local_result.dilithium_valid =
        dilithium_verify(info.public_key, info.public_key_len,
                         base_tbs, base_tbs_len,
                         info.signature, info.signature_len);
    local_result.hybrid_valid =
        local_result.sm2_valid && local_result.dilithium_valid;

done:
    OPENSSL_free(base_tbs);
    hybrid_pqc_info_cleanup(&info);
    if (result != NULL) {
        *result = local_result;
    }
    return local_result.hybrid_valid;
}

int hybrid_cert_verify_strict(X509 *certificate)
{
    return hybrid_cert_verify(certificate, HYBRID_VERIFY_STRICT, NULL);
}
