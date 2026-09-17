#ifndef HYBRID_PQC_HYBRID_CERT_H
#define HYBRID_PQC_HYBRID_CERT_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#define HYBRID_PQC_EXTENSION_OID "1.3.6.1.4.1.2.267.7"

#define DILITHIUM2_EXPERIMENTAL_OID "1.3.6.1.4.1.2.267.7.4.4"
#define HYBRID_PQC_INFO_VERSION 1L

typedef struct
{
    long version;
    char algorithm_oid[128];
    unsigned char *public_key;
    size_t public_key_len;
    unsigned char *signature;
    size_t signature_len;
} HYBRID_PQC_INFO;

void hybrid_pqc_info_init(HYBRID_PQC_INFO *info);
void hybrid_pqc_info_cleanup(HYBRID_PQC_INFO *info);

int hybrid_pqc_info_encode_der(const HYBRID_PQC_INFO *info,
                               unsigned char **der, size_t *der_len);
int hybrid_pqc_info_decode_der(const unsigned char *der, size_t der_len,
                               HYBRID_PQC_INFO *info);

int hybrid_cert_get_pqc_info(const X509 *certificate, HYBRID_PQC_INFO *info);
int hybrid_cert_set_pqc_info(X509 *certificate, const HYBRID_PQC_INFO *info);
int hybrid_cert_remove_pqc_extension(X509 *certificate);
int hybrid_cert_has_pqc_extension(const X509 *certificate);

int hybrid_cert_tbs_without_pqc_signature(X509 *certificate,
                                          unsigned char **der,
                                          size_t *der_len);

int hybrid_cert_sign_sm2(X509 *certificate, EVP_PKEY *private_key);

X509 *hybrid_cert_generate(EVP_PKEY *sm2_private_key,
                           const unsigned char *dilithium_public_key,
                           size_t dilithium_public_key_len,
                           const unsigned char *dilithium_secret_key,
                           size_t dilithium_secret_key_len,
                           const char *common_name);

int hybrid_cert_write_files(const X509 *certificate,
                            const char *pem_path, const char *der_path);

#endif
