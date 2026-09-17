#ifndef HYBRID_PQC_HYBRID_X509_H
#define HYBRID_PQC_HYBRID_X509_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/x509.h>

#include "composite_key.h"

/* RFC 5612 documentation PEN: experimental/demo use only, not standardized. */
#define COMPOSITE_SM2_DILITHIUM_EXPERIMENTAL_OID \
    "1.3.6.1.4.1.32473.1.1"
#define HYBRID_PQC_EXTENSION_OID "1.3.6.1.4.1.2.267.7"
#define HYBRID_DEFAULT_SERVER_NAME "server.local"

X509 *hybrid_x509_create_root(const HYBRID_PRIVATE_KEY *ca_private_key,
                              const HYBRID_PUBLIC_KEY *ca_public_key,
                              const char *common_name);

X509 *hybrid_x509_create_server(const HYBRID_PRIVATE_KEY *ca_private_key,
                                const HYBRID_PUBLIC_KEY *ca_public_key,
                                const HYBRID_PUBLIC_KEY *server_public_key,
                                const X509 *issuer_certificate,
                                const char *common_name,
                                const char *dns_name);

int hybrid_x509_get_tbs_der(X509 *certificate,
                            uint8_t **der, size_t *der_len);

int hybrid_x509_get_composite_public_key(const X509 *certificate,
                                         HYBRID_PUBLIC_KEY *public_key);

int hybrid_x509_public_key_matches(const X509 *certificate,
                                   const HYBRID_PUBLIC_KEY *public_key);

int hybrid_x509_get_signature(const X509 *certificate,
                              const uint8_t **signature,
                              size_t *signature_len);

int hybrid_x509_has_pqc_extension(const X509 *certificate);
int hybrid_x509_composite_algorithms_valid(const X509 *certificate);

int hybrid_x509_write_files(const X509 *certificate,
                            const char *pem_path, const char *der_path);
X509 *hybrid_x509_read_pem(const char *path);

#endif
