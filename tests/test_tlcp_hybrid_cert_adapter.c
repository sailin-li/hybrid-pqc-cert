#include "composite_key.h"
#include "hybrid_x509.h"
#include "sm2_wrapper.h"
#include "tlcp_hybrid_cert_adapter.h"

#include <openssl/crypto.h>
#include <openssl/x509.h>

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
    int length;

    if (certificate == NULL || der == NULL || der_len == NULL) {
        return 0;
    }
    length = i2d_X509(certificate, &encoded);
    if (length <= 0) {
        return 0;
    }
    *der = encoded;
    *der_len = (size_t)length;
    return 1;
}

int main(void)
{
    HYBRID_PRIVATE_KEY ca_private;
    HYBRID_PUBLIC_KEY ca_public;
    HYBRID_PRIVATE_KEY server_private;
    HYBRID_PUBLIC_KEY server_public;
    X509 *root = NULL;
    X509 *server = NULL;
    EVP_PKEY *sm2_enc_key = NULL;
    X509 *sm2_encryption = NULL;
    uint8_t *root_der = NULL;
    size_t root_der_len = 0;
    uint8_t *server_der = NULL;
    size_t server_der_len = 0;
    uint8_t *sm2_encryption_der = NULL;
    size_t sm2_encryption_der_len = 0;
    uint8_t *tlcp_chain_der = NULL;
    size_t tlcp_chain_der_len = 0;
    uint8_t *changed_der = NULL;
    uint8_t sm2_public[SM2_UNCOMPRESSED_PUBLIC_KEY_BYTES];
    TLCP_HYBRID_CERT_VERIFY_REPORT report;
    TLCP_HYBRID_CERT_ADAPTER_CONFIG config;
    static const uint8_t ordinary_der[] = {0x30, 0x00};
    int ok = EXIT_FAILURE;

    hybrid_private_key_init(&ca_private);
    hybrid_public_key_init(&ca_public);
    hybrid_private_key_init(&server_private);
    hybrid_public_key_init(&server_public);
    CHECK(composite_key_generate(&ca_private, &ca_public), "CA keys");
    CHECK(composite_key_generate(&server_private, &server_public),
          "server keys");
    root = hybrid_x509_create_root(&ca_private, &ca_public,
                                   "Root Hybrid CA");
    server = hybrid_x509_create_server(
        &ca_private, &ca_public, &server_public, root,
        HYBRID_DEFAULT_SERVER_NAME, HYBRID_DEFAULT_SERVER_NAME);
    CHECK(root != NULL && server != NULL, "certificates");
    CHECK(certificate_to_der(root, &root_der, &root_der_len) &&
          certificate_to_der(server, &server_der, &server_der_len),
          "DER encoding");

    sm2_enc_key = hybrid_sm2_generate_keypair();
    CHECK(sm2_enc_key != NULL, "SM2 TLCP encryption key");
    sm2_encryption = hybrid_x509_create_sm2_encryption(
        &ca_private, &ca_public, sm2_enc_key, root,
        HYBRID_DEFAULT_SERVER_NAME);
    CHECK(sm2_encryption != NULL &&
          certificate_to_der(sm2_encryption, &sm2_encryption_der,
                             &sm2_encryption_der_len),
          "Composite-signed TLCP encryption certificate");
    tlcp_chain_der_len = server_der_len + sm2_encryption_der_len;
    tlcp_chain_der = OPENSSL_malloc(tlcp_chain_der_len);
    CHECK(tlcp_chain_der != NULL, "TLCP chain allocation");
    memcpy(tlcp_chain_der, server_der, server_der_len);
    memcpy(tlcp_chain_der + server_der_len, sm2_encryption_der,
           sm2_encryption_der_len);

    CHECK(tlcp_hybrid_cert_verify_der(
              server_der, server_der_len, root_der, root_der_len,
              HYBRID_DEFAULT_SERVER_NAME, sm2_public, &report) ==
              TLCP_HYBRID_CERT_VALID &&
          report.dilithium_ok && report.sm2_ok && report.composite_ok,
          "valid adapter chain");
    puts("PASS: valid Composite signing certificate -> VALID");

    changed_der = OPENSSL_memdup(server_der, server_der_len);
    CHECK(changed_der != NULL, "changed DER allocation");
    changed_der[server_der_len - 1u] ^= 1u;
    CHECK(tlcp_hybrid_cert_verify_der(
              changed_der, server_der_len, root_der, root_der_len,
              HYBRID_DEFAULT_SERVER_NAME, sm2_public, &report) ==
              TLCP_HYBRID_CERT_INVALID && report.recognized_composite,
          "tampered Composite accepted");
    puts("PASS: recognized tampered Composite -> INVALID (no fallback)");

    CHECK(tlcp_hybrid_cert_verify_der(
              ordinary_der, sizeof(ordinary_der), root_der, root_der_len,
              NULL, sm2_public, &report) ==
              TLCP_HYBRID_CERT_NOT_APPLICABLE,
          "ordinary/non-Composite classification");
    puts("PASS: non-Composite -> NOT_APPLICABLE");

    memset(&config, 0, sizeof(config));
    config.trust_anchor_der = root_der;
    config.trust_anchor_der_len = root_der_len;
    config.expected_hostname = HYBRID_DEFAULT_SERVER_NAME;
    config.last_report = &report;
    CHECK(tlcp_hybrid_cert_gmssl_verify_callback(
          tlcp_chain_der, tlcp_chain_der_len,
              sm2_public, &config, 0) ==
              TLCP_HYBRID_CERT_VALID &&
          report.encryption_subject_spki_sm2_ok &&
          report.encryption_dilithium_ok && report.encryption_sm2_ok &&
          report.encryption_composite_ok,
          "GmSSL callback bridge");
    puts("PASS: GmSSL callback verifies both Composite-signed certificates");

    ok = EXIT_SUCCESS;

done:
    OPENSSL_free(tlcp_chain_der);
    OPENSSL_free(sm2_encryption_der);
    OPENSSL_free(changed_der);
    OPENSSL_free(server_der);
    OPENSSL_free(root_der);
    X509_free(server);
    X509_free(root);
    X509_free(sm2_encryption);
    EVP_PKEY_free(sm2_enc_key);
    hybrid_public_key_cleanup(&server_public);
    hybrid_private_key_cleanup(&server_private);
    hybrid_public_key_cleanup(&ca_public);
    hybrid_private_key_cleanup(&ca_private);
    return ok;
}
