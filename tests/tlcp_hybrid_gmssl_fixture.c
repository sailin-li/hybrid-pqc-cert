#define _POSIX_C_SOURCE 200809L

#include "tlcp_hybrid_gmssl_fixture.h"

#include "composite_key.h"
#include "composite_sig.h"
#include "hybrid_x509.h"
#include "sm2_wrapper.h"
#include "tlcp_hybrid_cert_adapter.h"

#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

typedef struct {
    HYBRID_PRIVATE_KEY ca_private;
    HYBRID_PUBLIC_KEY ca_public;
    HYBRID_PRIVATE_KEY server_private;
    HYBRID_PUBLIC_KEY server_public;
    EVP_PKEY *sm2_ca_key;
    EVP_PKEY *sm2_enc_key;
    X509 *root;
    X509 *server;
    X509 *sm2_encryption;
    X509 *ordinary_sm2;
    uint8_t *root_der;
    size_t root_der_len;
    TLCP_HYBRID_CERT_ADAPTER_CONFIG config;
    TLCP_HYBRID_CERT_VERIFY_REPORT report;
} FIXTURE_PRIVATE;

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

static int add_extension(X509 *certificate, int nid, const char *value)
{
    X509_EXTENSION *extension =
        X509V3_EXT_conf_nid(NULL, NULL, nid, value);
    int ok = extension != NULL && X509_add_ext(certificate, extension, -1);

    X509_EXTENSION_free(extension);
    return ok;
}

static X509 *make_sm2_certificate(EVP_PKEY *subject_key,
                                  EVP_PKEY *issuer_key,
                                  const X509_NAME *subject,
                                  const X509_NAME *issuer,
                                  int is_ca)
{
    X509 *certificate = X509_new();

    if (certificate == NULL || !X509_set_version(certificate, 2) ||
        !ASN1_INTEGER_set(X509_get_serialNumber(certificate), is_ca ? 30 : 31) ||
        X509_gmtime_adj(X509_getm_notBefore(certificate), -60) == NULL ||
        X509_gmtime_adj(X509_getm_notAfter(certificate), 86400) == NULL ||
        !X509_set_subject_name(certificate, subject) ||
        !X509_set_issuer_name(certificate, issuer) ||
        !X509_set_pubkey(certificate, subject_key) ||
        !add_extension(certificate, NID_basic_constraints,
                       is_ca ? "critical,CA:TRUE" : "critical,CA:FALSE") ||
        !add_extension(certificate, NID_key_usage,
                       is_ca ? "critical,keyCertSign,cRLSign"
                             : "critical,keyEncipherment,keyAgreement") ||
        X509_sign(certificate, issuer_key, EVP_sm3()) <= 0) {
        X509_free(certificate);
        return NULL;
    }
    return certificate;
}

static int private_key_to_der(EVP_PKEY *key,
                              uint8_t **der, size_t *der_len)
{
    unsigned char *encoded = NULL;
    int length = i2d_PrivateKey(key, &encoded);

    if (length <= 0) {
        OPENSSL_free(encoded);
        return 0;
    }
    *der = encoded;
    *der_len = (size_t)length;
    return 1;
}

static int set_fixture_path(char output[TEST_FIXTURE_PATH_SIZE],
                            const char *directory, const char *name)
{
    int length = snprintf(output, TEST_FIXTURE_PATH_SIZE,
                          "%s/%s", directory, name);

    return length > 0 && (size_t)length < TEST_FIXTURE_PATH_SIZE;
}

static int write_loader_files(TLCP_HYBRID_TEST_FIXTURE *fixture,
                              const FIXTURE_PRIVATE *state)
{
    char directory_template[] = "/tmp/hybrid-stage6b-loader.XXXXXX";
    FILE *certificates = NULL;
    int ok = 0;

    if (mkdtemp(directory_template) == NULL ||
        strlen(directory_template) >= sizeof(fixture->temporary_directory)) {
        return 0;
    }
    memcpy(fixture->temporary_directory, directory_template,
           strlen(directory_template) + 1u);
    if (!set_fixture_path(fixture->certificate_chain_file,
                          fixture->temporary_directory, "certs.pem") ||
        !set_fixture_path(fixture->key_file,
                          fixture->temporary_directory, "keys.pem") ||
        !set_fixture_path(fixture->wrong_encryption_key_file,
                          fixture->temporary_directory,
                          "wrong-keys.pem")) {
        goto done;
    }
    certificates = fopen(fixture->certificate_chain_file, "wb");
    if (certificates == NULL ||
        !PEM_write_X509(certificates, state->server) ||
        !PEM_write_X509(certificates, state->sm2_encryption) ||
        fflush(certificates) != 0) {
        goto done;
    }
    ok = 1;

done:
    if (certificates != NULL) fclose(certificates);
    return ok;
}

int tlcp_hybrid_test_fixture_init(TLCP_HYBRID_TEST_FIXTURE *fixture)
{
    FIXTURE_PRIVATE *state = NULL;
    uint8_t *server_der = NULL;
    size_t server_der_len = 0;
    uint8_t *encryption_der = NULL;
    size_t encryption_der_len = 0;
    uint8_t *ordinary_der = NULL;
    size_t ordinary_der_len = 0;
    int ok = 0;

    if (fixture == NULL) {
        return 0;
    }
    memset(fixture, 0, sizeof(*fixture));
    state = OPENSSL_zalloc(sizeof(*state));
    if (state == NULL) {
        return 0;
    }
    fixture->private_state = state;
    hybrid_private_key_init(&state->ca_private);
    hybrid_public_key_init(&state->ca_public);
    hybrid_private_key_init(&state->server_private);
    hybrid_public_key_init(&state->server_public);
    if (!composite_key_generate(&state->ca_private, &state->ca_public) ||
        !composite_key_generate(&state->server_private,
                                &state->server_public)) {
        goto done;
    }
    state->root = hybrid_x509_create_root(
        &state->ca_private, &state->ca_public, "Root Hybrid CA");
    state->server = hybrid_x509_create_server(
        &state->ca_private, &state->ca_public,
        &state->server_public, state->root,
        HYBRID_DEFAULT_SERVER_NAME, HYBRID_DEFAULT_SERVER_NAME);
    state->sm2_ca_key = hybrid_sm2_generate_keypair();
    state->sm2_enc_key = hybrid_sm2_generate_keypair();
    if (state->root == NULL || state->server == NULL ||
        state->sm2_ca_key == NULL || state->sm2_enc_key == NULL) {
        goto done;
    }
    state->ordinary_sm2 = make_sm2_certificate(
        state->sm2_enc_key, state->sm2_ca_key,
        X509_get_subject_name(state->server),
        X509_get_subject_name(state->root), 0);
    state->sm2_encryption = hybrid_x509_create_sm2_encryption(
        &state->ca_private, &state->ca_public, state->sm2_enc_key,
        state->root, HYBRID_DEFAULT_SERVER_NAME);
    if (state->sm2_encryption == NULL ||
        state->ordinary_sm2 == NULL ||
        !certificate_to_der(state->root, &state->root_der,
                            &state->root_der_len) ||
        !certificate_to_der(state->server, &server_der,
                            &server_der_len) ||
        !certificate_to_der(state->sm2_encryption, &encryption_der,
                            &encryption_der_len) ||
        !hybrid_x509_get_sm2_public_key_octets(
            state->sm2_encryption, fixture->encryption_public_key) ||
        !private_key_to_der(state->server_private.sm2_private_key,
                            &fixture->signing_private_key_der,
                            &fixture->signing_private_key_der_len) ||
        !private_key_to_der(state->sm2_enc_key,
                            &fixture->encryption_private_key_der,
                            &fixture->encryption_private_key_der_len) ||
        !certificate_to_der(state->ordinary_sm2, &ordinary_der,
                            &ordinary_der_len)) {
        goto done;
    }
    fixture->chain_len = server_der_len + encryption_der_len;
    fixture->chain = malloc(fixture->chain_len);
    if (fixture->chain == NULL) {
        goto done;
    }
    memcpy(fixture->chain, server_der, server_der_len);
    memcpy(fixture->chain + server_der_len, encryption_der,
           encryption_der_len);
    fixture->signing_cert_len = server_der_len;
    if (ordinary_der_len > SIZE_MAX / 2u) {
        goto done;
    }
    fixture->ordinary_chain_len = ordinary_der_len * 2u;
    fixture->ordinary_chain = malloc(fixture->ordinary_chain_len);
    if (fixture->ordinary_chain == NULL) {
        goto done;
    }
    memcpy(fixture->ordinary_chain, ordinary_der, ordinary_der_len);
    memcpy(fixture->ordinary_chain + ordinary_der_len,
           ordinary_der, ordinary_der_len);
    if (server_der_len > SIZE_MAX - ordinary_der_len) {
        goto done;
    }
    fixture->ordinary_encryption_chain_len =
        server_der_len + ordinary_der_len;
    fixture->ordinary_encryption_chain =
        malloc(fixture->ordinary_encryption_chain_len);
    if (fixture->ordinary_encryption_chain == NULL) {
        goto done;
    }
    memcpy(fixture->ordinary_encryption_chain, server_der, server_der_len);
    memcpy(fixture->ordinary_encryption_chain + server_der_len,
           ordinary_der, ordinary_der_len);
    state->config.trust_anchor_der = state->root_der;
    state->config.trust_anchor_der_len = state->root_der_len;
    state->config.expected_hostname = HYBRID_DEFAULT_SERVER_NAME;
    state->config.last_report = &state->report;
    if (!write_loader_files(fixture, state)) {
        goto done;
    }
    ok = 1;

done:
    OPENSSL_free(ordinary_der);
    OPENSSL_free(encryption_der);
    OPENSSL_free(server_der);
    if (!ok) {
        tlcp_hybrid_test_fixture_cleanup(fixture);
    }
    return ok;
}

void tlcp_hybrid_test_fixture_cleanup(TLCP_HYBRID_TEST_FIXTURE *fixture)
{
    FIXTURE_PRIVATE *state;

    if (fixture == NULL) {
        return;
    }
    state = fixture->private_state;
    if (state != NULL) {
        OPENSSL_free(state->root_der);
        X509_free(state->sm2_encryption);
        X509_free(state->ordinary_sm2);
        X509_free(state->server);
        X509_free(state->root);
        EVP_PKEY_free(state->sm2_enc_key);
        EVP_PKEY_free(state->sm2_ca_key);
        hybrid_public_key_cleanup(&state->server_public);
        hybrid_private_key_cleanup(&state->server_private);
        hybrid_public_key_cleanup(&state->ca_public);
        hybrid_private_key_cleanup(&state->ca_private);
        OPENSSL_free(state);
    }
    free(fixture->chain);
    free(fixture->ordinary_chain);
    free(fixture->ordinary_encryption_chain);
    if (fixture->signing_private_key_der != NULL) {
        OPENSSL_clear_free(fixture->signing_private_key_der,
                           fixture->signing_private_key_der_len);
    }
    if (fixture->encryption_private_key_der != NULL) {
        OPENSSL_clear_free(fixture->encryption_private_key_der,
                           fixture->encryption_private_key_der_len);
    }
    if (fixture->certificate_chain_file[0] != '\0') {
        unlink(fixture->certificate_chain_file);
    }
    if (fixture->key_file[0] != '\0') {
        unlink(fixture->key_file);
    }
    if (fixture->wrong_encryption_key_file[0] != '\0') {
        unlink(fixture->wrong_encryption_key_file);
    }
    if (fixture->temporary_directory[0] != '\0') {
        rmdir(fixture->temporary_directory);
    }
    memset(fixture, 0, sizeof(*fixture));
}

int tlcp_hybrid_test_verify_callback(
    const uint8_t *cert_chain, size_t cert_chain_len,
    uint8_t sm2_public_key[TEST_SM2_PUBLIC_KEY_SIZE],
    void *arg, int verbose)
{
    TLCP_HYBRID_TEST_FIXTURE *fixture = arg;
    FIXTURE_PRIVATE *state;

    if (fixture == NULL || fixture->private_state == NULL) {
        return -1;
    }
    state = fixture->private_state;
    return tlcp_hybrid_cert_gmssl_verify_callback(
        cert_chain, cert_chain_len, sm2_public_key,
        &state->config, verbose);
}

int tlcp_hybrid_test_fixture_report_ok(
    const TLCP_HYBRID_TEST_FIXTURE *fixture)
{
    const FIXTURE_PRIVATE *state;

    if (fixture == NULL || fixture->private_state == NULL) {
        return 0;
    }
    state = fixture->private_state;
    return state->report.composite_ok &&
           state->report.encryption_subject_spki_sm2_ok &&
           state->report.encryption_composite_ok &&
           state->report.encryption_certificate_ok &&
           state->report.tlcp_dual_certificate_ok;
}

static int sign_server_key_exchange_with_key(
    const TLCP_HYBRID_TEST_FIXTURE *fixture,
    EVP_PKEY *signing_key,
    const uint8_t client_random[32], const uint8_t server_random[32],
    uint8_t **signature, size_t *signature_len)
{
    const uint8_t *encryption_der;
    size_t encryption_der_len;
    uint8_t *message = NULL;
    size_t message_len;
    int ok = 0;

    if (fixture == NULL || fixture->private_state == NULL ||
        signing_key == NULL ||
        client_random == NULL || server_random == NULL ||
        signature == NULL || signature_len == NULL ||
        fixture->chain_len <= fixture->signing_cert_len) {
        return 0;
    }
    *signature = NULL;
    *signature_len = 0;
    encryption_der = fixture->chain + fixture->signing_cert_len;
    encryption_der_len = fixture->chain_len - fixture->signing_cert_len;
    if (encryption_der_len > 0xffffffu) {
        return 0;
    }
    message_len = 32u + 32u + 3u + encryption_der_len;
    message = OPENSSL_malloc(message_len);
    if (message == NULL) {
        return 0;
    }
    memcpy(message, client_random, 32);
    memcpy(message + 32, server_random, 32);
    message[64] = (uint8_t)(encryption_der_len >> 16);
    message[65] = (uint8_t)(encryption_der_len >> 8);
    message[66] = (uint8_t)encryption_der_len;
    memcpy(message + 67, encryption_der, encryption_der_len);
    ok = hybrid_sm2_sign(signing_key,
                         message, message_len, signature, signature_len);
    OPENSSL_free(message);
    return ok;
}

int tlcp_hybrid_test_sign_server_key_exchange(
    const TLCP_HYBRID_TEST_FIXTURE *fixture,
    const uint8_t client_random[32], const uint8_t server_random[32],
    uint8_t **signature, size_t *signature_len)
{
    const FIXTURE_PRIVATE *state;

    if (fixture == NULL || fixture->private_state == NULL) {
        return 0;
    }
    state = fixture->private_state;
    return sign_server_key_exchange_with_key(
        fixture, state->server_private.sm2_private_key,
        client_random, server_random, signature, signature_len);
}

int tlcp_hybrid_test_sign_server_key_exchange_wrong_key(
    const TLCP_HYBRID_TEST_FIXTURE *fixture,
    const uint8_t client_random[32], const uint8_t server_random[32],
    uint8_t **signature, size_t *signature_len)
{
    EVP_PKEY *wrong_key = hybrid_sm2_generate_keypair();
    int ok = sign_server_key_exchange_with_key(
        fixture, wrong_key, client_random, server_random,
        signature, signature_len);

    EVP_PKEY_free(wrong_key);
    return ok;
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

static int make_chain_with_encryption(
    const TLCP_HYBRID_TEST_FIXTURE *fixture, X509 *encryption,
    uint8_t **chain, size_t *chain_len)
{
    uint8_t *encryption_der = NULL;
    size_t encryption_der_len = 0;

    *chain = NULL;
    *chain_len = 0;
    if (!certificate_to_der(encryption, &encryption_der,
                            &encryption_der_len) ||
        fixture->signing_cert_len > SIZE_MAX - encryption_der_len) {
        OPENSSL_free(encryption_der);
        return 0;
    }
    *chain_len = fixture->signing_cert_len + encryption_der_len;
    *chain = OPENSSL_malloc(*chain_len);
    if (*chain == NULL) {
        OPENSSL_free(encryption_der);
        *chain_len = 0;
        return 0;
    }
    memcpy(*chain, fixture->chain, fixture->signing_cert_len);
    memcpy(*chain + fixture->signing_cert_len,
           encryption_der, encryption_der_len);
    OPENSSL_free(encryption_der);
    return 1;
}

int tlcp_hybrid_test_bad_encryption_dilithium_chain(
    const TLCP_HYBRID_TEST_FIXTURE *fixture,
    uint8_t **chain, size_t *chain_len)
{
    const FIXTURE_PRIVATE *state;
    const uint8_t *signature = NULL;
    size_t signature_len = 0;
    uint8_t *changed_signature = NULL;
    X509 *changed = NULL;
    int ok = 0;

    if (fixture == NULL || fixture->private_state == NULL ||
        chain == NULL || chain_len == NULL) {
        return 0;
    }
    state = fixture->private_state;
    changed = X509_dup(state->sm2_encryption);
    if (changed == NULL ||
        !hybrid_x509_get_signature(state->sm2_encryption,
                                   &signature, &signature_len) ||
        (changed_signature = OPENSSL_memdup(signature,
                                            signature_len)) == NULL) {
        goto done;
    }
    changed_signature[0] ^= 1u;
    ok = replace_signature(changed, changed_signature, signature_len) &&
         make_chain_with_encryption(fixture, changed, chain, chain_len);

done:
    OPENSSL_free(changed_signature);
    X509_free(changed);
    return ok;
}

int tlcp_hybrid_test_bad_encryption_sm2_chain(
    const TLCP_HYBRID_TEST_FIXTURE *fixture,
    uint8_t **chain, size_t *chain_len)
{
    const FIXTURE_PRIVATE *state;
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
    uint8_t *changed_signature = NULL;
    size_t changed_signature_len = 0;
    EVP_PKEY *wrong_key = NULL;
    X509 *changed = NULL;
    int ok = 0;

    if (fixture == NULL || fixture->private_state == NULL ||
        chain == NULL || chain_len == NULL) {
        return 0;
    }
    state = fixture->private_state;
    changed = X509_dup(state->sm2_encryption);
    wrong_key = hybrid_sm2_generate_keypair();
    if (changed == NULL || wrong_key == NULL ||
        !hybrid_x509_get_signature(state->sm2_encryption,
                                   &signature, &signature_len) ||
        !composite_parse_signature(signature, signature_len,
                                   &dilithium, &dilithium_len,
                                   &sm2, &sm2_len) ||
        !hybrid_x509_get_tbs_der(state->sm2_encryption, &tbs, &tbs_len) ||
        !hybrid_sm2_sign(wrong_key, tbs, tbs_len,
                         &wrong_sm2, &wrong_sm2_len) ||
        !composite_serialize_signature(dilithium, dilithium_len,
                                       wrong_sm2, wrong_sm2_len,
                                       &changed_signature,
                                       &changed_signature_len) ||
        !replace_signature(changed, changed_signature,
                           changed_signature_len)) {
        goto done;
    }
    ok = make_chain_with_encryption(fixture, changed, chain, chain_len);

done:
    X509_free(changed);
    EVP_PKEY_free(wrong_key);
    OPENSSL_free(changed_signature);
    OPENSSL_free(wrong_sm2);
    OPENSSL_free(tbs);
    return ok;
}

void tlcp_hybrid_test_free(void *pointer)
{
    OPENSSL_free(pointer);
}
