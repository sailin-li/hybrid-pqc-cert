#ifndef HYBRID_PQC_TEST_TLCP_HYBRID_GMSSL_FIXTURE_H
#define HYBRID_PQC_TEST_TLCP_HYBRID_GMSSL_FIXTURE_H

#include <stddef.h>
#include <stdint.h>

#define TEST_SM2_PUBLIC_KEY_SIZE 65u
#define TEST_FIXTURE_PATH_SIZE 512u
#define TEST_FIXTURE_KEY_PASSPHRASE "stage6b-loader-passphrase"

typedef struct {
    uint8_t *chain;
    size_t chain_len;
    size_t signing_cert_len;
    uint8_t *ordinary_chain;
    size_t ordinary_chain_len;
    uint8_t *ordinary_encryption_chain;
    size_t ordinary_encryption_chain_len;
    uint8_t encryption_public_key[TEST_SM2_PUBLIC_KEY_SIZE];
    uint8_t *signing_private_key_der;
    size_t signing_private_key_der_len;
    uint8_t *encryption_private_key_der;
    size_t encryption_private_key_der_len;
    char temporary_directory[TEST_FIXTURE_PATH_SIZE];
    char certificate_chain_file[TEST_FIXTURE_PATH_SIZE];
    char key_file[TEST_FIXTURE_PATH_SIZE];
    char wrong_encryption_key_file[TEST_FIXTURE_PATH_SIZE];
    void *private_state;
} TLCP_HYBRID_TEST_FIXTURE;

int tlcp_hybrid_test_fixture_init(TLCP_HYBRID_TEST_FIXTURE *fixture);
void tlcp_hybrid_test_fixture_cleanup(TLCP_HYBRID_TEST_FIXTURE *fixture);
int tlcp_hybrid_test_verify_callback(
    const uint8_t *cert_chain, size_t cert_chain_len,
    uint8_t sm2_public_key[TEST_SM2_PUBLIC_KEY_SIZE],
    void *arg, int verbose);
int tlcp_hybrid_test_fixture_report_ok(
    const TLCP_HYBRID_TEST_FIXTURE *fixture);
int tlcp_hybrid_test_sign_server_key_exchange(
    const TLCP_HYBRID_TEST_FIXTURE *fixture,
    const uint8_t client_random[32], const uint8_t server_random[32],
    uint8_t **signature, size_t *signature_len);
int tlcp_hybrid_test_sign_server_key_exchange_wrong_key(
    const TLCP_HYBRID_TEST_FIXTURE *fixture,
    const uint8_t client_random[32], const uint8_t server_random[32],
    uint8_t **signature, size_t *signature_len);
int tlcp_hybrid_test_bad_encryption_dilithium_chain(
    const TLCP_HYBRID_TEST_FIXTURE *fixture,
    uint8_t **chain, size_t *chain_len);
int tlcp_hybrid_test_bad_encryption_sm2_chain(
    const TLCP_HYBRID_TEST_FIXTURE *fixture,
    uint8_t **chain, size_t *chain_len);
void tlcp_hybrid_test_free(void *pointer);

#endif
