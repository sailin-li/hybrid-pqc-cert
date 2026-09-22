#include "tlcp_hybrid_gmssl_fixture.h"

#include <gmssl/digest.h>
#include <gmssl/sm2.h>
#include <gmssl/tls.h>
#include <gmssl/x509_cer.h>
#include <gmssl/x509_key.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition, text) do { \
    if (!(condition)) { fprintf(stderr, "FAIL: %s\n", text); goto done; } \
} while (0)

static int parse_sm2_private_key(const uint8_t *der, size_t der_len,
                                 X509_KEY *key)
{
    const uint8_t *cursor = der;
    size_t remaining = der_len;

    memset(key, 0, sizeof(*key));
    key->algor = OID_ec_public_key;
    key->algor_param = OID_sm2;
    return der != NULL && der_len != 0 &&
           sm2_private_key_from_der(&key->u.sm2_key,
                                    &cursor, &remaining) == 1 &&
           remaining == 0;
}

static int write_gmssl_key_file(const char *path,
                                const TLCP_HYBRID_TEST_FIXTURE *fixture,
                                int wrong_encryption_key)
{
    X509_KEY signing_key;
    X509_KEY encryption_key;
    FILE *output = NULL;
    int ok = 0;

    memset(&signing_key, 0, sizeof(signing_key));
    memset(&encryption_key, 0, sizeof(encryption_key));
    if (!parse_sm2_private_key(fixture->signing_private_key_der,
                               fixture->signing_private_key_der_len,
                               &signing_key)) {
        goto done;
    }
    if (wrong_encryption_key) {
        encryption_key.algor = OID_ec_public_key;
        encryption_key.algor_param = OID_sm2;
        if (sm2_key_generate(&encryption_key.u.sm2_key) != 1) {
            goto done;
        }
    } else if (!parse_sm2_private_key(
                   fixture->encryption_private_key_der,
                   fixture->encryption_private_key_der_len,
                   &encryption_key)) {
        goto done;
    }
    output = fopen(path, "wb");
    if (output == NULL || chmod(path, 0600) != 0 ||
        x509_private_key_info_encrypt_to_pem(
            &signing_key, TEST_FIXTURE_KEY_PASSPHRASE, output) != 1 ||
        x509_private_key_info_encrypt_to_pem(
            &encryption_key, TEST_FIXTURE_KEY_PASSPHRASE, output) != 1 ||
        fflush(output) != 0) {
        goto done;
    }
    ok = 1;

done:
    if (output != NULL) fclose(output);
    x509_key_cleanup(&encryption_key);
    x509_key_cleanup(&signing_key);
    return ok;
}

static int receive_certificate_record(TLS_CTX *context,
                                      const uint8_t *certs,
                                      size_t certs_len,
                                      TLS_CONNECT *connection,
                                      uint8_t alert[7])
{
    int sockets[2] = {-1, -1};
    uint8_t record[TLS_MAX_RECORD_SIZE];
    size_t record_len = 0;
    int cipher = TLS_cipher_ecc_sm4_cbc_sm3;
    int signature = TLS_sig_sm2sig_sm3;
    int result = -1;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0 ||
        tls_ctx_set_cipher_suites(context, &cipher, 1) != 1 ||
        tls_ctx_set_signature_algorithms(context, &signature, 1) != 1 ||
        tls_init(connection, context) != 1 ||
        tls_set_socket(connection, sockets[0]) != 1 ||
        digest_init(&connection->dgst_ctx, DIGEST_sm3()) != 1) {
        goto done;
    }
    connection->cipher_suite = cipher;
    memcpy(connection->host_name, "server.local", sizeof("server.local") - 1u);
    connection->host_name_len = sizeof("server.local") - 1u;
    if (tls_record_set_protocol(record, TLS_protocol_tlcp) != 1 ||
        tls_record_set_handshake_certificate(record, &record_len,
                                             certs, certs_len) != 1 ||
        write(sockets[1], record, record_len) != (ssize_t)record_len) {
        goto done;
    }
    result = tlcp_recv_server_certificate(connection);
    if (result != 1 && alert != NULL &&
        read(sockets[1], alert, 7) != 7) {
        result = -2;
    }

done:
    if (sockets[0] >= 0) close(sockets[0]);
    if (sockets[1] >= 0) close(sockets[1]);
    return result;
}

static int receive_server_key_exchange(TLS_CONNECT *connection,
                                       const uint8_t *signature,
                                       size_t signature_len,
                                       uint8_t alert[7])
{
    int sockets[2] = {-1, -1};
    uint8_t record[TLS_MAX_RECORD_SIZE];
    size_t record_len = 0;
    int result = -1;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0 ||
        tls_set_socket(connection, sockets[0]) != 1 ||
        tls_record_set_protocol(record, TLS_protocol_tlcp) != 1 ||
        tlcp_record_set_handshake_server_key_exchange_ecc(
            record, &record_len, signature, signature_len) != 1 ||
        write(sockets[1], record, record_len) != (ssize_t)record_len) {
        goto done;
    }
    result = tlcp_recv_server_key_exchange(connection);
    if (result != 1 && alert != NULL &&
        read(sockets[1], alert, 7) != 7) {
        result = -2;
    }

done:
    if (sockets[0] >= 0) close(sockets[0]);
    if (sockets[1] >= 0) close(sockets[1]);
    return result;
}

int main(void)
{
    TLCP_HYBRID_TEST_FIXTURE fixture;
    static TLS_CTX context;
    static TLS_CTX server_context;
    static TLS_CONNECT connection;
    uint8_t *changed = NULL;
    uint8_t *bad_encryption_chain = NULL;
    size_t bad_encryption_chain_len = 0;
    uint8_t *ske_signature = NULL;
    size_t ske_signature_len = 0;
    uint8_t alert[7];
    const uint8_t *encryption_cert = NULL;
    size_t encryption_cert_len = 0;
    X509_KEY encryption_key = {0};
    uint8_t encryption_public_key[TEST_SM2_PUBLIC_KEY_SIZE];
    uint8_t *encryption_public_key_ptr = encryption_public_key;
    size_t encryption_public_key_len = 0;
    int context_active = 0;
    int server_context_active = 0;
    int connection_active = 0;
    int ok = EXIT_FAILURE;

    memset(&fixture, 0, sizeof(fixture));
    CHECK(tlcp_hybrid_test_fixture_init(&fixture), "fixture");
    CHECK(write_gmssl_key_file(fixture.key_file, &fixture, 0) &&
          write_gmssl_key_file(fixture.wrong_encryption_key_file,
                               &fixture, 1),
          "GmSSL loader key files");
    CHECK(tls_ctx_init(&server_context, TLS_protocol_tlcp, 0) == 1,
          "hybrid server loader context");
    server_context_active = 1;
    CHECK(tls_ctx_set_tlcp_hybrid_cert_verify(
              &server_context, 1, tlcp_hybrid_test_verify_callback,
              &fixture) == 1 &&
          tls_ctx_set_tlcp_hybrid_server_certificate_and_keys(
              &server_context, fixture.certificate_chain_file,
              fixture.key_file, TEST_FIXTURE_KEY_PASSPHRASE) == 1,
          "hybrid server loader");
    puts("PASS: server loader matches signing and encryption private keys");
    tls_ctx_cleanup(&server_context);
    server_context_active = 0;

    CHECK(tls_ctx_init(&server_context, TLS_protocol_tlcp, 0) == 1,
          "mismatched server loader context");
    server_context_active = 1;
    CHECK(tls_ctx_set_tlcp_hybrid_cert_verify(
              &server_context, 1, tlcp_hybrid_test_verify_callback,
              &fixture) == 1 &&
          tls_ctx_set_tlcp_hybrid_server_certificate_and_keys(
              &server_context, fixture.certificate_chain_file,
              fixture.wrong_encryption_key_file,
              TEST_FIXTURE_KEY_PASSPHRASE) == -1,
          "mismatched encryption private key rejection");
    puts("PASS: server loader rejects mismatched encryption private key");
    tls_ctx_cleanup(&server_context);
    server_context_active = 0;

    CHECK(tls_ctx_init(&context, TLS_protocol_tlcp, 1) == 1,
          "client context");
    context_active = 1;
    CHECK(tls_ctx_set_tlcp_hybrid_cert_verify(
              &context, 1, tlcp_hybrid_test_verify_callback,
              &fixture) == 1 &&
          receive_certificate_record(&context, fixture.chain,
                                     fixture.chain_len,
                                     &connection, NULL) == 1,
          "hybrid Certificate handshake stage");
    connection_active = 1;
    CHECK(connection.tlcp_hybrid_sign_cert &&
          tlcp_hybrid_test_fixture_report_ok(&fixture),
          "hybrid verification result");
    puts("PASS: strict Hybrid Certificate record advances to ServerKeyExchange");
    memset(&encryption_key, 0, sizeof(encryption_key));
    CHECK(tls_cert_chain_get_cert_by_index_raw(
              connection.peer_cert_chain, connection.peer_cert_chain_len,
              1, &encryption_cert, &encryption_cert_len) == 1 &&
          x509_cert_get_subject_public_key(
              encryption_cert, encryption_cert_len, &encryption_key) == 1 &&
          encryption_key.algor == OID_ec_public_key &&
          encryption_key.algor_param == OID_sm2 &&
          x509_public_key_to_bytes(&encryption_key,
                                   &encryption_public_key_ptr,
                                   &encryption_public_key_len) == 1 &&
          encryption_public_key_len == sizeof(encryption_public_key) &&
          memcmp(encryption_public_key, fixture.encryption_public_key,
                 sizeof(encryption_public_key)) == 0,
          "GmSSL encryption certificate SM2 SPKI extraction");
    puts("PASS: GmSSL extracts the correct SM2 encryption public key");
    tls_clean_record(&connection);
    CHECK(tlcp_hybrid_test_sign_server_key_exchange(
              &fixture, connection.client_random, connection.server_random,
              &ske_signature, &ske_signature_len) &&
          receive_server_key_exchange(&connection, ske_signature,
                                      ske_signature_len, NULL) == 1,
          "ServerKeyExchange SM2 component verification");
    puts("PASS: ServerKeyExchange verifies with Composite SM2 component");
    tls_cleanup(&connection);
    connection_active = 0;
    tls_ctx_cleanup(&context);
    context_active = 0;

    changed = malloc(fixture.chain_len);
    CHECK(changed != NULL, "changed chain");
    memcpy(changed, fixture.chain, fixture.chain_len);
    changed[fixture.signing_cert_len - 1u] ^= 1u;
    memset(alert, 0, sizeof(alert));
    CHECK(tls_ctx_init(&context, TLS_protocol_tlcp, 1) == 1,
          "negative client context");
    context_active = 1;
    CHECK(tls_ctx_set_tlcp_hybrid_cert_verify(
              &context, 1, tlcp_hybrid_test_verify_callback,
              &fixture) == 1 &&
          receive_certificate_record(&context, changed, fixture.chain_len,
                                     &connection, alert) == -1 &&
          alert[6] == TLS_alert_bad_certificate,
          "tampered certificate alert");
    connection_active = 1;
    puts("PASS: tampered Composite -> fatal bad_certificate");
    tls_cleanup(&connection);
    connection_active = 0;
    tls_ctx_cleanup(&context);
    context_active = 0;

    CHECK(tlcp_hybrid_test_bad_encryption_dilithium_chain(
              &fixture, &bad_encryption_chain,
              &bad_encryption_chain_len),
          "bad encryption Dilithium chain");
    memset(alert, 0, sizeof(alert));
    CHECK(tls_ctx_init(&context, TLS_protocol_tlcp, 1) == 1,
          "bad encryption Dilithium context");
    context_active = 1;
    CHECK(tls_ctx_set_tlcp_hybrid_cert_verify(
              &context, 1, tlcp_hybrid_test_verify_callback,
              &fixture) == 1 &&
          receive_certificate_record(&context, bad_encryption_chain,
                                     bad_encryption_chain_len,
                                     &connection, alert) == -1 &&
          alert[6] == TLS_alert_bad_certificate,
          "bad encryption Dilithium alert");
    connection_active = 1;
    puts("PASS: encryption Dilithium failure -> fatal bad_certificate");
    tls_cleanup(&connection);
    connection_active = 0;
    tls_ctx_cleanup(&context);
    context_active = 0;
    tlcp_hybrid_test_free(bad_encryption_chain);
    bad_encryption_chain = NULL;
    bad_encryption_chain_len = 0;

    CHECK(tlcp_hybrid_test_bad_encryption_sm2_chain(
              &fixture, &bad_encryption_chain,
              &bad_encryption_chain_len),
          "bad encryption SM2 chain");
    memset(alert, 0, sizeof(alert));
    CHECK(tls_ctx_init(&context, TLS_protocol_tlcp, 1) == 1,
          "bad encryption SM2 context");
    context_active = 1;
    CHECK(tls_ctx_set_tlcp_hybrid_cert_verify(
              &context, 1, tlcp_hybrid_test_verify_callback,
              &fixture) == 1 &&
          receive_certificate_record(&context, bad_encryption_chain,
                                     bad_encryption_chain_len,
                                     &connection, alert) == -1 &&
          alert[6] == TLS_alert_bad_certificate,
          "bad encryption SM2 alert");
    connection_active = 1;
    puts("PASS: encryption SM2 failure -> fatal bad_certificate");
    tls_cleanup(&connection);
    connection_active = 0;
    tls_ctx_cleanup(&context);
    context_active = 0;
    tlcp_hybrid_test_free(bad_encryption_chain);
    bad_encryption_chain = NULL;
    bad_encryption_chain_len = 0;

    memset(alert, 0, sizeof(alert));
    CHECK(tls_ctx_init(&context, TLS_protocol_tlcp, 1) == 1,
          "downgrade client context");
    context_active = 1;
    CHECK(tls_ctx_set_tlcp_hybrid_cert_verify(
              &context, 1, tlcp_hybrid_test_verify_callback,
              &fixture) == 1 &&
          receive_certificate_record(&context, fixture.ordinary_chain,
                                     fixture.ordinary_chain_len,
                                     &connection, alert) == -1 &&
          alert[6] == TLS_alert_bad_certificate,
          "strict ordinary-certificate downgrade alert");
    connection_active = 1;
    puts("PASS: strict expected-hybrid rejects ordinary signing certificate");
    tls_cleanup(&connection);
    connection_active = 0;
    tls_ctx_cleanup(&context);
    context_active = 0;

    memset(alert, 0, sizeof(alert));
    CHECK(tls_ctx_init(&context, TLS_protocol_tlcp, 1) == 1,
          "ordinary encryption downgrade client context");
    context_active = 1;
    CHECK(tls_ctx_set_tlcp_hybrid_cert_verify(
              &context, 1, tlcp_hybrid_test_verify_callback,
              &fixture) == 1 &&
          receive_certificate_record(
              &context, fixture.ordinary_encryption_chain,
              fixture.ordinary_encryption_chain_len,
              &connection, alert) == -1 &&
          alert[6] == TLS_alert_bad_certificate,
          "strict ordinary-encryption-certificate downgrade alert");
    connection_active = 1;
    puts("PASS: strict expected-hybrid rejects ordinary-signed encryption certificate");
    tls_cleanup(&connection);
    connection_active = 0;
    tls_ctx_cleanup(&context);
    context_active = 0;

    CHECK(tls_ctx_init(&context, TLS_protocol_tlcp, 1) == 1,
          "wrong-SKE client context");
    context_active = 1;
    CHECK(tls_ctx_set_tlcp_hybrid_cert_verify(
              &context, 1, tlcp_hybrid_test_verify_callback,
              &fixture) == 1 &&
          receive_certificate_record(&context, fixture.chain,
                                     fixture.chain_len,
                                     &connection, NULL) == 1,
          "wrong-SKE certificate stage");
    connection_active = 1;
    tls_clean_record(&connection);
    tlcp_hybrid_test_free(ske_signature);
    ske_signature = NULL;
    ske_signature_len = 0;
    CHECK(tlcp_hybrid_test_sign_server_key_exchange_wrong_key(
              &fixture, connection.client_random, connection.server_random,
              &ske_signature, &ske_signature_len),
          "wrong-SKE signature generation");
    memset(alert, 0, sizeof(alert));
    CHECK(receive_server_key_exchange(&connection, ske_signature,
                                      ske_signature_len, alert) == -1 &&
          alert[6] == TLS_alert_decrypt_error,
          "wrong ServerKeyExchange key/signature rejection");
    puts("PASS: wrong ServerKeyExchange SM2 component key -> fatal decrypt_error");
    ok = EXIT_SUCCESS;

done:
    x509_key_cleanup(&encryption_key);
    if (server_context_active) tls_ctx_cleanup(&server_context);
    if (connection_active) tls_cleanup(&connection);
    if (context_active) tls_ctx_cleanup(&context);
    free(changed);
    tlcp_hybrid_test_free(bad_encryption_chain);
    tlcp_hybrid_test_free(ske_signature);
    tlcp_hybrid_test_fixture_cleanup(&fixture);
    return ok;
}
