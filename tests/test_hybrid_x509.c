#include "composite_key.h"
#include "composite_sig.h"
#include "hybrid_chain.h"
#include "hybrid_x509.h"

#include <openssl/x509.h>

#include <stdio.h>
#include <stdlib.h>

#define CHECK(condition, text) do { \
    if (!(condition)) { fprintf(stderr, "FAIL: %s\n", text); goto done; } \
} while (0)

int main(void)
{
    HYBRID_PRIVATE_KEY ca_private;
    HYBRID_PUBLIC_KEY ca_public;
    HYBRID_PRIVATE_KEY server_private;
    HYBRID_PUBLIC_KEY server_public;
    HYBRID_CHAIN_VERIFY_RESULT result;
    HYBRID_PUBLIC_KEY extracted;
    X509 *root = NULL;
    X509 *server = NULL;
    const uint8_t *signature = NULL;
    size_t signature_len = 0;
    int ok = EXIT_FAILURE;

    hybrid_private_key_init(&ca_private);
    hybrid_public_key_init(&ca_public);
    hybrid_private_key_init(&server_private);
    hybrid_public_key_init(&server_public);
    hybrid_public_key_init(&extracted);
    CHECK(composite_key_generate(&ca_private, &ca_public), "CA keys");
    CHECK(composite_key_generate(&server_private, &server_public),
          "server keys");
    CHECK((root = hybrid_x509_create_root(&ca_private, &ca_public,
                                          "Root Hybrid CA")) != NULL,
          "root certificate");
    CHECK((server = hybrid_x509_create_server(
               &ca_private, &ca_public, &server_public, root,
               HYBRID_DEFAULT_SERVER_NAME,
               HYBRID_DEFAULT_SERVER_NAME)) != NULL,
          "server certificate");
    CHECK(hybrid_verify_chain(root, server, &result), "chain verification");
    CHECK(result.root.dilithium_valid && result.root.sm2_valid &&
          result.server.dilithium_valid && result.server.sm2_valid,
          "component verification");
    CHECK(hybrid_x509_composite_algorithms_valid(root) &&
          hybrid_x509_composite_algorithms_valid(server),
          "composite AlgorithmIdentifiers");
    CHECK(hybrid_x509_get_composite_public_key(server, &extracted),
          "server SPKI parse");
    CHECK(hybrid_x509_get_signature(server, &signature, &signature_len) &&
          signature_len > DILITHIUM_SIGNATURE_BYTES,
          "raw composite signatureValue");
    puts("PASS: Root self-signature and Root -> Server composite chain valid");
    ok = EXIT_SUCCESS;

done:
    X509_free(server);
    X509_free(root);
    hybrid_public_key_cleanup(&extracted);
    hybrid_public_key_cleanup(&server_public);
    hybrid_private_key_cleanup(&server_private);
    hybrid_public_key_cleanup(&ca_public);
    hybrid_private_key_cleanup(&ca_private);
    return ok;
}
