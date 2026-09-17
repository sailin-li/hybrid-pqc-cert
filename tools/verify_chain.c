#include "dilithium_wrapper.h"
#include "hybrid_chain.h"
#include "hybrid_x509.h"

#include <openssl/crypto.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <stdlib.h>

static const char *pass_fail(int value)
{
    return value ? "PASS" : "FAIL";
}

int main(int argc, char **argv)
{
    X509 *root = NULL;
    X509 *server = NULL;
    HYBRID_CHAIN_VERIFY_RESULT result;
    char *root_subject = NULL;
    char *server_subject = NULL;
    int exit_code = EXIT_FAILURE;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s ROOT.crt SERVER.crt\n", argv[0]);
        return EXIT_FAILURE;
    }
    root = hybrid_x509_read_pem(argv[1]);
    server = hybrid_x509_read_pem(argv[2]);
    if (root == NULL || server == NULL) {
        fputs("Unable to read certificate chain\n", stderr);
        goto done;
    }
    root_subject = X509_NAME_oneline(X509_get_subject_name(root), NULL, 0);
    server_subject = X509_NAME_oneline(X509_get_subject_name(server), NULL, 0);
    (void)hybrid_verify_chain(root, server, &result);

    puts("=== Hybrid Certificate Chain Verification ===\n");
    puts("Trust Anchor:");
    printf("  Subject: %s\n", root_subject != NULL ? root_subject : "<invalid>");
    printf("  Composite Algorithm: %s\n",
           COMPOSITE_SM2_DILITHIUM_EXPERIMENTAL_OID);
    printf("  Dilithium component: %s (%u-byte public key)\n",
           dilithium_algorithm_name(), DILITHIUM_PUBLIC_KEY_BYTES);
    puts("  SM2 component: sm2p256v1 uncompressed point");
    puts("  [INFO] Root is configured as trust anchor\n");

    puts("Root self-signature:");
    printf("  Dilithium: %s\n", pass_fail(result.root.dilithium_valid));
    printf("  SM2:       %s\n", pass_fail(result.root.sm2_valid));
    printf("  Composite: %s\n",
           pass_fail(result.root.composite_valid));
    printf("  [%s] Root composite self-signature cryptographically %s\n\n",
           result.root.composite_valid ? "PASS" : "FAIL",
           result.root.composite_valid ? "valid" : "invalid");

    puts("Server Certificate:");
    printf("  Subject:             %s\n",
           server_subject != NULL ? server_subject : "<invalid>");
    printf("  Issuer/Subject link: %s\n",
           pass_fail(result.server.issuer_subject_link_valid));
    printf("  Validity:            %s\n",
           pass_fail(result.server.validity_valid));
    printf("  BasicConstraints:    %s\n",
           pass_fail(result.server.subject_constraints_valid));
    printf("  Issuer CA/KeyUsage:  %s\n",
           pass_fail(result.server.issuer_ca_constraints_valid));
    printf("  ExtendedKeyUsage:    %s\n", pass_fail(result.server.eku_valid));
    printf("  SubjectAltName:      %s\n", pass_fail(result.server.san_valid));
    printf("  SKI/AKI link:        %s\n",
           pass_fail(result.server.key_identifiers_valid));
    printf("  Course Dilithium/PQC extension: %s\n",
           pass_fail(result.server.pqc_extension_present));
    printf("  Composite OID:       %s\n\n",
           pass_fail(result.server.composite_oids_valid));

    puts("Certificate signature:");
    printf("  Format:     %s\n", pass_fail(result.server.signature_format_valid));
    printf("  Dilithium:  %s\n", pass_fail(result.server.dilithium_valid));
    printf("  SM2:        %s\n", pass_fail(result.server.sm2_valid));
    printf("  Composite:  %s\n\n",
           pass_fail(result.server.composite_valid));
    puts("Chain result:");
    printf("  %s\n", result.chain_valid ? "VALID" : "INVALID");
    exit_code = result.chain_valid ? EXIT_SUCCESS : EXIT_FAILURE;

done:
    OPENSSL_free(server_subject);
    OPENSSL_free(root_subject);
    X509_free(server);
    X509_free(root);
    return exit_code;
}
