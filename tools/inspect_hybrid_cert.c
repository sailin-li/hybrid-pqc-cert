#include "composite_key.h"
#include "composite_sig.h"
#include "dilithium_wrapper.h"
#include "hybrid_x509.h"

#include <openssl/crypto.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    X509 *certificate = NULL;
    HYBRID_PUBLIC_KEY public_key;
    const uint8_t *signature = NULL;
    const uint8_t *dilithium_signature = NULL;
    const uint8_t *sm2_signature = NULL;
    size_t signature_len = 0;
    size_t dilithium_signature_len = 0;
    size_t sm2_signature_len = 0;
    char *subject = NULL;
    char *issuer = NULL;
    int exit_code = EXIT_FAILURE;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s CERTIFICATE.crt\n", argv[0]);
        return EXIT_FAILURE;
    }
    hybrid_public_key_init(&public_key);
    certificate = hybrid_x509_read_pem(argv[1]);
    if (certificate == NULL ||
        !hybrid_x509_get_composite_public_key(certificate, &public_key) ||
        !hybrid_x509_get_signature(certificate, &signature, &signature_len) ||
        !composite_parse_signature(signature, signature_len,
                                   &dilithium_signature,
                                   &dilithium_signature_len,
                                   &sm2_signature, &sm2_signature_len)) {
        fprintf(stderr, "Invalid hybrid certificate: %s\n", argv[1]);
        goto done;
    }
    subject = X509_NAME_oneline(X509_get_subject_name(certificate), NULL, 0);
    issuer = X509_NAME_oneline(X509_get_issuer_name(certificate), NULL, 0);
    printf("Subject: %s\n", subject != NULL ? subject : "<invalid>");
    printf("Issuer: %s\n", issuer != NULL ? issuer : "<invalid>");
    printf("Composite Algorithm OID: %s (EXPERIMENTAL)\n",
           COMPOSITE_SM2_DILITHIUM_EXPERIMENTAL_OID);
    printf("AlgorithmIdentifiers/SPKI: %s\n",
           hybrid_x509_composite_algorithms_valid(certificate)
               ? "VALID" : "INVALID");
    printf("Course Dilithium/PQC X.509v3 identifier %s: %s\n",
           HYBRID_PQC_EXTENSION_OID,
           hybrid_x509_has_pqc_extension(certificate) ? "PRESENT" : "MISSING");
    printf("Composite public key: %u + %u = %u bytes\n",
           DILITHIUM_PUBLIC_KEY_BYTES, SM2_UNCOMPRESSED_PUBLIC_KEY_BYTES,
           COMPOSITE_PUBLIC_KEY_BYTES);
    printf("Composite signature: %zu + %zu = %zu bytes\n",
           dilithium_signature_len, sm2_signature_len, signature_len);
    printf("Dilithium parameter set: %s\n", dilithium_algorithm_name());
    puts("SM2 public key: 0x04 || X(32) || Y(32)");
    exit_code = EXIT_SUCCESS;

done:
    OPENSSL_free(issuer);
    OPENSSL_free(subject);
    hybrid_public_key_cleanup(&public_key);
    X509_free(certificate);
    return exit_code;
}
