#include "hybrid_cert.h"
#include "hybrid_verify.h"

#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *pass_fail(int value)
{
    return value ? "PASS" : "FAIL";
}

int main(int argc, char **argv)
{
    FILE *input = NULL;
    X509 *certificate = NULL;
    HYBRID_PQC_INFO info;
    HYBRID_VERIFY_RESULT result;
    char *subject = NULL;
    char *issuer = NULL;
    int info_valid = 0;
    int exit_code = EXIT_FAILURE;

    hybrid_pqc_info_init(&info);
    if (argc != 2) {
        fprintf(stderr, "Usage: %s CERTIFICATE.pem\n", argv[0]);
        return EXIT_FAILURE;
    }
    input = fopen(argv[1], "rb");
    if (input == NULL || (certificate = PEM_read_X509(input, NULL, NULL, NULL)) == NULL) {
        fprintf(stderr, "Unable to read certificate: %s\n", argv[1]);
        goto done;
    }
    subject = X509_NAME_oneline(X509_get_subject_name(certificate), NULL, 0);
    issuer = X509_NAME_oneline(X509_get_issuer_name(certificate), NULL, 0);
    info_valid = hybrid_cert_get_pqc_info(certificate, &info);
    (void)hybrid_cert_verify(certificate, HYBRID_VERIFY_STRICT, &result);

    puts("# Hybrid Certificate\n");
    printf("Version: %ld\n", X509_get_version(certificate) + 1);
    printf("Serial: %ld\n", ASN1_INTEGER_get(X509_get_serialNumber(certificate)));
    printf("Subject: %s\n", subject != NULL ? subject : "<invalid>");
    printf("Issuer: %s\n\n", issuer != NULL ? issuer : "<invalid>");
    puts("Classical Algorithm:\nSM2\n");
    puts("## PQC Extension\n");
    printf("OID:\n%s\n\n", HYBRID_PQC_EXTENSION_OID);
    printf("Algorithm:\n%s\n\n",
           info_valid && strcmp(info.algorithm_oid,
                                DILITHIUM2_EXPERIMENTAL_OID) == 0
               ? "CRYSTALS-Dilithium2 (experimental private OID)"
               : "UNKNOWN");
    printf("PQC Public Key Length: %zu\n",
           info_valid ? info.public_key_len : 0u);
    printf("PQC Signature Length: %zu\n\n",
           info_valid ? info.signature_len : 0u);
    puts("## Verification\n");
    printf("SM2:\n%s\n\n", pass_fail(result.sm2_valid));
    printf("Dilithium:\n%s\n\n", pass_fail(result.dilithium_valid));
    printf("Hybrid:\n%s\n", pass_fail(result.hybrid_valid));
    exit_code = result.hybrid_valid ? EXIT_SUCCESS : EXIT_FAILURE;

done:
    OPENSSL_free(subject);
    OPENSSL_free(issuer);
    hybrid_pqc_info_cleanup(&info);
    X509_free(certificate);
    if (input != NULL) {
        fclose(input);
    }
    return exit_code;
}
