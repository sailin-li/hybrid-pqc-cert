#include "dilithium_wrapper.h"
#include "hybrid_cert.h"
#include "hybrid_verify.h"
#include "sm2_wrapper.h"

#include <openssl/evp.h>

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    uint8_t public_key[DILITHIUM_PUBLIC_KEY_BYTES];
    uint8_t secret_key[DILITHIUM_SECRET_KEY_BYTES];
    EVP_PKEY *sm2_key = NULL;
    X509 *certificate = NULL;
    int ok = EXIT_FAILURE;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s OUTPUT.pem OUTPUT.der\n", argv[0]);
        return EXIT_FAILURE;
    }
    if ((sm2_key = sm2_generate_keypair()) == NULL ||
        !dilithium_generate_keypair(public_key, sizeof(public_key),
                                    secret_key, sizeof(secret_key)) ||
        (certificate = hybrid_cert_generate(sm2_key, public_key,
                                             sizeof(public_key), secret_key,
                                             sizeof(secret_key),
                                             "Hybrid PQC Certificate Demo")) == NULL ||
        !hybrid_cert_verify_strict(certificate) ||
        !hybrid_cert_write_files(certificate, argv[1], argv[2])) {
        fputs("Failed to generate and verify hybrid certificate\n", stderr);
        goto done;
    }
    printf("Generated %s and %s\n", argv[1], argv[2]);
    ok = EXIT_SUCCESS;

done:
    X509_free(certificate);
    EVP_PKEY_free(sm2_key);
    dilithium_clear_secret_key(secret_key, sizeof(secret_key));
    return ok;
}
