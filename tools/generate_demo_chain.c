#define _POSIX_C_SOURCE 200809L

#include "composite_key.h"
#include "hybrid_chain.h"
#include "hybrid_key_store.h"
#include "hybrid_x509.h"
#include "sm2_wrapper.h"

#include <openssl/crypto.h>
#include <openssl/x509.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static char *key_subdirectory(const char *root, const char *name)
{
    size_t root_len;
    size_t name_len;
    char *path;

    if (root == NULL || name == NULL) {
        return NULL;
    }
    root_len = strlen(root);
    name_len = strlen(name);
    if (root_len == 0 || name_len == 0 ||
        root_len > SIZE_MAX - name_len - 2u) {
        return NULL;
    }
    path = OPENSSL_malloc(root_len + name_len + 2u);
    if (path == NULL) {
        return NULL;
    }
    memcpy(path, root, root_len);
    path[root_len] = '/';
    memcpy(path + root_len + 1u, name, name_len + 1u);
    return path;
}

static int ensure_key_root(const char *path)
{
    struct stat status;

    if (path == NULL || path[0] == '\0') {
        return 0;
    }
    if (lstat(path, &status) != 0) {
        if (errno != ENOENT || mkdir(path, 0700) != 0 ||
            lstat(path, &status) != 0) {
            return 0;
        }
    }
    return S_ISDIR(status.st_mode) && !S_ISLNK(status.st_mode) &&
           (status.st_mode & 0077) == 0;
}

int main(int argc, char **argv)
{
    HYBRID_PRIVATE_KEY ca_private;
    HYBRID_PUBLIC_KEY ca_public;
    HYBRID_PRIVATE_KEY server_private;
    HYBRID_PUBLIC_KEY server_public;
    HYBRID_CHAIN_VERIFY_RESULT result;
    HYBRID_KEY_STORE_STATUS ca_status;
    HYBRID_KEY_STORE_STATUS server_status;
    HYBRID_KEY_STORE_STATUS encryption_status;
    HYBRID_CERT_VERIFY_RESULT encryption_verify;
    EVP_PKEY *encryption_private_key = NULL;
    X509 *existing_root = NULL;
    X509 *existing_server = NULL;
    X509 *existing_encryption = NULL;
    X509 *root = NULL;
    X509 *server = NULL;
    X509 *encryption = NULL;
    const char *key_root;
    const char *passphrase;
    const char *encryption_pem = NULL;
    const char *encryption_der = NULL;
    char *ca_directory = NULL;
    char *server_directory = NULL;
    char *encryption_directory = NULL;
    int generate_encryption;
    int loaded = 0;
    int exit_code = EXIT_FAILURE;

    if (argc != 5 && argc != 6 && argc != 7 && argc != 8) {
        fprintf(stderr,
                "Usage: %s ROOT.crt ROOT.der SIGN.crt SIGN.der "
                "[ENC.crt ENC.der] [KEY_ROOT]\n",
                argv[0]);
        return EXIT_FAILURE;
    }
    generate_encryption = argc == 7 || argc == 8;
    if (generate_encryption) {
        encryption_pem = argv[5];
        encryption_der = argv[6];
    }
    key_root = argc == 6 ? argv[5] : (argc == 8 ? argv[7] : "keys");
    passphrase = getenv(HYBRID_KEY_STORE_PASSPHRASE_ENV);
    if (passphrase == NULL || strlen(passphrase) < 12u) {
        fprintf(stderr, "%s must contain at least 12 bytes\n",
                HYBRID_KEY_STORE_PASSPHRASE_ENV);
        return EXIT_FAILURE;
    }
    hybrid_private_key_init(&ca_private);
    hybrid_public_key_init(&ca_public);
    hybrid_private_key_init(&server_private);
    hybrid_public_key_init(&server_public);
    if (!ensure_key_root(key_root) ||
        (ca_directory = key_subdirectory(key_root, "ca")) == NULL ||
        (server_directory = key_subdirectory(key_root, "server")) == NULL ||
        (generate_encryption &&
         (encryption_directory = key_subdirectory(
              key_root, "server-encryption")) == NULL)) {
        fputs("Unable to create secure key directory hierarchy\n", stderr);
        goto done;
    }
    ca_status = hybrid_key_store_status(ca_directory);
    server_status = hybrid_key_store_status(server_directory);
    if (ca_status == HYBRID_KEY_STORE_MISSING &&
        server_status == HYBRID_KEY_STORE_MISSING) {
        if (!composite_key_generate(&ca_private, &ca_public) ||
            !composite_key_generate(&server_private, &server_public) ||
            !hybrid_key_store_save(ca_directory, &ca_private, &ca_public,
                                   passphrase) ||
            !hybrid_key_store_save(server_directory, &server_private,
                                   &server_public, passphrase)) {
            fputs("Unable to generate and persist Hybrid private keys\n", stderr);
            goto done;
        }
        puts("Generated and persisted fresh, non-reused CA and Server Hybrid keypairs");
    } else if (ca_status == HYBRID_KEY_STORE_COMPLETE &&
               server_status == HYBRID_KEY_STORE_COMPLETE) {
        if (!hybrid_key_store_load(ca_directory, passphrase,
                                   &ca_private, &ca_public) ||
            !hybrid_key_store_load(server_directory, passphrase,
                                   &server_private, &server_public)) {
            fputs("Unable to load persisted Hybrid private keys\n", stderr);
            goto done;
        }
        loaded = 1;
        existing_root = hybrid_x509_read_pem(argv[1]);
        existing_server = hybrid_x509_read_pem(argv[3]);
        if (existing_root == NULL || existing_server == NULL ||
            !hybrid_x509_public_key_matches(existing_root, &ca_public) ||
            !hybrid_x509_public_key_matches(existing_server, &server_public) ||
            !hybrid_verify_chain(existing_root, existing_server, &result)) {
            fputs("Loaded Hybrid private key does not match the existing certificate chain\n",
                  stderr);
            goto done;
        }
        printf("Loaded CA Hybrid private key matches %s Composite SPKI exactly\n",
               argv[1]);
        printf("Loaded Server Hybrid private key matches %s Composite SPKI exactly\n",
               argv[3]);
    } else {
        fputs("Incomplete CA/Server Hybrid key store; refusing partial fallback\n",
              stderr);
        goto done;
    }

    if (generate_encryption) {
        encryption_status =
            hybrid_sm2_key_store_status(encryption_directory);
        if (encryption_status == HYBRID_KEY_STORE_MISSING) {
            encryption_private_key = hybrid_sm2_generate_keypair();
            if (encryption_private_key == NULL ||
                !hybrid_sm2_key_store_save(encryption_directory,
                                           encryption_private_key,
                                           passphrase)) {
                fputs("Unable to generate and persist TLCP encryption key\n",
                      stderr);
                goto done;
            }
            puts("Generated and persisted a distinct TLCP SM2 encryption keypair");
        } else if (encryption_status == HYBRID_KEY_STORE_COMPLETE && loaded) {
            encryption_private_key =
                hybrid_sm2_key_store_load(encryption_directory, passphrase);
            existing_encryption = hybrid_x509_read_pem(encryption_pem);
            if (encryption_private_key == NULL || existing_encryption == NULL ||
                !hybrid_x509_sm2_public_key_matches(
                    existing_encryption, encryption_private_key) ||
                !hybrid_verify_encryption_certificate(
                    existing_encryption, existing_root,
                    &encryption_verify)) {
                fputs("Loaded TLCP encryption key does not match the existing Hybrid-signed encryption certificate\n",
                      stderr);
                goto done;
            }
            printf("Loaded TLCP encryption private key matches %s SM2 SPKI exactly\n",
                   encryption_pem);
        } else {
            fputs("Incomplete or inconsistent TLCP encryption key store\n",
                  stderr);
            goto done;
        }
    }

    root = hybrid_x509_create_root(&ca_private, &ca_public, "Root Hybrid CA");
    if (root == NULL ||
        (server = hybrid_x509_create_server(
             &ca_private, &ca_public, &server_public, root,
             HYBRID_DEFAULT_SERVER_NAME,
             HYBRID_DEFAULT_SERVER_NAME)) == NULL ||
        !hybrid_x509_public_key_matches(server, &server_public) ||
        !hybrid_verify_chain(root, server, &result) ||
        (generate_encryption &&
         ((encryption = hybrid_x509_create_sm2_encryption(
               &ca_private, &ca_public, encryption_private_key, root,
               HYBRID_DEFAULT_SERVER_NAME)) == NULL ||
          !hybrid_x509_sm2_public_key_matches(
              encryption, encryption_private_key) ||
          !hybrid_verify_encryption_certificate(
              encryption, root, &encryption_verify))) ||
        !hybrid_x509_write_files(root, argv[1], argv[2]) ||
        !hybrid_x509_write_files(server, argv[3], argv[4]) ||
        (generate_encryption &&
         !hybrid_x509_write_files(encryption,
                                  encryption_pem, encryption_der))) {
        fputs("Failed to generate and verify demo chain\n", stderr);
        goto done;
    }
    printf("%s persisted key material\n", loaded ? "Reused validated" : "Used new");
    printf("Wrote Root certificate: %s, %s\n", argv[1], argv[2]);
    printf("Wrote Server certificate: %s, %s\n", argv[3], argv[4]);
    if (generate_encryption) {
        printf("Wrote TLCP encryption certificate: %s, %s\n",
               encryption_pem, encryption_der);
    }
    exit_code = EXIT_SUCCESS;

done:
    OPENSSL_free(encryption_directory);
    OPENSSL_free(server_directory);
    OPENSSL_free(ca_directory);
    X509_free(server);
    X509_free(encryption);
    X509_free(root);
    X509_free(existing_server);
    X509_free(existing_encryption);
    X509_free(existing_root);
    hybrid_public_key_cleanup(&server_public);
    hybrid_private_key_cleanup(&server_private);
    hybrid_public_key_cleanup(&ca_public);
    hybrid_private_key_cleanup(&ca_private);
    EVP_PKEY_free(encryption_private_key);
    return exit_code;
}
