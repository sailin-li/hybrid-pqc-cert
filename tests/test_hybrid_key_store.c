#define _POSIX_C_SOURCE 200809L

#include "composite_key.h"
#include "hybrid_key_store.h"
#include "hybrid_x509.h"

#include <openssl/x509.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(condition, text) do { \
    if (!(condition)) { fprintf(stderr, "FAIL: %s\n", text); goto done; } \
} while (0)

static int file_mode_is_0600(const char *path)
{
    struct stat status;

    return stat(path, &status) == 0 && S_ISREG(status.st_mode) &&
           (status.st_mode & 0777) == 0600;
}

static int tamper_last_byte(const char *path)
{
    int descriptor = -1;
    unsigned char value;
    int ok = 0;

    descriptor = open(path, O_RDWR | O_NOFOLLOW);
    if (descriptor < 0 || lseek(descriptor, -1, SEEK_END) < 0 ||
        read(descriptor, &value, 1) != 1 ||
        lseek(descriptor, -1, SEEK_CUR) < 0) {
        goto done;
    }
    value ^= 1u;
    if (write(descriptor, &value, 1) == 1 && fsync(descriptor) == 0) {
        ok = 1;
    }

done:
    if (descriptor >= 0) {
        close(descriptor);
    }
    return ok;
}

int main(void)
{
    static const char passphrase[] = "unit-test-passphrase-2026";
    char temporary_root[] = "/tmp/hybrid-key-store-XXXXXX";
    char ca_directory[256] = {0};
    char server_directory[256] = {0};
    char ca_sm2[320] = {0};
    char ca_dilithium[320] = {0};
    char server_sm2[320] = {0};
    char server_dilithium[320] = {0};
    HYBRID_PRIVATE_KEY ca_private;
    HYBRID_PUBLIC_KEY ca_public;
    HYBRID_PRIVATE_KEY server_private;
    HYBRID_PUBLIC_KEY server_public;
    HYBRID_PRIVATE_KEY loaded_ca_private;
    HYBRID_PUBLIC_KEY loaded_ca_public;
    HYBRID_PRIVATE_KEY loaded_server_private;
    HYBRID_PUBLIC_KEY loaded_server_public;
    HYBRID_PRIVATE_KEY rejected_private;
    HYBRID_PUBLIC_KEY rejected_public;
    X509 *root = NULL;
    X509 *server = NULL;
    int result = EXIT_FAILURE;

    hybrid_private_key_init(&ca_private);
    hybrid_public_key_init(&ca_public);
    hybrid_private_key_init(&server_private);
    hybrid_public_key_init(&server_public);
    hybrid_private_key_init(&loaded_ca_private);
    hybrid_public_key_init(&loaded_ca_public);
    hybrid_private_key_init(&loaded_server_private);
    hybrid_public_key_init(&loaded_server_public);
    hybrid_private_key_init(&rejected_private);
    hybrid_public_key_init(&rejected_public);
    CHECK(mkdtemp(temporary_root) != NULL, "temporary directory");
    CHECK(snprintf(ca_directory, sizeof(ca_directory), "%s/ca", temporary_root) > 0 &&
          snprintf(server_directory, sizeof(server_directory), "%s/server",
                   temporary_root) > 0,
          "key directory paths");
    CHECK(snprintf(ca_sm2, sizeof(ca_sm2), "%s/%s", ca_directory,
                   HYBRID_SM2_PRIVATE_KEY_FILE) > 0 &&
          snprintf(ca_dilithium, sizeof(ca_dilithium), "%s/%s", ca_directory,
                   HYBRID_DILITHIUM_PRIVATE_KEY_FILE) > 0 &&
          snprintf(server_sm2, sizeof(server_sm2), "%s/%s", server_directory,
                   HYBRID_SM2_PRIVATE_KEY_FILE) > 0 &&
          snprintf(server_dilithium, sizeof(server_dilithium), "%s/%s",
                   server_directory, HYBRID_DILITHIUM_PRIVATE_KEY_FILE) > 0,
          "private key paths");
    CHECK(composite_key_generate(&ca_private, &ca_public), "CA key generation");
    CHECK(composite_key_generate(&server_private, &server_public),
          "Server key generation");
    CHECK(hybrid_key_store_save(ca_directory, &ca_private, &ca_public,
                                passphrase),
          "CA Hybrid key persistence");
    CHECK(hybrid_key_store_save(server_directory, &server_private,
                                &server_public, passphrase),
          "Server Hybrid key persistence");
    CHECK(hybrid_key_store_status(ca_directory) == HYBRID_KEY_STORE_COMPLETE &&
          hybrid_key_store_status(server_directory) == HYBRID_KEY_STORE_COMPLETE,
          "complete key stores");
    CHECK(file_mode_is_0600(ca_sm2) && file_mode_is_0600(ca_dilithium) &&
          file_mode_is_0600(server_sm2) &&
          file_mode_is_0600(server_dilithium),
          "private key file permissions");
    CHECK(hybrid_key_store_load(ca_directory, passphrase,
                                &loaded_ca_private, &loaded_ca_public),
          "CA Hybrid key load");
    CHECK(hybrid_key_store_load(server_directory, passphrase,
                                &loaded_server_private, &loaded_server_public),
          "Server Hybrid key load");
    CHECK(composite_public_keys_equal(&ca_public, &loaded_ca_public) &&
          composite_public_keys_equal(&server_public, &loaded_server_public),
          "loaded public key equality");

    root = hybrid_x509_create_root(&loaded_ca_private, &loaded_ca_public,
                                   "Root Hybrid CA");
    server = hybrid_x509_create_server(&loaded_ca_private, &loaded_ca_public,
                                       &loaded_server_public, root,
                                       HYBRID_DEFAULT_SERVER_NAME,
                                       HYBRID_DEFAULT_SERVER_NAME);
    CHECK(root != NULL && server != NULL, "certificate generation from loaded keys");
    CHECK(hybrid_x509_public_key_matches(server, &loaded_server_public),
          "loaded Server Hybrid key vs certificate SPKI");
    CHECK(!hybrid_x509_public_key_matches(server, &loaded_ca_public),
          "mismatched Hybrid key accepted for Server certificate");
    CHECK(!hybrid_key_store_load(server_directory, "wrong-passphrase-2026",
                                 &rejected_private, &rejected_public),
          "wrong passphrase accepted");
    CHECK(tamper_last_byte(server_dilithium), "tamper authenticated container");
    CHECK(!hybrid_key_store_load(server_directory, passphrase,
                                 &rejected_private, &rejected_public),
          "tampered Dilithium container accepted");

    puts("PASS: CA/Server Hybrid private keys persist, load, authenticate, and match SPKI");
    result = EXIT_SUCCESS;

done:
    X509_free(server);
    X509_free(root);
    hybrid_public_key_cleanup(&rejected_public);
    hybrid_private_key_cleanup(&rejected_private);
    hybrid_public_key_cleanup(&loaded_server_public);
    hybrid_private_key_cleanup(&loaded_server_private);
    hybrid_public_key_cleanup(&loaded_ca_public);
    hybrid_private_key_cleanup(&loaded_ca_private);
    hybrid_public_key_cleanup(&server_public);
    hybrid_private_key_cleanup(&server_private);
    hybrid_public_key_cleanup(&ca_public);
    hybrid_private_key_cleanup(&ca_private);
    unlink(server_dilithium);
    unlink(server_sm2);
    unlink(ca_dilithium);
    unlink(ca_sm2);
    rmdir(server_directory);
    rmdir(ca_directory);
    rmdir(temporary_root);
    return result;
}
