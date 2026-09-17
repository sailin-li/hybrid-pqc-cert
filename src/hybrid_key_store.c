#define _POSIX_C_SOURCE 200809L

#include "hybrid_key_store.h"

#include "composite_sig.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DILITHIUM_STORE_MAGIC "HPQCDK01"
#define DILITHIUM_PLAINTEXT_MAGIC "DIL2K001"
#define DILITHIUM_STORE_SALT_BYTES 16u
#define DILITHIUM_STORE_IV_BYTES 12u
#define DILITHIUM_STORE_TAG_BYTES 16u
#define DILITHIUM_STORE_KEY_BYTES 32u
#define DILITHIUM_STORE_ITERATIONS 200000u
#define DILITHIUM_STORE_HEADER_BYTES \
    (8u + 4u + DILITHIUM_STORE_SALT_BYTES + DILITHIUM_STORE_IV_BYTES + 4u)
#define DILITHIUM_STORE_PLAINTEXT_BYTES \
    (8u + DILITHIUM_PUBLIC_KEY_BYTES + DILITHIUM_SECRET_KEY_BYTES)
#define DILITHIUM_STORE_FILE_BYTES \
    (DILITHIUM_STORE_HEADER_BYTES + DILITHIUM_STORE_PLAINTEXT_BYTES + \
     DILITHIUM_STORE_TAG_BYTES)

typedef struct {
    const char *bytes;
    size_t length;
} PASSPHRASE_DATA;

static char *join_path(const char *directory, const char *name)
{
    size_t directory_len;
    size_t name_len;
    char *path;

    if (directory == NULL || name == NULL) {
        return NULL;
    }
    directory_len = strlen(directory);
    name_len = strlen(name);
    if (directory_len == 0 || name_len == 0 ||
        directory_len > SIZE_MAX - name_len - 2u) {
        return NULL;
    }
    path = OPENSSL_malloc(directory_len + name_len + 2u);
    if (path == NULL) {
        return NULL;
    }
    memcpy(path, directory, directory_len);
    path[directory_len] = '/';
    memcpy(path + directory_len + 1u, name, name_len + 1u);
    return path;
}

static int passphrase_valid(const char *passphrase)
{
    size_t length;

    if (passphrase == NULL) {
        return 0;
    }
    length = strlen(passphrase);
    return length >= 12u && length <= INT_MAX;
}

static int ensure_private_directory(const char *directory)
{
    struct stat status;

    if (directory == NULL || directory[0] == '\0') {
        return 0;
    }
    if (lstat(directory, &status) != 0) {
        if (errno != ENOENT || mkdir(directory, 0700) != 0 ||
            lstat(directory, &status) != 0) {
            return 0;
        }
    }
    return S_ISDIR(status.st_mode) && !S_ISLNK(status.st_mode) &&
           (status.st_mode & 0077) == 0;
}

static int secure_regular_file(const char *path, off_t expected_size)
{
    struct stat status;

    return path != NULL && lstat(path, &status) == 0 &&
           S_ISREG(status.st_mode) && !S_ISLNK(status.st_mode) &&
           (status.st_mode & 0077) == 0 &&
           (expected_size < 0 || status.st_size == expected_size);
}

HYBRID_KEY_STORE_STATUS hybrid_key_store_status(const char *directory)
{
    char *sm2_path = NULL;
    char *dilithium_path = NULL;
    int sm2_exists;
    int dilithium_exists;
    HYBRID_KEY_STORE_STATUS result = HYBRID_KEY_STORE_INCOMPLETE;

    sm2_path = join_path(directory, HYBRID_SM2_PRIVATE_KEY_FILE);
    dilithium_path = join_path(directory, HYBRID_DILITHIUM_PRIVATE_KEY_FILE);
    if (sm2_path == NULL || dilithium_path == NULL) {
        goto done;
    }
    sm2_exists = access(sm2_path, F_OK) == 0;
    dilithium_exists = access(dilithium_path, F_OK) == 0;
    if (!sm2_exists && !dilithium_exists) {
        result = HYBRID_KEY_STORE_MISSING;
    } else if (sm2_exists && dilithium_exists) {
        result = HYBRID_KEY_STORE_COMPLETE;
    }

done:
    OPENSSL_free(dilithium_path);
    OPENSSL_free(sm2_path);
    return result;
}

static void put_u32_be(unsigned char output[4], uint32_t value)
{
    output[0] = (unsigned char)(value >> 24);
    output[1] = (unsigned char)(value >> 16);
    output[2] = (unsigned char)(value >> 8);
    output[3] = (unsigned char)value;
}

static uint32_t get_u32_be(const unsigned char input[4])
{
    return ((uint32_t)input[0] << 24) |
           ((uint32_t)input[1] << 16) |
           ((uint32_t)input[2] << 8) |
           (uint32_t)input[3];
}

static int derive_encryption_key(const char *passphrase,
                                 const unsigned char *salt,
                                 unsigned char key[DILITHIUM_STORE_KEY_BYTES])
{
    return passphrase_valid(passphrase) && salt != NULL &&
           PKCS5_PBKDF2_HMAC(passphrase, (int)strlen(passphrase),
                             salt, DILITHIUM_STORE_SALT_BYTES,
                             DILITHIUM_STORE_ITERATIONS, EVP_sha256(),
                             DILITHIUM_STORE_KEY_BYTES, key) == 1;
}

static int write_all(int descriptor, const unsigned char *data, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t written = write(descriptor, data + offset, length - offset);
        if (written <= 0) {
            return 0;
        }
        offset += (size_t)written;
    }
    return 1;
}

static int read_all(int descriptor, unsigned char *data, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t count = read(descriptor, data + offset, length - offset);
        if (count <= 0) {
            return 0;
        }
        offset += (size_t)count;
    }
    return 1;
}

static int password_callback(char *buffer, int size, int writing, void *userdata)
{
    PASSPHRASE_DATA *data = userdata;

    (void)writing;
    if (buffer == NULL || size <= 0 || data == NULL ||
        data->length > (size_t)size) {
        return 0;
    }
    memcpy(buffer, data->bytes, data->length);
    return (int)data->length;
}

static int save_sm2_private_key(const char *path, EVP_PKEY *private_key,
                                const char *passphrase)
{
    int descriptor = -1;
    FILE *output = NULL;
    int ok = 0;

    if (path == NULL || private_key == NULL || !passphrase_valid(passphrase)) {
        return 0;
    }
    descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (descriptor < 0) {
        return 0;
    }
    output = fdopen(descriptor, "wb");
    if (output == NULL) {
        close(descriptor);
        descriptor = -1;
        goto done;
    }
    descriptor = -1;
    if (!PEM_write_PKCS8PrivateKey(output, private_key, EVP_aes_256_cbc(),
                                   (char *)passphrase,
                                   (int)strlen(passphrase), NULL, NULL) ||
        fflush(output) != 0 || fsync(fileno(output)) != 0) {
        goto done;
    }
    if (fclose(output) != 0) {
        output = NULL;
        goto done;
    }
    output = NULL;
    ok = 1;

done:
    if (output != NULL) {
        fclose(output);
    }
    if (!ok) {
        unlink(path);
    }
    return ok;
}

static EVP_PKEY *load_sm2_private_key(const char *path,
                                      const char *passphrase)
{
    FILE *input = NULL;
    EVP_PKEY *private_key = NULL;
    EVP_PKEY_CTX *check_context = NULL;
    PASSPHRASE_DATA password;

    if (!secure_regular_file(path, -1) || !passphrase_valid(passphrase)) {
        return NULL;
    }
    input = fopen(path, "rb");
    if (input == NULL) {
        return NULL;
    }
    password.bytes = passphrase;
    password.length = strlen(passphrase);
    private_key = PEM_read_PrivateKey(input, NULL, password_callback, &password);
    fclose(input);
    if (private_key == NULL || !EVP_PKEY_is_a(private_key, "SM2")) {
        EVP_PKEY_free(private_key);
        return NULL;
    }
    check_context = EVP_PKEY_CTX_new_from_pkey(NULL, private_key, NULL);
    if (check_context == NULL || EVP_PKEY_private_check(check_context) <= 0) {
        EVP_PKEY_free(private_key);
        private_key = NULL;
    }
    EVP_PKEY_CTX_free(check_context);
    return private_key;
}

static int encrypt_dilithium_payload(
    const HYBRID_PRIVATE_KEY *private_key,
    const HYBRID_PUBLIC_KEY *public_key,
    const char *passphrase,
    unsigned char output[DILITHIUM_STORE_FILE_BYTES])
{
    EVP_CIPHER_CTX *context = NULL;
    unsigned char plaintext[DILITHIUM_STORE_PLAINTEXT_BYTES];
    unsigned char encryption_key[DILITHIUM_STORE_KEY_BYTES];
    unsigned char *salt = output + 12u;
    unsigned char *iv = salt + DILITHIUM_STORE_SALT_BYTES;
    unsigned char *ciphertext = output + DILITHIUM_STORE_HEADER_BYTES;
    unsigned char *tag = ciphertext + DILITHIUM_STORE_PLAINTEXT_BYTES;
    int produced = 0;
    int final_produced = 0;
    int ok = 0;

    memset(plaintext, 0, sizeof(plaintext));
    memset(encryption_key, 0, sizeof(encryption_key));
    memcpy(output, DILITHIUM_STORE_MAGIC, 8u);
    put_u32_be(output + 8u, DILITHIUM_STORE_ITERATIONS);
    put_u32_be(output + DILITHIUM_STORE_HEADER_BYTES - 4u,
               DILITHIUM_STORE_PLAINTEXT_BYTES);
    if (RAND_bytes(salt, DILITHIUM_STORE_SALT_BYTES) <= 0 ||
        RAND_bytes(iv, DILITHIUM_STORE_IV_BYTES) <= 0 ||
        !derive_encryption_key(passphrase, salt, encryption_key)) {
        goto done;
    }
    memcpy(plaintext, DILITHIUM_PLAINTEXT_MAGIC, 8u);
    memcpy(plaintext + 8u, public_key->dilithium_public_key,
           DILITHIUM_PUBLIC_KEY_BYTES);
    memcpy(plaintext + 8u + DILITHIUM_PUBLIC_KEY_BYTES,
           private_key->dilithium_secret_key, DILITHIUM_SECRET_KEY_BYTES);
    context = EVP_CIPHER_CTX_new();
    if (context == NULL ||
        EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN,
                            DILITHIUM_STORE_IV_BYTES, NULL) <= 0 ||
        EVP_EncryptInit_ex(context, NULL, NULL, encryption_key, iv) <= 0 ||
        EVP_EncryptUpdate(context, NULL, &produced, output,
                          DILITHIUM_STORE_HEADER_BYTES) <= 0 ||
        EVP_EncryptUpdate(context, ciphertext, &produced, plaintext,
                          DILITHIUM_STORE_PLAINTEXT_BYTES) <= 0 ||
        produced != (int)DILITHIUM_STORE_PLAINTEXT_BYTES ||
        EVP_EncryptFinal_ex(context, ciphertext + produced,
                            &final_produced) <= 0 || final_produced != 0 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG,
                            DILITHIUM_STORE_TAG_BYTES, tag) <= 0) {
        goto done;
    }
    ok = 1;

done:
    OPENSSL_cleanse(encryption_key, sizeof(encryption_key));
    OPENSSL_cleanse(plaintext, sizeof(plaintext));
    EVP_CIPHER_CTX_free(context);
    return ok;
}

static int save_dilithium_private_key(const char *path,
                                      const HYBRID_PRIVATE_KEY *private_key,
                                      const HYBRID_PUBLIC_KEY *public_key,
                                      const char *passphrase)
{
    unsigned char *file_data = NULL;
    int descriptor = -1;
    int ok = 0;

    file_data = OPENSSL_malloc(DILITHIUM_STORE_FILE_BYTES);
    if (path == NULL || file_data == NULL ||
        !encrypt_dilithium_payload(private_key, public_key, passphrase,
                                   file_data)) {
        goto done;
    }
    descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (descriptor < 0 ||
        !write_all(descriptor, file_data, DILITHIUM_STORE_FILE_BYTES) ||
        fsync(descriptor) != 0) {
        goto done;
    }
    if (close(descriptor) != 0) {
        descriptor = -1;
        goto done;
    }
    descriptor = -1;
    ok = 1;

done:
    if (descriptor >= 0) {
        close(descriptor);
    }
    OPENSSL_clear_free(file_data, DILITHIUM_STORE_FILE_BYTES);
    if (!ok && path != NULL) {
        unlink(path);
    }
    return ok;
}

static int decrypt_dilithium_payload(
    const unsigned char input[DILITHIUM_STORE_FILE_BYTES],
    const char *passphrase,
    uint8_t public_key[DILITHIUM_PUBLIC_KEY_BYTES],
    uint8_t secret_key[DILITHIUM_SECRET_KEY_BYTES])
{
    EVP_CIPHER_CTX *context = NULL;
    unsigned char plaintext[DILITHIUM_STORE_PLAINTEXT_BYTES];
    unsigned char encryption_key[DILITHIUM_STORE_KEY_BYTES];
    const unsigned char *salt = input + 12u;
    const unsigned char *iv = salt + DILITHIUM_STORE_SALT_BYTES;
    const unsigned char *ciphertext = input + DILITHIUM_STORE_HEADER_BYTES;
    const unsigned char *tag = ciphertext + DILITHIUM_STORE_PLAINTEXT_BYTES;
    int produced = 0;
    int final_produced = 0;
    int ok = 0;

    memset(plaintext, 0, sizeof(plaintext));
    memset(encryption_key, 0, sizeof(encryption_key));
    if (CRYPTO_memcmp(input, DILITHIUM_STORE_MAGIC, 8u) != 0 ||
        get_u32_be(input + 8u) != DILITHIUM_STORE_ITERATIONS ||
        get_u32_be(input + DILITHIUM_STORE_HEADER_BYTES - 4u) !=
            DILITHIUM_STORE_PLAINTEXT_BYTES ||
        !derive_encryption_key(passphrase, salt, encryption_key)) {
        goto done;
    }
    context = EVP_CIPHER_CTX_new();
    if (context == NULL ||
        EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN,
                            DILITHIUM_STORE_IV_BYTES, NULL) <= 0 ||
        EVP_DecryptInit_ex(context, NULL, NULL, encryption_key, iv) <= 0 ||
        EVP_DecryptUpdate(context, NULL, &produced, input,
                          DILITHIUM_STORE_HEADER_BYTES) <= 0 ||
        EVP_DecryptUpdate(context, plaintext, &produced, ciphertext,
                          DILITHIUM_STORE_PLAINTEXT_BYTES) <= 0 ||
        produced != (int)DILITHIUM_STORE_PLAINTEXT_BYTES ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG,
                            DILITHIUM_STORE_TAG_BYTES, (void *)tag) <= 0 ||
        EVP_DecryptFinal_ex(context, plaintext + produced,
                            &final_produced) <= 0 || final_produced != 0 ||
        CRYPTO_memcmp(plaintext, DILITHIUM_PLAINTEXT_MAGIC, 8u) != 0) {
        goto done;
    }
    memcpy(public_key, plaintext + 8u, DILITHIUM_PUBLIC_KEY_BYTES);
    memcpy(secret_key, plaintext + 8u + DILITHIUM_PUBLIC_KEY_BYTES,
           DILITHIUM_SECRET_KEY_BYTES);
    ok = 1;

done:
    OPENSSL_cleanse(encryption_key, sizeof(encryption_key));
    OPENSSL_cleanse(plaintext, sizeof(plaintext));
    EVP_CIPHER_CTX_free(context);
    return ok;
}

static int load_dilithium_private_key(
    const char *path, const char *passphrase,
    uint8_t public_key[DILITHIUM_PUBLIC_KEY_BYTES],
    uint8_t secret_key[DILITHIUM_SECRET_KEY_BYTES])
{
    unsigned char *file_data = NULL;
    int descriptor = -1;
    int ok = 0;

    if (!secure_regular_file(path, DILITHIUM_STORE_FILE_BYTES)) {
        return 0;
    }
    file_data = OPENSSL_malloc(DILITHIUM_STORE_FILE_BYTES);
    descriptor = open(path, O_RDONLY | O_NOFOLLOW);
    if (file_data == NULL || descriptor < 0 ||
        !read_all(descriptor, file_data, DILITHIUM_STORE_FILE_BYTES) ||
        !decrypt_dilithium_payload(file_data, passphrase,
                                   public_key, secret_key)) {
        goto done;
    }
    ok = 1;

done:
    if (descriptor >= 0) {
        close(descriptor);
    }
    OPENSSL_clear_free(file_data, DILITHIUM_STORE_FILE_BYTES);
    return ok;
}

int composite_public_keys_equal(const HYBRID_PUBLIC_KEY *left,
                                const HYBRID_PUBLIC_KEY *right)
{
    uint8_t *left_bytes = NULL;
    uint8_t *right_bytes = NULL;
    size_t left_len = 0;
    size_t right_len = 0;
    int equal = 0;

    if (composite_serialize_public_key(left, &left_bytes, &left_len) &&
        composite_serialize_public_key(right, &right_bytes, &right_len) &&
        left_len == right_len &&
        CRYPTO_memcmp(left_bytes, right_bytes, left_len) == 0) {
        equal = 1;
    }
    OPENSSL_free(right_bytes);
    OPENSSL_free(left_bytes);
    return equal;
}

static int keypair_self_test(const HYBRID_PRIVATE_KEY *private_key,
                             const HYBRID_PUBLIC_KEY *public_key)
{
    static const uint8_t challenge[] = "hybrid-key-store-self-test";
    uint8_t *signature = NULL;
    size_t signature_len = 0;
    int valid = 0;

    if (composite_sign(private_key, challenge, sizeof(challenge) - 1u,
                       NULL, 0, &signature, &signature_len)) {
        valid = composite_verify(public_key, challenge,
                                 sizeof(challenge) - 1u,
                                 NULL, 0, signature, signature_len);
    }
    OPENSSL_free(signature);
    return valid;
}

int hybrid_key_store_save(const char *directory,
                          const HYBRID_PRIVATE_KEY *private_key,
                          const HYBRID_PUBLIC_KEY *public_key,
                          const char *passphrase)
{
    char *sm2_path = NULL;
    char *dilithium_path = NULL;
    int sm2_saved = 0;
    int ok = 0;

    if (private_key == NULL || public_key == NULL ||
        !passphrase_valid(passphrase) ||
        !keypair_self_test(private_key, public_key) ||
        !ensure_private_directory(directory) ||
        hybrid_key_store_status(directory) != HYBRID_KEY_STORE_MISSING) {
        return 0;
    }
    sm2_path = join_path(directory, HYBRID_SM2_PRIVATE_KEY_FILE);
    dilithium_path = join_path(directory, HYBRID_DILITHIUM_PRIVATE_KEY_FILE);
    if (sm2_path == NULL || dilithium_path == NULL ||
        !save_sm2_private_key(sm2_path, private_key->sm2_private_key,
                              passphrase)) {
        goto done;
    }
    sm2_saved = 1;
    if (!save_dilithium_private_key(dilithium_path, private_key, public_key,
                                    passphrase)) {
        goto done;
    }
    ok = 1;

done:
    if (!ok) {
        if (sm2_saved) {
            unlink(sm2_path);
        }
        if (dilithium_path != NULL) {
            unlink(dilithium_path);
        }
    }
    OPENSSL_free(dilithium_path);
    OPENSSL_free(sm2_path);
    return ok;
}

int hybrid_key_store_load(const char *directory,
                          const char *passphrase,
                          HYBRID_PRIVATE_KEY *private_key,
                          HYBRID_PUBLIC_KEY *public_key)
{
    HYBRID_PRIVATE_KEY loaded_private;
    HYBRID_PUBLIC_KEY loaded_public;
    char *sm2_path = NULL;
    char *dilithium_path = NULL;
    int ok = 0;

    if (private_key == NULL || public_key == NULL ||
        !passphrase_valid(passphrase) ||
        !ensure_private_directory(directory) ||
        hybrid_key_store_status(directory) != HYBRID_KEY_STORE_COMPLETE) {
        return 0;
    }
    hybrid_private_key_init(&loaded_private);
    hybrid_public_key_init(&loaded_public);
    sm2_path = join_path(directory, HYBRID_SM2_PRIVATE_KEY_FILE);
    dilithium_path = join_path(directory, HYBRID_DILITHIUM_PRIVATE_KEY_FILE);
    if (sm2_path == NULL || dilithium_path == NULL ||
        (loaded_private.sm2_private_key =
             load_sm2_private_key(sm2_path, passphrase)) == NULL ||
        !load_dilithium_private_key(dilithium_path, passphrase,
                                    loaded_public.dilithium_public_key,
                                    loaded_private.dilithium_secret_key) ||
        !EVP_PKEY_up_ref(loaded_private.sm2_private_key)) {
        goto done;
    }
    loaded_public.sm2_public_key = loaded_private.sm2_private_key;
    if (!keypair_self_test(&loaded_private, &loaded_public)) {
        goto done;
    }
    hybrid_private_key_cleanup(private_key);
    hybrid_public_key_cleanup(public_key);
    *private_key = loaded_private;
    *public_key = loaded_public;
    hybrid_private_key_init(&loaded_private);
    hybrid_public_key_init(&loaded_public);
    ok = 1;

done:
    OPENSSL_free(dilithium_path);
    OPENSSL_free(sm2_path);
    hybrid_public_key_cleanup(&loaded_public);
    hybrid_private_key_cleanup(&loaded_private);
    return ok;
}
