#include "sm2_wrapper.h"

#include <openssl/crypto.h>
#include <openssl/err.h>

#include <string.h>

EVP_PKEY *hybrid_sm2_generate_keypair(void)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
    EVP_PKEY *key = NULL;

    if (context == NULL || EVP_PKEY_keygen_init(context) <= 0 ||
        EVP_PKEY_generate(context, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

int hybrid_sm2_sign(EVP_PKEY *private_key,
                    const unsigned char *message, size_t message_len,
                    unsigned char **signature, size_t *signature_len)
{
    EVP_MD_CTX *context = NULL;
    EVP_PKEY_CTX *pkey_context = NULL;
    unsigned char *output = NULL;
    size_t output_len = 0;
    int ok = 0;

    if (signature == NULL || signature_len == NULL) {
        return 0;
    }
    *signature = NULL;
    *signature_len = 0;
    if (private_key == NULL || (message == NULL && message_len != 0)) {
        return 0;
    }

    context = EVP_MD_CTX_new();
    if (context == NULL ||
        EVP_DigestSignInit_ex(context, &pkey_context, "SM3", NULL, NULL,
                              private_key, NULL) <= 0 ||
        EVP_PKEY_CTX_set1_id(pkey_context, SM2_DEFAULT_USER_ID,
                             strlen(SM2_DEFAULT_USER_ID)) <= 0 ||
        EVP_DigestSign(context, NULL, &output_len, message, message_len) <= 0) {
        goto done;
    }

    output = OPENSSL_malloc(output_len);
    if (output == NULL ||
        EVP_DigestSign(context, output, &output_len, message, message_len) <= 0) {
        goto done;
    }
    *signature = output;
    *signature_len = output_len;
    output = NULL;
    ok = 1;

done:
    OPENSSL_free(output);
    EVP_MD_CTX_free(context);
    return ok;
}

int hybrid_sm2_verify(EVP_PKEY *public_key,
                      const unsigned char *message, size_t message_len,
                      const unsigned char *signature, size_t signature_len)
{
    EVP_MD_CTX *context = NULL;
    EVP_PKEY_CTX *pkey_context = NULL;
    int result = 0;

    if (public_key == NULL || signature == NULL ||
        (message == NULL && message_len != 0)) {
        return 0;
    }
    context = EVP_MD_CTX_new();
    if (context == NULL ||
        EVP_DigestVerifyInit_ex(context, &pkey_context, "SM3", NULL, NULL,
                                public_key, NULL) <= 0 ||
        EVP_PKEY_CTX_set1_id(pkey_context, SM2_DEFAULT_USER_ID,
                             strlen(SM2_DEFAULT_USER_ID)) <= 0) {
        goto done;
    }
    result = EVP_DigestVerify(context, signature, signature_len,
                              message, message_len) == 1;

done:
    EVP_MD_CTX_free(context);
    return result;
}
