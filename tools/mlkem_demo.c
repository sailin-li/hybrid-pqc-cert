#include "mlkem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    MLKEM_KEYPAIR client = {0};
    uint8_t ciphertext[MLKEM768_CIPHERTEXT_BYTES];
    uint8_t server_secret[MLKEM768_SHARED_SECRET_BYTES] = {0};
    uint8_t client_secret[MLKEM768_SHARED_SECRET_BYTES] = {0};
    size_t ciphertext_len = 0;
    int keygen_ok;
    int encaps_ok = 0;
    int decaps_ok = 0;
    int match_ok = 0;

    printf("=== FIPS 203 ML-KEM Demo ===\n\n");
    printf("Algorithm:\n  %s\n", mlkem768_algorithm_name());
    printf("Provider:\n  %s %s\n\n", mlkem_provider_name(),
           mlkem_provider_version());
    printf("Parameters:\n");
    printf("  Encapsulation key: %u bytes\n",
           MLKEM768_ENCAPSULATION_KEY_BYTES);
    printf("  Decapsulation key: %u bytes\n",
           MLKEM768_DECAPSULATION_KEY_BYTES);
    printf("  Ciphertext:        %u bytes\n", MLKEM768_CIPHERTEXT_BYTES);
    printf("  Shared secret:       %u bytes\n\n",
           MLKEM768_SHARED_SECRET_BYTES);

    keygen_ok = mlkem768_provider_check() && mlkem768_keygen(&client);
    if (keygen_ok) {
        encaps_ok = mlkem768_encaps(client.encapsulation_key,
                                    client.encapsulation_key_len,
                                    ciphertext, sizeof(ciphertext),
                                    &ciphertext_len, server_secret);
    }
    if (encaps_ok) {
        decaps_ok = mlkem768_decaps(client.decapsulation_key,
                                    client.decapsulation_key_len,
                                    ciphertext, ciphertext_len,
                                    client_secret);
    }
    if (decaps_ok) {
        match_ok = memcmp(server_secret, client_secret,
                          MLKEM768_SHARED_SECRET_BYTES) == 0;
    }

    printf("KeyGen:\n  %s\n\n", keygen_ok ? "PASS" : "FAIL");
    printf("Encapsulation:\n  %s\n\n", encaps_ok ? "PASS" : "FAIL");
    printf("Decapsulation:\n  %s\n\n", decaps_ok ? "PASS" : "FAIL");
    printf("Shared secret:\n  %s\n\n", match_ok ? "MATCH" : "MISMATCH");
    printf("Result:\n  ML-KEM-768 %s\n",
           keygen_ok && encaps_ok && decaps_ok && match_ok ? "PASS" : "FAIL");

    mlkem_shared_secret_cleanup(server_secret);
    mlkem_shared_secret_cleanup(client_secret);
    mlkem_keypair_cleanup(&client);
    return keygen_ok && encaps_ok && decaps_ok && match_ok
               ? EXIT_SUCCESS : EXIT_FAILURE;
}
