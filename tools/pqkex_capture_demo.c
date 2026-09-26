#include <gmssl/tls.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define DEFAULT_CAPTURE_PORT 44330u

static int parse_port(const char *text, uint16_t *port)
{
    char *end = NULL;
    unsigned long value;

    if (text == NULL || port == NULL || text[0] == '\0') {
        return 0;
    }
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value == 0 ||
        value > UINT16_MAX) {
        return 0;
    }
    *port = (uint16_t)value;
    return 1;
}

static int configure_pqkex_context(TLS_CTX *ctx, int is_client)
{
    static const int cipher_suites[] = {TLS_cipher_ecc_sm4_cbc_sm3};
    static const uint16_t kems[] = {TLS_PQKEX_KEM_MLKEM768};

    return tls_ctx_init(ctx, TLS_protocol_tlcp, is_client) == 1 &&
           tls_ctx_set_cipher_suites(
               ctx, cipher_suites,
               sizeof(cipher_suites) / sizeof(cipher_suites[0])) == 1 &&
           tls_ctx_set_pqkex_kems(ctx, kems,
                                  sizeof(kems) / sizeof(kems[0])) == 1;
}

static int connect_to_loopback(uint16_t port)
{
    struct sockaddr_in address;
    int sock = -1;

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0 || connect(sock, (const struct sockaddr *)&address,
                            sizeof(address)) != 0) {
        perror("PQKEX client connect");
        if (sock >= 0) {
            close(sock);
        }
        return -1;
    }
    return sock;
}

static int send_client_hello(uint16_t port)
{
    TLS_CTX ctx;
    TLS_CONNECT connection;
    int sock = -1;
    int ok = 0;

    memset(&ctx, 0, sizeof(ctx));
    memset(&connection, 0, sizeof(connection));
    if (!configure_pqkex_context(&ctx, TLS_client_mode)) {
        fprintf(stderr, "PQKEX client context setup failed\n");
        goto done;
    }
    sock = connect_to_loopback(port);
    if (sock < 0 || tls_init(&connection, &ctx) != 1 ||
        tls_set_socket(&connection, sock) != 1 ||
        tlcp_send_client_hello(&connection) != 1) {
        fprintf(stderr, "PQKEX ClientHello send failed\n");
        goto done;
    }
    puts("Client: sent a real TLCP ClientHello with PQKEX 0xFF02");
    fflush(stdout);
    ok = 1;

done:
    tls_cleanup(&connection);
    tls_ctx_cleanup(&ctx);
    if (sock >= 0) {
        close(sock);
    }
    return ok;
}

static int process_client_hello_record(int sock, TLS_CTX *ctx)
{
    TLS_CONNECT connection;
    int protocol = 0;
    const uint8_t *client_random = NULL;
    const uint8_t *session_id = NULL;
    size_t session_id_len = 0;
    const uint8_t *cipher_suites = NULL;
    size_t cipher_suites_len = 0;
    const uint8_t *extensions = NULL;
    size_t extensions_len = 0;
    int pqkex_count = 0;

    memset(&connection, 0, sizeof(connection));
    connection.protocol = TLS_protocol_tlcp;
    connection.ctx = ctx;

    if (tls_set_socket(&connection, sock) != 1 ||
        tls_recv_record(&connection) != 1 ||
        tls_record_get_handshake_client_hello(
            connection.record, &protocol, &client_random, &session_id,
            &session_id_len, &cipher_suites, &cipher_suites_len,
            &extensions, &extensions_len) != 1 ||
        protocol != TLS_protocol_tlcp) {
        fprintf(stderr, "Server: invalid TLCP ClientHello record\n");
        return 0;
    }

    while (extensions_len != 0) {
        int extension_type = 0;
        const uint8_t *extension_data = NULL;
        size_t extension_data_len = 0;

        if (tls_ext_from_bytes(&extension_type, &extension_data,
                               &extension_data_len, &extensions,
                               &extensions_len) != 1) {
            fprintf(stderr, "Server: malformed ClientHello extension\n");
            return 0;
        }
        if (extension_type == TLS_extension_pqkex) {
            pqkex_count++;
            if (pqkex_count != 1 ||
                tlcp_process_client_pqkex(&connection, extension_data,
                                          extension_data_len) != 1) {
                fprintf(stderr, "Server: invalid or duplicate PQKEX extension\n");
                return 0;
            }
        }
    }

    if (pqkex_count != 1 || !connection.pqkex_offered ||
        !connection.pqkex_negotiated ||
        connection.pqkex_selected_kem != TLS_PQKEX_KEM_MLKEM768) {
        fprintf(stderr, "Server: PQKEX capability selection failed\n");
        return 0;
    }

    printf("Server: parsed 0xFF02 and selected KEM 0x%04X\n",
           connection.pqkex_selected_kem);
    return 1;
}

static int create_listener(uint16_t port)
{
    struct sockaddr_in address;
    int enabled = 1;
    int sock = -1;

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0 ||
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enabled,
                   sizeof(enabled)) != 0 ||
        bind(sock, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(sock, 1) != 0) {
        perror("PQKEX server listen");
        if (sock >= 0) {
            close(sock);
        }
        return -1;
    }
    return sock;
}

int main(int argc, char **argv)
{
    TLS_CTX server_ctx;
    uint16_t port = DEFAULT_CAPTURE_PORT;
    int listener = -1;
    int peer = -1;
    pid_t child;
    int child_status = 0;
    int server_ok = 0;

    if (argc > 2 || (argc == 2 && !parse_port(argv[1], &port))) {
        fprintf(stderr, "usage: %s [port]\n", argv[0]);
        return EXIT_FAILURE;
    }

    signal(SIGPIPE, SIG_IGN);
    memset(&server_ctx, 0, sizeof(server_ctx));
    if (!configure_pqkex_context(&server_ctx, TLS_server_mode)) {
        fprintf(stderr, "PQKEX server context setup failed\n");
        return EXIT_FAILURE;
    }
    listener = create_listener(port);
    if (listener < 0) {
        tls_ctx_cleanup(&server_ctx);
        return EXIT_FAILURE;
    }

    printf("Capture interface: lo\nCapture filter: tcp port %u\n",
           (unsigned int)port);
    fflush(stdout);

    child = fork();
    if (child < 0) {
        perror("fork");
        close(listener);
        tls_ctx_cleanup(&server_ctx);
        return EXIT_FAILURE;
    }
    if (child == 0) {
        int client_ok;

        close(listener);
        tls_ctx_cleanup(&server_ctx);
        client_ok = send_client_hello(port);
        _exit(client_ok ? EXIT_SUCCESS : EXIT_FAILURE);
    }

    peer = accept(listener, NULL, NULL);
    if (peer < 0) {
        perror("accept");
    } else {
        server_ok = process_client_hello_record(peer, &server_ctx);
        close(peer);
    }
    close(listener);
    tls_ctx_cleanup(&server_ctx);

    if (waitpid(child, &child_status, 0) < 0) {
        perror("waitpid");
        return EXIT_FAILURE;
    }
    if (!server_ok || !WIFEXITED(child_status) ||
        WEXITSTATUS(child_status) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    puts("PASS: wire vector FF02000400020001 was sent and selected");
    puts("NOTE: capability-only; no ML-KEM operation or ServerHello echo");
    return EXIT_SUCCESS;
}
