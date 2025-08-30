#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/quic.h>
#include <openssl/bio.h>

#define DEFAULT_PORT 4433
#define BUFFER_SIZE 1024
#define MAX_STREAMS 10

static volatile int server_running = 1;
static int server_fd = -1;

/*
 * ALPN (Application-Layer Protocol Negotiation) Configuration
 *
 * QUIC mandates ALPN negotiation during the TLS handshake. We use "http/1.0"
 * for this demonstration echo server instead of the standard HTTP/3 protocols
 * for the following reasons:
 *
 * 1. SIMPLICITY: Our server only echoes messages - no HTTP parsing needed
 * 2. EDUCATIONAL: Following OpenSSL's official QUIC tutorial pattern
 * 3. CLARITY: Makes it obvious this is a demo, not a production HTTP/3 server
 *
 * Real-world QUIC applications typically use:
 * - "h3" for HTTP/3 (0x02 + "h3")
 * - "h3-29" for HTTP/3 draft 29 (0x05 + "h3-29")
 *
 * But implementing actual HTTP/3 would require:
 * - HTTP/3 frame parsing
 * - QPACK header compression
 * - Stream multiplexing logic
 * - Much more complex code
 *
 * Format: Length-prefixed strings (not null-terminated)
 * "\x08http/1.0" = 8-byte length + "http/1.0" content
 */
static const unsigned char alpn_protocols[] = "\x08http/1.0";

// ALPN selection callback - negotiates which protocol to use
static int alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen, void *arg)
{
    (void)ssl;
    (void)arg;

    if (SSL_select_next_proto((unsigned char **)out, outlen,
                              alpn_protocols, sizeof(alpn_protocols) - 1,
                              in, inlen) == OPENSSL_NPN_NEGOTIATED)
    {
        return SSL_TLSEXT_ERR_OK;
    }

    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

// Signal handler for graceful shutdown
void sigint_handler(int signum)
{
    (void)signum;
    printf("\nReceived SIGINT, shutting down gracefully...\n");
    server_running = 0;
    if (server_fd != -1)
    {
        close(server_fd);
    }
}

// Enhanced function to print certificate and key algorithm information
void print_cert_info(SSL_CTX *ctx)
{
    (void)ctx; // Avoid unused parameter warning

    printf("\n=== QUIC Server Certificate & Key ===\n");

    // Load and print certificate algorithm info from file
    FILE *cert_file = fopen("./certs/server-cert.pem", "r");
    if (cert_file)
    {
        X509 *cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
        if (cert)
        {
            // Get the exact algorithm name from certificate
            X509_PUBKEY *pubkey = X509_get_X509_PUBKEY(cert);
            if (pubkey)
            {
                ASN1_OBJECT *alg_obj;
                X509_ALGOR *algor;
                if (X509_PUBKEY_get0_param(&alg_obj, NULL, NULL, &algor, pubkey))
                {
                    int nid = OBJ_obj2nid(alg_obj);
                    const char *long_name = OBJ_nid2ln(nid);
                    if (long_name)
                    {
                        printf("Server certificate algorithm: %s\n", long_name);
                    }
                }
            }

            EVP_PKEY *cert_key = X509_get_pubkey(cert);
            if (cert_key)
            {
                int key_size = EVP_PKEY_bits(cert_key);
                printf("Server certificate key size: %d bits\n", key_size);
                EVP_PKEY_free(cert_key);
            }
            X509_free(cert);
        }
        fclose(cert_file);
    }

    // Load and print private key algorithm info from file
    FILE *key_file = fopen("./certs/server-key.pem", "r");
    if (key_file)
    {
        EVP_PKEY *pkey = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
        if (pkey)
        {
            int key_size = EVP_PKEY_bits(pkey);
            const char *type_name = EVP_PKEY_get0_type_name(pkey);
            if (type_name)
            {
                printf("Server private key algorithm: %s (%d bits)\n", type_name, key_size);
            }
            EVP_PKEY_free(pkey);
        }
        fclose(key_file);
    }

    printf("======================================\n\n");
}

// Print QUIC connection details
void print_quic_connection_info(SSL *ssl)
{
    printf("\n=== QUIC Connection ===\n");

    const char *version = SSL_get_version(ssl);
    printf("QUIC version: %s\n", version);

    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    if (cipher)
    {
        printf("Cipher suite: %s\n", SSL_CIPHER_get_name(cipher));
    }

    // Key exchange group for QUIC
    const char *group_name = SSL_get0_group_name(ssl);
    int group_nid = SSL_get_negotiated_group(ssl);

    if (group_name)
    {
        printf("Key exchange: %s\n", group_name);
    }
    else if (group_nid != 0)
    {
        const char *nid_name = SSL_group_to_name(ssl, group_nid);
        if (nid_name)
        {
            printf("Key exchange: %s\n", nid_name);
        }
        else
        {
            printf("Key exchange: NID %d\n", group_nid);
        }
    }

    // Server signature algorithm
    const char *local_sig_name = NULL;
    if (SSL_get0_signature_name(ssl, &local_sig_name) && local_sig_name)
    {
        printf("Server signature: %s\n", local_sig_name);
    }

    printf("========================\n");
}

// Initialize OpenSSL and create QUIC SSL context
SSL_CTX *create_quic_context()
{
    SSL_CTX *ctx;

    // Initialize OpenSSL for QUIC
    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL) != 1)
    {
        fprintf(stderr, "Failed to initialize OpenSSL\n");
        return NULL;
    }

    // Create QUIC server SSL context using the correct method
    ctx = SSL_CTX_new(OSSL_QUIC_server_method());
    if (!ctx)
    {
        fprintf(stderr, "Failed to create QUIC SSL context\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Configure classical-only key exchange groups (no post-quantum)
    const char *classical_groups = "X25519:X448:secp256r1:secp384r1:secp521r1";
    if (SSL_CTX_set1_groups_list(ctx, classical_groups) != 1)
    {
        printf("Warning: Could not set classical groups list\n");
        ERR_print_errors_fp(stderr);
        // Continue anyway as this is not always fatal
    }
    else
    {
        printf("QUIC key exchange groups configured (X25519, ECDH)\n");
    }

    // Set ALPN selection callback for server
    // The callback will be invoked during TLS handshake to negotiate protocol
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, NULL);
    printf("ALPN protocols configured (demo: http/1.0, not actual HTTP/3)\n");

    printf("QUIC SSL context created successfully\n");
    return ctx;
}

// Load certificate and private key
int load_certificates(SSL_CTX *ctx)
{
    // Load server certificate
    if (SSL_CTX_use_certificate_file(ctx, "./certs/server-cert.pem", SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Failed to load server certificate\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    printf("Server certificate loaded from ./certs/server-cert.pem\n");

    // Load private key
    if (SSL_CTX_use_PrivateKey_file(ctx, "./certs/server-key.pem", SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Failed to load server private key\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    printf("Server private key loaded from ./certs/server-key.pem\n");

    // Verify that certificate and private key match
    if (SSL_CTX_check_private_key(ctx) != 1)
    {
        fprintf(stderr, "Certificate and private key do not match\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    printf("Certificate and private key match verified\n");

    // Print certificate and key information
    print_cert_info(ctx);

    return 0;
}

// Create and bind QUIC server socket
int create_server_socket(int port)
{
    int sockfd;
    struct sockaddr_in addr;
    int opt = 1;

    // Create UDP socket for QUIC
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("Failed to create UDP socket");
        return -1;
    }

    // Set SO_REUSEADDR option
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("Failed to set SO_REUSEADDR");
        close(sockfd);
        return -1;
    }

    // Bind to address
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("Failed to bind UDP socket");
        close(sockfd);
        return -1;
    }

    printf("QUIC server bound to UDP port %d\n", port);
    return sockfd;
}

// Handle QUIC stream data
void handle_stream_data(SSL *ssl, uint64_t stream_id, const char *data, size_t len)
{
    // Create a clean copy of the data for display (remove newlines)
    char display_data[BUFFER_SIZE];
    size_t display_len = len;
    if (display_len >= BUFFER_SIZE)
        display_len = BUFFER_SIZE - 1;

    memcpy(display_data, data, display_len);
    display_data[display_len] = '\0';

    // Remove trailing newline for cleaner display
    if (display_len > 0 && display_data[display_len - 1] == '\n')
    {
        display_data[display_len - 1] = '\0';
        display_len--;
    }

    printf("Stream %lu received %zu bytes: %s\n", stream_id, len, display_data);

    // Echo back the data on the same stream
    size_t bytes_written;
    if (SSL_write_ex(ssl, data, len, &bytes_written) != 1)
    {
        fprintf(stderr, "Failed to write to QUIC stream %lu\n", stream_id);
        ERR_print_errors_fp(stderr);
    }
    else
    {
        printf("Echoed %zu bytes back to stream %lu\n", bytes_written, stream_id);
    }
}

// Handle QUIC client connection
void handle_quic_client(SSL *ssl)
{
    char buffer[BUFFER_SIZE];
    size_t bytes_read;
    uint64_t stream_id;

    printf("QUIC client connected. Starting stream handling...\n");

    // Main QUIC connection loop
    while (server_running)
    {
        // Check for incoming stream data
        int result = SSL_read_ex(ssl, buffer, sizeof(buffer) - 1, &bytes_read);
        if (result == 1 && bytes_read > 0)
        {
            buffer[bytes_read] = '\0';

            // Get the current stream ID (this is simplified)
            stream_id = 0; // In a real implementation, you'd track stream IDs

            // Remove newline if present for cleaner logging
            if (bytes_read > 0 && buffer[bytes_read - 1] == '\n')
            {
                buffer[bytes_read - 1] = '\0';
                bytes_read--;
            }

            handle_stream_data(ssl, stream_id, buffer, bytes_read);
        }
        else
        {
            int ssl_error = SSL_get_error(ssl, result);
            if (ssl_error == SSL_ERROR_WANT_READ)
            {
                // No data available, continue
                usleep(10000); // 10ms
                continue;
            }
            else if (ssl_error == SSL_ERROR_ZERO_RETURN)
            {
                printf("QUIC client closed connection cleanly\n");
                break;
            }
            else if (ssl_error == SSL_ERROR_SSL)
            {
                // Check if connection was closed by peer
                int stream_state = SSL_get_stream_read_state(ssl);
                if (stream_state == SSL_STREAM_STATE_CONN_CLOSED)
                {
                    printf("QUIC client disconnected\n");
                    break;
                }
                else if (stream_state == SSL_STREAM_STATE_RESET_REMOTE)
                {
                    printf("QUIC stream reset by client\n");
                    break;
                }
                else
                {
                    printf("QUIC SSL error (connection may be closed)\n");
                    break;
                }
            }
            else
            {
                printf("QUIC connection ended (error: %d)\n", ssl_error);
                break;
            }
        }
    }

    printf("QUIC connection handling completed\n");
}

// Handle QUIC connection
int handle_quic_connection(SSL *listener)
{
    SSL *conn;

    // Wait for and accept QUIC connection
    printf("Waiting for QUIC connection...\n");

    // Note: The ssl object (conn) can be used directly for SSL_read_ex/SSL_write_ex as it provides the default bidirectional stream automatically
    conn = SSL_accept_connection(listener, 0);
    // For multiple streams: use SSL_new_stream(conn, flags)

    if (!conn)
    {
        fprintf(stderr, "Failed to accept QUIC connection\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    printf("QUIC connection established\n");

    // Print QUIC connection details using the connection (default stream)
    print_quic_connection_info(conn);

    // Handle the QUIC connection using the default stream
    handle_quic_client(conn);

    // Clean shutdown of connection
    printf("Shutting down QUIC connection...\n");
    SSL_SHUTDOWN_EX_ARGS shutdown_args = {0};
    int shutdown_attempts = 0;
    int shutdown_result;
    do
    {
        shutdown_result = SSL_shutdown_ex(conn, 0, &shutdown_args, sizeof(SSL_SHUTDOWN_EX_ARGS));
        if (shutdown_result != 1)
        {
            usleep(1000);
            shutdown_attempts++;
        }
    } while (shutdown_result != 1 && shutdown_attempts < 5);

    SSL_free(conn);
    return 0;
}

int main(int argc, char *argv[])
{
    int port = DEFAULT_PORT;
    SSL_CTX *ctx;

    // Parse command line arguments
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
        {
            port = atoi(argv[++i]);
            if (port <= 0 || port > 65535)
            {
                fprintf(stderr, "Invalid port number: %d\n", port);
                return 1;
            }
        }
        else
        {
            fprintf(stderr, "Usage: %s [--port PORT]\n", argv[0]);
            return 1;
        }
    }

    printf("=== QUIC Classical Echo Server ===\n\n");

    // Install signal handler
    signal(SIGINT, sigint_handler);

    // Create QUIC SSL context
    ctx = create_quic_context();
    if (!ctx)
    {
        return 1;
    }

    // Load certificates
    if (load_certificates(ctx) != 0)
    {
        SSL_CTX_free(ctx);
        return 1;
    }

    // Create server socket
    server_fd = create_server_socket(port);
    if (server_fd < 0)
    {
        SSL_CTX_free(ctx);
        return 1;
    }

    printf("QUIC server ready on port %d. Press Ctrl+C to stop.\n", port);

    // Create QUIC listener
    SSL *listener = SSL_new_listener(ctx, 0);
    if (!listener)
    {
        fprintf(stderr, "Failed to create QUIC listener\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        close(server_fd);
        return 1;
    }

    /*
     * Set blocking mode (1 - default for QUIC)
     * 1 = blocking: functions wait until complete
     * 0 = non-blocking: functions return immediately
     */
    // SSL_set_blocking_mode(listener, 1);

    // Associate listener with socket
    if (SSL_set_fd(listener, server_fd) != 1)
    {
        fprintf(stderr, "Failed to associate listener with UDP socket\n");
        ERR_print_errors_fp(stderr);
        SSL_free(listener);
        SSL_CTX_free(ctx);
        close(server_fd);
        return 1;
    }

    // Begin listening
    if (SSL_listen(listener) != 1)
    {
        fprintf(stderr, "Failed to start listening\n");
        ERR_print_errors_fp(stderr);
        SSL_free(listener);
        SSL_CTX_free(ctx);
        close(server_fd);
        return 1;
    }

    // Accept QUIC connections
    while (server_running)
    {
        if (handle_quic_connection(listener) < 0)
        {
            if (server_running)
            {
                printf("Failed to handle QUIC connection, continuing...\n");
            }
        }
        printf("QUIC connection closed\n");
    }

    SSL_free(listener);

    // Cleanup
    if (server_fd != -1)
    {
        close(server_fd);
    }
    SSL_CTX_free(ctx);

    printf("QUIC server shut down complete\n");
    return 0;
}