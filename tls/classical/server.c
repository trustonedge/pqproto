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

#define DEFAULT_PORT 8443
#define BUFFER_SIZE 1024

static volatile int server_running = 1;
static int server_fd = -1;

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

// Print certificate and key algorithm information
void print_cert_info(SSL_CTX *ctx)
{
    (void)ctx; // Avoid unused parameter warning
    printf("Certificate and key algorithm information will be displayed after loading\n");
}

// Initialize OpenSSL and create SSL context
SSL_CTX *create_ssl_context()
{
    SSL_CTX *ctx;

    // Initialize OpenSSL
    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL) != 1)
    {
        fprintf(stderr, "Failed to initialize OpenSSL\n");
        return NULL;
    }

    // Create SSL context
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
    {
        fprintf(stderr, "Failed to create SSL context\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Enforce TLS 1.3 only
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1)
    {
        fprintf(stderr, "Failed to set minimum TLS version\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1)
    {
        fprintf(stderr, "Failed to set maximum TLS version\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    printf("SSL context created with TLS 1.3 enforcement\n");
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

    // Load and print certificate algorithm info from file
    FILE *cert_file = fopen("./certs/server-cert.pem", "r");
    if (cert_file)
    {
        X509 *cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
        if (cert)
        {
            EVP_PKEY *cert_key = X509_get_pubkey(cert);
            if (cert_key)
            {
                int key_type = EVP_PKEY_base_id(cert_key);
                int key_size = EVP_PKEY_bits(cert_key);

                switch (key_type)
                {
                case EVP_PKEY_RSA:
                    printf("Certificate algorithm: RSA-%d\n", key_size);
                    break;
                case EVP_PKEY_EC:
                    printf("Certificate algorithm: ECDSA-P%d\n", key_size);
                    break;
                // TODO: add support for other key types
                default:
                    printf("Certificate algorithm: Unknown (type=%d, size=%d)\n", key_type, key_size);
                    break;
                }
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
            int key_type = EVP_PKEY_base_id(pkey);
            int key_size = EVP_PKEY_bits(pkey);

            switch (key_type)
            {
            case EVP_PKEY_RSA:
                printf("Private key algorithm: RSA-%d\n", key_size);
                break;
            case EVP_PKEY_EC:
                printf("Private key algorithm: ECDSA-P%d\n", key_size);
                break;
            // TODO: add support for other key types
            default:
                printf("Private key algorithm: Unknown (type=%d, size=%d)\n", key_type, key_size);
                break;
            }
            EVP_PKEY_free(pkey);
        }
        fclose(key_file);
    }

    return 0;
}

// Create and bind server socket
int create_server_socket(int port)
{
    int sockfd;
    struct sockaddr_in addr;
    int opt = 1;

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("Failed to create socket");
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
        perror("Failed to bind socket");
        close(sockfd);
        return -1;
    }

    // Listen for connections
    if (listen(sockfd, 5) < 0)
    {
        perror("Failed to listen on socket");
        close(sockfd);
        return -1;
    }

    printf("Server listening on port %d\n", port);
    return sockfd;
}

// Handle client connection
void handle_client(int client_fd, SSL_CTX *ctx)
{
    SSL *ssl;
    char buffer[BUFFER_SIZE];
    int bytes;

    // Create SSL object
    ssl = SSL_new(ctx);
    if (!ssl)
    {
        fprintf(stderr, "Failed to create SSL object\n");
        ERR_print_errors_fp(stderr);
        return;
    }

    // Associate SSL with socket
    if (SSL_set_fd(ssl, client_fd) != 1)
    {
        fprintf(stderr, "Failed to associate SSL with socket\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return;
    }

    // Perform TLS handshake
    printf("Starting TLS handshake...\n");
    int result = SSL_accept(ssl);
    if (result != 1)
    {
        int ssl_error = SSL_get_error(ssl, result);
        fprintf(stderr, "TLS handshake failed (error: %d)\n", ssl_error);
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return;
    }
    printf("TLS handshake successful\n");

    // Print connection details
    printf("Connected using %s\n", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));

    // Echo loop
    printf("Client connected. Starting echo service...\n");
    while (server_running)
    {
        bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes <= 0)
        {
            int ssl_error = SSL_get_error(ssl, bytes);
            if (ssl_error == SSL_ERROR_ZERO_RETURN)
            {
                printf("Client closed connection\n");
                break;
            }
            else if (ssl_error == SSL_ERROR_SYSCALL || ssl_error == SSL_ERROR_SSL)
            {
                printf("SSL read error: %d\n", ssl_error);
                ERR_print_errors_fp(stderr);
                break;
            }
            continue;
        }

        buffer[bytes] = '\0';

        // Remove newline if present for cleaner logging
        if (buffer[bytes - 1] == '\n')
        {
            buffer[bytes - 1] = '\0';
            bytes--;
        }

        printf("Client sent: %s\n", buffer);

        // Add newline back for echo
        if (bytes < (int)(sizeof(buffer) - 2))
        {
            buffer[bytes] = '\n';
            buffer[bytes + 1] = '\0';
            bytes++;
        }

        // Echo back to client
        int sent = SSL_write(ssl, buffer, bytes);
        if (sent <= 0)
        {
            int ssl_error = SSL_get_error(ssl, sent);
            printf("SSL write error: %d\n", ssl_error);
            ERR_print_errors_fp(stderr);
            break;
        }
        printf("Server echoed: %.*s", sent, buffer);
    }

    // Clean shutdown
    printf("Shutting down SSL connection...\n");
    int shutdown_result = SSL_shutdown(ssl);
    if (shutdown_result == 0)
    {
        // First phase completed, wait for peer's close_notify
        shutdown_result = SSL_shutdown(ssl);
    }
    if (shutdown_result < 0)
    {
        printf("SSL shutdown warning (this is often normal)\n");
    }
    else
    {
        printf("SSL connection shut down cleanly\n");
    }

    SSL_free(ssl);
}

int main(int argc, char *argv[])
{
    int port = DEFAULT_PORT;
    SSL_CTX *ctx;
    int client_fd;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

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

    // Install signal handler
    signal(SIGINT, sigint_handler);

    // Create SSL context
    ctx = create_ssl_context();
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

    printf("TLS 1.3 server ready. Press Ctrl+C to stop.\n");

    // Accept connections
    while (server_running)
    {
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0)
        {
            if (server_running)
            {
                perror("Failed to accept connection");
            }
            break;
        }

        printf("New connection from %s:%d\n",
               inet_ntoa(client_addr.sin_addr),
               ntohs(client_addr.sin_port));

        // Handle client (blocking, one at a time as requested)
        handle_client(client_fd, ctx);
        close(client_fd);

        printf("Connection closed\n");
    }

    // Cleanup
    if (server_fd != -1)
    {
        close(server_fd);
    }
    SSL_CTX_free(ctx);

    printf("Server shut down complete\n");
    return 0;
}