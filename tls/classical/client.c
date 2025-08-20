#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#define DEFAULT_PORT 8443
#define BUFFER_SIZE 1024

// Print certificate algorithm information
void print_peer_cert_info(SSL *ssl)
{
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert)
    {
        EVP_PKEY *pkey = X509_get_pubkey(cert);
        if (pkey)
        {
            int key_type = EVP_PKEY_base_id(pkey);
            int key_size = EVP_PKEY_bits(pkey);

            switch (key_type)
            {
            case EVP_PKEY_RSA:
                printf("Server certificate: RSA-%d\n", key_size);
                break;
            case EVP_PKEY_EC:
                printf("Server certificate: ECDSA-P%d\n", key_size);
                break;
            // TODO: add support for other key types
            default:
                printf("Server certificate: Unknown algorithm (type=%d, size=%d)\n", key_type, key_size);
                break;
            }
            EVP_PKEY_free(pkey);
        }
        X509_free(cert);
    }
    else
    {
        printf("No server certificate received\n");
    }
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
    ctx = SSL_CTX_new(TLS_client_method());
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

// Load CA certificate for server verification
int load_ca_certificate(SSL_CTX *ctx)
{
    if (SSL_CTX_load_verify_locations(ctx, "./certs/ca-cert.pem", NULL) != 1)
    {
        fprintf(stderr, "Failed to load CA certificate\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    printf("CA certificate loaded from ./certs/ca-cert.pem\n");

    // Enable peer verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    printf("Server certificate verification enabled\n");

    return 0;
}

// Resolve hostname and create socket connection
int connect_to_server(const char *hostname, int port)
{
    int sockfd;
    struct sockaddr_in server_addr;
    struct hostent *host;

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("Failed to create socket");
        return -1;
    }

    // Resolve hostname
    host = gethostbyname(hostname);
    if (!host)
    {
        fprintf(stderr, "Failed to resolve hostname: %s\n", hostname);
        close(sockfd);
        return -1;
    }
    printf("Resolved %s to %s\n", hostname, inet_ntoa(*((struct in_addr *)host->h_addr_list[0])));

    // Connect to server
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr, host->h_addr_list[0], host->h_length);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Failed to connect to server");
        close(sockfd);
        return -1;
    }

    printf("Connected to %s:%d\n", hostname, port);
    return sockfd;
}

// Interactive communication loop
void interactive_session(SSL *ssl)
{
    char send_buffer[BUFFER_SIZE];
    char recv_buffer[BUFFER_SIZE];
    int bytes_sent, bytes_received;

    printf("Connected! Type messages to send to server (Ctrl+C to exit):\n");
    printf("> ");
    fflush(stdout);

    while (fgets(send_buffer, sizeof(send_buffer), stdin))
    {
        size_t len = strlen(send_buffer);

        // Send message to server
        bytes_sent = SSL_write(ssl, send_buffer, (int)len);
        if (bytes_sent <= 0)
        {
            int ssl_error = SSL_get_error(ssl, bytes_sent);
            fprintf(stderr, "SSL write error: %d\n", ssl_error);
            ERR_print_errors_fp(stderr);
            break;
        }

        // Receive echo from server
        bytes_received = SSL_read(ssl, recv_buffer, sizeof(recv_buffer) - 1);
        if (bytes_received <= 0)
        {
            int ssl_error = SSL_get_error(ssl, bytes_received);
            if (ssl_error == SSL_ERROR_ZERO_RETURN)
            {
                printf("Server closed connection\n");
                break;
            }
            else
            {
                fprintf(stderr, "SSL read error: %d\n", ssl_error);
                ERR_print_errors_fp(stderr);
                break;
            }
        }

        recv_buffer[bytes_received] = '\0';
        printf("Server echoed: %s", recv_buffer);
        printf("> ");
        fflush(stdout);
    }
}

int main(int argc, char *argv[])
{
    char *hostname = "localhost";
    int port = DEFAULT_PORT;
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;

    // Parse command line arguments
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc)
        {
            hostname = argv[++i];
        }
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
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
            fprintf(stderr, "Usage: %s [--host HOSTNAME] [--port PORT]\n", argv[0]);
            return 1;
        }
    }

    // Create SSL context
    ctx = create_ssl_context();
    if (!ctx)
    {
        return 1;
    }

    // Load CA certificate
    if (load_ca_certificate(ctx) != 0)
    {
        SSL_CTX_free(ctx);
        return 1;
    }

    // Connect to server
    sockfd = connect_to_server(hostname, port);
    if (sockfd < 0)
    {
        SSL_CTX_free(ctx);
        return 1;
    }

    // Create SSL object
    ssl = SSL_new(ctx);
    if (!ssl)
    {
        fprintf(stderr, "Failed to create SSL object\n");
        ERR_print_errors_fp(stderr);
        close(sockfd);
        SSL_CTX_free(ctx);
        return 1;
    }

    // Associate SSL with socket
    if (SSL_set_fd(ssl, sockfd) != 1)
    {
        fprintf(stderr, "Failed to associate SSL with socket\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        return 1;
    }

    // Set SNI (Server Name Indication)
    if (SSL_set_tlsext_host_name(ssl, hostname) != 1)
    {
        fprintf(stderr, "Failed to set SNI hostname\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        return 1;
    }
    printf("SNI hostname set to: %s\n", hostname);

    // Set hostname for verification
    if (SSL_set1_host(ssl, hostname) != 1)
    {
        fprintf(stderr, "Failed to set hostname for verification\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        return 1;
    }
    printf("Hostname verification enabled for: %s\n", hostname);

    // Perform TLS handshake
    printf("Starting TLS handshake...\n");
    int result = SSL_connect(ssl);
    if (result != 1)
    {
        int ssl_error = SSL_get_error(ssl, result);
        fprintf(stderr, "TLS handshake failed (error: %d)\n", ssl_error);
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        return 1;
    }
    printf("TLS handshake successful\n");

    // Print connection details
    printf("Connected using %s\n", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));

    // Print server certificate information
    print_peer_cert_info(ssl);

    // Start interactive session
    interactive_session(ssl);

    // Clean shutdown
    printf("\nShutting down SSL connection...\n");
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

    // Cleanup
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);

    printf("Client shutdown complete\n");
    return 0;
}