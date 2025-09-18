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

// Print DTLS connection details
void print_dtls_connection_info(SSL *ssl)
{
    printf("\n=== DTLS Connection ===\n");

    const char *version = SSL_get_version(ssl);
    printf("DTLS version: %s\n", version);

    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    printf("Cipher suite: %s\n", SSL_CIPHER_get_name(cipher));

    // Key exchange group
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

    // Server signature algorithm (from certificate)
    const char *peer_sig_name = NULL;
    if (SSL_get0_peer_signature_name(ssl, &peer_sig_name) && peer_sig_name)
    {
        printf("Peer signature algorithm: %s\n", peer_sig_name);
    }

    printf("========================\n");
}

// Enhanced function to print certificate algorithm information
void print_peer_cert_info(SSL *ssl)
{
    printf("\n=== Server Certificate ===\n");

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert)
    {
        printf("No server certificate received\n");
        printf("==========================\n\n");
        return;
    }

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
                printf("Certificate algorithm: %s\n", long_name);
            }
        }
    }

    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (pkey)
    {
        int key_size = EVP_PKEY_bits(pkey);
        printf("Certificate key size: %d bits\n", key_size);
        EVP_PKEY_free(pkey);
    }

    X509_free(cert);
    printf("===================================\n\n");
}

// Initialize OpenSSL and create SSL context for DTLS client
SSL_CTX *create_dtls_client_context()
{
    SSL_CTX *ctx;

    // Initialize OpenSSL
    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL) != 1)
    {
        fprintf(stderr, "Failed to initialize OpenSSL\n");
        return NULL;
    }

    // Create DTLS client context
    ctx = SSL_CTX_new(DTLS_client_method());
    if (!ctx)
    {
        fprintf(stderr, "Failed to create DTLS context\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Set DTLS version to 1.2 (DTLS 1.3 is not widely supported yet)
    // Note: DTLS 1.3 RFC 9147 was published in 2022, but unlike TLS 1.3,
    // DTLS 1.3 support is still limited in OpenSSL and other implementations
    if (SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION) != 1)
    {
        fprintf(stderr, "Failed to set minimum DTLS version\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_set_max_proto_version(ctx, DTLS1_2_VERSION) != 1)
    {
        fprintf(stderr, "Failed to set maximum DTLS version\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
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
        printf("Key exchange groups configured (X25519, ECDH)\n");
    }

    printf("DTLS client context created with DTLS 1.2 enforcement\n");
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

// Create UDP socket and connect to server
int connect_to_dtls_server(const char *hostname, int port, struct sockaddr_in *server_addr)
{
    int sockfd;
    struct hostent *host;

    // Create UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("Failed to create UDP socket");
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

    // Setup server address structure
    memset(server_addr, 0, sizeof(*server_addr));
    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(port);
    memcpy(&server_addr->sin_addr, host->h_addr_list[0], host->h_length);

    // Connect UDP socket to server (for easier send/recv)
    if (connect(sockfd, (struct sockaddr *)server_addr, sizeof(*server_addr)) < 0)
    {
        perror("Failed to connect UDP socket");
        close(sockfd);
        return -1;
    }

    printf("UDP socket connected to DTLS server %s:%d\n", hostname, port);
    return sockfd;
}

// Interactive communication loop for DTLS
void interactive_dtls_session(SSL *ssl)
{
    char send_buffer[BUFFER_SIZE];
    char recv_buffer[BUFFER_SIZE];
    int bytes_sent, bytes_received;

    printf("DTLS connection established! Type messages to send to server (Ctrl+C to exit):\n");
    printf("> ");
    fflush(stdout);

    while (fgets(send_buffer, sizeof(send_buffer), stdin))
    {
        size_t len = strlen(send_buffer);

        // Send message to server via DTLS
        bytes_sent = SSL_write(ssl, send_buffer, (int)len);
        if (bytes_sent <= 0)
        {
            int ssl_error = SSL_get_error(ssl, bytes_sent);
            fprintf(stderr, "DTLS write error: %d\n", ssl_error);
            ERR_print_errors_fp(stderr);
            break;
        }

        // Receive echo from server via DTLS
        bytes_received = SSL_read(ssl, recv_buffer, sizeof(recv_buffer) - 1);
        if (bytes_received <= 0)
        {
            int ssl_error = SSL_get_error(ssl, bytes_received);
            if (ssl_error == SSL_ERROR_ZERO_RETURN)
            {
                printf("Server closed DTLS connection\n");
                break;
            }
            else if (ssl_error == SSL_ERROR_WANT_READ)
            {
                printf("SSL_ERROR_WANT_READ - timeout waiting for server response\n");
                printf("> ");
                fflush(stdout);
                continue;
            }
            else
            {
                fprintf(stderr, "DTLS read error: %d\n", ssl_error);
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
    BIO *bio;
    int sockfd;
    struct sockaddr_in server_addr;

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

    printf("=== DTLS 1.2 Client ===\n\n");

    // Create DTLS client context
    ctx = create_dtls_client_context();
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

    // Connect to DTLS server
    sockfd = connect_to_dtls_server(hostname, port, &server_addr);
    if (sockfd < 0)
    {
        SSL_CTX_free(ctx);
        return 1;
    }

    // Create UDP BIO for DTLS
    bio = BIO_new_dgram(sockfd, BIO_CLOSE);
    if (!bio)
    {
        fprintf(stderr, "Failed to create UDP BIO\n");
        ERR_print_errors_fp(stderr);
        close(sockfd);
        SSL_CTX_free(ctx);
        return 1;
    }

    // Set connected peer address in BIO
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &server_addr);

    // Set timeout for reads
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    // Create SSL object
    ssl = SSL_new(ctx);
    if (!ssl)
    {
        fprintf(stderr, "Failed to create SSL object\n");
        ERR_print_errors_fp(stderr);
        BIO_free(bio);
        SSL_CTX_free(ctx);
        return 1;
    }

    // Associate SSL with BIO
    SSL_set_bio(ssl, bio, bio);

    // Set SNI (Server Name Indication)
    if (SSL_set_tlsext_host_name(ssl, hostname) != 1)
    {
        fprintf(stderr, "Failed to set SNI hostname\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
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
        SSL_CTX_free(ctx);
        return 1;
    }
    printf("Hostname verification enabled for: %s\n", hostname);

    // Perform DTLS handshake
    printf("Starting DTLS handshake...\n");
    int result = SSL_connect(ssl);
    if (result != 1)
    {
        int ssl_error = SSL_get_error(ssl, result);
        fprintf(stderr, "DTLS handshake failed (error: %d)\n", ssl_error);
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 1;
    }
    printf("DTLS handshake successful\n");

    // Print classical DTLS connection details
    print_dtls_connection_info(ssl);

    // Print server certificate information
    print_peer_cert_info(ssl);

    // Start interactive session
    interactive_dtls_session(ssl);

    // Clean shutdown
    printf("\nShutting down DTLS connection...\n");
    int shutdown_result = SSL_shutdown(ssl);
    if (shutdown_result < 0)
    {
        printf("DTLS shutdown warning (this is often normal for UDP)\n");
    }
    else
    {
        printf("DTLS connection shut down cleanly\n");
    }

    // Cleanup
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    printf("DTLS client shutdown complete\n");
    return 0;
}