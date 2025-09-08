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
#include <openssl/rand.h>

#define DEFAULT_PORT 8443
#define BUFFER_SIZE 1024

static volatile int server_running = 1;
static int server_fd = -1;
static unsigned char cookie_secret[32];
static int cookie_initialized = 0;

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

// Initialize cookie secret for DTLS
int init_cookie_secret()
{
    if (!cookie_initialized)
    {
        if (RAND_bytes(cookie_secret, sizeof(cookie_secret)) != 1)
        {
            fprintf(stderr, "Failed to generate cookie secret\n");
            return -1;
        }
        cookie_initialized = 1;
        printf("DTLS cookie secret initialized\n");
    }
    return 0;
}

// Generate DTLS cookie based on client address
int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length = 0, resultlength;
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in s4;
        struct sockaddr_in6 s6;
    } peer;
    
    // Get peer address from BIO
    BIO *wbio = SSL_get_wbio(ssl);
    if (BIO_dgram_get_peer(wbio, &peer) <= 0)
    {
        return 0;
    }

    // Create buffer with peer address and secret
    if (peer.ss.ss_family == AF_INET)
    {
        length = sizeof(struct sockaddr_in);
    }
    else if (peer.ss.ss_family == AF_INET6)
    {
        length = sizeof(struct sockaddr_in6);
    }
    else
    {
        return 0;
    }

    length += sizeof(cookie_secret);
    buffer = (unsigned char *)malloc(length);

    if (buffer == NULL)
    {
        fprintf(stderr, "Out of memory for cookie generation\n");
        return 0;
    }

    memcpy(buffer, &peer, length - sizeof(cookie_secret));
    memcpy(buffer + length - sizeof(cookie_secret), cookie_secret, sizeof(cookie_secret));

    // Generate SHA256 hash of peer address + secret
    if (!EVP_Digest(buffer, length, result, &resultlength, EVP_sha256(), NULL))
    {
        free(buffer);
        return 0;
    }

    free(buffer);
    memcpy(cookie, result, resultlength);
    *cookie_len = resultlength;

    return 1;
}

// Verify DTLS cookie
int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
    unsigned char result[32];
    unsigned int resultlength = sizeof(result);

    if (!generate_cookie(ssl, result, &resultlength))
        return 0;

    if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
        return 1;

    return 0;
}

// Enhanced function to print certificate and key algorithm information
void print_cert_info(SSL_CTX *ctx)
{
    (void)ctx; // Avoid unused parameter warning

    printf("\n=== Certificate & Key ===\n");

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
                        printf("Certificate algorithm: %s\n", long_name);
                    }
                }
            }

            EVP_PKEY *cert_key = X509_get_pubkey(cert);
            if (cert_key)
            {
                int key_size = EVP_PKEY_bits(cert_key);
                printf("Certificate key size: %d bits\n", key_size);
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
                printf("Private key algorithm: %s (%d bits)\n", type_name, key_size);
            }
            EVP_PKEY_free(pkey);
        }
        fclose(key_file);
    }

    printf("==========================\n\n");
}

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
    const char *local_sig_name = NULL;
    if (SSL_get0_signature_name(ssl, &local_sig_name) && local_sig_name)
    {
        printf("Server signature: %s\n", local_sig_name);
    }

    printf("========================\n\n");
}

// Initialize OpenSSL and create SSL context for DTLS
SSL_CTX *create_dtls_context()
{
    SSL_CTX *ctx;

    // Initialize OpenSSL
    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL) != 1)
    {
        fprintf(stderr, "Failed to initialize OpenSSL\n");
        return NULL;
    }

    // Create DTLS context
    ctx = SSL_CTX_new(DTLS_server_method());
    if (!ctx)
    {
        fprintf(stderr, "Failed to create DTLS context\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Set DTLS version to 1.2 (DTLS 1.3 is not widely supported yet)
    // Note: DTLS 1.3 RFC 9147 was published in 2022 but OpenSSL support is limited
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

    // Initialize cookie secret
    if (init_cookie_secret() != 0)
    {
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Set cookie generation and verification callbacks
    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);
    printf("DTLS cookie exchange enabled for DoS protection\n");

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

    printf("DTLS context created with DTLS 1.2 enforcement\n");
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

// Create and bind UDP server socket for DTLS
int create_dtls_server_socket(int port)
{
    int sockfd;
    struct sockaddr_in addr;
    int opt = 1;

    // Create UDP socket
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

    printf("DTLS server listening on UDP port %d\n", port);
    return sockfd;
}

// Handle client DTLS connection
void handle_dtls_client(int server_fd, SSL_CTX *ctx, struct sockaddr_in *client_addr, socklen_t client_len)
{
    SSL *ssl;
    BIO *bio;
    char buffer[BUFFER_SIZE];
    int bytes;

    // Create a new UDP BIO
    bio = BIO_new_dgram(server_fd, BIO_NOCLOSE);
    if (!bio)
    {
        fprintf(stderr, "Failed to create UDP BIO\n");
        ERR_print_errors_fp(stderr);
        return;
    }

    // Set the peer address for the BIO
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_PEER, 0, client_addr);

    // Create SSL object
    ssl = SSL_new(ctx);
    if (!ssl)
    {
        fprintf(stderr, "Failed to create SSL object\n");
        ERR_print_errors_fp(stderr);
        BIO_free(bio);
        return;
    }

    // Associate SSL with BIO
    SSL_set_bio(ssl, bio, bio);

    // Set DTLS options - enable cookie exchange for DoS protection
    SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

    // Perform DTLS handshake
    printf("Starting DTLS handshake with client %s:%d...\n",
           inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));
    
    int result = SSL_accept(ssl);
    if (result != 1)
    {
        int ssl_error = SSL_get_error(ssl, result);
        fprintf(stderr, "DTLS handshake failed (error: %d)\n", ssl_error);
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return;
    }
    printf("DTLS handshake successful\n");

    // Print classical DTLS connection details
    print_dtls_connection_info(ssl);

    // Echo loop for DTLS
    printf("Client connected via DTLS. Starting echo service...\n");
    for (int message_count = 0; message_count < 10 && server_running; message_count++)
    {
        bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes <= 0)
        {
            int ssl_error = SSL_get_error(ssl, bytes);
            if (ssl_error == SSL_ERROR_ZERO_RETURN)
            {
                printf("Client closed DTLS connection\n");
                break;
            }
            else if (ssl_error == SSL_ERROR_WANT_READ)
            {
                printf("SSL_ERROR_WANT_READ - waiting for more data\n");
                continue;
            }
            else if (ssl_error == SSL_ERROR_SYSCALL || ssl_error == SSL_ERROR_SSL)
            {
                printf("DTLS read error: %d\n", ssl_error);
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
            printf("DTLS write error: %d\n", ssl_error);
            ERR_print_errors_fp(stderr);
            break;
        }
        printf("Server echoed: %.*s", sent, buffer);
    }

    // Clean shutdown
    printf("Shutting down DTLS connection...\n");
    int shutdown_result = SSL_shutdown(ssl);
    if (shutdown_result < 0)
    {
        printf("DTLS shutdown warning (this is often normal for UDP)\n");
    }
    else
    {
        printf("DTLS connection shut down cleanly\n");
    }

    SSL_free(ssl);
}

int main(int argc, char *argv[])
{
    int port = DEFAULT_PORT;
    SSL_CTX *ctx;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

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

    printf("=== DTLS 1.2 Echo Server ===\n\n");

    // Install signal handler
    signal(SIGINT, sigint_handler);

    // Create DTLS context
    ctx = create_dtls_context();
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

    // Create UDP server socket
    server_fd = create_dtls_server_socket(port);
    if (server_fd < 0)
    {
        SSL_CTX_free(ctx);
        return 1;
    }

    printf("DTLS 1.2 server ready. Press Ctrl+C to stop.\n");

    // Accept DTLS connections
    while (server_running)
    {
        // Wait for initial UDP packet to identify client
        int bytes = recvfrom(server_fd, buffer, sizeof(buffer), MSG_PEEK,
                            (struct sockaddr *)&client_addr, &client_len);
        if (bytes < 0)
        {
            if (server_running)
            {
                perror("Failed to receive UDP packet");
            }
            break;
        }

        printf("New DTLS connection attempt from %s:%d\n",
               inet_ntoa(client_addr.sin_addr),
               ntohs(client_addr.sin_port));

        // Handle DTLS client (blocking, one at a time)
        handle_dtls_client(server_fd, ctx, &client_addr, client_len);

        printf("DTLS connection closed\n");
    }

    // Cleanup
    if (server_fd != -1)
    {
        close(server_fd);
    }
    SSL_CTX_free(ctx);

    printf("DTLS server shut down complete\n");
    return 0;
}