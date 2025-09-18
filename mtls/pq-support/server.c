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

// Enhanced function to print certificate and key algorithm information
void print_cert_info(SSL_CTX *ctx)
{
    (void)ctx; // Avoid unused parameter warning

    printf("\n=== Server Certificate & Key ===\n");

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

    printf("==================================\n\n");
}

// Print client certificate information
void print_client_cert_info(SSL *ssl)
{
    printf("\n=== Client Certificate ===\n");

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert)
    {
        printf("No client certificate received\n");
        printf("===========================\n\n");
        return;
    }

    // Print subject name
    char *subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    if (subject)
    {
        printf("Client subject: %s\n", subject);
        OPENSSL_free(subject);
    }

    // Print issuer name
    char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    if (issuer)
    {
        printf("Client issuer: %s\n", issuer);
        OPENSSL_free(issuer);
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
                printf("Client certificate algorithm: %s\n", long_name);
            }
        }
    }

    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (pkey)
    {
        int key_size = EVP_PKEY_bits(pkey);
        printf("Client certificate key size: %d bits\n", key_size);
        EVP_PKEY_free(pkey);
    }

    X509_free(cert);
    printf("===========================\n\n");
}

// Print TLS connection details for post-quantum mTLS analysis
void print_tls_connection_info(SSL *ssl)
{
    printf("\n=== Post-Quantum mTLS Connection ===\n");

    const char *version = SSL_get_version(ssl);
    printf("TLS version: %s\n", version);

    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    printf("Cipher suite: %s\n", SSL_CIPHER_get_name(cipher));

    // Key exchange group (ML-KEM for post-quantum)
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

    // Client signature algorithm (from client certificate)
    const char *peer_sig_name = NULL;
    if (SSL_get0_peer_signature_name(ssl, &peer_sig_name) && peer_sig_name)
    {
        printf("Client signature: %s\n", peer_sig_name);
    }

    printf("=====================================\n\n");
}

// Client certificate verification callback
int verify_client_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    int err = X509_STORE_CTX_get_error(ctx);
    int depth = X509_STORE_CTX_get_error_depth(ctx);

    printf("Certificate verification: depth=%d, preverify_ok=%d\n", depth, preverify_ok);

    if (!preverify_ok)
    {
        printf("Certificate verification failed: %s\n", X509_verify_cert_error_string(err));

        if (cert)
        {
            char *subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
            if (subject)
            {
                printf("Certificate subject: %s\n", subject);
                OPENSSL_free(subject);
            }
        }
        return 0; // Reject certificate
    }

    printf("Certificate verification successful\n");
    return 1; // Accept certificate
}

// Initialize OpenSSL and create SSL context for post-quantum mTLS
SSL_CTX *create_pq_mtls_ssl_context()
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

    // Enforce TLS 1.3 only (required for post-quantum algorithms)
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

    printf("SSL context created with TLS 1.3 enforcement (required for post-quantum mTLS)\n");
    return ctx;
}

// Set post-quantum specific SSL context options for mTLS server
int configure_pq_mtls_context(SSL_CTX *ctx)
{
    // Enable post-quantum signature algorithms
    // Note: These are the NIST standardized post-quantum algorithms
    const char *pq_sigalgs = "ML-DSA-44:ML-DSA-65:ML-DSA-87:"
                             // SLH-DSA algorithms currently not supported for TLS signature configuration
                             // Uncomment the following line when SLH-DSA support is added to OpenSSL TLS
                             // "SLH-DSA-SHA2-128s:SLH-DSA-SHA2-128f:SLH-DSA-SHA2-192s:SLH-DSA-SHA2-192f:"
                             // "SLH-DSA-SHA2-256s:SLH-DSA-SHA2-256f:SLH-DSA-SHAKE-128s:SLH-DSA-SHAKE-128f:"
                             "ECDSA+SHA256:ECDSA+SHA384:RSA+SHA256";

    if (SSL_CTX_set1_sigalgs_list(ctx, pq_sigalgs) != 1)
    {
        printf("Warning: Could not set post-quantum signature algorithms list\n");
        ERR_print_errors_fp(stderr);
        // Continue anyway as this is not always fatal
    }
    else
    {
        printf("Post-quantum signature algorithms configured for mTLS server\n");
    }

    // Configure supported groups (key exchange algorithms)
    const char *pq_groups = "MLKEM768:MLKEM1024:MLKEM512:X25519:X448:secp256r1:secp384r1"
                            "X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024:";

    if (SSL_CTX_set1_groups_list(ctx, pq_groups) != 1)
    {
        printf("Warning: Could not set post-quantum groups list\n");
        ERR_print_errors_fp(stderr);
        // Continue anyway as this is not always fatal
    }
    else
    {
        printf("Post-quantum key exchange groups configured for mTLS server\n");
    }

    return 0;
}

// Load server certificate, private key, and configure client certificate verification for post-quantum mTLS
int load_pq_mtls_certificates(SSL_CTX *ctx)
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
    printf("Server certificate and private key match verified\n");

    // Load CA certificate for client verification
    if (SSL_CTX_load_verify_locations(ctx, "./certs/ca-cert.pem", NULL) != 1)
    {
        fprintf(stderr, "Failed to load CA certificate for client verification\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    printf("CA certificate loaded for client verification\n");

    // Enable client certificate verification (post-quantum mutual TLS)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_client_callback);
    printf("Client certificate verification enabled (post-quantum mutual TLS)\n");

    // Print certificate and key information
    print_cert_info(ctx);

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

    printf("Post-quantum mTLS server listening on port %d\n", port);
    return sockfd;
}

// Handle client connection with post-quantum mTLS
void handle_pq_mtls_client(int client_fd, SSL_CTX *ctx)
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
    printf("Starting post-quantum mTLS handshake...\n");
    int result = SSL_accept(ssl);
    if (result != 1)
    {
        int ssl_error = SSL_get_error(ssl, result);
        fprintf(stderr, "Post-quantum mTLS handshake failed (error: %d)\n", ssl_error);
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return;
    }
    printf("Post-quantum mTLS handshake successful\n");

    // Print post-quantum mTLS connection details
    print_tls_connection_info(ssl);

    // Print client certificate information
    print_client_cert_info(ssl);

    // Echo loop
    printf("Client connected with post-quantum mTLS. Starting echo service...\n");
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

    printf("=== Post-Quantum mTLS 1.3 Echo Server ===\n\n");

    // Install signal handler
    signal(SIGINT, sigint_handler);

    // Create SSL context
    ctx = create_pq_mtls_ssl_context();
    if (!ctx)
    {
        return 1;
    }

    // Configure post-quantum specific options
    if (configure_pq_mtls_context(ctx) != 0)
    {
        SSL_CTX_free(ctx);
        return 1;
    }

    // Load certificates
    if (load_pq_mtls_certificates(ctx) != 0)
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

    printf("Post-quantum mTLS 1.3 server ready. Press Ctrl+C to stop.\n");

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

        // Handle client (blocking, one at a time)
        handle_pq_mtls_client(client_fd, ctx);
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