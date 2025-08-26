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

    // Server signature algorithm (from server certificate)
    const char *peer_sig_name = NULL;
    if (SSL_get0_peer_signature_name(ssl, &peer_sig_name) && peer_sig_name)
    {
        printf("Server signature algorithm: %s\n", peer_sig_name);
    }

    // Client signature algorithm (from our certificate)
    const char *local_sig_name = NULL;
    if (SSL_get0_signature_name(ssl, &local_sig_name) && local_sig_name)
    {
        printf("Client signature algorithm: %s\n", local_sig_name);
    }

    printf("=====================================\n");
}

// Enhanced function to print server certificate algorithm information
void print_peer_cert_info(SSL *ssl)
{
    printf("\n=== Server Certificate ===\n");

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert)
    {
        printf("No server certificate received\n");
        printf("===========================\n\n");
        return;
    }

    // Print subject name
    char *subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    if (subject)
    {
        printf("Server subject: %s\n", subject);
        OPENSSL_free(subject);
    }

    // Print issuer name
    char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    if (issuer)
    {
        printf("Server issuer: %s\n", issuer);
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
                printf("Server certificate algorithm: %s\n", long_name);
            }
        }
    }

    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (pkey)
    {
        int key_size = EVP_PKEY_bits(pkey);
        printf("Server certificate key size: %d bits\n", key_size);
        EVP_PKEY_free(pkey);
    }

    X509_free(cert);
    printf("============================\n\n");
}

// Print client certificate information
void print_client_cert_info()
{
    printf("\n=== Client Certificate & Key ===\n");

    // Load and print certificate algorithm info from file
    FILE *cert_file = fopen("./certs/client-cert.pem", "r");
    if (cert_file)
    {
        X509 *cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
        if (cert)
        {
            // Print subject name
            char *subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
            if (subject)
            {
                printf("Client subject: %s\n", subject);
                OPENSSL_free(subject);
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

            EVP_PKEY *cert_key = X509_get_pubkey(cert);
            if (cert_key)
            {
                int key_size = EVP_PKEY_bits(cert_key);
                printf("Client certificate key size: %d bits\n", key_size);
                EVP_PKEY_free(cert_key);
            }
            X509_free(cert);
        }
        fclose(cert_file);
    }

    // Load and print private key algorithm info from file
    FILE *key_file = fopen("./certs/client-key.pem", "r");
    if (key_file)
    {
        EVP_PKEY *pkey = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
        if (pkey)
        {
            int key_size = EVP_PKEY_bits(pkey);
            const char *type_name = EVP_PKEY_get0_type_name(pkey);
            if (type_name)
            {
                printf("Client private key algorithm: %s (%d bits)\n", type_name, key_size);
            }
            EVP_PKEY_free(pkey);
        }
        fclose(key_file);
    }

    printf("=================================\n\n");
}

// Initialize OpenSSL and create SSL context for post-quantum mTLS support
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

// Configure post-quantum algorithms for mTLS client
int configure_client_context(SSL_CTX *ctx)
{
    // Enable post-quantum signature algorithms (same as server for compatibility)
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
        printf("Post-quantum signature algorithms configured for mTLS client\n");
    }

    // Configure supported groups (key exchange algorithms) with preference for post-quantum
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
        printf("Post-quantum key exchange groups configured for mTLS client\n");
    }

    return 0;
}

// Load client certificate, private key, and CA certificate for post-quantum mTLS
int load_certificates(SSL_CTX *ctx)
{
    // Load client certificate for mutual TLS
    if (SSL_CTX_use_certificate_file(ctx, "./certs/client-cert.pem", SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Failed to load client certificate\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    printf("Client certificate loaded from ./certs/client-cert.pem\n");

    // Load client private key for mutual TLS
    if (SSL_CTX_use_PrivateKey_file(ctx, "./certs/client-key.pem", SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Failed to load client private key\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    printf("Client private key loaded from ./certs/client-key.pem\n");

    // Verify that certificate and private key match
    if (SSL_CTX_check_private_key(ctx) != 1)
    {
        fprintf(stderr, "Client certificate and private key do not match\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    printf("Client certificate and private key match verified\n");

    // Load CA certificate for server verification
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

    // Print client certificate and key information
    print_client_cert_info();

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

    printf("Connected to post-quantum mTLS server %s:%d\n", hostname, port);
    return sockfd;
}

// Interactive communication loop
void interactive_session(SSL *ssl)
{
    char send_buffer[BUFFER_SIZE];
    char recv_buffer[BUFFER_SIZE];
    int bytes_sent, bytes_received;

    printf("Post-quantum mTLS connection established! Type messages to send to server (Ctrl+C to exit):\n");
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
    int client_fd;

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

    printf("=== Post-Quantum mTLS 1.3 Client ===\n\n");

    // Create SSL context
    ctx = create_ssl_context();
    if (!ctx)
    {
        return 1;
    }

    // Configure post-quantum algorithms
    if (configure_client_context(ctx) != 0)
    {
        SSL_CTX_free(ctx);
        return 1;
    }

    // Load certificates
    if (load_certificates(ctx) != 0)
    {
        SSL_CTX_free(ctx);
        return 1;
    }

    // Connect to server
    client_fd = connect_to_server(hostname, port);
    if (client_fd < 0)
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
        close(client_fd);
        SSL_CTX_free(ctx);
        return 1;
    }

    // Associate SSL with socket
    if (SSL_set_fd(ssl, client_fd) != 1)
    {
        fprintf(stderr, "Failed to associate SSL with socket\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_fd);
        SSL_CTX_free(ctx);
        return 1;
    }

    // Set SNI (Server Name Indication)
    if (SSL_set_tlsext_host_name(ssl, hostname) != 1)
    {
        fprintf(stderr, "Failed to set SNI hostname\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_fd);
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
        close(client_fd);
        SSL_CTX_free(ctx);
        return 1;
    }
    printf("Hostname verification enabled for: %s\n", hostname);

    // Perform TLS handshake
    printf("Starting post-quantum mTLS handshake...\n");
    int result = SSL_connect(ssl);
    if (result != 1)
    {
        int ssl_error = SSL_get_error(ssl, result);
        fprintf(stderr, "Post-quantum mTLS handshake failed (error: %d)\n", ssl_error);
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_fd);
        SSL_CTX_free(ctx);
        return 1;
    }
    printf("Post-quantum mTLS handshake successful!\n");

    // Print post-quantum mTLS connection details
    print_tls_connection_info(ssl);

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
    close(client_fd);
    SSL_CTX_free(ctx);

    printf("Client shutdown complete\n");
    return 0;
}