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
#include <openssl/quic.h>
#include <openssl/bio.h>

#define DEFAULT_PORT 4433
#define BUFFER_SIZE 1024

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

    // Server signature algorithm (from server certificate)
    const char *peer_sig_name = NULL;
    if (SSL_get0_peer_signature_name(ssl, &peer_sig_name) && peer_sig_name)
    {
        printf("Peer signature algorithm: %s\n", peer_sig_name);
    }

    printf("========================\n");
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
    printf("===========================\n\n");
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

    // Create QUIC client SSL context using the correct method
    ctx = SSL_CTX_new(OSSL_QUIC_client_method());
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

    // Note: ALPN will be set per-connection in main(), not at context level
    // This allows for more flexible per-connection protocol negotiation
    printf("ALPN will be configured per-connection (demo: http/1.0)\n");

    printf("QUIC SSL context created successfully\n");
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

// Create UDP socket and BIO for QUIC client
BIO *create_client_bio(const char *hostname, int port, BIO_ADDR **peer_addr)
{
    BIO_ADDRINFO *res = NULL;
    const BIO_ADDRINFO *ai = NULL;
    int sock = -1;
    BIO *bio = NULL;

    // Lookup server address
    if (!BIO_lookup_ex(hostname, NULL, BIO_LOOKUP_CLIENT, AF_INET, SOCK_DGRAM, 0, &res))
    {
        fprintf(stderr, "Failed to lookup hostname: %s\n", hostname);
        return NULL;
    }

    // Try to connect to server
    for (ai = res; ai != NULL; ai = BIO_ADDRINFO_next(ai))
    {
        // Create UDP socket
        sock = BIO_socket(BIO_ADDRINFO_family(ai), SOCK_DGRAM, 0, 0);
        if (sock == -1)
            continue;

        // Connect to server address with our port
        struct sockaddr_in server_addr;
        memcpy(&server_addr, BIO_ADDRINFO_address(ai), sizeof(server_addr));
        server_addr.sin_port = htons(port);

        if (!BIO_connect(sock, (BIO_ADDR *)&server_addr, 0))
        {
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }

        // Set socket to nonblocking (required for QUIC)
        if (!BIO_socket_nbio(sock, 1))
        {
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }

        // Save peer address
        *peer_addr = BIO_ADDR_dup((BIO_ADDR *)&server_addr);
        if (*peer_addr == NULL)
        {
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }

        break;
    }

    BIO_ADDRINFO_free(res);

    if (sock == -1)
    {
        fprintf(stderr, "Failed to create and connect socket\n");
        return NULL;
    }

    // Create datagram BIO
    bio = BIO_new(BIO_s_datagram());
    if (bio == NULL)
    {
        BIO_closesocket(sock);
        BIO_ADDR_free(*peer_addr);
        *peer_addr = NULL;
        return NULL;
    }

    // Associate BIO with socket
    BIO_set_fd(bio, sock, BIO_CLOSE);

    printf("QUIC UDP socket created and connected\n");
    return bio;
}

// Send data on QUIC stream
int send_quic_data(SSL *ssl, const char *data, size_t len)
{
    size_t bytes_written;

    if (SSL_write_ex(ssl, data, len, &bytes_written) != 1)
    {
        int ssl_error = SSL_get_error(ssl, 0);
        fprintf(stderr, "QUIC write error: %d\n", ssl_error);
        ERR_print_errors_fp(stderr);
        return -1;
    }

    printf("Sent %zu bytes on QUIC stream\n", bytes_written);
    return (int)bytes_written;
}

// Receive data from QUIC stream
int receive_quic_data(SSL *ssl, char *buffer, size_t buffer_size)
{
    size_t bytes_read;

    if (SSL_read_ex(ssl, buffer, buffer_size - 1, &bytes_read) != 1)
    {
        int ssl_error = SSL_get_error(ssl, 0);
        if (ssl_error == SSL_ERROR_WANT_READ)
        {
            return 0; // No data available
        }
        else if (ssl_error == SSL_ERROR_ZERO_RETURN)
        {
            printf("QUIC server closed connection\n");
            return -1;
        }
        else
        {
            fprintf(stderr, "QUIC read error: %d\n", ssl_error);
            ERR_print_errors_fp(stderr);
            return -1;
        }
    }

    buffer[bytes_read] = '\0';
    printf("Received %zu bytes from QUIC stream\n", bytes_read);
    return (int)bytes_read;
}

// Interactive communication loop
void interactive_quic_session(SSL *ssl)
{
    char send_buffer[BUFFER_SIZE];
    char recv_buffer[BUFFER_SIZE];
    int bytes_sent, bytes_received;

    printf("QUIC connection established! Type messages to send to server (Ctrl+C to exit):\n");
    printf("> ");
    fflush(stdout);

    while (fgets(send_buffer, sizeof(send_buffer), stdin))
    {
        size_t len = strlen(send_buffer);

        // Send message to server
        bytes_sent = send_quic_data(ssl, send_buffer, len);
        if (bytes_sent <= 0)
        {
            printf("Failed to send data, exiting\n");
            break;
        }

        // Receive echo from server
        bytes_received = receive_quic_data(ssl, recv_buffer, sizeof(recv_buffer));
        if (bytes_received < 0)
        {
            printf("Connection closed by server\n");
            break;
        }
        else if (bytes_received > 0)
        {
            printf("Server echoed: %s\n", recv_buffer);
        }

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

    printf("=== QUIC Classical Client ===\n\n");

    // Create QUIC SSL context
    ctx = create_quic_context();
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

    // Create UDP socket and BIO
    BIO_ADDR *peer_addr = NULL;
    BIO *bio = create_client_bio(hostname, port, &peer_addr);
    if (!bio)
    {
        SSL_CTX_free(ctx);
        return 1;
    }

    // Create QUIC SSL object
    ssl = SSL_new(ctx);
    if (!ssl)
    {
        fprintf(stderr, "Failed to create QUIC SSL object\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        BIO_ADDR_free(peer_addr);
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
        BIO_ADDR_free(peer_addr);
        SSL_CTX_free(ctx);
        return 1;
    }

    // Set hostname for verification
    if (SSL_set1_host(ssl, hostname) != 1)
    {
        fprintf(stderr, "Failed to set hostname for verification\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        BIO_ADDR_free(peer_addr);
        SSL_CTX_free(ctx);
        return 1;
    }

    /*
     * Set ALPN (Application-Layer Protocol Negotiation)
     *
     * QUIC requires ALPN negotiation. We use "http/1.0" for this demo
     * instead of standard HTTP/3 protocols like "h3" because:
     *
     * - This is an educational echo client, not a real HTTP/3 implementation
     * - "http/1.0" makes it clear this is demo/testing code
     * - Avoids complexity of implementing full HTTP/3 protocol stack
     *
     * Format: Length-prefixed array (not null-terminated string)
     * {8, 'h', 't', 't', 'p', '/', '1', '.', '0'} = 8-byte length + "http/1.0"
     *
     * Real HTTP/3 clients would use: {2, 'h', '3'} for "h3"
     */
    unsigned char alpn[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '0'};
    if (SSL_set_alpn_protos(ssl, alpn, sizeof(alpn)) != 0)
    {
        fprintf(stderr, "Failed to set ALPN\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        BIO_ADDR_free(peer_addr);
        SSL_CTX_free(ctx);
        return 1;
    }

    // Set initial peer address
    if (SSL_set1_initial_peer_addr(ssl, peer_addr) != 1)
    {
        fprintf(stderr, "Failed to set initial peer address\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        BIO_ADDR_free(peer_addr);
        SSL_CTX_free(ctx);
        return 1;
    }

    printf("QUIC client configured for %s:%d\n", hostname, port);
    printf("Starting QUIC handshake...\n");

    int result = SSL_connect(ssl);
    if (result != 1)
    {
        int ssl_error = SSL_get_error(ssl, result);
        fprintf(stderr, "QUIC handshake failed (error: %d)\n", ssl_error);
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        BIO_ADDR_free(peer_addr);
        SSL_CTX_free(ctx);
        return 1;
    }
    printf("QUIC handshake successful\n");

    // Print QUIC connection details
    print_quic_connection_info(ssl);

    // Print server certificate information
    print_peer_cert_info(ssl);

    printf("Using OpenSSL %s with QUIC support\n", OpenSSL_version(OPENSSL_VERSION));

    // Start interactive session
    interactive_quic_session(ssl);

    // Clean shutdown
    printf("\nShutting down QUIC connection...\n");
    int shutdown_result = SSL_shutdown(ssl);
    if (shutdown_result < 0)
    {
        printf("QUIC shutdown warning (this is often normal)\n");
    }
    else
    {
        printf("QUIC connection shut down cleanly\n");
    }

    // Cleanup
    BIO_ADDR_free(peer_addr);
    SSL_free(ssl); // This will also free the BIO
    SSL_CTX_free(ctx);

    printf("QUIC client shutdown complete\n");
    return 0;
}