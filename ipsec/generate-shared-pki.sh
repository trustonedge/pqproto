#!/bin/bash

# Shared PKI Generation Script for IPSec Setup
# This generates a complete PKI that both server and client containers will use

MODE=${1:-classical}
echo "Generating shared PKI for mode: $MODE"

if [ "$MODE" = "pq-support" ]; then
    echo "=== Generating PQ-Support PKI (Classical RSA for now) ==="
    echo "Note: ML-DSA-65 support will be added once available"

    # Clean up previous PKI and create structure
    rm -rf pq-support/pki/
    mkdir -p pq-support/pki/{cacerts,certs,private}

    # CA private key (RSA-4096 - ML-DSA-65 not yet supported)
    # TODO: Replace with ML-DSA-65 when supported: openssl genpkey -algorithm ML-DSA-65 -out pq-support/pki/private/ca-key.pem
    openssl genrsa -out pq-support/pki/private/ca-key.pem 4096

    # CA certificate
    openssl req -new -x509 -key pq-support/pki/private/ca-key.pem -out pq-support/pki/cacerts/ca-cert.pem -days 3650 \
        -subj "/C=US/ST=Test/L=Test/O=Test PQ CA/CN=Test PQ CA"

    # Server private key (RSA-4096 - ML-DSA-65 not yet supported)
    # TODO: Replace with ML-DSA-65 when supported: openssl genpkey -algorithm ML-DSA-65 -out pq-support/pki/private/server-key.pem
    openssl genrsa -out pq-support/pki/private/server-key.pem 4096

    # Server certificate
    openssl req -new -key pq-support/pki/private/server-key.pem -out server.csr \
        -subj "/C=US/ST=Test/L=Test/O=Test Server/OU=Test/CN=vpn.test.local"

    openssl x509 -req -in server.csr -CA pq-support/pki/cacerts/ca-cert.pem -CAkey pq-support/pki/private/ca-key.pem \
        -CAcreateserial -out pq-support/pki/certs/server-cert.pem -days 365

    # Client private key (RSA-4096 - ML-DSA-65 not yet supported)
    # TODO: Replace with ML-DSA-65 when supported: openssl genpkey -algorithm ML-DSA-65 -out pq-support/pki/private/client-key.pem
    openssl genrsa -out pq-support/pki/private/client-key.pem 4096

    # Client certificate
    openssl req -new -key pq-support/pki/private/client-key.pem -out client.csr \
        -subj "/C=US/ST=Test/L=Test/O=Test Client/OU=Test/CN=client.test.local"
        
    openssl x509 -req -in client.csr -CA pq-support/pki/cacerts/ca-cert.pem -CAkey pq-support/pki/private/ca-key.pem \
        -CAcreateserial -out pq-support/pki/certs/client-cert.pem -days 365

    # Set proper permissions
    chmod 700 pq-support/pki/private
    chmod 600 pq-support/pki/private/*
    chmod 644 pq-support/pki/cacerts/*
    chmod 644 pq-support/pki/certs/*

    echo "=== PKI Generated Successfully ==="
    echo "CA Certificate: pq-support/pki/cacerts/ca-cert.pem"
    echo "Server Certificate: pq-support/pki/certs/server-cert.pem"
    echo "Client Certificate: pq-support/pki/certs/client-cert.pem"
    echo "Private Keys: pq-support/pki/private/"

    # Verify certificates
    echo ""
    echo "=== Certificate Verification ==="
    openssl verify -CAfile pq-support/pki/cacerts/ca-cert.pem pq-support/pki/certs/server-cert.pem
    openssl verify -CAfile pq-support/pki/cacerts/ca-cert.pem pq-support/pki/certs/client-cert.pem

else
    echo "=== Generating Classical PKI (RSA-4096) ==="

    # Clean up previous PKI and create structure
    rm -rf classical/pki/
    mkdir -p classical/pki/{cacerts,certs,private}

    # CA private key (RSA-4096)
    openssl genrsa -out classical/pki/private/ca-key.pem 4096

    # CA certificate
    openssl req -new -x509 -key classical/pki/private/ca-key.pem -out classical/pki/cacerts/ca-cert.pem -days 3650 \
        -subj "/C=US/ST=Test/L=Test/O=Test CA/OU=Test/CN=Test CA"

    # Server private key (RSA-4096)
    openssl genrsa -out classical/pki/private/server-key.pem 4096

    # Server certificate
    openssl req -new -key classical/pki/private/server-key.pem -out server.csr \
        -subj "/C=US/ST=Test/L=Test/O=Test Server/OU=Test/CN=vpn.test.local"
    openssl x509 -req -in server.csr -CA classical/pki/cacerts/ca-cert.pem -CAkey classical/pki/private/ca-key.pem \
        -CAcreateserial -out classical/pki/certs/server-cert.pem -days 365

    # Client private key (RSA-4096)
    openssl genrsa -out classical/pki/private/client-key.pem 4096

    # Client certificate
    openssl req -new -key classical/pki/private/client-key.pem -out client.csr \
        -subj "/C=US/ST=Test/L=Test/O=Test Client/OU=Test/CN=client.test.local"
    openssl x509 -req -in client.csr -CA classical/pki/cacerts/ca-cert.pem -CAkey classical/pki/private/ca-key.pem \
        -CAcreateserial -out classical/pki/certs/client-cert.pem -days 365

    # Set proper permissions
    chmod 700 classical/pki/private
    chmod 600 classical/pki/private/*
    chmod 644 classical/pki/cacerts/*
    chmod 644 classical/pki/certs/*

    echo "=== PKI Generated Successfully ==="
    echo "CA Certificate: classical/pki/cacerts/ca-cert.pem"
    echo "Server Certificate: classical/pki/certs/server-cert.pem"
    echo "Client Certificate: classical/pki/certs/client-cert.pem"
    echo "Private Keys: classical/pki/private/"

    # Verify certificates
    echo ""
    echo "=== Certificate Verification ==="
    openssl verify -CAfile classical/pki/cacerts/ca-cert.pem classical/pki/certs/server-cert.pem
    openssl verify -CAfile classical/pki/cacerts/ca-cert.pem classical/pki/certs/client-cert.pem
fi

# Clean up CSR files
rm -f server.csr client.csr

echo ""
echo "PKI generation completed for $MODE mode!"
echo "Ready to build containers with: IPSEC_MODE=$MODE docker compose up -d"