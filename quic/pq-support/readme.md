# QUIC Post-Quantum Client-Server Prototype

A minimal but complete QUIC echo server and client implementation using OpenSSL 3.5.2 with post-quantum cryptography support (Kyber KEM algorithms and hybrid classical+PQ schemes).

## Certificate Generation

Generate post-quantum certificates using Dilithium signature algorithms:

```bash
# Create certs directory
mkdir -p certs
cd certs

# Generate post-quantum CA private key (Dilithium3)
openssl genpkey -algorithm ML-DSA-65 -out ca-key.pem

# Generate CA certificate
openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -days 365 -subj "/C=US/ST=CA/L=San Francisco/O=QUIC PQ Test CA/CN=QUIC PQ Test CA"

# Generate post-quantum server private key (Dilithium3)
openssl genpkey -algorithm ML-DSA-65 -out server-key.pem

# Generate server certificate signing request
openssl req -new -key server-key.pem -out server.csr -subj "/C=US/ST=CA/L=San Francisco/O=QUIC PQ Test Server/CN=localhost"

# Sign server certificate with CA
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
    -CAcreateserial -out server-cert.pem -days 365

# Clean up temporary files
rm *.csr *.srl

cd ..
```

## Build Instructions

Build both programs using make:

```bash
make
```

To clean build artifacts:

```bash
make clean
```

## Run Instructions

### Start the QUIC Post-Quantum Server

```bash
./server --port 5433
```

### Run the QUIC Post-Quantum Client

In another terminal:

```bash
./client --host localhost --port 5433
```
