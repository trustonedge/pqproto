# QUIC Client-Server Prototype

A minimal complete QUIC echo server and client implementation using OpenSSL 3.5.2 with classical cryptography (RSA, X25519, ECDH).

## Certificate Generation

Before running the programs, generate the required certificates in the `certs/` directory:

```bash
# Create certs directory
mkdir -p certs
cd certs

# Generate CA private key
openssl genpkey -algorithm RSA -out ca-key.pem -pkeyopt rsa_keygen_bits:2048

# Generate CA certificate
openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -days 365 \
    -subj "/C=US/ST=CA/L=San Francisco/O=QUIC Test CA/CN=QUIC Test CA"

# Generate server private key
openssl genpkey -algorithm RSA -out server-key.pem -pkeyopt rsa_keygen_bits:2048

# Generate server certificate signing request
openssl req -new -key server-key.pem -out server.csr \
    -subj "/C=US/ST=CA/L=San Francisco/O=QUIC Test Server/CN=localhost"

# Sign server certificate with CA
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
    -CAcreateserial -out server-cert.pem -days 365

# Clean up temporary files
rm server.csr

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

### Start the QUIC Server

```bash
./server --port 4433
```

### Run the QUIC Client

In another terminal:

```bash
./client --host localhost --port 4433
```
