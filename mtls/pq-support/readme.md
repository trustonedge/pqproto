# Post-Quantum mTLS 1.3 Client-Server Prototype

A minimal but complete mutual TLS 1.3 echo server and client implementation using **NIST-standardized post-quantum cryptographic algorithms** with OpenSSL 3.5.2.

## Post-Quantum mTLS Certificate Generation

Before running the programs, generate post-quantum certificates for mutual authentication in the `certs/` directory:

```bash
# Create certs directory
mkdir -p certs
cd certs

# Generate CA private key using ML-DSA-65
openssl genpkey -algorithm ML-DSA-65 -out ca-key.pem

# Generate CA certificate
openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -days 365 \
    -subj "/C=US/ST=Test/L=Test/O=Test PQ CA/CN=Test PQ CA"

# Generate server private key using ML-DSA-65
openssl genpkey -algorithm ML-DSA-65 -out server-key.pem

# Generate server certificate signing request
openssl req -new -key server-key.pem -out server.csr \
    -subj "/C=US/ST=Test/L=Test/O=Test PQ/CN=localhost"

# Sign server certificate with CA
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
    -CAcreateserial -out server-cert.pem -days 365

# Generate client private key using ML-DSA-65
openssl genpkey -algorithm ML-DSA-65 -out client-key.pem

# Generate client certificate signing request
openssl req -new -key client-key.pem -out client.csr \
    -subj "/C=US/ST=Test/L=Test/O=Test PQ Client/CN=Test PQ Client"

# Sign client certificate with CA
openssl x509 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem \
    -CAcreateserial -out client-cert.pem -days 365

# Clean up temporary files
rm server.csr client.csr ca-cert.srl

cd ..
```

### Verify Post-Quantum Certificates

```bash
# Check server certificate algorithm
openssl x509 -in certs/server-cert.pem -text -noout | grep -A5 "Public Key Algorithm"

# Check client certificate algorithm
openssl x509 -in certs/client-cert.pem -text -noout | grep -A5 "Public Key Algorithm"
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

### Start Server

```bash
./server --port 8443
```

### Run Client

In another terminal:

```bash
./client --host localhost --port 8443
```
