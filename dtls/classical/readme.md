# DTLS 1.2 Client-Server Prototype

A minimal but complete DTLS 1.2 echo server and client implementation using OpenSSL 3.5.2.

## Certificate Generation

Before running the programs, generate the required certificates in the `certs/` directory:

```bash
# Create certs directory
mkdir -p certs
cd certs

# Generate CA private key
openssl genrsa -out ca-key.pem 4096

# Generate CA certificate
openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -days 365 \
    -subj "/C=US/ST=Test/L=Test/O=Test CA/CN=Test CA"

# Generate server private key
openssl genrsa -out server-key.pem 4096

# Generate server certificate signing request
openssl req -new -key server-key.pem -out server.csr \
    -subj "/C=US/ST=Test/L=Test/O=Test/CN=localhost"

# Sign server certificate with CA
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
    -CAcreateserial -out server-cert.pem -days 365 \
    -extensions v3_req -extfile server.conf

# Clean up temporary files
rm server.csr ca-cert.srl

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

### Start the DTLS Server

```bash
./server --port 8443
```

### Run the DTLS Client

In another terminal:

```bash
./client --host localhost --port 8443
```
