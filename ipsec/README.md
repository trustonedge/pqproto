# IPSec VPN with Post-Quantum Cryptography

This demonstration compares classical IPSec VPN against post-quantum cryptography enhanced IPSec using containerized StrongSwan. The setup includes two operational modes: classical RSA/ECC cryptography and post-quantum ML-KEM key exchange algorithms.

The system establishes IKEv2 VPN tunnels between client and server containers with configurable authentication methods (certificates or pre-shared keys). Classical mode uses traditional RSA-4096 certificates and ECC curves, while post-quantum mode integrates ML-KEM768/1024 key exchange with backwards compatibility fallback to classical algorithms.

## Prerequisites

1. **Docker Installation**: Follow [install-docker.md](../../docs/install-docker.md)
2. **System Requirements**: Linux with kernel modules support

## Environment Variables

- `IPSEC_MODE`: `classical` (default) or `pq-support`
- `AUTH_METHOD`: `certs` (default) or `psk`
- `OPENSSL_VERSION`: OpenSSL version to use (default: `3.5.3`)

## Usage

### Classical Mode (Default)

Uses traditional RSA-4096 certificates:

```bash
# Generate shared PKI for classical mode
./generate-shared-pki.sh classical

# Build and start containers in classical mode
docker compose up -d

# Check status
docker compose ps
```

### Post-Quantum Mode

```bash
# Generate shared PKI for PQ mode
./generate-shared-pki.sh pq-support

# Build and start containers in PQ mode
IPSEC_MODE=pq-support docker compose up -d

# Check status
docker compose ps
```

### Authentication Methods

Both modes support certificate-based or PSK authentication:

```bash
# Classical mode with PSK authentication
AUTH_METHOD=psk docker compose up -d

# PQ mode with certificate authentication (default)
IPSEC_MODE=pq-support AUTH_METHOD=certs docker compose up -d

# PQ mode with PSK authentication
IPSEC_MODE=pq-support AUTH_METHOD=psk docker compose up -d
```

### Custom OpenSSL Version

```bash
# Use different OpenSSL version
OPENSSL_VERSION=3.5.2 docker compose up -d

# Combine with other flags
IPSEC_MODE=pq-support AUTH_METHOD=psk OPENSSL_VERSION=3.5.2 docker compose up -d
```

## Verify Setup

```bash
# View logs
docker logs ipsec-server
docker logs ipsec-client

# Check connections
docker exec ipsec-server swanctl --list-conns
docker exec ipsec-client swanctl --list-conns

# Verify OpenSSL version inside container
docker exec ipsec-server openssl version
```

## Test IPSec Tunnel

```bash
# Test basic connectivity through tunnel
docker exec ipsec-client ping -c 3 10.1.0.1

# Check tunnel status (should show ESTABLISHED and INSTALLED)
docker exec ipsec-server swanctl --list-sas
docker exec ipsec-client swanctl --list-sas

# Check tunnel IP assignments
# Server has static IP on tunnel0 interface
docker exec ipsec-server ip addr show tunnel0

# Client gets virtual IP assigned from pool (visible in SA, not as interface)
docker exec ipsec-server swanctl --list-pools

# Check tunnel traffic (should show bytes and packets)
docker exec ipsec-server swanctl --list-sas | grep -E "(bytes|packets)"

# Manual tunnel initiation (if needed)
docker exec ipsec-client swanctl --initiate --child tunnel-to-corp
```

> [!NOTE]
> The client receives a virtual IP from the server's pool but this IP is managed by StrongSwan internally for tunnel traffic. The actual tunneling happens at the kernel level through IPsec policies, so you won't see a separate tunnel interface on the client side.

## Test Applications

```bash
# Start test server
docker exec -d ipsec-server python3 /usr/local/bin/test-server.py

# Run test client (interactive)
docker exec -it ipsec-client python3 /usr/local/bin/test-client.py
```

## Inspect Certificates

### Classical Mode Certificates

```bash
# View RSA certificates
docker exec ipsec-server openssl x509 -in /etc/swanctl/x509ca/ca-cert.pem -text -noout
docker exec ipsec-server openssl rsa -in /etc/swanctl/private/server-key.pem -text -noout
```

### Post-Quantum Mode Certificates

```bash
# View RSA certificates (ML-DSA not yet supported)
docker exec ipsec-server openssl x509 -in /etc/swanctl/x509ca/ca-cert.pem -text -noout
docker exec ipsec-server openssl rsa -in /etc/swanctl/private/server-key.pem -text -noout
```

## Switch Between Modes

To switch modes, stop containers, regenerate PKI, and rebuild:

```bash
# Stop current setup
docker compose down

# Switch to PQ mode
./generate-shared-pki.sh pq-support
IPSEC_MODE=pq-support docker compose up -d --build

# Switch back to classical mode
./generate-shared-pki.sh classical
IPSEC_MODE=classical docker compose up -d --build
```

## Troubleshooting

### Connection Issues

```bash
# Check if tunnels are established
docker exec ipsec-server swanctl --list-conns
docker exec ipsec-client swanctl --list-conns

# Manual tunnel initiation (if auto-start fails)
docker exec ipsec-client swanctl --initiate --child tunnel-to-corp

# Check if server has tunnel IP
docker exec ipsec-server ip addr show tunnel0
```

### Network Debugging

```bash
# Check IPSec policies and state
docker exec ipsec-server ip xfrm policy list
docker exec ipsec-client ip xfrm policy list
docker exec ipsec-server ip xfrm state list
docker exec ipsec-client ip xfrm state list

# Check routing tables
docker exec ipsec-server ip route show
docker exec ipsec-client ip route show

# Monitor connection logs
docker logs -f ipsec-server
docker logs -f ipsec-client

# Test with verbose ping
docker exec ipsec-client ping -v -c 5 10.1.0.1
```

### Certificate Issues

```bash
# Check certificate validity
docker exec ipsec-server openssl x509 -in /etc/swanctl/x509/server-cert.pem -text -noout
docker exec ipsec-client openssl x509 -in /etc/swanctl/x509/client-cert.pem -text -noout

# Check OpenSSL algorithms supported
docker exec ipsec-server openssl list -signature-algorithms
```

## Cleanup

```bash
# Stop containers
docker compose down

# Remove all (including volumes and images)
docker compose down --volumes --remove-orphans --rmi all
```

## Performance Comparison

You can compare performance between classical and PQ modes:

```bash
# Test classical mode performance
docker exec ipsec-client time ping -c 100 10.1.0.1

# Switch to PQ mode and test
IPSEC_MODE=pq-support docker compose up -d --build
docker exec ipsec-client time ping -c 100 10.1.0.1
```
