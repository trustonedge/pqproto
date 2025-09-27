#!/bin/bash

# Enable strict error handling
set -euo pipefail

# Function to handle errors
handle_error() {
    echo "ERROR: Script failed at line $1"
    echo "Command: $2"
    echo "Exit code: $3"
    exit 1
}

# Set error trap
trap 'handle_error ${LINENO} "$BASH_COMMAND" $?' ERR

echo "Starting IPsec Client Container (StrongSwan 6.0.2)"
echo "===================================================="

# Validate environment variables
if [ -z "${IPSEC_MODE:-}" ]; then
    echo "WARNING: IPSEC_MODE not set, defaulting to 'classical'"
    export IPSEC_MODE="classical"
fi

if [ -z "${AUTH_METHOD:-}" ]; then
    echo "WARNING: AUTH_METHOD not set, defaulting to 'certs'"
    export AUTH_METHOD="certs"
fi

echo "Configuration: Mode=$IPSEC_MODE, Auth=$AUTH_METHOD"

# Apply sysctl settings
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.all.send_redirects=0

# Note: Tunnel IPs will be assigned automatically by StrongSwan once tunnel is established
# Client will get IP from pool 10.2.0.2-10.2.0.100 as configured in server's swanctl.conf

# Wait for server to be ready
echo "Waiting for server to be ready..."
sleep 10

# Start StrongSwan 6.0.2 daemon
echo "Starting StrongSwan 6.0.2 daemon..."
/usr/sbin/charon-systemd &
CHARON_PID=$!

if [ -z "$CHARON_PID" ]; then
    echo "ERROR: Failed to start charon-systemd daemon"
    exit 1
fi
echo "StrongSwan daemon started with PID: $CHARON_PID"

# Wait for daemon to start and verify it's running
echo "Waiting for daemon to initialize..."
sleep 5

if ! pgrep charon-systemd > /dev/null; then
    echo "ERROR: charon-systemd daemon is not running"
    exit 1
fi

echo "Daemon initialization: COMPLETED"

# Certificate validation function
validate_certificates() {
    echo "Validating certificates..."

    if [ "$AUTH_METHOD" = "certs" ]; then
        local ca_cert="/etc/swanctl/x509ca/ca-cert.pem"
        local client_cert="/etc/swanctl/x509/client-cert.pem"
        local client_key="/etc/swanctl/private/client-key.pem"

        # Check if certificate files exist
        for cert_file in "$ca_cert" "$client_cert" "$client_key"; do
            if [ ! -f "$cert_file" ]; then
                echo "ERROR: Certificate file not found: $cert_file"
                return 1
            fi
        done

        # Check certificate expiry
        local expiry_date=$(openssl x509 -enddate -noout -in "$client_cert" | cut -d= -f2)
        local expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null || echo "0")
        local current_epoch=$(date +%s)
        local days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))

        if [ "$expiry_epoch" -gt 0 ]; then
            echo "Client certificate expires in $days_until_expiry days ($expiry_date)"

            if [ "$days_until_expiry" -lt 30 ]; then
                echo "WARNING: Client certificate expires in less than 30 days!"
            elif [ "$days_until_expiry" -lt 0 ]; then
                echo "ERROR: Client certificate has expired!"
                return 1
            fi
        fi

        # Verify certificate chain
        if openssl verify -CAfile "$ca_cert" "$client_cert" >/dev/null 2>&1; then
            echo "Certificate chain validation: PASSED"
        else
            echo "ERROR: Certificate chain validation failed"
            return 1
        fi

        echo "Certificate validation: COMPLETED"
    else
        echo "PSK authentication mode - skipping certificate validation"
    fi

    return 0
}

# Validate certificates before loading configuration
if ! validate_certificates; then
    echo "Certificate validation failed - exiting"
    exit 1
fi

# Load swanctl configuration
echo "Loading client configuration..."
if ! swanctl --load-all; then
    echo "ERROR: Failed to load swanctl configuration"
    echo "Checking configuration file..."
    ls -la /etc/swanctl/swanctl.conf || echo "Configuration file not found"
    exit 1
fi

echo "Configuration loaded successfully"

# Auto-connect to server (with retry logic)
echo "Auto-connecting to server..."
sleep 5

# Function to establish tunnel
establish_tunnel() {
    local retries=3
    local retry=0

    while [ $retry -lt $retries ]; do
        echo "Attempting tunnel initiation (attempt $((retry + 1))/$retries)..."

        if swanctl --initiate --child tunnel-to-corp >/dev/null 2>&1; then
            echo "Tunnel established successfully!"
            return 0
        fi

        retry=$((retry + 1))
        if [ $retry -lt $retries ]; then
            echo "Attempt failed, retrying in 3 seconds..."
            sleep 3
        fi
    done

    echo "WARNING: All tunnel initiation attempts failed"
    return 1
}

# Check if tunnel is already established
if swanctl --list-sas | grep -q "INSTALLED"; then
    echo "Tunnel already established"
else
    establish_tunnel
fi

# Add route for tunnel traffic (if tunnel is established)
if swanctl --list-sas | grep -q "INSTALLED"; then
    echo "Adding route for tunnel traffic..."
    ip route add 10.1.0.1/32 dev eth0 2>/dev/null || true
fi

# Final connection status
echo "Final connection status:"
swanctl --list-sas

echo
echo "To check connection:"
echo "  docker exec ipsec-client swanctl --list-sas"
echo
echo "To run test client:"
echo "  docker exec ipsec-client python3 /usr/local/bin/test-client.py"
echo
echo "To manually initiate connection:"
echo "   docker exec ipsec-client swanctl --initiate --child tunnel-to-corp"
echo
echo "StrongSwan version:"
swanctl --version
echo

# Show network configuration
echo "Network configuration:"
ip addr show

# Setup logging
mkdir -p /var/log/strongswan
echo "Logging StrongSwan events to /var/log/strongswan/charon.log"

# Keep container running and show logs
echo "Real-time StrongSwan 6.0.2 logs:"
echo "Monitoring multiple log sources..."

# Function to monitor logs
monitor_logs() {
    # Disable strict error handling for log monitoring
    set +e

    while true; do
        # Monitor charon logs from multiple possible locations
        if [ -f /var/log/strongswan/charon.log ]; then
            tail -f /var/log/strongswan/charon.log 2>/dev/null &
        fi

        if [ -f /var/log/syslog ]; then
            tail -f /var/log/syslog 2>/dev/null | grep -E "(charon|ipsec)" &
        fi

        # Monitor daemon logs via journalctl if available
        if command -v journalctl >/dev/null 2>&1; then
            journalctl -f -u strongswan 2>/dev/null &
        fi

        # If no logs available, just sleep
        sleep 60
    done
}

monitor_logs