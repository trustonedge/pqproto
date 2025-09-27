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

echo "Starting IPsec Server Container (StrongSwan 6.0.2)"
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

# Note: Server will get tunnel IP 10.1.0.1 and clients get IPs from pool 10.2.0.2-10.2.0.100
# Create and configure tunnel interface for server
ip link add name tunnel0 type dummy 2>/dev/null || true
ip addr add 10.1.0.1/32 dev tunnel0 2>/dev/null || true
ip link set tunnel0 up 2>/dev/null || true

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
        local server_cert="/etc/swanctl/x509/server-cert.pem"
        local server_key="/etc/swanctl/private/server-key.pem"

        # Check if certificate files exist
        for cert_file in "$ca_cert" "$server_cert" "$server_key"; do
            if [ ! -f "$cert_file" ]; then
                echo "ERROR: Certificate file not found: $cert_file"
                return 1
            fi
        done

        # Check certificate expiry
        local expiry_date=$(openssl x509 -enddate -noout -in "$server_cert" | cut -d= -f2)
        local expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null || echo "0")
        local current_epoch=$(date +%s)
        local days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))

        if [ "$expiry_epoch" -gt 0 ]; then
            echo "Server certificate expires in $days_until_expiry days ($expiry_date)"

            if [ "$days_until_expiry" -lt 30 ]; then
                echo "WARNING: Server certificate expires in less than 30 days!"
            elif [ "$days_until_expiry" -lt 0 ]; then
                echo "ERROR: Server certificate has expired!"
                return 1
            fi
        fi

        # Verify certificate chain
        if openssl verify -CAfile "$ca_cert" "$server_cert" >/dev/null 2>&1; then
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
echo "Loading server configuration..."
if ! swanctl --load-all; then
    echo "ERROR: Failed to load swanctl configuration"
    echo "Checking configuration file..."
    ls -la /etc/swanctl/swanctl.conf || echo "Configuration file not found"
    exit 1
fi

echo "Configuration loaded successfully"

echo "Server ready and waiting for connections"
echo "Server status:"
if ! swanctl --list-conns; then
    echo "WARNING: Failed to list connections, but continuing..."
fi

echo
echo "To monitor connections:"
echo "   docker exec ipsec-server swanctl --list-sas"
echo
echo "To start test server:"
echo "   docker exec ipsec-server python3 /usr/local/bin/test-server.py"
echo
echo "StrongSwan version:"
swanctl --version
echo

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