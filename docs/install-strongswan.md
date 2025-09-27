# StrongSwan Deployment

For a more detailed explanation, see the repository: [chmodshubham/strongswan](https://github.com/chmodshubham/strongswan).

## Pre-requisites

```bash
# Install build dependencies
sudo apt update
sudo apt install -y build-essential git wget curl autoconf automake libtool pkg-config \
    gettext bison flex gperf libssl-dev libgmp-dev libcurl4-openssl-dev \
    libsystemd-dev libpam0g-dev libldap2-dev libsqlite3-dev \
    libmysqlclient-dev libpq-dev libxml2-dev libjson-c-dev libcap-dev \
    libiptc-dev libnm-dev libxtables-dev libip4tc-dev libip6tc-dev \
    libnetfilter-conntrack-dev iproute2 iputils-ping net-tools
```

## StrongSwan Installation

```bash
# Download and build StrongSwan latest
mkdir -p ~/strongswan-build/
cd ~/strongswan-build/
wget https://download.strongswan.org/strongswan-6.0.2.tar.bz2 --no-check-certificate
tar xjf strongswan-6.0.2.tar.bz2
cd strongswan-6.0.2

# Configure build
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
    --runstatedir=/var/run --with-systemdsystemunitdir=/lib/systemd/system \
    --disable-defaults --enable-silent-rules --enable-charon \
    --enable-systemd --enable-ikev2 --enable-vici --enable-swanctl \
    --enable-nonce --enable-random --enable-drbg --enable-openssl \
    --enable-curl --enable-pem --enable-x509 --enable-constraints \
    --enable-revocation --enable-pki --enable-pubkey --enable-socket-default \
    --enable-kernel-netlink --enable-resolve --enable-eap-identity \
    --enable-eap-md5 --enable-eap-dynamic --enable-eap-tls --enable-updown \
    --enable-sha2 --enable-pkcs11 --enable-hmac --enable-gcm --enable-mgf1 \
    --enable-aes --enable-des --enable-sha1 --enable-md5 --enable-gmp \
    --enable-stroke

# Compile and install
make -j$(nproc)
sudo make install
sudo ldconfig
```

## Enable IP Forwarding

```bash
# Enable IP forwarding
echo 'net.ipv4.ip_forward = 1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

## Start StrongSwan Service

```bash
# Enable and start strongswan service
sudo systemctl enable strongswan
sudo systemctl start strongswan

# Check status
sudo systemctl status strongswan
```

## Verification Commands

```bash
# Check StrongSwan version
sudo swanctl --version

# Check daemon status
sudo swanctl --stats

# Monitor logs
sudo journalctl -u strongswan -f
```
