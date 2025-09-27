# Install Docker on Ubuntu

Follow these commands sequentially to install the latest stable Docker Engine on Ubuntu.

## 1. Update System Packages

```bash
sudo apt update -y
sudo apt upgrade -y
```

## 2. Install Prerequisite Packages

```bash
sudo apt install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release
```

## 3. Add Docker’s Official GPG Key

```bash
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
```

## 4. Set Up the Docker Repository

```bash
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```

## 5. Update Package Index

```bash
sudo apt update -y
```

If you receive a GPG error while running `apt update`, then try granting read permission for the Docker public key file before updating the package index:

```bash
sudo chmod a+r /etc/apt/keyrings/docker.gpg
sudo apt-get update
```

## 6. Install the Latest Docker Engine and Components

```bash
sudo apt install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin
```

## 7. Post-Installation Steps

Allow running Docker without `sudo`:

```bash
sudo usermod -aG docker $USER
sudo chmod 666 /var/run/docker.sock
```

## Verify Installation

Check the Docker version to confirm installation:

```bash
docker version
```
