#!/bin/bash

# Check if the script is being run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root or with sudo privileges."
    exit 1
fi

# Update the package list and upgrade the system
echo "Updating the package list and upgrading the system..."
apt update && apt upgrade -y

# Install prerequisite packages for using packages over HTTPS
echo "Installing prerequisite packages..."
apt install -y apt-transport-https ca-certificates curl software-properties-common gnupg2

# Add the GPG key for the official Docker repository
echo "Adding the GPG key for the official Docker repository..."
curl -fsSL https://download.docker.com/linux/debian/gpg | apt-key add -

# Add the Docker repository to APT sources
echo "Adding the Docker repository to APT sources..."
echo "deb [arch=amd64] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list

# Update the package list again
echo "Updating the package list again..."
apt update

# Install Docker
echo "Installing Docker..."
apt install -y docker-ce

# Ensure Docker starts on boot
echo "Enabling Docker to start on boot..."
systemctl enable docker

# Install Docker Compose
echo "Installing Docker Compose..."
DOCKER_COMPOSE_VERSION="1.29.2"
curl -L "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose

# Grant execution permissions to Docker Compose
chmod +x /usr/local/bin/docker-compose

# Verify Docker Compose installation
echo "Verifying Docker Compose installation..."
docker-compose --version

echo "Docker and Docker Compose have been installed successfully."
