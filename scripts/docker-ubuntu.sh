#!/bin/bash

# Update the list of available packages
echo "Updating the list of available packages..."
sudo apt update

# Install prerequisite packages for using packages over HTTPS
echo "Installing prerequisite packages..."
sudo apt install -y apt-transport-https ca-certificates curl software-properties-common

# Add the GPG key for the official Docker repository
echo "Adding the GPG key for the official Docker repository..."
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# Add the Docker repository to APT sources
echo "Adding the Docker repository to APT sources..."
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Update the list of available packages again
echo "Updating the list of available packages again..."
sudo apt update

# Verify that Docker will be installed from the official repository
echo "Verifying the Docker package source..."
apt-cache policy docker-ce

# Install Docker
echo "Installing Docker..."
sudo apt install -y docker-ce

# Install Docker Compose
echo "Installing Docker Compose..."
DOCKER_COMPOSE_VERSION="1.29.2"
sudo curl -L "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose

# Grant execution permissions to Docker Compose
sudo chmod +x /usr/local/bin/docker-compose

# Verify Docker Compose installation
echo "Verifying Docker Compose installation..."
docker-compose --version

echo "Docker and Docker Compose have been installed successfully."
