#!/bin/bash

# Script Name: setup-debian-env.sh
# Description: Sets up a Python virtual environment and installs necessary dependencies.

# Check if the script is being run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root or with sudo privileges."
    exit 1
fi

# Detect the operating system
if [ -f /etc/debian_version ]; then
    OS="Debian"
else
    echo "Unsupported operating system. This script is only compatible with Debian."
    exit 1
fi

# Function to configure sources.list for Debian 12
configure_sources_list_debian() {
    echo "Configuring sources.list for Debian 12..."
    cat <<EOF >/etc/apt/sources.list
deb http://deb.debian.org/debian/ bookworm main non-free-firmware contrib non-free
deb-src http://deb.debian.org/debian/ bookworm main non-free-firmware contrib non-free

deb http://security.debian.org/debian-security bookworm-security main non-free-firmware contrib non-free
deb-src http://security.debian.org/debian-security bookworm-security main non-free-firmware contrib non-free

deb http://deb.debian.org/debian/ bookworm-updates main non-free-firmware contrib non-free
deb-src http://deb.debian.org/debian/ bookworm-updates main non-free-firmware contrib non-free
EOF
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 0E98404D386FA1D9
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 6ED0E7B82643E131
    apt update
}

# Function to install build tools and Python 3.11 on Debian
install_build_tools_and_python() {
    echo "Installing build tools and Python 3.11 on Debian..."
    configure_sources_list_debian
    apt update
    # Install required build tools
    apt install -y build-essential autoconf gcc python3.11 python3.11-venv python3.11-dev
}

# Install Python 3.11 and build tools on Debian
if [ "$OS" = "Debian" ]; then
    install_build_tools_and_python
else
    echo "Unsupported operating system."
    exit 1
fi

# Check if the python3.11 command exists
if ! command -v python3.11 &> /dev/null; then
    echo "Python 3.11 is not installed. Please install it before continuing."
    exit 1
fi

# Change to the project root directory
PROJECT_ROOT="$(dirname "$(dirname "$(realpath "$0")")")"
cd "$PROJECT_ROOT"

# Create the virtual environment in the project root directory
echo "Creating the virtual environment in $PROJECT_ROOT/venv..."
python3.11 -m venv venv

# Activate the virtual environment
echo "Activating the virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies from the requirements.txt file in the project root directory
if [ -f requirements.txt ]; then
    echo "Installing dependencies from requirements.txt..."
    pip install --force-reinstall -r requirements.txt
    pip install --upgrade tenacity
else
    echo "The requirements.txt file is not found. Please ensure it exists in the project root directory."
    deactivate
    exit 1
fi

# Ensure mega.py is up to date to prevent RSA public exponent error
echo "Upgrading mega.py to ensure compatibility..."
pip install --upgrade mega.py

echo "The virtual environment has been set up and dependencies have been installed successfully."
