#!/bin/bash

# Script Name: setup-ubuntu-env.sh
# Description: Sets up a Python virtual environment and installs necessary dependencies.

# Ensure you have pip and necessary tools
sudo apt-get update
sudo apt-get install -y python3-pip python3-venv

# Change to the project root directory
PROJECT_ROOT="$(dirname "$(dirname "$(realpath "$0")")")"
cd "$PROJECT_ROOT"

# Create the virtual environment in the project root directory
echo "Creating the virtual environment in $PROJECT_ROOT/venv..."
python3 -m venv venv

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

# Ensure mega.py is installed and updated
echo "Upgrading mega.py..."
pip install --upgrade mega.py

# Check if mega.py was installed correctly
if pip show mega.py > /dev/null 2>&1; then
    echo "mega.py installed and updated successfully."
else
    echo "Error: mega.py could not be installed or updated."
    deactivate
    exit 1
fi

echo "The virtual environment has been set up and dependencies have been installed successfully."
