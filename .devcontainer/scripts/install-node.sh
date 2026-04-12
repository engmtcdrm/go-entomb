#!/bin/bash
# This script is needed to install nvm to a specific version for SonarQube to not complain.

# Exit immediately if a command exits with a non-zero status
set -e

# Install nvm (Node Version Manager)
echo "Installing nvm..."
NVM_DIR="$HOME/.nvm"
if [ ! -d "$NVM_DIR" ]; then
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.4/install.sh | bash
else
  echo "nvm is already installed."
fi

# Load nvm into the current shell session
export NVM_DIR="$HOME/.nvm"
source "$NVM_DIR/nvm.sh"  # This loads nvm
source "$NVM_DIR/bash_completion"  # This loads nvm bash_completion

# Install a specific version of Node.js
NODE_VERSION="20.12.0"
echo "Installing Node.js version $NODE_VERSION..."
nvm install $NODE_VERSION

# Set the installed version as the default
nvm alias default $NODE_VERSION
nvm use default

echo "Node.js version $(node -v) installed successfully."
