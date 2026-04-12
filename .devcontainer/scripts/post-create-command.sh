#!/bin/zsh

echo "Running Post Create Command script..."

scriptPath="$(dirname "$0")"

installNodeScript="$scriptPath/install-node.sh"

if [ -f "$installNodeScript" ]; then
  echo "Running Node.js installation script..."
  source "$installNodeScript"
else
  echo "Node.js installation script not found at $installNodeScript"
fi
