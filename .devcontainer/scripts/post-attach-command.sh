#!/bin/bash

scriptDir="$(dirname "$0")"

echo "Running Post Attach Command script..."
echo ""
echo "Copying Oh My Zsh custom scripts..."

cp -pv "$scriptDir"/omz/* "$HOME/.oh-my-zsh/custom/"
