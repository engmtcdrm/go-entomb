#!/bin/bash

scriptDir="$(dirname "$0")"

echo "Running Post Attach Command script..."
echo ""
echo "Copying Oh My Zsh custom scripts..."

cp -pv "$scriptDir"/oh-my-zsh/* "$HOME/.oh-my-zsh/custom/"
