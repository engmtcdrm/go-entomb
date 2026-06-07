#!/bin/bash

workspaceFolder=${WORKSPACE_FOLDER:-$(pwd)}

echo "Generating documentation for the project at $workspaceFolder..."
gomarkdoc -v "$workspaceFolder" --config "$workspaceFolder/.gomarkdoc.yml" -o "$workspaceFolder/README.md"

echo ""
echo "Generating documentation for the 'crypt' package..."
gomarkdoc -v "$workspaceFolder/crypt" --config "$workspaceFolder/.gomarkdoc.yml" -o "$workspaceFolder/crypt/README.md"

echo ""
echo "Generating documentation for the 'internal/testutils' package..."
gomarkdoc -v "$workspaceFolder/internal/testutils" --config "$workspaceFolder/.gomarkdoc.yml" -o "$workspaceFolder/internal/testutils/README.md"
