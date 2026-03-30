#!/usr/bin/env bash
# HashAxe clean uninstall script

set -e

echo "🧹 Removing HashAxe installation..."

rm -rf "$HOME/.hashaxe"
rm -f "$HOME/.local/bin/hashaxe"

echo "✅ HashAxe has been fully removed."