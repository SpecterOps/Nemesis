#!/usr/bin/env bash
set -e

# Get the absolute path to the project root (one level up from the tools folder)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"

# Directories to check
TARGET_DIRS=("$BASE_DIR/libs" "$BASE_DIR/projects")

echo "🚀 Starting Poetry installation scan..."
echo "Project root: $BASE_DIR"

for dir in "${TARGET_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        echo ""
        echo "🔍 Scanning: $dir"
        # Find directories that contain a pyproject.toml file
        find "$dir" -type f -name "pyproject.toml" | while read -r file; do
            proj_dir=$(dirname "$file")
            echo ""
            echo ">>> Installing dependencies for: $proj_dir"
            (
                cd "$proj_dir"
                poetry install
            )
        done
    else
        echo "⚠️  Directory not found: $dir"
    fi
done

echo ""
echo "✅ All Poetry projects processed successfully!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🧩 VS Code environment cache cleanup recommended:"
echo ""
echo "1️⃣  In VS Code, open the Command Palette (Ctrl+Shift+P / Cmd+Shift+P)"
echo "2️⃣  Run:  Python: Clear Cache and Reload Window"
echo ""
echo "If VS Code still behaves oddly, you can also run:"
echo "   rm -rf ~/.config/Code/User/workspaceStorage/*/workspace.json"
echo ""
echo "This clears stale Python environment cache across workspaces."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
