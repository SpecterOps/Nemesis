#!/usr/bin/env bash
set -e

# Get the absolute path to the project root (one level up from the tools folder)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"

cd "$BASE_DIR"

# Deactivate any active virtual environment so it doesn't interfere
if [ -n "$VIRTUAL_ENV" ]; then
    PATH="$(echo "$PATH" | tr ':' '\n' | grep -Fv "$VIRTUAL_ENV" | paste -sd ':')"
    unset VIRTUAL_ENV
fi

# Check that ruff is available via uvx
if ! command -v uvx &> /dev/null; then
    echo "Error: 'uvx' not found. Install uv first:"
    echo "  curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

if ! uvx ruff version &> /dev/null; then
    echo "Error: 'ruff' could not be run via uvx."
    echo "  Try: uvx ruff version"
    echo "  Or install ruff directly: uv tool install ruff@latest"
    exit 1
fi

echo "Running ruff check with --fix..."
uvx ruff check . --fix

echo ""
echo "Running ruff format..."
uvx ruff format .

# Check that pyright is available in at least one project
PYRIGHT_FOUND=0
for config in $(find "$BASE_DIR/projects" "$BASE_DIR/libs" -name "pyrightconfig.json" -maxdepth 2 2>/dev/null); do
    PROJECT_DIR="$(dirname "$config")"
    if (cd "$PROJECT_DIR" && uv run pyright --version &> /dev/null); then
        PYRIGHT_FOUND=1
        break
    fi
done
if [ "$PYRIGHT_FOUND" -eq 0 ]; then
    echo "Error: 'pyright' not found in any project's dev dependencies."
    echo "  Add pyright to your project's [dependency-groups] dev and run: uv sync"
    exit 1
fi

echo ""
echo "Running pyright type checking..."
PYRIGHT_FAILED=0
for config in $(find "$BASE_DIR/projects" "$BASE_DIR/libs" -name "pyrightconfig.json" -maxdepth 2 2>/dev/null); do
    PROJECT_DIR="$(dirname "$config")"
    PROJECT_NAME="$(basename "$PROJECT_DIR")"
    echo "  Checking $PROJECT_NAME..."
    if (cd "$PROJECT_DIR" && uv run pyright); then
        echo "  $PROJECT_NAME: passed"
    else
        echo "  $PROJECT_NAME: failed"
        PYRIGHT_FAILED=1
    fi
done

if [ "$PYRIGHT_FAILED" -eq 1 ]; then
    echo ""
    echo "Pyright type checking failed."
    exit 1
fi

echo ""
echo "Linting, formatting, and type checking complete."
