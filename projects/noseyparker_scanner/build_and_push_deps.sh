#!/bin/bash

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== NoseyParker Dependencies Builder ===${NC}"

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        DOCKER_ARCH="amd64"
        PLATFORM="linux/amd64"
        ;;
    aarch64|arm64)
        DOCKER_ARCH="arm64"
        PLATFORM="linux/arm64"
        ;;
    *)
        echo -e "${RED}Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

echo -e "${GREEN}Detected architecture: $ARCH -> Docker: $DOCKER_ARCH${NC}"

# Prompt for Docker username
read -p "Enter your Docker Hub username: " DOCKER_USERNAME
if [[ -z "$DOCKER_USERNAME" ]]; then
    echo -e "${RED}Docker username cannot be empty${NC}"
    exit 1
fi

REPO="$DOCKER_USERNAME/noseyparker-scanner-deps"
TAG_ARCH="$REPO:$DOCKER_ARCH"
TAG_LATEST="$REPO:latest"

echo -e "${BLUE}Will build and push: $TAG_ARCH${NC}"

# Docker login
echo -e "${YELLOW}Logging into Docker Hub...${NC}"
docker login

# Check if Dockerfile.deps exists
if [[ ! -f "Dockerfile.deps" ]]; then
    echo -e "${RED}Dockerfile.deps not found in current directory${NC}"
    echo -e "${YELLOW}Make sure you're in the project root directory${NC}"
    exit 1
fi

# Build the dependencies image
echo -e "${BLUE}Building dependencies image for $DOCKER_ARCH...${NC}"
echo -e "${YELLOW}This will take a while (compiling Rust dependencies)...${NC}"

docker build \
    --platform "$PLATFORM" \
    -f Dockerfile.deps \
    -t "$TAG_ARCH" \
    .

# Push the architecture-specific image
echo -e "${BLUE}Pushing $TAG_ARCH...${NC}"
docker push "$TAG_ARCH"

echo -e "${GREEN}✓ Successfully built and pushed $TAG_ARCH${NC}"

# Check if both architectures exist (for manifest creation)
echo -e "${BLUE}Checking for multi-arch images...${NC}"

# Function to check if image exists
image_exists() {
    docker manifest inspect "$1" >/dev/null 2>&1
}

AMD64_IMAGE="$REPO:amd64"
ARM64_IMAGE="$REPO:arm64"

AMD64_EXISTS=false
ARM64_EXISTS=false

if image_exists "$AMD64_IMAGE"; then
    AMD64_EXISTS=true
    echo -e "${GREEN}✓ Found amd64 image${NC}"
else
    echo -e "${YELLOW}⚠ amd64 image not found${NC}"
fi

if image_exists "$ARM64_IMAGE"; then
    ARM64_EXISTS=true
    echo -e "${GREEN}✓ Found arm64 image${NC}"
else
    echo -e "${YELLOW}⚠ arm64 image not found${NC}"
fi

# Create multi-arch manifest if both architectures exist
if [[ "$AMD64_EXISTS" == true && "$ARM64_EXISTS" == true ]]; then
    echo -e "${BLUE}Creating multi-arch manifest...${NC}"

    # Remove existing manifest if it exists
    docker manifest rm "$TAG_LATEST" 2>/dev/null || true

    # Create new manifest
    docker manifest create "$TAG_LATEST" \
        --amend "$AMD64_IMAGE" \
        --amend "$ARM64_IMAGE"

    # Annotate architectures
    docker manifest annotate "$TAG_LATEST" "$AMD64_IMAGE" --arch amd64
    docker manifest annotate "$TAG_LATEST" "$ARM64_IMAGE" --arch arm64

    # Push manifest
    docker manifest push "$TAG_LATEST"

    echo -e "${GREEN}✓ Multi-arch manifest created and pushed: $TAG_LATEST${NC}"
    echo -e "${GREEN}✓ You can now use: $TAG_LATEST${NC}"
else
    echo -e "${YELLOW}⚠ Multi-arch manifest not created${NC}"
    echo -e "${YELLOW}  Run this script on both amd64 and arm64 systems to create the manifest${NC}"
    if [[ "$AMD64_EXISTS" == false ]]; then
        echo -e "${YELLOW}  Missing: $AMD64_IMAGE${NC}"
    fi
    if [[ "$ARM64_EXISTS" == false ]]; then
        echo -e "${YELLOW}  Missing: $ARM64_IMAGE${NC}"
    fi
fi

echo -e "${GREEN}=== Build Complete ===${NC}"
echo -e "${BLUE}Architecture-specific image: $TAG_ARCH${NC}"
if [[ "$AMD64_EXISTS" == true && "$ARM64_EXISTS" == true ]]; then
    echo -e "${BLUE}Multi-arch image: $TAG_LATEST${NC}"
fi