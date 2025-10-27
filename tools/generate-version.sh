#!/bin/bash

# Generate version.json with git and build information

OUTPUT_FILE="${1:-version.json}"
BUILD_SOURCE="${2:-local}"

# Get git information
GIT_SHA=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
GIT_SHA_SHORT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
GIT_TAG=$(git describe --tags --exact-match 2>/dev/null || echo "")
GIT_DIRTY=$(git diff --quiet 2>/dev/null || echo "true")

# Check if working directory is clean
if [ -z "$GIT_DIRTY" ]; then
    GIT_DIRTY="false"
else
    GIT_DIRTY="true"
fi

# Get build timestamp
BUILD_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Get last commit timestamp
if [ "$GIT_SHA" != "unknown" ]; then
    COMMIT_TIMESTAMP=$(git log -1 --format=%cI 2>/dev/null || echo "")
    COMMIT_MESSAGE=$(git log -1 --pretty=%B 2>/dev/null | head -n 1 || echo "")
    COMMIT_AUTHOR=$(git log -1 --pretty=format:'%an' 2>/dev/null || echo "")
else
    COMMIT_TIMESTAMP=""
    COMMIT_MESSAGE=""
    COMMIT_AUTHOR=""
fi

# Create JSON output
cat > "$OUTPUT_FILE" <<EOF
{
  "git": {
    "sha": "$GIT_SHA",
    "shaShort": "$GIT_SHA_SHORT",
    "branch": "$GIT_BRANCH",
    "tag": "$GIT_TAG",
    "dirty": $GIT_DIRTY,
    "commitTimestamp": "$COMMIT_TIMESTAMP",
    "commitMessage": "$COMMIT_MESSAGE",
    "commitAuthor": "$COMMIT_AUTHOR"
  },
  "build": {
    "timestamp": "$BUILD_TIMESTAMP",
    "source": "$BUILD_SOURCE"
  }
}
EOF

echo "Version information written to $OUTPUT_FILE"