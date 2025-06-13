#!/bin/bash

# Get the full path to the script
SCRIPT_PATH="$(realpath "$0")"

echo -e "\nTo start Nemesis, run the following:"

if [ -z "$USERS" ] && [ -z "$PASSWORD" ]; then
    echo -e "\n    # No users specified. Default user & pass are both the letter 'n')"

    echo -e "    export ENVIRONMENT=prod"
    echo -e "    docker compose -f docker-compose.base.yml build"
    echo -e "    docker compose -f docker-compose.yml -f docker-compose.prod.yml pull"
    echo -e "    docker compose -f docker-compose.yml -f docker-compose.prod.yml up\n\n"

    echo "To add users, set the USERS (comma-separated) and PASSWORD environment variables and re-run this script."
    echo "Note: All users will share the same password."
    echo -e "Example:\n"
    echo -e "    USERS='alice,bob,carol' PASSWORD='password' $SCRIPT_PATH\n"
    exit 1
fi

# Check if htpasswd is in the system path
if ! command -v htpasswd &> /dev/null; then
    echo "Error: 'htpasswd' command not found. Please install it."
    echo "You can install it using: sudo apt install apache2-utils"
    echo
    exit 1
fi

# Split USERS into an array
IFS=',' read -ra USERS_ARR <<< "$USERS"

# Generate hashed password
hash=$(echo "${PASSWORD}" | htpasswd -nmi n | cut -c3-)

# Create BASIC_AUTH_USERS export string
entries=""
for user in "${USERS_ARR[@]}"; do
    escaped=$(echo "${user}:${hash}")
    entries="${entries}${escaped},"
done

# Output the export statement and docker compose command

echo -e "\n    export ENVIRONMENT=prod"
echo -e "    export BASIC_AUTH_USERS='${entries%,}'"
echo -e "    docker compose -f docker-compose.base.yml build"
echo -e "    docker compose -f docker-compose.yml -f docker-compose.prod.yml pull"
echo -e "    docker compose -f docker-compose.yml -f docker-compose.prod.yml up\n\n"
