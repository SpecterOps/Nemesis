#!/bin/sh

# Replace the placeholder with actual env variable
# Check if we're in dev mode (source files) or prod mode (built files)
if [ -f "/usr/share/nginx/html/env.js" ]; then
    # Production mode - files are served by nginx from /usr/share/nginx/html/
    sed -i "s/%HASURA_ADMIN_SECRET%/$HASURA_ADMIN_SECRET/g" /usr/share/nginx/html/env.js
elif [ -f "/app/public/env.js" ]; then
    # Development mode - files are served from /app/public/
    sed -i "s/%HASURA_ADMIN_SECRET%/$HASURA_ADMIN_SECRET/g" /app/public/env.js
fi

# Start your server
exec "$@"