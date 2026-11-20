# Build stage
FROM node:20-alpine AS base

RUN apk add --no-cache wget

WORKDIR /app

COPY package.json package-lock.json ./

# Install dependencies
RUN npm ci
COPY . .

# Note: version.json will be mounted as a volume in dev or copied during CI build

########################
# Development
########################
FROM base AS dev
COPY --from=base /app /app/

COPY env.sh /usr/local/bin/env.sh
RUN chmod +x /usr/local/bin/env.sh

EXPOSE 80
ENTRYPOINT ["/usr/local/bin/env.sh"]
CMD ["npm", "run", "dev"]

####################
# Production image
####################
FROM base AS bundle
COPY --from=base /app /app/

# public/version.json comes from CI or tools/nemesis-ctl.sh; builds without one get a minimal
# placeholder so the Settings page never requests a missing file
RUN npm run build && \
    if [ ! -f dist/version.json ]; then \
      printf '{"git":{"sha":"unknown","shaShort":"unknown","branch":"unknown","tag":"","dirty":false,"commitTimestamp":"","commitMessage":"","commitAuthor":""},"build":{"timestamp":"%s","source":"unknown"}}\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > dist/version.json; \
    fi


FROM nginx:alpine AS prod
RUN apk add --no-cache wget

COPY --from=bundle /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Create env.js with placeholder for runtime substitution
RUN echo "window.ENV = { HASURA_ADMIN_SECRET: '%HASURA_ADMIN_SECRET%' };" > /usr/share/nginx/html/env.js

EXPOSE 3000

COPY env.sh /usr/local/bin/env.sh
RUN chmod +x /usr/local/bin/env.sh
ENTRYPOINT ["/usr/local/bin/env.sh"]
CMD ["nginx", "-g", "daemon off;"]
