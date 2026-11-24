# Build stage
FROM node:24.22.3-alpine AS base

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

EXPOSE 80
CMD ["npm", "run", "dev"]

####################
# Production image
####################
FROM base AS bundle
COPY --from=base /app /app/

# Bundling Monaco with sourcemaps outgrows Node's default ~2 GB heap
ENV NODE_OPTIONS=--max-old-space-size=4096

# public/version.json comes from CI or tools/nemesis-ctl.sh; builds without one get a minimal
# placeholder so the Settings page never requests a missing file
RUN npm run build && \
    if [ ! -f dist/version.json ]; then \
      printf '{"git":{"sha":"unknown","shaShort":"unknown","branch":"unknown","tag":"","dirty":false,"commitTimestamp":"","commitMessage":"","commitAuthor":""},"build":{"timestamp":"%s","source":"unknown"}}\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > dist/version.json; \
    fi


FROM nginx:1.31.10-alpine AS prod
RUN apk add --no-cache wget

COPY --from=bundle /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 3000

CMD ["nginx", "-g", "daemon off;"]
