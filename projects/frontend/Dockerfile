# Build stage
FROM node:24.22.3-alpine AS base

RUN apk add --no-cache wget

WORKDIR /app

COPY package.json package-lock.json ./

# Install dependencies
RUN npm ci
# public/version.json carries a build timestamp, so it changes on every build: leaving it out here keeps the bundle
# cached; the prod image adds it last (dev mounts it as a volume)
COPY --exclude=public/version.json . .

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

# A minimal placeholder version.json so the Settings page never requests a missing file; the prod stage replaces it
# with public/version.json (from CI or tools/nemesis-ctl.sh) when there is one
RUN npm run build && \
    printf '{"git":{"sha":"unknown","shaShort":"unknown","branch":"unknown","tag":"","dirty":false,"commitTimestamp":"","commitMessage":"","commitAuthor":""},"build":{"timestamp":"%s","source":"unknown"}}\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > dist/version.json


FROM nginx:1.31.10-alpine AS prod
RUN apk add --no-cache wget

COPY --from=bundle /app/dist /usr/share/nginx/html
# The glob copies nothing (no error) when the file is absent, keeping the placeholder
COPY public/version.jso[n] /usr/share/nginx/html/
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 3000

CMD ["nginx", "-g", "daemon off;"]
