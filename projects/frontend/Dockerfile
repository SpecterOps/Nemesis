# Build stage
FROM node:20-alpine AS base

RUN apk add --no-cache wget

WORKDIR /app

COPY package.json ./

# Generate package-lock.json and install dependencies
RUN npm install
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

RUN npm run build


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