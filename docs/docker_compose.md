# Deploying Nemesis with Docker Compose
In general, we recommend that people use the `./tools/nemesis-ctl.sh` script to deploy Nemesis. However, more complex deployment scenarios will require understanding how to deploy Nemesis components manually using Docker Compose. The documentation below details how you can launch Nemesis in a variety

# Use Published Production Docker Images
## Step 1 - Configure environment variables
cp env.example .env
vim .env

## Step 2 - Pull and start the images
The examples below show various ways you can pull and start Nemesis.

**Example 1: Start production images (no monitoring/jupyter)**
```bash
docker compose -f compose.yaml up -d
```

**Example 2: Start production images + monitoring**
```bash
NEMESIS_MONITORING=enabled \
docker compose \
  -f compose.yaml \
  --profile monitoring \
  up -d
```

**Example 3: Start production images + monitoring + jupyter**
```bash
NEMESIS_MONITORING=enabled \
docker compose \
  -f compose.yaml \
  -f compose.prod.build.yaml \
  --profile monitoring \
  --profile jupyter
  up -d
```


# Building and Using Production Images Locally

**Step 1 - Build base images**
```bash
docker compose -f compose.base.yaml build
```

## Step 2 - Build & then start production images
**Example 4: Build & then start production images without monitoring/jupyter**
```bash
docker compose \
  -f compose.yaml \
  -f compose.prod.build.yaml \
  up --build -d
```

**Example 5: Build & then start production images with monitoring**
```bash
NEMESIS_MONITORING=enabled \
docker compose \
  -f compose.yaml \
  -f compose.prod.build.yaml \
  --profile monitoring \
  up --build -d
```


# Building and Using Development Images
Development images are not published and must be built locally. The instructions below detail how.

## Step 1 - Configure environment variables
```bash
cp env.example .env
vim .env
```

## Step 2 - Build base images
```bash
docker compose -f compose.base.yaml build
```

## Step 3 - Build and start dev images
**Example 6: Build and start dev images (implicitly merges compose.yaml and compose.override.yaml)**
```bash
docker compose up -d
```

**Example 7: Build and start dev images with monitoring + jupyter**
```bash
NEMESIS_MONITORING=enabled \
docker compose \
  --profile monitoring \
  --profile jupyter \
  up -d
```