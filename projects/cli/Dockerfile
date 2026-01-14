ARG PYTHON_BASE_DEV_IMAGE=nemesis-python-base-dev
ARG PYTHON_BASE_PROD_IMAGE=nemesis-python-base-prod
FROM ${PYTHON_BASE_DEV_IMAGE} AS base

# Install build dependencies needed for plyvel and other native packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        libleveldb-dev \
        libleveldb1d \
        pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# If dependencies change, re-copy all the dependencies
# In the future we can be more efficient with this an only copy the lib folders
# that this project uses
COPY ./projects/cli/uv.lock ./projects/cli/pyproject.toml /src/projects/cli/

COPY ./libs /src/libs
COPY ./projects/cli /src/projects/cli/

WORKDIR /src/projects/cli

########################
# Development
########################
FROM base AS dev
COPY --from=base /src /src

WORKDIR /src/projects/cli
RUN uv sync --frozen

# Immediate output (no buffering)
ENV PYTHONUNBUFFERED=1
# No .pyc/pycache files
ENV PYTHONDONTWRITEBYTECODE=1

ENV LOG_LEVEL=DEBUG

ENTRYPOINT ["uv", "run", "python", "-m", "cli"]

########################
# Production
########################
FROM base AS bundle
COPY --from=base /src /src

WORKDIR /src/projects/cli
RUN uv export --frozen --no-dev --no-hashes -o requirements.txt && \
    uv venv /venv --python /usr/local/bin/python3 --seed && \
    /venv/bin/pip install --no-cache-dir -r requirements.txt && \
    /venv/bin/pip install --no-cache-dir /src/libs/common /src/projects/cli

FROM ${PYTHON_BASE_PROD_IMAGE} AS prod

# Install ONLY runtime dependencies for plyvel (not build dependencies)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libleveldb1d && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=bundle /venv /venv

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV LOG_LEVEL=INFO

ENTRYPOINT ["/venv/bin/python", "-m", "cli"]
