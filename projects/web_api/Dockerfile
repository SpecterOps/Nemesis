# FROM nemesis-python-base-dev AS base
ARG PYTHON_BASE_DEV_IMAGE=nemesis-python-base-dev
ARG PYTHON_BASE_PROD_IMAGE=nemesis-python-base-prod
FROM ${PYTHON_BASE_DEV_IMAGE} AS base

# Install dependencies in a single RUN command to reduce layers
# Added build-essential and other build dependencies for pytsk3
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        libpq-dev \
        libtsk-dev \
        postgresql-client \
        build-essential \
        gcc \
        g++ \
        make \
        autoconf \
        automake \
        libtool \
        pkg-config \
        python3-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# If dependencies change, re-copy all the dependencies
# In the future we can be more efficient with this an only copy the lib folders
# that this project uses
COPY ./projects/web_api/poetry.lock ./projects/web_api/pyproject.toml /src/projects/web_api/

COPY ./libs /src/libs
COPY ./projects/web_api /src/projects/web_api/

WORKDIR /src/projects/web_api

########################
# Development
########################
FROM base AS dev
COPY --from=base /src /src

WORKDIR /src/projects/web_api
RUN poetry install

# Immediate output (no buffering)
ENV PYTHONUNBUFFERED=1
# No .pyc/pycache files
ENV PYTHONDONTWRITEBYTECODE=1

ENV LOG_LEVEL=DEBUG

ENV UVICORN_HOST="0.0.0.0"
ENV UVICORN_PORT=8000
ENV UVICORN_WORKERS=1
ENV UVICORN_RELOAD_DIR="/src/"

ENTRYPOINT ["/bin/sh", "-c", " \
    poetry run uvicorn web_api.main:app \
    --host ${UVICORN_HOST} \
    --port ${UVICORN_PORT} \
    --workers ${UVICORN_WORKERS} \
    --reload \
    --reload-dir ${UVICORN_RELOAD_DIR} \
    "]

########################
# Production
########################
FROM base AS bundle
COPY --from=base /src /src

WORKDIR /src/projects/web_api
RUN poetry bundle venv --python=/usr/bin/python3 --only=main /venv

FROM ${PYTHON_BASE_PROD_IMAGE} AS prod

RUN apt-get update && \
    apt-get install -y \
       libpq5 \
         && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=bundle /venv /venv

# Uvicorn production settings
ENV UVICORN_HOST=0.0.0.0 \
    UVICORN_PORT=8000 \
    UVICORN_PROXY_HEADERS=1 \
    UVICORN_WORKERS=1 \
    UVICORN_ACCESS_LOG=false \
    UVICORN_LOG_LEVEL=info

# TODO: Re-enable when we're ready for release
# USER nemesis

ENTRYPOINT ["/bin/sh", "-c", "\
    /venv/bin/uvicorn \"web_api.main:app\" \
    --host ${UVICORN_HOST} \
    --port ${UVICORN_PORT} \
    --workers ${UVICORN_WORKERS} \
    --proxy-headers \
    --no-access-log \
    "]