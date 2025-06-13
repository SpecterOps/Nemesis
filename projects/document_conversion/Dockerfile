# FROM nemesis-python-base-dev AS base
ARG PYTHON_BASE_DEV_IMAGE=nemesis-python-base-dev
ARG PYTHON_BASE_PROD_IMAGE=nemesis-python-base-prod
FROM ${PYTHON_BASE_DEV_IMAGE} AS base

# Install dependencies in a single RUN command to reduce layers
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openjdk-17-jre-headless \
        wget \
        tesseract-ocr \
        tesseract-ocr-eng \
        libpq-dev \
        postgresql-client \
        binutils && \
    wget https://archive.apache.org/dist/tika/3.1.0/tika-server-standard-3.1.0.jar -O /tika-server-standard.jar && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set JAVA_HOME for JRE
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64/jre

# Copy only what's needed for dependency installation first (leveraging Docker cache)
COPY ./projects/document_conversion/poetry.lock ./projects/document_conversion/pyproject.toml /src/projects/document_conversion/
WORKDIR /src/projects/document_conversion

# Copy remaining files
COPY ./libs /src/libs
COPY ./projects/document_conversion /src/projects/document_conversion/

########################
# Development
########################
FROM base AS dev

# Set environment variables together in one layer
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LOG_LEVEL=DEBUG \
    UVICORN_HOST="0.0.0.0" \
    UVICORN_PORT=8000 \
    UVICORN_RELOAD_DIR="/src/"

RUN poetry install

ENTRYPOINT ["/bin/sh", "-c", " \
    poetry run uvicorn document_conversion.main:app \
    --host ${UVICORN_HOST} \
    --port ${UVICORN_PORT} \
    --reload \
    --reload-dir ${UVICORN_RELOAD_DIR} \
"]

########################
# Runtime - Bundle the app
########################
FROM base AS bundle

RUN poetry bundle venv --python=/usr/bin/python3 --only=main /venv

########################
# Make the final image
########################
# FROM nemesis-python-base-prod AS prod
FROM ${PYTHON_BASE_PROD_IMAGE} AS prod

# Install dependencies in a single RUN command to reduce layers
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openjdk-17-jre-headless \
        wget \
        tesseract-ocr \
        tesseract-ocr-eng \
        libpq-dev \
        postgresql-client \
        binutils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*


ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64/jre \
    LOG_LEVEL=INFO \
    UVICORN_HOST=0.0.0.0 \
    UVICORN_PORT=8000 \
    UVICORN_WORKERS=1 \
    UVICORN_PROXY_HEADERS=1 \
    UVICORN_ACCESS_LOG=false

# Copy only the virtual environment from the bundle stage
COPY --from=bundle /venv /venv
# Copy the Tika JAR from base so we don't download again
COPY --from=base /tika-server-standard.jar /tika-server-standard.jar

# TODO: Re-enable when we're ready for release
# USER nemesis

ENTRYPOINT ["/bin/sh", "-c", "\
    /venv/bin/uvicorn \"document_conversion.main:app\" \
    --host ${UVICORN_HOST} \
    --port ${UVICORN_PORT} \
    --workers ${UVICORN_WORKERS} \
    --proxy-headers \
    --no-access-log \
"]