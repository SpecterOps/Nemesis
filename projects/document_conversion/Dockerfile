# FROM nemesis-python-base-dev AS base
ARG PYTHON_BASE_DEV_IMAGE=nemesis-python-base-dev
ARG PYTHON_BASE_PROD_IMAGE=nemesis-python-base-prod
FROM ${PYTHON_BASE_DEV_IMAGE} AS base

ARG TIKA_OCR_LANGUAGES="eng"
ARG TIKA_VERSION="3.2.3"

# Install dependencies including multiple Tesseract language packs
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openjdk-17-jre-headless \
        wget \
        tesseract-ocr \
        libpq-dev \
        postgresql-client \
        binutils \
        imagemagick \
        # Install fonts for better CJK support
        fonts-noto-cjk \
        fonts-noto-color-emoji && \
    # Install Tesseract language packs dynamically
    for lang in ${TIKA_OCR_LANGUAGES}; do \
        apt-get install -y --no-install-recommends tesseract-ocr-${lang} || echo "Warning: Failed to install tesseract-ocr-${lang}"; \
    done && \
    # Download Tika server
    wget https://archive.apache.org/dist/tika/${TIKA_VERSION}/tika-server-standard-${TIKA_VERSION}.jar -O /tika-server-standard.jar && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set JAVA_HOME for JRE
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk
ENV PATH="$JAVA_HOME/bin:$PATH"

# Copy only what's needed for dependency installation first (leveraging Docker cache)
COPY ./projects/document_conversion/uv.lock ./projects/document_conversion/pyproject.toml /src/projects/document_conversion/
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
    UVICORN_PORT=8000

RUN uv sync --frozen

ENTRYPOINT ["/bin/sh", "-c", " \
    uv run python -m uvicorn document_conversion.main:app \
    --host ${UVICORN_HOST} \
    --port ${UVICORN_PORT} \
    --reload \
    --reload-dir /src/projects/document_conversion/document_conversion \
    --reload-dir /src/libs \
    --reload-include '*.py' \
"]

########################
# Runtime - Bundle the app
########################
FROM base AS bundle

RUN uv export --frozen --no-dev --no-hashes -o requirements.txt && \
    uv venv /venv --python /usr/local/bin/python3 --seed && \
    /venv/bin/pip install --no-cache-dir -r requirements.txt

########################
# Make the final image
########################
# FROM nemesis-python-base-prod AS prod
FROM ${PYTHON_BASE_PROD_IMAGE} AS prod

ARG TIKA_OCR_LANGUAGES="eng"

# Install dependencies in a single RUN command to reduce layers
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openjdk-17-jre-headless \
        wget \
        tesseract-ocr \
        libpq-dev \
        postgresql-client \
        binutils \
        imagemagick \
        # Install fonts for better CJK support
        fonts-noto-cjk \
        fonts-noto-color-emoji && \
    # Install Tesseract language packs dynamically
    for lang in ${TIKA_OCR_LANGUAGES}; do \
        apt-get install -y --no-install-recommends tesseract-ocr-${lang} || echo "Warning: Failed to install tesseract-ocr-${lang}"; \
    done && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*


ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk
ENV PATH="$JAVA_HOME/bin:$PATH" \
    LOG_LEVEL=INFO \
    UVICORN_HOST=0.0.0.0 \
    UVICORN_PORT=8000 \
    UVICORN_PROXY_HEADERS=1 \
    UVICORN_WORKERS=1 \
    UVICORN_ACCESS_LOG=false \
    UVICORN_LOG_LEVEL=info

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
