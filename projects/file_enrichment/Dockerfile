# FROM nemesis-python-base-dev AS base
ARG PYTHON_BASE_DEV_IMAGE=nemesis-python-base-dev
ARG PYTHON_BASE_PROD_IMAGE=nemesis-python-base-prod
FROM ${PYTHON_BASE_DEV_IMAGE} AS base

# If dependencies change, re-copy all the dependencies
# In the future we can be more efficient with this an only copy the lib folders
# that this project uses

RUN apt-get update && \
    apt-get install -y libmagic1 libpq5 binutils \
    gcc g++ libc6-dev curl pkg-config make \
    autoconf automake autopoint libtool \
    python3-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Rust
# Pin to a specific version for reproducibility
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    RUST_VERSION=1.83.0

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > rustup-init.sh \
    && sh rustup-init.sh -y --no-modify-path --default-toolchain ${RUST_VERSION} \
    && rm rustup-init.sh \
    && chmod -R a+w $RUSTUP_HOME $CARGO_HOME


# Clone our base Yara rules
#   License: Detection Rule License (DRL) 1.1 - https://github.com/Neo23x0/signature-base/blob/master/LICENSE
# Set a specific commit for the rule base in case someone changes the license
#   Commit date - March 2, 2024
# ENV YARA_COMMIT=cd7651d2ccf4158a35a8d1cc0441928f7d92818f
# RUN wget -nv -O /tmp/signature-base.tar.gz https://github.com/Neo23x0/signature-base/archive/${YARA_COMMIT}.tar.gz && \
#     tar -xzf /tmp/signature-base.tar.gz -C / && \
#     mv /signature-base-${YARA_COMMIT} /signature-base && \
#     rm /tmp/signature-base.tar.gz

# Copy dependency files first for better caching
# This layer will only rebuild if pyproject.toml or uv.lock files change
COPY ./projects/file_enrichment/uv.lock ./projects/file_enrichment/pyproject.toml /src/projects/file_enrichment/

# Copy all libs (needed for local path dependencies in pyproject.toml)
# uv needs the full lib code to resolve path dependencies
COPY ./libs /src/libs

WORKDIR /src/projects/file_enrichment

# Install all dependencies including local libs
# This layer is cached unless uv.lock or lib dependencies change
RUN uv sync --frozen --no-install-project

# Copy the project source code last
# Changes to project code won't invalidate the dependency cache above
COPY ./projects/file_enrichment /src/projects/file_enrichment/

# Install the project itself in editable mode (fast since dependencies are already installed)
# This ensures the project is importable and uv run commands work
RUN uv sync --frozen

# Pre-download Presidio's spaCy model (~400MB) to avoid runtime delay
# Install pip first (uv doesn't include it by default), then download the model
RUN uv pip install pip && uv run python -m spacy download en_core_web_lg

########################
# Development
########################
FROM base AS dev
#COPY --from=base /signature-base /signature-base

WORKDIR /src/projects/file_enrichment
# RUN uv run python /src/libs/file_enrichment_modules/file_enrichment_modules/yara/clean_yara_rules.py \
#     -i /signature-base/ \
#     -o /src/libs/file_enrichment_modules/file_enrichment_modules/yara/signature-base.yara

# Make a dir
ENV YARA_RULES_FOLDER_PATH=/yara_rules/
RUN mkdir -p /yara_rules/
#    cp /src/libs/file_enrichment_modules/yara_rules/dev.yara /yara_rules/

# Immediate output (no buffering)
ENV PYTHONUNBUFFERED=1
# No .pyc/pycache files
ENV PYTHONDONTWRITEBYTECODE=1

ENV PYTHONDEVMODE=1
ENV PYTHONASYNCIODEBUG=1

ENV LOG_LEVEL=DEBUG

ENV UVICORN_HOST="0.0.0.0"
ENV UVICORN_PORT=8001
ENV UVICORN_WORKERS=1

ENTRYPOINT ["/bin/sh", "-c", " \
    uv run python -m uvicorn file_enrichment.controller:app \
    --host ${UVICORN_HOST} \
    --port ${UVICORN_PORT} \
    --workers ${UVICORN_WORKERS} \
    --reload \
    --reload-dir /src/projects/file_enrichment/file_enrichment \
    --reload-dir /src/libs \
    --reload-include '*.py' \
    "]
########################
# Production
########################
FROM base AS bundle

WORKDIR /src/projects/file_enrichment
RUN uv export --frozen --no-dev --no-hashes -o requirements.txt && \
    uv venv /venv --python /usr/local/bin/python3 && \
    /venv/bin/python -m ensurepip --default-pip && \
    /venv/bin/pip install --no-cache-dir -r requirements.txt && \
    /venv/bin/pip install --no-cache-dir \
        /src/libs/common \
        /src/libs/chromium \
        /src/libs/nemesis_dpapi \
        /src/libs/file_linking \
        /src/libs/file_enrichment_modules \
        /src/projects/file_enrichment && \
    /venv/bin/pip uninstall -y pip setuptools && \
    find /venv -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true

# FROM nemesis-python-base-prod AS prod
FROM ${PYTHON_BASE_PROD_IMAGE} AS prod

RUN apt-get update && \
    apt-get install -y \
    libmagic1 libpq5 \
    binutils \
    && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy the cleaned rules from the dev image
COPY --from=bundle /venv /venv

ENV YARA_RULES_FOLDER_PATH=/yara_rules/
RUN mkdir -p /yara_rules/

# Uvicorn production settings
ENV UVICORN_HOST=0.0.0.0 \
    UVICORN_PORT=8001 \
    UVICORN_PROXY_HEADERS=1 \
    UVICORN_WORKERS=1 \
    UVICORN_ACCESS_LOG=false \
    UVICORN_LOG_LEVEL=info


# TODO: Re-enable when we're ready for release
# USER nemesis

ENTRYPOINT ["/bin/sh", "-c", "\
    /venv/bin/uvicorn \"file_enrichment.controller:app\" \
    --host ${UVICORN_HOST} \
    --port ${UVICORN_PORT} \
    --workers ${UVICORN_WORKERS} \
    --proxy-headers \
    --no-access-log \
    "]
