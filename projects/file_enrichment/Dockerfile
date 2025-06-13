# FROM nemesis-python-base-dev AS base
ARG PYTHON_BASE_DEV_IMAGE=nemesis-python-base-dev
ARG PYTHON_BASE_PROD_IMAGE=nemesis-python-base-prod
FROM ${PYTHON_BASE_DEV_IMAGE} AS base

# If dependencies change, re-copy all the dependencies
# In the future we can be more efficient with this an only copy the lib folders
# that this project uses

RUN apt-get update && \
    apt-get install -y libmagic1 libpq5 \
    gcc libc6-dev curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Rust
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > rustup-init.sh \
    && sh rustup-init.sh -y --no-modify-path --default-toolchain stable \
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

COPY ./projects/file_enrichment/poetry.lock ./projects/file_enrichment/pyproject.toml /src/projects/file_enrichment/

COPY ./libs /src/libs
COPY ./projects/file_enrichment /src/projects/file_enrichment/

WORKDIR /src/projects/file_enrichment

########################
# Development
########################
FROM base AS dev
#COPY --from=base /signature-base /signature-base
COPY --from=base /src /src

WORKDIR /src/projects/file_enrichment
RUN poetry install
# RUN poetry run python /src/libs/file_enrichment_modules/file_enrichment_modules/yara/clean_yara_rules.py \
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

ENV LOG_LEVEL=DEBUG

ENV UVICORN_HOST="0.0.0.0"
ENV UVICORN_PORT=8001
ENV UVICORN_WORKERS=1
ENV UVICORN_RELOAD=true
ENV UVICORN_RELOAD_DIR="/src/"

ENTRYPOINT ["/bin/sh", "-c", " \
    poetry run uvicorn file_enrichment.controller:app \
    --host ${UVICORN_HOST} \
    --port ${UVICORN_PORT} \
    --workers ${UVICORN_WORKERS} \
    --reload \
    --reload-dir ${UVICORN_RELOAD_DIR} \
"]
########################
# Production
########################
FROM dev AS bundle
COPY --from=base /src /src

WORKDIR /src/projects/file_enrichment
RUN poetry bundle venv --python=/usr/bin/python3 --only=main /venv

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
    UVICORN_WORKERS=4 \
    UVICORN_PROXY_HEADERS=1 \
    UVICORN_ACCESS_LOG=false

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
