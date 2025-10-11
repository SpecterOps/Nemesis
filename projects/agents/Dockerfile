# FROM nemesis-python-base-dev AS base
ARG PYTHON_BASE_DEV_IMAGE=nemesis-python-base-dev
ARG PYTHON_BASE_PROD_IMAGE=nemesis-python-base-prod
FROM ${PYTHON_BASE_DEV_IMAGE} AS base

RUN apt-get update && \
    apt-get install -y libpq5 \
    gcc libc6-dev curl wget libicu-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*


# Install .NET Runtime
ENV DOTNET_ROOT=/usr/local/dotnet \
    PATH=/usr/local/dotnet:$PATH

RUN curl -sSL https://dot.net/v1/dotnet-install.sh | bash /dev/stdin \
    --version latest \
    --runtime aspnetcore \
    --install-dir /usr/local/dotnet \
    && chmod +x /usr/local/dotnet/dotnet


# If dependencies change, re-copy all the dependencies
# In the future we can be more efficient with this an only copy the lib folders
# that this project uses
COPY ./projects/agents/poetry.lock ./projects/agents/pyproject.toml /src/projects/agents/

COPY ./libs /src/libs
COPY ./projects/agents /src/projects/agents/

WORKDIR /src/projects/agents

########################
# Development
########################
FROM base AS dev
COPY --from=base /src /src

WORKDIR /src/projects/agents
RUN poetry install

# Immediate output (no buffering)
ENV PYTHONUNBUFFERED=1
# No .pyc/pycache files
ENV PYTHONDONTWRITEBYTECODE=1

ENV LOG_LEVEL=DEBUG

ENV UVICORN_HOST="0.0.0.0"
ENV UVICORN_PORT=8000
ENV UVICORN_RELOAD_DIR="/src/"

ENTRYPOINT ["/bin/sh", "-c", " \
    poetry run uvicorn agents.main:app \
    --host ${UVICORN_HOST} \
    --port ${UVICORN_PORT} \
    --reload \
    --reload-dir ${UVICORN_RELOAD_DIR} \
    "]

########################
# Production
########################
FROM base AS bundle
COPY --from=base /src /src

WORKDIR /src/projects/agents
RUN poetry bundle venv --python=/usr/bin/python3 --only=main /venv

# FROM nemesis-python-base-prod AS prod
FROM ${PYTHON_BASE_PROD_IMAGE} AS prod

# Install runtime dependencies for psycopg and .NET
RUN apt-get update && \
    apt-get install -y libpq5 libicu72 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy .NET runtime from base stage
ENV DOTNET_ROOT=/usr/local/dotnet \
    PATH=/usr/local/dotnet:$PATH
COPY --from=base /usr/local/dotnet /usr/local/dotnet

COPY --from=bundle /venv /venv


# Uvicorn production settings
ENV UVICORN_HOST=0.0.0.0 \
    UVICORN_PORT=8000 \
    UVICORN_WORKERS=1 \
    UVICORN_PROXY_HEADERS=1 \
    UVICORN_ACCESS_LOG=false

# TODO: Re-enable when we're ready for release
# USER nemesis

ENTRYPOINT ["/bin/sh", "-c", "\
    /venv/bin/uvicorn \"agents.main:app\" \
    --host ${UVICORN_HOST} \
    --port ${UVICORN_PORT} \
    --workers ${UVICORN_WORKERS} \
    --proxy-headers \
    --no-access-log \
    "]