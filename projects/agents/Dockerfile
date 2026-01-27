# FROM nemesis-python-base-dev AS base
ARG PYTHON_BASE_DEV_IMAGE=nemesis-python-base-dev
ARG PYTHON_BASE_PROD_IMAGE=nemesis-python-base-prod
FROM ${PYTHON_BASE_DEV_IMAGE} AS base

RUN apt-get update && \
    apt-get install -y libpq5 \
    gcc libc6-dev curl wget libicu-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    ARCH=$(dpkg --print-architecture) && \
    wget https://go.dev/dl/go1.25.4.linux-${ARCH}.tar.gz && \
    tar -C /usr/local -xzf go1.25.4.linux-${ARCH}.tar.gz && \
    rm go1.25.4.linux-${ARCH}.tar.gz


# Install genai-toolbox for chatbot MCP functionality
ENV GOPATH=/go \
    PATH=/usr/local/go/bin:/go/bin:$PATH
RUN go install github.com/googleapis/genai-toolbox@v0.18.0


# Install .NET Runtime
ENV DOTNET_ROOT=/usr/local/dotnet \
    PATH=/usr/local/dotnet:$PATH

RUN curl -sSL https://dot.net/v1/dotnet-install.sh | bash /dev/stdin \
    --channel 8.0 \
    --runtime aspnetcore \
    --install-dir /usr/local/dotnet \
    && chmod +x /usr/local/dotnet/dotnet


# If dependencies change, re-copy all the dependencies
# In the future we can be more efficient with this an only copy the lib folders
# that this project uses
COPY ./projects/agents/uv.lock ./projects/agents/pyproject.toml /src/projects/agents/

COPY ./libs /src/libs
COPY ./projects/agents /src/projects/agents/

WORKDIR /src/projects/agents

########################
# Development
########################
FROM base AS dev
COPY --from=base /src /src

WORKDIR /src/projects/agents
RUN uv sync --frozen

# Immediate output (no buffering)
ENV PYTHONUNBUFFERED=1
# No .pyc/pycache files
ENV PYTHONDONTWRITEBYTECODE=1

ENV LOG_LEVEL=DEBUG

ENV UVICORN_HOST="0.0.0.0"
ENV UVICORN_PORT=8000

ENTRYPOINT ["/bin/sh", "-c", " \
    uv run python -m uvicorn agents.main:app \
    --host ${UVICORN_HOST} \
    --port ${UVICORN_PORT} \
    --reload \
    --reload-dir /src/projects/agents/agents \
    --reload-dir /src/libs \
    --reload-include '*.py' \
    "]

########################
# Production
########################
FROM base AS bundle
COPY --from=base /src /src

WORKDIR /src/projects/agents
RUN uv export --frozen --no-dev --no-hashes -o requirements.txt && \
    uv venv /venv --python /usr/local/bin/python3 --seed && \
    /venv/bin/pip install --no-cache-dir -r requirements.txt && \
    /venv/bin/pip install --no-cache-dir /src/libs/common /src/projects/agents

# FROM nemesis-python-base-prod AS prod
FROM ${PYTHON_BASE_PROD_IMAGE} AS prod

# Install runtime dependencies for psycopg and .NET
RUN apt-get update && \
    apt-get install -y libpq5 libicu76 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy .NET runtime from base stage
ENV DOTNET_ROOT=/usr/local/dotnet \
    PATH=/usr/local/dotnet:$PATH
COPY --from=base /usr/local/dotnet /usr/local/dotnet

# Copy genai-toolbox binary from base stage
ENV GOPATH=/go \
    PATH=/go/bin:$PATH
COPY --from=base /go/bin/genai-toolbox /go/bin/genai-toolbox

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
    /venv/bin/uvicorn \"agents.main:app\" \
    --host ${UVICORN_HOST} \
    --port ${UVICORN_PORT} \
    --workers ${UVICORN_WORKERS} \
    --proxy-headers \
    --no-access-log \
    "]
