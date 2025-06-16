# FROM nemesis-python-base-dev AS base
ARG PYTHON_BASE_DEV_IMAGE=nemesis-python-base-dev
ARG PYTHON_BASE_PROD_IMAGE=nemesis-python-base-prod
ARG INSPECT_ASSEMBLY_IMAGE=nemesis-inspect-assembly

FROM ${INSPECT_ASSEMBLY_IMAGE} AS inspect-assembly

FROM ${PYTHON_BASE_DEV_IMAGE} AS base

ENV DOTNET_CLI_TELEMETRY_OPTOUT=1

# Install dotnet 6.0
# - libicu72 is required for dotnet 6.0 (see https://stackoverflow.com/a/61661331)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    ca-certificates \
    apt-transport-https \
    gnupg \
    libicu72 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install .NET SDK using Microsoft's script
RUN wget https://dot.net/v1/dotnet-install.sh
RUN chmod +x dotnet-install.sh
RUN ./dotnet-install.sh --version 6.0.418 --install-dir /usr/share/dotnet
RUN ln -s /usr/share/dotnet/dotnet /usr/bin/dotnet
RUN rm dotnet-install.sh

# Install ilspy where any user can access it
RUN mkdir -p /opt/dotnet/tools && \
    chmod 755 /opt/dotnet/tools

ENV DOTNET_TOOL_PATH=/opt/dotnet/tools
RUN dotnet tool install --no-cache ilspycmd --tool-path /opt/dotnet/tools --version 7.2.1.6856

ENV PATH="${PATH}:/opt/dotnet/tools"

# If dependencies change, re-copy all the dependencies
# In the future we can be more efficient with this an only copy the lib folders
# that this project uses
COPY ./projects/dotnet_api/poetry.lock ./projects/dotnet_api/pyproject.toml /src/projects/dotnet_api/

COPY ./libs /src/libs
COPY ./projects/dotnet_api /src/projects/dotnet_api/

WORKDIR /src/projects/dotnet_api

########################
# Development
########################
FROM base AS dev

# First copy source files
COPY --from=base /src /src

# Now copy from the separately defined inspect-assembly stage
COPY --from=inspect-assembly /app/ /opt/InspectAssembly

WORKDIR /src/projects/dotnet_api
RUN poetry install

# Immediate output (no buffering)
ENV PYTHONUNBUFFERED=1
# No .pyc/pycache files
ENV PYTHONDONTWRITEBYTECODE=1

ENV LOG_LEVEL=DEBUG

ENV UVICORN_HOST="0.0.0.0"
ENV UVICORN_PORT=1337
ENV UVICORN_RELOAD_DIR="/src/"

ENTRYPOINT ["/bin/sh", "-c", " \
    poetry run uvicorn dotnet_api.main:app \
    --host ${UVICORN_HOST} \
    --port ${UVICORN_PORT} \
    --reload \
    --reload-dir ${UVICORN_RELOAD_DIR} \
"]

########################
# Runtime
########################
# Bundle the app
FROM base AS bundle
COPY --from=base /src /src

WORKDIR /src/projects/dotnet_api
RUN poetry bundle venv --python=/usr/bin/python3 --only=main /venv

########################
# Make the final image
########################
FROM ${PYTHON_BASE_PROD_IMAGE} AS prod

# Copy from the inspect-assembly stage defined at the top
COPY --from=inspect-assembly /app/ /opt/InspectAssembly

ENV DOTNET_CLI_TELEMETRY_OPTOUT=1

# Install dotnet 6.0
# - libicu72 is required for dotnet 6.0 (see https://stackoverflow.com/a/61661331)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    ca-certificates \
    apt-transport-https \
    gnupg \
    libicu72 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install .NET SDK using Microsoft's script
RUN wget https://dot.net/v1/dotnet-install.sh
RUN chmod +x dotnet-install.sh
RUN ./dotnet-install.sh --version 6.0.418 --install-dir /usr/share/dotnet
RUN ln -s /usr/share/dotnet/dotnet /usr/bin/dotnet
RUN rm dotnet-install.sh

# Install ilspy where any user can access it
RUN mkdir -p /opt/dotnet/tools && \
    chmod 755 /opt/dotnet/tools

ENV DOTNET_TOOL_PATH=/opt/dotnet/tools
RUN dotnet tool install --no-cache ilspycmd --tool-path /opt/dotnet/tools --version 7.2.1.6856

ENV PATH="${PATH}:/opt/dotnet/tools"

# TODO: Re-enable when we're ready for release
# USER nemesis

COPY --from=bundle /venv /venv

# Uvicorn production settings
ENV UVICORN_HOST=0.0.0.0 \
    UVICORN_PORT=1337 \
    UVICORN_WORKERS=1 \
    UVICORN_PROXY_HEADERS=1 \
    UVICORN_ACCESS_LOG=false

ENTRYPOINT ["/bin/sh", "-c", "\
    /venv/bin/uvicorn \"dotnet_api.main:app\" \
    --host ${UVICORN_HOST} \
    --port ${UVICORN_PORT} \
    --workers ${UVICORN_WORKERS} \
    --proxy-headers \
    --no-access-log \
"]