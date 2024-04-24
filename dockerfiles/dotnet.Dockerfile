########################
# Common python dependencies layer
########################
FROM python:3.11.2-bullseye AS netbuild
WORKDIR /app/cmd/dotnet

ENV PYTHONUNBUFFERED=1

########################
# Download dependent packages
########################
FROM netbuild AS dependencies

ARG ENVIRONMENT
ENV POETRY_HOME=/opt/poetry
ENV POETRY_VIRTUALENVS_IN_PROJECT=true
ENV PATH="$POETRY_HOME/bin:$PATH"
ENV DEBIAN_FRONTEND=noninteractive
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1

# Install dotnet 6.0
RUN apt-get update \
    # Install prerequisites
    && apt-get install -y --no-install-recommends \
       wget \
       ca-certificates \
    \
    # Install Microsoft package feed
    && wget -q https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb \
    && dpkg -i packages-microsoft-prod.deb \
    && rm packages-microsoft-prod.deb \
    \
    # Install .NET
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       # dotnet-runtime-6.0 \
       dotnet-sdk-6.0 \
    \
    # Cleanup
    && rm -rf /var/lib/apt/lists/*


# install Python
RUN apt-get update -y && apt-get install python3 -y && apt-get install python3-pip -y

RUN pip install poetry==1.8.2

COPY cmd/dotnet/poetry.lock cmd/dotnet/pyproject.toml ./
COPY cmd/dotnet/dotnet/__init__.py ./dotnet/

# install ilspy
RUN dotnet tool install --no-cache ilspycmd --tool-path /usr/local/bin/ --version 7.2.1.6856

# Copy local libraries
COPY packages/python/nemesispb/ /app/packages/python/nemesispb/
COPY packages/python/nemesiscommon/ /app/packages/python/nemesiscommon/

RUN poetry install $(test "$ENVIRONMENT" == production && echo "--no-dev") --no-interaction --no-ansi -vvv

########################
# Base image for building images
########################
FROM dependencies AS build
COPY cmd/dotnet/dotnet/ ./dotnet/

FROM build AS runtime
ENV PATH="/app/cmd/dotnet/.venv/bin:$PATH"

EXPOSE 9800

CMD ["python", "-m", "dotnet"]