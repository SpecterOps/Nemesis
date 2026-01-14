# This is the development image for python projects
# It is a slim image with dev tools/programs installed
FROM python:3.12.3-slim

RUN apt-get update && \
    apt-get install --no-install-suggests --no-install-recommends --yes \
    wget curl procps net-tools htop jq iputils-ping git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install uv from official image
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1

WORKDIR /src
