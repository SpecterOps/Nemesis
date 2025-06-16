# FROM nemesis-python-base-dev AS base
ARG PYTHON_BASE_DEV_IMAGE=nemesis-python-base-dev
ARG PYTHON_BASE_PROD_IMAGE=nemesis-python-base-prod
FROM ${PYTHON_BASE_DEV_IMAGE} AS base

# If dependencies change, re-copy all the dependencies
# In the future we can be more efficient with this an only copy the lib folders
# that this project uses
COPY ./projects/triage/poetry.lock ./projects/triage/pyproject.toml /src/projects/triage/

COPY ./libs /src/libs
COPY ./projects/triage /src/projects/triage/

WORKDIR /src/projects/triage

########################
# Development
########################
FROM base AS dev
COPY --from=base /src /src

WORKDIR /src/projects/triage
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
    poetry run uvicorn triage.main:app \
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

WORKDIR /src/projects/triage
RUN poetry bundle venv --python=/usr/bin/python3 --only=main /venv

# FROM nemesis-python-base-prod AS prod
FROM ${PYTHON_BASE_PROD_IMAGE} AS prod
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
    /venv/bin/uvicorn \"triage.main:app\" \
    --host ${UVICORN_HOST} \
    --port ${UVICORN_PORT} \
    --workers ${UVICORN_WORKERS} \
    --proxy-headers \
    --no-access-log \
    "]