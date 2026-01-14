# FROM nemesis-python-base-dev AS base
ARG PYTHON_BASE_DEV_IMAGE=nemesis-python-base-dev
ARG PYTHON_BASE_PROD_IMAGE=nemesis-python-base-prod
FROM ${PYTHON_BASE_DEV_IMAGE} AS base

# If dependencies change, re-copy all the dependencies
# In the future we can be more efficient with this an only copy the lib folders
# that this project uses
COPY ./projects/alerting/uv.lock ./projects/alerting/pyproject.toml /src/projects/alerting/

COPY ./libs /src/libs
COPY ./projects/alerting /src/projects/alerting/

WORKDIR /src/projects/alerting

########################
# Development
########################
FROM base AS dev
COPY --from=base /src /src

WORKDIR /src/projects/alerting
RUN uv sync --frozen

# Immediate output (no buffering)
ENV PYTHONUNBUFFERED=1
# No .pyc/pycache files
ENV PYTHONDONTWRITEBYTECODE=1

ENV LOG_LEVEL=DEBUG

ENV UVICORN_HOST="0.0.0.0"
ENV UVICORN_PORT=8000

ENTRYPOINT ["/bin/sh", "-c", " \
    uv run python -m uvicorn alerting.main:app \
    --host ${UVICORN_HOST} \
    --port ${UVICORN_PORT} \
    --reload \
    --reload-dir /src/projects/alerting/alerting \
    --reload-dir /src/libs \
    --reload-include '*.py' \
    "]

########################
# Production
########################
FROM base AS bundle
COPY --from=base /src /src

WORKDIR /src/projects/alerting
RUN uv export --frozen --no-dev --no-hashes -o requirements.txt && \
    uv venv /venv --python /usr/local/bin/python3 --seed && \
    /venv/bin/pip install --no-cache-dir -r requirements.txt && \
    /venv/bin/pip install --no-cache-dir /src/libs/common /src/projects/alerting

# FROM nemesis-python-base-prod AS prod
FROM ${PYTHON_BASE_PROD_IMAGE} AS prod
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
    /venv/bin/uvicorn \"alerting.main:app\" \
    --host ${UVICORN_HOST} \
    --port ${UVICORN_PORT} \
    --workers ${UVICORN_WORKERS} \
    --proxy-headers \
    --no-access-log \
    "]
