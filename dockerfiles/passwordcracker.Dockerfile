####################################
# Pre-built python:3.11.2-bullseye base w/ JTR
####################################
FROM specterops/nemesis-jtr-base AS dependencies-os
WORKDIR /app/cmd/passwordcracker


####################################
# Python dependencies
####################################
FROM dependencies-os AS dependencies-python

ARG ENVIRONMENT=dev
ENV POETRY_HOME=/opt/poetry
ENV POETRY_VIRTUALENVS_IN_PROJECT=true

RUN pip install poetry==1.8.2

####################################
# Container specific dependencies
####################################
FROM dependencies-python AS build

COPY cmd/passwordcracker/poetry.lock cmd/passwordcracker/pyproject.toml ./

# copy local libraries
COPY packages/python/nemesispb/ /app/packages/python/nemesispb/
COPY packages/python/nemesiscommon/ /app/packages/python/nemesiscommon/

# use Poetry to install the local packages
RUN poetry install $(if [ "${ENVIRONMENT}" = 'production' ]; then echo "--without dev"; fi;) --no-root --no-interaction --no-ansi -vvv

COPY cmd/passwordcracker/passwordcracker/ ./passwordcracker/


####################################
# Runtime
####################################
FROM build AS runtime
ENV PATH="/app/cmd/passwordcracker/.venv/bin:$PATH"

CMD ["python3", "-m", "passwordcracker"]

