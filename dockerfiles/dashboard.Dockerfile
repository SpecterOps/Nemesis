####################################
# Common python dependencies layer
####################################
FROM python:3.11.2-bullseye AS debcommon
WORKDIR /app/cmd/dashboard

ENV PYTHONUNBUFFERED=1


####################################
# OS dependencies
####################################
FROM debcommon AS dependencies-os

# install our necessary dependencies
# RUN apt-get update -y


####################################
# Python dependencies
####################################
FROM dependencies-os AS dependencies-python

ARG ENVIRONMENT=dev
ENV POETRY_HOME=/opt/poetry
ENV POETRY_VIRTUALENVS_IN_PROJECT=true
ENV PATH="$POETRY_HOME/bin:$PATH"

# install Poetry
RUN python3 -c 'from urllib.request import urlopen; print(urlopen("https://install.python-poetry.org").read().decode())' | python3 -

# The next two commands should always be by each other
# Use Poetry to install the local packages only when the lock file changes
COPY cmd/dashboard/poetry.lock cmd/dashboard/pyproject.toml ./
RUN poetry install $(if [ "${ENVIRONMENT}" = 'production' ]; then echo "--without dev"; fi;) --no-interaction --no-ansi -vvv

COPY cmd/dashboard/dashboard/__init__.py ./dashboard/
COPY cmd/dashboard/README.md /app/cmd/dashboard/


####################################
# Container specific dependencies
####################################
FROM dependencies-python AS build

# the main dashboard container code
COPY cmd/dashboard/dashboard/ ./dashboard/

ENV PATH="/app/cmd/dashboard/.venv/bin:$PATH"

WORKDIR /app/cmd/dashboard/dashboard/

CMD [ "python3", "-m", "streamlit", "run", "--server.fileWatcherType=poll", "/app/cmd/dashboard/dashboard/Nemesis.py"]
