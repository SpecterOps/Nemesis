####################################
# Common python dependencies layer
####################################
FROM python:3.11.2-bullseye AS debcommon
WORKDIR /app/cmd/passwordcracker

ENV PYTHONUNBUFFERED=true


####################################
# OS dependencies
####################################
FROM debcommon AS dependencies-os

# install our necessary dependencies
RUN apt-get update -y && apt-get install yara -y && apt-get install git -y && apt-get install wamerican -y && apt-get install libcompress-raw-lzma-perl -y

# build JTR so we build get various X-2john binaries for file hash extraction
RUN cd /opt/ && git clone https://github.com/openwall/john && cd john/src && ./configure && make


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
