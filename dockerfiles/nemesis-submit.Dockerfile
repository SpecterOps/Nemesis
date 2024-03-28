####################################
# Common python dependencies layer
####################################
FROM python:3.11.2-bullseye AS debcommon
WORKDIR /opt/Nemesis/

ENV PYTHONUNBUFFERED=true


####################################
# Python dependencies
####################################
FROM debcommon AS dependencies-python

ARG ENVIRONMENT=dev
ENV POETRY_HOME=/opt/poetry
ENV POETRY_VIRTUALENVS_IN_PROJECT=true
ENV PATH="$POETRY_HOME/bin:$PATH"

# install Poetry
RUN python3 -c 'from urllib.request import urlopen; print(urlopen("https://install.python-poetry.org").read().decode())' | python3 -

RUN git clone --depth 1 https://www.github.com/SpecterOps/Nemesis /opt/Nemesis/
RUN mkdir /submit/

RUN poetry -C ./cmd/enrichment/ install


####################################
# Container specific dependencies
####################################
FROM dependencies-python AS build

WORKDIR /opt/Nemesis/
RUN ln -s /opt/Nemesis/cmd/enrichment/enrichment/cli/submit_to_nemesis/submit_to_nemesis.yaml /config.yaml

entrypoint ["bash", "./scripts/submit_to_nemesis.sh", "-m", "/submit/"]
