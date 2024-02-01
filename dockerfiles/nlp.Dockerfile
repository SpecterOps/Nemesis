####################################
# Common python dependencies layer
####################################
FROM python:3.11.2-bullseye AS debcommon
WORKDIR /app/cmd/nlp

ENV PYTHONUNBUFFERED=true


####################################
# OS dependencies
####################################
FROM debcommon AS dependencies-os

# install our necessary dependencies
#RUN apt-get update -y


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

COPY cmd/nlp/poetry.lock cmd/nlp/pyproject.toml ./

# copy local libraries
COPY packages/python/nemesispb/ /app/packages/python/nemesispb/
COPY packages/python/nemesiscommon/ /app/packages/python/nemesiscommon/

# use Poetry to install the local packages
RUN poetry install $(if [ "${ENVIRONMENT}" = 'production' ]; then echo "--without dev"; fi;) --no-root --no-interaction --no-ansi -vvv


####################################
# Runtime
####################################
FROM build AS model_download
ENV PATH="/app/cmd/nlp/.venv/bin:$PATH"

# preload the main embedding model(s) we're using so we don't have to wait for it to download on first use

# better ranked but slower
RUN python3 -c "from langchain.embeddings import HuggingFaceEmbeddings; embeddings=HuggingFaceEmbeddings(model_name='TaylorAI/gte-tiny')"
# faster but not as effective
RUN python3 -c "from langchain.embeddings import HuggingFaceEmbeddings; embeddings=HuggingFaceEmbeddings(model_name='TaylorAI/bge-micro-v2')"


####################################
# Runtime
####################################
FROM model_download AS runtime
ENV PATH="/app/cmd/nlp/.venv/bin:$PATH"

# copy in the main nlp container code
COPY cmd/nlp/nlp/ ./nlp/


# for the semantic search api
EXPOSE 9803

CMD ["python3", "-m", "nlp"]
