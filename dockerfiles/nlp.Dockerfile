
####################################
# Python build dependencies and configuration
####################################
FROM python:3.11.2-slim-bullseye AS dependencies-python

ENV POETRY_HOME=/opt/poetry
ENV POETRY_VIRTUALENVS_IN_PROJECT=true
ENV PYTHONUNBUFFERED=true

RUN pip install poetry==1.8.2


####################################
# Container specific dependencies
####################################
FROM dependencies-python AS build

WORKDIR /app/cmd/nlp

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

# Pre-download the embedding model(s) we're using so we don't have to wait for it to download on first use
#   in ascending order of size, descending order of processing speed
RUN python -c "from langchain_community.embeddings import HuggingFaceEmbeddings; \
embeddings = [HuggingFaceEmbeddings(model_name=model) for model in [ \
    'TaylorAI/bge-micro-v2', \
    'Harmj0y/nemesis-gte-tiny', \
    'TaylorAI/gte-tiny', \
    'thenlper/gte-small' \
]]"


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