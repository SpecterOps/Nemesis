# This is the development image for python projects
# It is a slim image with dev tools/programs installed
FROM python:3.12.3-slim
RUN apt-get update && \
    apt-get install --no-install-suggests --no-install-recommends --yes \
    pipx wget curl procps net-tools htop
ENV PATH="/root/.local/bin:${PATH}"
RUN pipx install poetry==2.0.1
RUN pipx inject poetry poetry-plugin-bundle

WORKDIR /src