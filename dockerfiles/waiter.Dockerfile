FROM debian:11-slim

RUN apt-get update && apt-get install -y jq curl postgresql-client