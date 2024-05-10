FROM debian:bookworm-20240423-slim

RUN apt-get update && apt-get install -y jq curl postgresql-client