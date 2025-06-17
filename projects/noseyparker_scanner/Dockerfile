# Use cargo-chef as prepared image with exact tag
FROM lukemathwalker/cargo-chef:latest-rust-1.86.0-slim-bookworm AS chef
WORKDIR /app

# Install build dependencies
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    cmake \
    g++ \
    pkg-config \
    libssl-dev \
    libboost-all-dev \
    ragel && \
    rm -rf /var/lib/apt/lists/*

# Prepare recipe (cargo-chef planning phase)
FROM chef AS planner
COPY ./projects/noseyparker_scanner/ .
RUN cargo chef prepare --recipe-path recipe.json

# Build dependencies for dev
FROM chef AS dev-deps
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies for dev
RUN cargo chef cook --recipe-path recipe.json

# Build dependencies for prod
FROM chef AS prod-deps
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies for prod with your specified flags
RUN cargo chef cook --locked --profile release --recipe-path recipe.json

# Development build target
FROM dev-deps AS dev
COPY ./projects/noseyparker_scanner/ .
RUN cargo build
ENV RUST_LOG=debug
# Use development binary
CMD ["/app/target/debug/noseyparker-scanner", "--log-level", "debug"]

# Production build target
FROM prod-deps AS prod

# Slim runtime image
RUN apt-get update && \
    apt-get install -y \
    ca-certificates \
    libssl-dev && \
    rm -rf /var/lib/apt/lists/*

COPY ./projects/noseyparker_scanner/ .
RUN cargo build --release
ENV RUST_LOG=info
# Use production binary
CMD ["/app/target/release/noseyparker-scanner", "--log-level", "info"]