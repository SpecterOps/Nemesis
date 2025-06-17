# # Use cargo-chef as prepared image with exact tag
# FROM lukemathwalker/cargo-chef:latest-rust-1.86.0-slim-bookworm AS chef
# WORKDIR /app

# # Install build dependencies
# RUN apt-get update && \
#     apt-get install -y \
#     build-essential \
#     cmake \
#     g++ \
#     pkg-config \
#     libssl-dev \
#     libboost-all-dev \
#     ragel && \
#     rm -rf /var/lib/apt/lists/*

# # Prepare recipe (cargo-chef planning phase)
# FROM chef AS planner
# COPY ./projects/noseyparker_scanner/ .
# RUN cargo chef prepare --recipe-path recipe.json

# # Build dependencies for dev
# FROM chef AS dev-deps
# COPY --from=planner /app/recipe.json recipe.json
# # Build dependencies for dev
# RUN cargo chef cook --recipe-path recipe.json

# # Build dependencies for prod
# FROM chef AS prod-deps
# COPY --from=planner /app/recipe.json recipe.json
# # Build dependencies for prod with your specified flags
# RUN cargo chef cook --locked --profile release --recipe-path recipe.json

# # Development build target
# FROM dev-deps AS dev
# COPY ./projects/noseyparker_scanner/ .
# RUN cargo build
# ENV RUST_LOG=debug
# # Use development binary
# CMD ["/app/target/debug/noseyparker-scanner", "--log-level", "debug"]

# # Production build target
# FROM prod-deps AS prod

# # Slim runtime image
# RUN apt-get update && \
#     apt-get install -y \
#     ca-certificates \
#     libssl-dev && \
#     rm -rf /var/lib/apt/lists/*

# COPY ./projects/noseyparker_scanner/ .
# RUN cargo build --release
# ENV RUST_LOG=info
# # Use production binary
# CMD ["/app/target/release/noseyparker-scanner", "--log-level", "info"]







# # New Dockerfile using pre-built dependencies
# ARG DEPS_IMAGE=harmj0y/noseyparker-scanner-deps:arm64
# FROM ${DEPS_IMAGE} AS base

# WORKDIR /app

# # Copy source code (dependencies already compiled in base image)
# COPY ./projects/noseyparker_scanner/ .

# # Development build target
# FROM base AS dev
# RUN cargo build
# ENV RUST_LOG=debug
# # Use development binary
# CMD ["/app/target/debug/noseyparker-scanner", "--log-level", "debug"]

# # Production build target
# FROM base AS prod-builder
# RUN cargo build --release

# # Production runtime image
# FROM debian:bookworm-slim AS prod

# # Install runtime dependencies
# RUN apt-get update && \
#     apt-get install -y \
#     ca-certificates \
#     libssl-dev && \
#     rm -rf /var/lib/apt/lists/*

# # Copy only the binary from builder
# COPY --from=prod-builder /app/target/release/noseyparker-scanner /usr/local/bin/noseyparker-scanner

# ENV RUST_LOG=info
# # Use production binary
# CMD ["noseyparker-scanner", "--log-level", "info"]







# Multi-path Dockerfile: dev from scratch, prod from pre-built deps

########################################
# Development path - build from scratch
########################################
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

# Build dependencies for dev from scratch
FROM chef AS dev-deps
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --recipe-path recipe.json

# Development build target - builds everything from scratch
FROM dev-deps AS dev
COPY ./projects/noseyparker_scanner/ .
RUN cargo build
ENV RUST_LOG=debug
CMD ["/app/target/debug/noseyparker-scanner", "--log-level", "debug"]

########################################
# Production path - use pre-built deps
########################################
FROM harmj0y/noseyparker-scanner-deps:latest AS base

WORKDIR /app
# Copy source code (dependencies already compiled in base image)
COPY ./projects/noseyparker_scanner/ .

# Production build target using pre-compiled deps
FROM base AS prod-builder
RUN cargo build --release

# Production runtime image
FROM debian:bookworm-slim AS prod

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y \
    ca-certificates \
    libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy only the binary from builder
COPY --from=prod-builder /app/target/release/noseyparker-scanner /usr/local/bin/noseyparker-scanner

ENV RUST_LOG=info
CMD ["noseyparker-scanner", "--log-level", "info"]