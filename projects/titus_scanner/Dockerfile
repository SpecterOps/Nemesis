FROM golang:1.25.3-bookworm AS builder
RUN apt-get update && apt-get install -y libvectorscan-dev pkg-config && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY projects/titus_scanner/go.mod projects/titus_scanner/go.sum* ./
RUN go mod download
COPY projects/titus_scanner/ .
RUN CGO_ENABLED=1 go build -tags vectorscan -o /titus-scanner ./cmd/titus-scanner/

FROM builder AS dev
ENV LOG_LEVEL=debug
CMD ["/titus-scanner"]

FROM debian:12-slim AS prod
RUN apt-get update && apt-get install -y ca-certificates git libvectorscan5 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /titus-scanner /usr/local/bin/titus-scanner

# Add GitHub Container Registry labels for linking to repository
LABEL org.opencontainers.image.source=https://github.com/SpecterOps/Nemesis
LABEL org.opencontainers.image.description="Nemesis Titus Scanner"
LABEL org.opencontainers.image.licenses=BSD-3-Clause

ENV LOG_LEVEL=info
CMD ["titus-scanner"]
