# ── Build stage ──────────────────────────────────────────────────────────────
FROM rust:latest AS builder

WORKDIR /build

# Copy the entire Rust workspace
COPY rust/ .

# Build the saas-server binary in release mode.
# rusqlite uses the "bundled" feature so no system SQLite is required.
RUN cargo build --release --bin saas-server

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# Install minimal runtime dependencies (OpenSSL + CA certs for HTTPS calls)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /build/target/release/saas-server /app/saas-server

# Expose the default port (Railway injects $PORT at runtime)
EXPOSE 8080

CMD ["/app/saas-server"]
