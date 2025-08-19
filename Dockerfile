# Multi-stage build for the Inkan Key Management Module
FROM rust:1.86-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy manifest files
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies
RUN cargo build --release

# Remove dummy main.rs and copy source code
RUN rm -rf src
COPY src ./src

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false inkan

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/target/release/inkan-key-management-module /app/inkan-key-management-module

# Create data directory
RUN mkdir -p /app/data && chown -R inkan:inkan /app

# Switch to non-root user
USER inkan

# Expose port
EXPOSE 3002

# Set environment variables
ENV RUST_LOG=info
ENV STORAGE_PATH=/app/data/keys.json

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3002/health || exit 1

# Run the application
CMD ["./inkan-key-management-module"]
