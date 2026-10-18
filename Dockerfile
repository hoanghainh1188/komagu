# ==============================================================================
# Komainu — Security-First Legacy Modernization Platform
# All-in-One Zero-Install Container Image
# ==============================================================================

FROM python:3.11-slim AS base

LABEL org.opencontainers.image.title="Komainu Security-First Modernization Platform"
LABEL org.opencontainers.image.description="All-in-one zero-install security audit and BOLA verification container"
LABEL org.opencontainers.image.source="https://github.com/hoanghainh1188/komainu"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Install essential system utilities for repository analysis
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user and group
RUN groupadd -g 1000 komainu \
    && useradd -u 1000 -g komainu -m -s /bin/bash komainu

WORKDIR /app

# Copy Komainu platform modules and executables
COPY bin/ /app/bin/
COPY assess/ /app/assess/
COPY operate/ /app/operate/
COPY remediate/ /app/remediate/
COPY contracts/ /app/contracts/

# Ensure executable permissions on CLI entrypoints
RUN chmod +x /app/bin/komainu

# Configure environment
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    PATH=/app/bin:${PATH}

# Switch to non-root user and workspace
USER komainu
WORKDIR /workspace

# Set default entrypoint and command
ENTRYPOINT ["/app/bin/komainu"]
CMD ["--help"]
