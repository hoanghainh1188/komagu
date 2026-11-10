# ==============================================================================
# Komagu — Security-First Legacy Modernization Platform
# All-in-One Zero-Install Container Image
# ==============================================================================

# Pinned by digest (multi-arch index) so builds are reproducible; Dependabot's
# docker ecosystem refreshes the digest.
FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS base

LABEL org.opencontainers.image.title="Komagu Security-First Modernization Platform"
LABEL org.opencontainers.image.description="All-in-one zero-install security audit and BOLA verification container"
LABEL org.opencontainers.image.source="https://github.com/hoanghainh1188/komagu"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Apply Debian security fixes released since the base image was built, then
# install essential system utilities for repository analysis
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The CLI is standard-library only and never installs packages at runtime, so
# pip (and the urllib3/msgpack it vendors) is removed from the shipped image
RUN python -m pip uninstall -y pip \
    && rm -f /usr/local/lib/python3.13/ensurepip/_bundled/pip-*.whl

# Create non-root user and group
RUN groupadd -g 1000 komagu \
    && useradd -u 1000 -g komagu -m -s /bin/bash komagu

WORKDIR /app

# Copy Komagu platform modules and executables
COPY bin/ /app/bin/
COPY assess/ /app/assess/
COPY operate/ /app/operate/
COPY remediate/ /app/remediate/
COPY contracts/ /app/contracts/
COPY governance/ /app/governance/
COPY examples/ /app/examples/

# Ensure executable permissions on CLI entrypoints
RUN chmod +x /app/bin/komagu

# Configure environment
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    PATH=/app/bin:${PATH}

# Switch to non-root user and workspace
USER komagu
WORKDIR /workspace

# Set default entrypoint and command
ENTRYPOINT ["/app/bin/komagu"]
CMD ["--help"]
