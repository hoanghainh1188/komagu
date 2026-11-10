# ==============================================================================
# Komagu — Security-First Legacy Modernization Platform
# All-in-One Zero-Install Container Image
# ==============================================================================

# Pinned by digest (multi-arch index) so builds are reproducible; Dependabot's
# docker ecosystem refreshes the digest.
FROM python:3.13-alpine@sha256:1e1f6334529d1fb26a2ef619d7cffb30a7c7d7cc1cc7338ebee283a58d1aeaca AS base

LABEL org.opencontainers.image.title="Komagu Security-First Modernization Platform"
LABEL org.opencontainers.image.description="All-in-one zero-install security audit and BOLA verification container"
LABEL org.opencontainers.image.source="https://github.com/hoanghainh1188/komagu"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Apply Alpine security fixes released since the base image was built, then
# install essential system utilities for repository analysis
RUN apk upgrade --no-cache \
    && apk add --no-cache git ca-certificates

# The CLI is standard-library only and never installs packages at runtime, so
# pip (and the urllib3/msgpack it vendors) is removed from the shipped image
RUN python -m pip uninstall -y pip \
    && rm -f /usr/local/lib/python3.13/ensurepip/_bundled/pip-*.whl

# Create non-root user and group
RUN addgroup -g 1000 komagu \
    && adduser -u 1000 -G komagu -D -s /bin/sh komagu

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
