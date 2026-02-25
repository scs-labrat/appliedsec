FROM python:3.12-slim AS base

# System deps for confluent-kafka (librdkafka) and asyncpg
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        librdkafka-dev \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (cache layer)
COPY pyproject.toml ./
RUN pip install --no-cache-dir -e . 2>/dev/null || true

# Copy full project (all services share the same codebase)
COPY . .
RUN pip install --no-cache-dir -e .

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Default: health check via curl (overridden per service)
HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8080}/health || exit 1
