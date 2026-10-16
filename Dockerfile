# OpenSOC Forge Central Management Plane & Web Console Container
# Multi-service management API (FastAPI) and pre-compiled React 18 UI
FROM docker.io/library/python:3.12-slim

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install curl for healthcheck, ca-certificates, and netcat for diagnostics
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Set working directory to standard OpenSOC Forge path
WORKDIR /opt/opensoc-forge

# Copy packaging specifications first for layer caching
COPY pyproject.toml ./

# Install Python dependencies from pyproject.toml
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Copy application components
COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY adapters/ ./adapters/
COPY configs/ ./configs/
COPY scripts/ ./scripts/
COPY orchestration/ ./orchestration/
COPY compatibility/ ./compatibility/
COPY releases/ ./releases/
COPY rules/ ./rules/

# Create runtime directories
RUN touch /opt/opensoc-forge/rules/__init__.py /opt/opensoc-forge/rules/sigma/__init__.py && \
    mkdir -p /var/log/suricata /var/lib/opensoc /etc/opensoc /var/log/opensoc/syslog

# Expose FastAPI and static UI port
EXPOSE 7070

# Healthcheck testing HTTP endpoint on port 7070
HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=5 \
    CMD curl -f http://localhost:7070/ || exit 1

# Launch central management plane
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "7070"]
