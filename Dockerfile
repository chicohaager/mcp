## Build stage
FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

## Runtime stage
FROM python:3.11-slim

LABEL maintainer="Holger Kuehn"
LABEL description="ZimaOS Universal MCP Server"
LABEL version="1.2.2"

# Install docker CLI for container management
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        dnsutils \
        git \
        iputils-ping \
        iproute2 \
        procps \
        traceroute \
        util-linux \
    && curl -fsSL https://download.docker.com/linux/static/stable/$(uname -m)/docker-27.5.1.tgz \
       | tar xz --strip-components=1 -C /usr/local/bin docker/docker \
    && apt-get purge -y --auto-remove curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Create app directory
WORKDIR /app

# Copy application code
COPY server.py config.py security.py skills.py api.py templates.py ./
COPY tools/ ./tools/
COPY web/ ./web/

# Create data directory
RUN mkdir -p /DATA/AppData/zimaos-mcp/backups /DATA/AppData/zimaos-mcp/skills

# Environment defaults
ENV MCP_PORT=8717 \
    MCP_LOG_LEVEL=INFO \
    DOCKER_CONFIG=/DATA/.docker \
    PYTHONUNBUFFERED=1

EXPOSE 8717

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8717/api/health')" || exit 1

CMD ["python", "server.py"]
