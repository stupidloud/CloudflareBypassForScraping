# Stage 1: Builder - Install dependencies and fetch Camoufox
FROM ubuntu:rolling AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-pip \
    python3-venv \
    wget \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /app

# Create virtual environment and install Python dependencies
COPY server_requirements.txt .
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --upgrade pip && \
    /app/venv/bin/pip install --no-cache-dir -r server_requirements.txt

# Fetch Camoufox browser
RUN /app/venv/bin/camoufox fetch

# Stage 2: Runtime - Minimal runtime image
FROM ubuntu:rolling

# Metadata
LABEL maintainer="CloudflareBypassForScraping"
LABEL description="Cloudflare Bypasser with HTTP Proxy Server"
LABEL version="2.0.0"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PATH="/app/venv/bin:$PATH"

# Install only runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    curl \
    xvfb \
    libgtk-3-0 \
    libxss1 \
    libxtst6 \
    libxrandr2 \
    libasound2t64 \
    libpangocairo-1.0-0 \
    libatk1.0-0 \
    libcairo-gobject2 \
    libgdk-pixbuf-2.0-0 \
    libdbus-glib-1-2 \
    libxt6 \
    libxcomposite1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxrender1 \
    libxi6 \
    fonts-liberation \
    libnss3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /app/venv /app/venv

# Copy application code
COPY . .

# Change ownership to ubuntu user
RUN chown -R ubuntu:ubuntu /app

# Switch to ubuntu user
USER ubuntu

# Fix permissions for playwright_captcha addon directory
RUN chmod -R 755 /app/venv/lib/python*/site-packages/playwright_captcha/utils/camoufox_add_init_script/addon/ 2>/dev/null || true

# Expose ports
EXPOSE 8000 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["python3", "server.py"]