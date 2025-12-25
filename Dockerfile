FROM ubuntu:rolling

# Set environment variables to avoid interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive
# Install system dependencies for Chrome and Python packages
USER root
RUN apt-get update && apt-get install -y \
    software-properties-common \
    python3-pip \
    python3-venv \
    wget \
    gnupg \
    curl \
    xvfb \
    libgtk-3-0 \
    libgtk-3-dev \
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
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only requirements first to leverage Docker cache
COPY server_requirements.txt .

# Create venv and install dependencies as root to avoid permission issues during install, 
# then we will fix ownership later.
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r server_requirements.txt

# Copy the rest of the application
COPY . .

# Fetch Camoufox
RUN camoufox fetch

# Fix permissions: change ownership to ubuntu user and set specific permissions
RUN chown -R ubuntu:ubuntu /app && \
    chmod -R 777 /app/venv/lib/python*/site-packages/playwright_captcha/utils/camoufox_add_init_script/addon/ || true

# Switch to non-root user for runtime
USER ubuntu

# RUN the application
CMD ["python3", "server.py"]