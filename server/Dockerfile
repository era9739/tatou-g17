# Server image: minimal Flask + Gunicorn
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates openssh-client \
 && rm -rf /var/lib/apt/lists/*

# ✅ Create logs directory inside container
RUN mkdir -p /app/logs

# Copy project description, to install dependencies
COPY pyproject.toml /app/pyproject.toml

# Install runtime dependencies
RUN pip install --no-cache-dir -e .

# Copy sources after dependencies installation
COPY src /app/src
COPY flag /app/flag
COPY entrypoint.sh /app/entrypoint.sh
COPY group_17_rmap.pdf /app/group_17_rmap.pdf
RUN pip install --no-cache-dir -e .

EXPOSE 5000

# Default command runs the web server
CMD ["./entrypoint.sh"]
