FROM python:3.12-slim-bullseye

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VERSION=1.7.1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    postgresql-client \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create scripts directory if it doesn't exist
RUN mkdir -p scripts

# Install netcat for health checks in entrypoint
RUN apt-get update && apt-get install -y netcat && rm -rf /var/lib/apt/lists/*

# Make entrypoint executable
RUN chmod +x scripts/entrypoint.sh

# Expose the application port
EXPOSE 8000

# Use entrypoint script
ENTRYPOINT ["./scripts/entrypoint.sh"]

# Default command (can be overridden)
CMD ["uvicorn", "src.presentation.app:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]