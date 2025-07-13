#!/bin/bash

set -e

echo "Starting Identity Module..."

# Function to wait for a service
wait_for_service() {
    local host=$1
    local port=$2
    local service=$3
    
    echo "Waiting for $service to be ready..."
    
    while ! nc -z $host $port; do
        echo "$service is not ready yet. Waiting..."
        sleep 2
    done
    
    echo "$service is ready!"
}

# Wait for PostgreSQL
if [[ "$DATABASE_URL" == *"@db:"* ]]; then
    wait_for_service db 5432 "PostgreSQL"
elif [[ "$DATABASE_URL" == *"@localhost:"* ]]; then
    wait_for_service localhost 5432 "PostgreSQL"
fi

# Wait for Redis
if [[ "$REDIS_URL" == *"redis:"* ]]; then
    wait_for_service redis 6379 "Redis"
elif [[ "$REDIS_URL" == *"localhost:"* ]]; then
    wait_for_service localhost 6379 "Redis"
fi

# Wait for RabbitMQ if configured
if [[ ! -z "$RABBITMQ_URL" ]]; then
    if [[ "$RABBITMQ_URL" == *"@rabbitmq:"* ]]; then
        wait_for_service rabbitmq 5672 "RabbitMQ"
    elif [[ "$RABBITMQ_URL" == *"@localhost:"* ]]; then
        wait_for_service localhost 5672 "RabbitMQ"
    fi
fi

# Run database migrations
echo "Running database migrations..."
alembic upgrade head

echo "Database migrations completed!"

# Start the application
echo "Starting the application..."
exec "$@"