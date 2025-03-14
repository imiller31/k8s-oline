#!/bin/bash

# Exit on error
set -e

echo "Starting webhook server in Docker..."

# Remove existing container if it exists
if docker ps -a | grep -q k8s-oline; then
    echo "Removing existing k8s-oline container..."
    docker rm -f k8s-oline
fi

# Build the Docker image
echo "Building Docker image..."
docker build -t k8s-oline:latest .

# Run the webhook container
echo "Starting webhook container..."
docker run -d \
  --name k8s-oline \
  --network kind \
  -p 8443:8443 \
  -v "$(pwd)/webhook-cert.pem:/app/webhook-cert.pem:ro" \
  -v "$(pwd)/webhook-key.pem:/app/webhook-key.pem:ro" \
  -e TLS_CERT_FILE=/app/webhook-cert.pem \
  -e TLS_KEY_FILE=/app/webhook-key.pem \
  k8s-oline:latest

echo "Webhook server is running in Docker container 'k8s-oline'"
echo "Tailing logs (Ctrl+C to stop)..."
docker logs -f k8s-oline