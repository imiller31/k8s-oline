#!/bin/bash

# Exit on error
set -e

echo "Setting up Kind cluster with local authorization webhook..."

# Clean up any existing cluster and resources
if kind get clusters | grep -q auth-webhook-test; then
    echo "Removing existing Kind cluster..."
    kind delete cluster --name k8s-oline-test
fi

if docker ps -a | grep -q k8s-oline; then
    echo "Removing existing k8s-oline container..."
    docker rm -f k8s-oline
fi

# Remove existing certificates
echo "Removing existing certificates..."
rm -f webhook-cert.pem webhook-key.pem

# Generate certificates
echo "Generating webhook certificates..."
cat > openssl.conf << EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = k8s-oline
DNS.2 = localhost
DNS.3 = 127.0.0.1
IP.1 = 127.0.0.1
EOF

# Generate certificate with SANs
openssl req -x509 -newkey rsa:4096 \
    -keyout webhook-key.pem \
    -out webhook-cert.pem \
    -days 365 \
    -nodes \
    -subj "/CN=k8s-oline" \
    -extensions v3_req \
    -config openssl.conf

# Set proper permissions
chmod 644 webhook-cert.pem
chmod 600 webhook-key.pem

# Clean up config file
rm openssl.conf

# Build the webhook image
echo "Building webhook image..."
docker build -t k8s-oline:latest .

# Delete the cluster if it exists
echo "Deleting existing Kind cluster..."
kind delete cluster --name k8s-oline-test

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

# Create Kind cluster
echo "Creating Kind cluster..."
kind create cluster --config kind-config.yaml --name k8s-oline-test

# Wait for the cluster to be ready
echo "Waiting for cluster to be ready..."
kubectl wait --for=condition=ready node --all --timeout=120s