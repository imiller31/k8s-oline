# Kubernetes Authorization Webhook

This is a custom Kubernetes authorization webhook that implements specific authorization rules for protecting resources with configurable prefixes. The webhook is implemented in Go and integrates with Kubernetes using the authorization webhook mechanism.

## Features

- Protects resources with configurable prefix (default: `aks-automatic-`)
- Configurable privileged user (default: `support`) allowed to delete protected resources
- Provides detailed error messages when access is denied
- Uses TLS for secure communication
- Runs as a local container alongside a Kind cluster

## Prerequisites

- Docker
- Kind (Kubernetes in Docker)
- kubectl
- Go 1.21 or later

## Quick Start

1. Clone the repository:
```bash
git clone <repository-url>
cd <repository-directory>
```

2. Run the setup script to create the Kind cluster and generate certificates:
```bash
./setup-cluster.sh
```

3. Start the webhook server:
```bash
./run-webhook.sh
```

## Configuration

The webhook can be configured using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Port the webhook listens on | `8443` |
| `TLS_CERT_FILE` | Path to TLS certificate file | `/app/webhook-cert.pem` |
| `TLS_KEY_FILE` | Path to TLS key file | `/app/webhook-key.pem` |
| `PROTECTED_PREFIX` | Prefix of resource names to protect | `aks-automatic-` |
| `PRIVILEGED_USER` | Username allowed to delete protected resources | `support` |

You can override these when running the container:
```bash
docker run -d \
  --name k8s-oline \
  --network kind \
  -p 8443:8443 \
  -v "$(pwd)/webhook-cert.pem:/app/webhook-cert.pem:ro" \
  -v "$(pwd)/webhook-key.pem:/app/webhook-key.pem:ro" \
  -e PROTECTED_PREFIX=custom-prefix- \
  -e PRIVILEGED_USER=admin \
  k8s-oline:latest
```

## Testing the Webhook

1. Create a test pod with the protected prefix:
```bash
kubectl run aks-automatic-test --image=nginx:latest
```

2. Try to delete the pod (this should be denied):
```bash
kubectl delete pod aks-automatic-test
```
You should receive an error message indicating that only privileged users can delete resources with the protected prefix.

3. Other operations on the pod should work:
```bash
kubectl get pod aks-automatic-test
kubectl describe pod aks-automatic-test
```

## Authorization Rules

The webhook implements the following authorization rules:

1. All operations are allowed by default
2. DELETE operations on resources with names starting with the protected prefix are:
   - Denied for all users except the configured privileged user
   - When denied, a detailed error message is provided
   - The denial reason includes the username and explanation

## Architecture

- The webhook runs as a Docker container in the same network as the Kind cluster
- TLS certificates are automatically generated during setup
- The webhook listens on the configured port (default: 8443)
- The API server is configured to use the webhook for authorization decisions
- All authorization decisions are logged for debugging

## Configuration Files

- `kind-config.yaml`: Kind cluster configuration with webhook settings
- `webhook-config.yaml`: Webhook configuration for the API server
- `setup-cluster.sh`: Script to set up the Kind cluster and generate certificates
- `run-webhook.sh`: Script to build and run the webhook container

## Development

To modify the webhook:

1. Update the Go code in `main.go`
2. The main authorization logic is in the `processAuthRequest` function
3. Run `./setup-cluster.sh` and `./run-webhook.sh` to apply changes

## Troubleshooting

1. Check webhook logs:
```bash
docker logs -f k8s-oline
```

2. Verify the webhook is running:
```bash
docker ps | grep k8s-oline
```

3. Check API server logs:
```bash
docker exec auth-webhook-test-control-plane crictl logs $(docker exec auth-webhook-test-control-plane crictl ps --name kube-apiserver -q)
```

## Security Considerations

- The webhook uses TLS for secure communication
- Certificates are generated with proper permissions
- The webhook container runs in the same network as the Kind cluster
- Authorization decisions are logged for audit purposes
- Detailed error messages help with debugging while maintaining security
- Configuration through environment variables allows for secure deployment in different environments