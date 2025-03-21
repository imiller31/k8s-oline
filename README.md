# Kubernetes Authorization Webhook

This is a custom Kubernetes authorization webhook that implements specific authorization rules for protecting resources with configurable prefixes. The webhook is implemented in Go and integrates with Kubernetes using the authorization webhook mechanism.

WARNING: This is a partially vibe-coded PoC. This shouldn't be used by anyone, anywhere, for anything.

## Features

- Protects resources with configurable prefix (default: `aks-automatic-`)
- Configurable privileged user (default: `support`) allowed to delete protected resources
- Blocks unauthorized impersonation of system:masters group
- Provides detailed error messages when access is denied
- Uses TLS for secure communication
- Runs as a local container alongside a Kind cluster
- Supports CEL (Common Expression Language) rules for flexible authorization policies

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

The webhook can be configured using environment variables or a YAML configuration file. Environment variables take precedence over YAML configuration.

### Environment Variables

- `PORT`: Port to listen on (default: "8080")
- `TLS_CERT_FILE`: Path to TLS certificate file (required)
- `TLS_KEY_FILE`: Path to TLS key file (required)
- `PROTECTED_PREFIX`: Prefix for protected resources (default: "aks-automatic-")
- `PRIVILEGED_USER`: Username for privileged operations (default: "support")
- `CEL_RULES`: Semicolon-separated list of CEL expressions for authorization (default: "")
- `CONFIG_FILE`: Path to YAML configuration file (optional)

### YAML Configuration

You can also configure the webhook using a YAML file. Set the `CONFIG_FILE` environment variable to point to your YAML configuration file:

```yaml
port: 8443
tlsCertFile: "/path/to/cert.pem"
tlsKeyFile: "/path/to/key.pem"
protectedPrefix: "custom-"
privilegedUser: "admin"
celRules:
  - "'system:masters' in groups"
  - "!(resourceAttributes != null && resourceAttributes.verb == 'delete' && resourceAttributes.name.startsWith('custom-'))"
```

Example command with YAML configuration:
```bash
docker run -d \
  -p 8443:8443 \
  -v /path/to/config.yaml:/config.yaml \
  -e CONFIG_FILE=/config.yaml \
  -e TLS_CERT_FILE=/path/to/cert.pem \
  -e TLS_KEY_FILE=/path/to/key.pem \
  k8s-auth-webhook
```

## CEL Rules

The webhook supports CEL (Common Expression Language) rules for flexible authorization policies. CEL rules are boolean expressions that determine whether a request should be allowed. Multiple rules can be specified, separated by semicolons. All rules must evaluate to true for the request to be allowed.

Available variables in CEL expressions:
- `request`: The full SubjectAccessReview request
- `user`: The username making the request
- `groups`: List of groups the user belongs to
- `resourceAttributes`: Resource attributes of the request (if any)
- `nonResourceAttributes`: Non-resource attributes of the request (if any)

Example CEL rules:
```bash
# Only allow admin user
user == 'admin'

# Allow users in system:masters group
'system:masters' in groups

# Allow all operations except delete on protected resources
!(resourceAttributes != null && resourceAttributes.verb == 'delete' && resourceAttributes.name.startsWith('aks-automatic-'))

# Allow specific namespace access
resourceAttributes != null && resourceAttributes.namespace == 'prod'

# Block access to specific resources
!(resourceAttributes != null && resourceAttributes.resource == 'secrets' && resourceAttributes.name.startsWith('prod-'))
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

1. CEL rules are evaluated first (if configured)
2. All operations are allowed by default
3. DELETE operations on resources with names starting with the protected prefix are:
   - Allowed for:
     - The configured privileged user (default: `support`)
     - Members of the `system:masters` group
     - Members of the `system:nodes` group
   - Denied for all other users
   - When denied, a detailed error message is provided
   - The denial reason includes the username and explanation of which users/groups are allowed
4. Impersonation of the system:masters group is:
   - Blocked for all users
   - Applies to both direct group impersonation and userextras impersonation
   - Returns clear error messages explaining why the impersonation was denied

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
- Prevents privilege escalation through system:masters group impersonation
- CEL rules provide flexible but safe authorization policies