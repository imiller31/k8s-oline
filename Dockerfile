# Build stage
FROM golang:1.23.5-alpine AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o webhook

# Final stage
FROM alpine:latest

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/webhook .

# Create directory for configuration
RUN mkdir -p /app/config

# Copy default configuration
COPY config.yaml /app/config/default.yaml

# Copy TLS certificates
COPY webhook-cert.pem .
COPY webhook-key.pem .

EXPOSE 8443

# Use the default configuration if no config file is mounted
CMD ["./webhook", "--config", "/app/config/default.yaml"]