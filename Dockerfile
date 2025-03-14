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

# Copy TLS certificates
COPY webhook-cert.pem .
COPY webhook-key.pem .

# Set environment variables
ENV PORT=8443
ENV TLS_CERT_FILE=/app/webhook-cert.pem
ENV TLS_KEY_FILE=/app/webhook-key.pem
ENV PROTECTED_PREFIX=aks-automatic-
ENV PRIVILEGED_USER=support

EXPOSE 8443

CMD ["./webhook"]