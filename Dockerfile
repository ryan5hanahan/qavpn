# Multi-stage hardened Docker build for QAVPN Relay
# Uses minimal base images and security best practices

# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Create non-root user for build
RUN adduser -D -g '' appuser

# Set working directory
WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary with security flags
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -a -installsuffix cgo \
    -ldflags='-w -s -extldflags "-static"' \
    -tags netgo \
    -o qavpn-relay .

# Runtime stage - minimal distroless image
FROM gcr.io/distroless/static:nonroot

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy CA certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary
COPY --from=builder /build/qavpn-relay /usr/local/bin/qavpn-relay

# Copy configuration files
COPY --from=builder /build/docker/relay-config.conf /etc/qavpn/config
COPY --from=builder /build/docker/entrypoint.sh /entrypoint.sh

# Create necessary directories with proper permissions
USER 65532:65532

# Set environment variables for security
ENV GOGC=100
ENV GOMAXPROCS=2
ENV TZ=UTC

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/qavpn-relay", "status"]

# Expose relay port
EXPOSE 9051/tcp
EXPOSE 9051/udp

# Use entrypoint script for secure startup
ENTRYPOINT ["/entrypoint.sh"]
CMD ["relay", "-verbose"]
