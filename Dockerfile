# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=1.0.0 -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -a -installsuffix cgo \
    -o termvault-server ./cmd/termvault-server

# Final stage
FROM alpine:3.18

# Add non-root user for security
RUN addgroup -g 1000 -S termvault && \
    adduser -u 1000 -S termvault -G termvault

# Install ca-certificates and timezone data
RUN apk --no-cache add ca-certificates tzdata

# Set timezone (can be overridden)
ENV TZ=UTC

WORKDIR /home/termvault

# Copy the binary from builder
COPY --from=builder --chown=termvault:termvault /app/termvault-server .

# Create data directory
RUN mkdir -p /data && chown termvault:termvault /data

# Switch to non-root user
USER termvault

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Command to run the application
CMD ["./termvault-server"]
