# Build stage
FROM golang:1.23-alpine AS builder

# Install git and ca-certificates (needed for go mod download with private repos)
RUN apk add --no-cache ca-certificates git tzdata

# Set working directory
WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o jacked \
    ./cmd/jacked

# Final stage - minimal scratch image
FROM scratch

# Copy ca-certificates for HTTPS requests
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy passwd file for non-root user support
COPY --from=builder /etc/passwd /etc/passwd

# Copy the binary
COPY --from=builder /build/jacked /jacked

# Set working directory
WORKDIR /workspace

# Add metadata
LABEL maintainer="Carbonetes Engineering <eng@carbonetes.com>"
LABEL description="Jacked - Vulnerability scanner for container images and filesystems"
LABEL version="latest"

# Run as non-root user for security
USER 65534:65534

# Set entrypoint
ENTRYPOINT ["/jacked"]