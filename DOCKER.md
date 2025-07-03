# Docker Setup for Jacked

This directory contains multiple Docker configurations for different use cases.

## Available Dockerfiles

### 1. `Dockerfile` (Production - Scratch-based)
- **Use case**: Production deployments requiring minimal image size
- **Base image**: `scratch`
- **Size**: ~15-20MB
- **Features**: 
  - Multi-stage build for optimal caching
  - Static binary compilation
  - Non-root user execution
  - CA certificates and timezone data included
  - Optimized for security and size

### 2. `Dockerfile.dev` (Development)
- **Use case**: Development and debugging
- **Base image**: `golang:1.23-alpine`
- **Size**: ~400MB
- **Features**:
  - Includes debugging tools (bash, curl, vim)
  - Source code mounted as volume
  - Hot reload capabilities
  - Shell access for debugging

### 3. `Dockerfile.multi` (Multi-target)
- **Use case**: Flexible builds with multiple final image options
- **Targets available**:
  - `distroless`: Secure minimal image with basic shell (~25MB)
  - `scratch`: Ultra-minimal image (~15MB)

## Quick Start

### Build and Run (Production)
```bash
# Build the production image
docker build -t jacked:latest .

# Run vulnerability scan on a directory
docker run --rm -v $(pwd):/workspace jacked:latest /workspace

# Run on a container image
docker run --rm jacked:latest alpine:latest
```

### Development Setup
```bash
# Build development image
docker build -f Dockerfile.dev -t jacked:dev .

# Run with source code mounted for development
docker run --rm -it -v $(pwd):/app jacked:dev bash
```

### Using Docker Compose
```bash
# Build and run all variants
docker-compose up

# Build specific variant
docker-compose up jacked-dev

# Run specific service
docker-compose run --rm jacked alpine:latest
```

## Build Script

Use the provided build script for convenience:

```bash
# Basic build
./docker-build.sh

# Development build
./docker-build.sh --dev

# Build with custom name and tag
./docker-build.sh -n myregistry/jacked -t v1.0.0

# Build and push to registry
./docker-build.sh -n myregistry/jacked -t v1.0.0 --push

# Show help
./docker-build.sh --help
```

## Image Comparison

| Image Type | Base | Size | Security | Use Case |
|------------|------|------|----------|----------|
| Production (scratch) | scratch | ~15MB | Highest | Production, CI/CD |
| Distroless | distroless | ~25MB | High | Production with debugging |
| Development | alpine | ~400MB | Medium | Development, testing |

## Security Features

### Non-root Execution
All production images run as non-root user (UID 65534) for enhanced security.

### Minimal Attack Surface
- Scratch-based images contain only the binary and essential certificates
- No shell or package manager in production images
- Static compilation eliminates runtime dependencies

### Build Optimizations
- Multi-stage builds minimize final image size
- Layer caching for faster rebuilds
- Only necessary files copied to final image

## Configuration

### Environment Variables
The application respects these environment variables:
- `JACKED_CONFIG`: Path to configuration file
- `JACKED_DB`: Database file path
- `TZ`: Timezone (supported in all images)

### Volumes
- `/workspace`: Default working directory for scanning
- `/etc/jacked`: Configuration directory (if needed)
- `/tmp/jacked`: Temporary files and cache

### Examples

#### Scan a local directory
```bash
docker run --rm \
  -v /path/to/scan:/workspace:ro \
  jacked:latest \
  /workspace
```

#### Scan with custom configuration
```bash
docker run --rm \
  -v /path/to/config:/etc/jacked:ro \
  -v /path/to/scan:/workspace:ro \
  -e JACKED_CONFIG=/etc/jacked/config.yaml \
  jacked:latest \
  /workspace
```

#### Interactive development session
```bash
docker run --rm -it \
  -v $(pwd):/app \
  jacked:dev \
  bash
```

## Troubleshooting

### Permission Issues
If you encounter permission issues, ensure the directories you're mounting have appropriate read permissions:
```bash
chmod -R +r /path/to/scan
```

### Docker Desktop on Windows
Make sure Docker Desktop is running and configured to use Linux containers.

### Build Issues
If builds fail, try:
1. Clean Docker cache: `docker system prune -a`
2. Update Docker to latest version
3. Check available disk space
4. Verify internet connectivity for dependency downloads

## CI/CD Integration

### GitHub Actions Example
```yaml
- name: Build Docker image
  run: |
    docker build -t jacked:${{ github.sha }} .
    docker tag jacked:${{ github.sha }} jacked:latest
```

### Registry Push
```bash
# Tag for registry
docker tag jacked:latest myregistry.com/jacked:latest

# Push to registry
docker push myregistry.com/jacked:latest
```
