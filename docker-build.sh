#!/bin/bash

# Docker build script for Jacked vulnerability scanner

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
IMAGE_NAME="jacked"
TAG="latest"
DOCKERFILE="Dockerfile"
PUSH=false
PLATFORM="linux/amd64"

# Help function
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -n, --name NAME         Image name (default: jacked)"
    echo "  -t, --tag TAG           Image tag (default: latest)"
    echo "  -f, --file DOCKERFILE   Dockerfile to use (default: Dockerfile)"
    echo "  -p, --push              Push image to registry after build"
    echo "  --platform PLATFORM    Target platform (default: linux/amd64)"
    echo "  --dev                   Use development Dockerfile"
    echo "  --multi                 Use multi-stage Dockerfile with distroless"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Build with defaults"
    echo "  $0 --dev                             # Build development image"
    echo "  $0 --multi                           # Build with distroless base"
    echo "  $0 -n myregistry/jacked -t v1.0.0 -p # Build and push to registry"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -n|--name)
            IMAGE_NAME="$2"
            shift 2
            ;;
        -t|--tag)
            TAG="$2"
            shift 2
            ;;
        -f|--file)
            DOCKERFILE="$2"
            shift 2
            ;;
        -p|--push)
            PUSH=true
            shift
            ;;
        --platform)
            PLATFORM="$2"
            shift 2
            ;;
        --dev)
            DOCKERFILE="Dockerfile.dev"
            shift
            ;;
        --multi)
            DOCKERFILE="Dockerfile.multi"
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

FULL_IMAGE_NAME="${IMAGE_NAME}:${TAG}"

echo -e "${GREEN}Building Docker image...${NC}"
echo -e "${YELLOW}Image:${NC} ${FULL_IMAGE_NAME}"
echo -e "${YELLOW}Dockerfile:${NC} ${DOCKERFILE}"
echo -e "${YELLOW}Platform:${NC} ${PLATFORM}"

# Build the image
echo -e "${GREEN}Starting build...${NC}"
docker build \
    --platform "${PLATFORM}" \
    -f "${DOCKERFILE}" \
    -t "${FULL_IMAGE_NAME}" \
    .

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Build successful!${NC}"
    
    # Show image size
    echo -e "${YELLOW}Image size:${NC}"
    docker images "${IMAGE_NAME}" --filter "tag=${TAG}" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"
    
    if [ "$PUSH" = true ]; then
        echo -e "${GREEN}Pushing image to registry...${NC}"
        docker push "${FULL_IMAGE_NAME}"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓ Push successful!${NC}"
        else
            echo -e "${RED}✗ Push failed!${NC}"
            exit 1
        fi
    fi
    
    echo -e "${GREEN}Done! You can run the image with:${NC}"
    echo "docker run --rm ${FULL_IMAGE_NAME} --help"
else
    echo -e "${RED}✗ Build failed!${NC}"
    exit 1
fi
