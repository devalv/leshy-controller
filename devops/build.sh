#!/bin/bash

set -e

# Переходим в корень проекта
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "Project root: $PROJECT_ROOT"

DOCKERFILE_PATH="devops/docker/cbpf/Dockerfile.astra184"
IMAGE_NAME="cbpf-builder"
ARTIFACT_NAME="l4_filter.o"

# Сборка образа
echo "Building Docker image..."
docker build --platform linux/amd64 \
    -t "$IMAGE_NAME" \
    -f "$PROJECT_ROOT/$DOCKERFILE_PATH" \
    "$PROJECT_ROOT"

# Создание временного контейнера и копирование артефактов
echo "Creating container and extracting artifact..."
CONTAINER_ID=$(docker create --platform linux/amd64 "$IMAGE_NAME" 2>/dev/null || \
               docker create "$IMAGE_NAME")

docker cp "${CONTAINER_ID}:/$ARTIFACT_NAME" "$PROJECT_ROOT/$ARTIFACT_NAME"
docker rm "$CONTAINER_ID"

echo "Artifact saved as: $PROJECT_ROOT/$ARTIFACT_NAME"
