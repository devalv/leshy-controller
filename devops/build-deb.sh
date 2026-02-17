#!/bin/bash

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKERFILE_PATH="devops/docker/deb/Dockerfile.astra184"
IMAGE_NAME="leshy-controller-deb-builder"
PACKAGE_ARCH="amd64"
PACKAGE_VERSION="${PACKAGE_VERSION:-}"

if [[ -z "${PACKAGE_VERSION}" ]]; then
    echo "PACKAGE_VERSION is required"
    echo "Usage: PACKAGE_VERSION=1.2.3 ./devops/build-deb.sh"
    exit 1
fi

ARTIFACT_NAME="leshy-controller_${PACKAGE_VERSION}_${PACKAGE_ARCH}.deb"

echo "Project root: ${PROJECT_ROOT}"
echo "Package version: ${PACKAGE_VERSION}"

echo "Building Docker image..."
docker build \
    --target builder \
    --build-arg "PACKAGE_VERSION=${PACKAGE_VERSION}" \
    --build-arg "PACKAGE_ARCH=${PACKAGE_ARCH}" \
    -t "${IMAGE_NAME}" \
    -f "${PROJECT_ROOT}/${DOCKERFILE_PATH}" \
    "${PROJECT_ROOT}"

echo "Creating container and extracting artifact..."
CONTAINER_ID=$(docker create "${IMAGE_NAME}" sh -c "true")

docker cp "${CONTAINER_ID}:/tmp/${ARTIFACT_NAME}" "${PROJECT_ROOT}/${ARTIFACT_NAME}"
docker rm "${CONTAINER_ID}" >/dev/null

echo "Deb package saved as: ${PROJECT_ROOT}/${ARTIFACT_NAME}"
