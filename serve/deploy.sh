#!/bin/bash

# Build and deploy the testing web server for tinyproxy tests
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" 
NAMESPACE="${1:-default}"

echo "Building test file server image..."
docker build -t fileserver:local "$SCRIPT_DIR"

echo "Add image to kind cluster..."
kind load docker-image fileserver:local --name tinyproxy

echo "Deploying test file server to Kubernetes..."
kubectl apply -f "$SCRIPT_DIR/k8s-deployment.yaml" -n $NAMESPACE

echo ""
echo "Waiting for test file server to be ready..."
kubectl wait --for=condition=ready pod -l app=fileserver --timeout=60s

echo ""
echo "✓ Test file server is running!"