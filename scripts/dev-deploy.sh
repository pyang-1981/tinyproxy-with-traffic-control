#!/usr/bin/env bash
# Helper script to build tinyproxy and config-watcher images and deploy via Helm
# Usage: ./scripts/dev-deploy.sh [--image repo] [--tag tag] [--watcher-image repo] [--watcher-tag tag] [--values file] [--namespace ns] [--release name] [--push registry]

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT_DIR"

# Defaults
IMAGE_REPO=${IMAGE_REPO:-tinyproxy}
IMAGE_TAG=${IMAGE_TAG:-local}
PULL_POLICY=${PULL_POLICY:-IfNotPresent}
WATCHER_REPO=${WATCHER_REPO:-tinyproxy-config-watcher}
WATCHER_TAG=${WATCHER_TAG:-latest}
VALUES_FILE=${VALUES_FILE:-helm/tinyproxy/values.yaml}
NAMESPACE=${NAMESPACE:-default}
RELEASE=${RELEASE:-tinyproxy}
PUSH_REGISTRY=""

print_usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --image repo           Set main image repository (default: ${IMAGE_REPO})
  --tag tag              Set main image tag (default: ${IMAGE_TAG})
  --watcher-image repo   Set watcher image repository (default: ${WATCHER_REPO})
  --watcher-tag tag      Set watcher image tag (default: ${WATCHER_TAG})
  --values file          Helm values file (default: ${VALUES_FILE})
  --namespace ns         Kubernetes namespace (default: ${NAMESPACE})
  --release name         Helm release name (default: ${RELEASE})
  --push registry        Tag and push images to registry (e.g. registry.example.com/project)
  -h, --help             Show this help

Example:
  $0 --image tinyproxy --tag local --watcher-image tinyproxy-config-watcher --watcher-tag latest

EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image)
      IMAGE_REPO="$2"; shift 2;;
    --tag)
      IMAGE_TAG="$2"; shift 2;;
    --watcher-image)
      WATCHER_REPO="$2"; shift 2;;
    --watcher-tag)
      WATCHER_TAG="$2"; shift 2;;
    --values)
      VALUES_FILE="$2"; shift 2;;
    --namespace)
      NAMESPACE="$2"; shift 2;;
    --release)
      RELEASE="$2"; shift 2;;
    --push)
      PUSH_REGISTRY="$2"; shift 2;;
    -h|--help)
      print_usage; exit 0;;
    *)
      echo "Unknown arg: $1"; print_usage; exit 1;;
  esac
done

echo "Building tinyproxy image: ${IMAGE_REPO}:${IMAGE_TAG}"
docker build -t "${IMAGE_REPO}:${IMAGE_TAG}" .

echo "Building config-watcher image: ${WATCHER_REPO}:${WATCHER_TAG}"
docker build -t "${WATCHER_REPO}:${WATCHER_TAG}" ./helm/tinyproxy/config-watcher

if [[ -n "$PUSH_REGISTRY" ]]; then
  echo "Tagging and pushing images to ${PUSH_REGISTRY}"
  docker tag "${IMAGE_REPO}:${IMAGE_TAG}" "${PUSH_REGISTRY}/${IMAGE_REPO}:${IMAGE_TAG}"
  docker tag "${WATCHER_REPO}:${WATCHER_TAG}" "${PUSH_REGISTRY}/${WATCHER_REPO}:${WATCHER_TAG}"
  docker push "${PUSH_REGISTRY}/${IMAGE_REPO}:${IMAGE_TAG}"
  docker push "${PUSH_REGISTRY}/${WATCHER_REPO}:${WATCHER_TAG}"
  # update repo names for helm values
  IMAGE_REPO="${PUSH_REGISTRY}/${IMAGE_REPO}"
  WATCHER_REPO="${PUSH_REGISTRY}/${WATCHER_REPO}"
fi

echo "Deploying Helm chart (release=${RELEASE}, namespace=${NAMESPACE})"

helm upgrade --install "${RELEASE}" ./helm/tinyproxy \
  --namespace "${NAMESPACE}" --create-namespace \
  --set image.repository="${IMAGE_REPO}" \
  --set image.tag="${IMAGE_TAG}" \
  --set image.pullPolicy="${PULL_POLICY}" \
  --set configWatcher.image.repository="${WATCHER_REPO}" \
  --set configWatcher.image.tag="${WATCHER_TAG}" \
  --set configWatcher.image.pullPolicy="${PULL_POLICY}" \
  -f "${VALUES_FILE}"

echo "Deployment complete. Verify pods with: kubectl get pods -n ${NAMESPACE} -l app=tinyproxy"

echo "To view config-watcher logs: kubectl logs -n ${NAMESPACE} -l app=tinyproxy -c config-watcher"
echo "To view tinyproxy logs: kubectl logs -n ${NAMESPACE} -l app=tinyproxy -c tinyproxy"
