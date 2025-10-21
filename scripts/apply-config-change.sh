#!/bin/bash
set -e

# Script to apply tinyproxy configuration changes via Helm
# This updates the ConfigMap and the config-watcher will reload tinyproxy
#
# Usage: ./apply-config-change.sh [namespace]
#   namespace: Kubernetes namespace (default: default)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VALUES_FILE="${PROJECT_DIR}/helm/tinyproxy/values.yaml"
RELEASE_NAME="tinyproxy"
NAMESPACE="${1:-default}"

echo "========================================="
echo "Tinyproxy Config Update Script"
echo "========================================="
echo "Namespace: $NAMESPACE"
echo ""

# Check if values file exists
if [ ! -f "$VALUES_FILE" ]; then
    echo "ERROR: values.yaml not found at $VALUES_FILE"
    exit 1
fi

# Get current pod name
POD_NAME=$(kubectl get pods -n "$NAMESPACE" -l app=tinyproxy -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
if [ -z "$POD_NAME" ]; then
    echo "ERROR: No tinyproxy pod found in namespace $NAMESPACE"
    exit 1
fi

echo "Current pod: $POD_NAME"
echo ""

# Show current config value
echo "Current configuration:"
kubectl exec -n "$NAMESPACE" "$POD_NAME" -c tinyproxy -- cat /etc/tinyproxy/tinyproxy.conf | grep -E "TrafficControl" | head -5
echo ""

# Apply the Helm upgrade
echo "Applying Helm upgrade at $(date)..."
helm upgrade "$RELEASE_NAME" "${PROJECT_DIR}/helm/tinyproxy" --values "$VALUES_FILE" -n "$NAMESPACE"

if [ $? -ne 0 ]; then
    echo "ERROR: Helm upgrade failed"
    exit 1
fi

echo ""
echo "Helm upgrade successful. ConfigMap has been updated."
echo ""

# Check if user wants to wait and monitor
read -p "Wait and monitor for config reload? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Waiting 90 seconds for ConfigMap propagation to pod..."
    echo "(ConfigMap updates can take 60-120 seconds to sync to mounted volumes)"
    echo ""
    
    # Show a progress indicator
    for i in {1..90}; do
        echo -ne "\rWaiting... $i/90 seconds"
        sleep 1
    done
    echo ""
    echo ""
    
    # Check config-watcher logs
    echo "========================================="
    echo "Config-watcher logs:"
    echo "========================================="
    kubectl logs -n "$NAMESPACE" "$POD_NAME" -c config-watcher --tail=20
    echo ""
    
    # Check if reload happened
    if kubectl logs -n "$NAMESPACE" "$POD_NAME" -c config-watcher --tail=20 | grep -q "change detected"; then
        echo "✓ Config change detected by watcher!"
        
        if kubectl logs -n "$NAMESPACE" "$POD_NAME" -c config-watcher --tail=20 | grep -q "SIGUSR1 sent successfully"; then
            echo "✓ SIGUSR1 sent successfully to tinyproxy"
        else
            echo "⚠ Warning: Could not confirm SIGUSR1 was sent"
        fi
    else
        echo "⚠ Config change not yet detected. ConfigMap may still be propagating."
        echo "  Run this command to check later:"
        echo "  kubectl logs -n $NAMESPACE $POD_NAME -c config-watcher --tail=20"
    fi
    echo ""
    
    # Check tinyproxy logs for reload
    echo "========================================="
    echo "Tinyproxy logs (last 10 lines):"
    echo "========================================="
    kubectl logs -n "$NAMESPACE" "$POD_NAME" -c tinyproxy --tail=10
    echo ""
    
    if kubectl logs -n "$NAMESPACE" "$POD_NAME" -c tinyproxy --tail=20 | grep -q "Reloading config"; then
        echo "✓ Config reload detected in tinyproxy logs!"
    fi
    echo ""
    
    # Show new config
    echo "========================================="
    echo "Current configuration in pod:"
    echo "========================================="
    kubectl exec -n "$NAMESPACE" "$POD_NAME" -c tinyproxy -- cat /etc/tinyproxy/tinyproxy.conf | grep -E "TrafficControl" | head -5
    echo ""
fi

echo "========================================="
echo "Config update process complete!"
echo "========================================="
echo ""
echo "To manually verify the reload:"
echo "  kubectl logs -n $NAMESPACE $POD_NAME -c config-watcher"
echo "  kubectl logs -n $NAMESPACE $POD_NAME -c tinyproxy | grep -i reload"
echo ""
echo "To check current config:"
echo "  kubectl exec -n $NAMESPACE $POD_NAME -c tinyproxy -- cat /etc/tinyproxy/tinyproxy.conf | grep TrafficControl"
echo ""
