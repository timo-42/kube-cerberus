#!/usr/bin/env bash
# Teardown kind cluster

set -e

CLUSTER_NAME="${CLUSTER_NAME:-cerberus-test}"

echo "🧹 Tearing down kind cluster: $CLUSTER_NAME"

if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    kind delete cluster --name "$CLUSTER_NAME"
    echo "✅ Cluster deleted"
else
    echo "ℹ️  Cluster $CLUSTER_NAME does not exist"
fi
