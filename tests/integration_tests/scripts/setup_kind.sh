#!/usr/bin/env bash
# Setup kind cluster for integration tests
# Works both locally and in CI

set -e

CLUSTER_NAME="${CLUSTER_NAME:-cerberus-test}"
KIND_CONFIG="${KIND_CONFIG:-}"

echo "🔧 Setting up kind cluster: $CLUSTER_NAME"

# Check if kind is installed
if ! command -v kind &> /dev/null; then
    echo "❌ kind not found. Installing..."
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-darwin-amd64
    else
        echo "❌ Unsupported OS: $OSTYPE"
        exit 1
    fi
    chmod +x ./kind
    sudo mv ./kind /usr/local/bin/kind
    echo "✅ kind installed"
fi

# Check if kubectl is installed
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl not found. Please install kubectl first."
    echo "   Visit: https://kubernetes.io/docs/tasks/tools/"
    exit 1
fi

# Check if cluster already exists
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    echo "✅ Cluster $CLUSTER_NAME already exists"
else
    echo "🚀 Creating kind cluster..."
    
    # Create cluster with extra port mappings for webhook server
    cat <<EOF | kind create cluster --name "$CLUSTER_NAME" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: 443
    hostPort: 6443
    protocol: TCP
EOF
    
    echo "⏳ Waiting for cluster to be ready..."
    kubectl wait --for=condition=Ready nodes --all --timeout=300s --context "kind-${CLUSTER_NAME}"
fi

# Set kubectl context
kubectl config use-context "kind-${CLUSTER_NAME}"

echo "✅ Kind cluster ready!"
kubectl cluster-info --context "kind-${CLUSTER_NAME}"
kubectl get nodes
