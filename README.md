# kube-cerberus

A Kubernetes admission validation framework in Python that provides a simple decorator-based approach for creating admission controllers.

## Features

- **Simple decorator-based API** - Use `@validating` decorator to register validation functions
- **Flexible filtering** - Filter by kind, namespace, apiVersion, or operation using strings or regex
- **Proper Kubernetes format** - Returns standard AdmissionReview responses
- **Zero dependencies** - Core framework has no external dependencies
- **Comprehensive testing** - Unit tests and integration tests with kind

## TODO

- Add mutating webhook framework

## Quick Start

Create your admission webhook server in just a few lines:

```python
from kube_cerberus.validator import validating
from kube_cerberus.registry import Registry
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

# Define your validators
@validating(name="pod-validator", kind="Pod")
def validate_pods(object: dict) -> bool:
    """Validate Pod resources - ensure they have resource limits"""
    containers = object.get("spec", {}).get("containers", [])
    for container in containers:
        resources = container.get("resources", {})
        if not resources.get("limits"):
            return False  # Reject pods without resource limits
    return True

@validating(name="namespace-validator", kind="Namespace")
def validate_namespaces(object: dict) -> bool:
    """Ensure namespaces follow naming conventions"""
    name = object.get("metadata", {}).get("name", "")
    return name.startswith(("dev-", "prod-", "staging-"))

# Create webhook server
class AdmissionWebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)
        admission_request = json.loads(body)
        
        # Process with registry
        registry = Registry()
        result = registry.process_admission_review(admission_request)
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(result).encode())

if __name__ == "__main__":
    server = HTTPServer(('0.0.0.0', 8443), AdmissionWebhookHandler)
    print("Admission webhook server running on port 8443...")
    server.serve_forever()
```

Run your webhook server:
```bash
python webhook_server.py
```

## Development

### Running Tests

```bash
# Run unit tests only
make test-unit

# Run integration tests (requires Docker)
make test-integration

# Run all tests
make test-all

# Build wheel
make build-wheel

# Clean up
make clean
```

### Integration Tests

Integration tests use [kind](https://kind.sigs.k8s.io/) (Kubernetes in Docker) to test the admission webhook in a real Kubernetes cluster.

**Prerequisites:**
- Docker Desktop (or Docker daemon)
- kubectl (install from [kubernetes.io](https://kubernetes.io/docs/tasks/tools/))
- kind (auto-installed by setup script if missing)

**Running integration tests:**

```bash
# Setup kind cluster (one-time)
make test-integration-setup

# Run integration tests
make test-integration

# Cleanup cluster when done
make test-integration-teardown
```

**Note:** The kind cluster is reused across test runs for speed. To start fresh, run `make test-integration-teardown` first.

### Test Coverage

- **Unit tests** (`tests/unit_tests/`): Fast tests with no external dependencies
  - Registry and validator logic
  - Pre-condition checking
  - Field extraction
  - End-to-end validation flows

- **Integration tests** (`tests/integration_tests/`): Real Kubernetes cluster tests
  - Pod validation acceptance
  - Pod validation rejection
  - Multiple validators
  - Resource limit validation
  - Webhook server health checks