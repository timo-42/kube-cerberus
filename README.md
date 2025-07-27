# kube-cerberus

A Kubernetes admission validation framework in Python that provides a simple decorator-based approach for creating admission controllers.

## TODO

- Return proper Kubernetes admission response dictionary format instead of simple boolean
- Add integration test with kind
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
        result = registry.validate(admission_request)
        
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

```bash
# Run tests
make test-unit

# Build wheel
make build-wheel

# Clean up
make clean
```