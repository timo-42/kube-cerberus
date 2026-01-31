"""Integration tests for admission webhooks with kind cluster."""
import time
from typing import Dict, Any

import pytest
from kubernetes import client
from kubernetes.client.rest import ApiException

from kube_cerberus.validator import validating


@pytest.mark.integration
def test_kind_cluster_available(k8s_client):
    """Verify kind cluster is running and accessible."""
    core_api = k8s_client["core"]
    
    # List nodes
    nodes = core_api.list_node()
    assert len(nodes.items) > 0
    
    # Check node is ready
    node = nodes.items[0]
    ready_condition = next(
        (c for c in node.status.conditions if c.type == "Ready"), 
        None
    )
    assert ready_condition is not None
    assert ready_condition.status == "True"


@pytest.mark.integration
def test_webhook_server_running(webhook_server):
    """Verify webhook server is running and responsive."""
    import requests
    import json
    import urllib3
    
    # Disable SSL warnings for self-signed cert
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Create a test admission review
    admission_review = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "test-uid-123",
            "operation": "CREATE",
            "object": {
                "kind": "Pod",
                "apiVersion": "v1",
                "metadata": {"name": "test-pod", "labels": {}}
            }
        }
    }
    
    # Send request to webhook
    response = requests.post(
        f"https://localhost:8443/",
        json=admission_review,
        verify=False,  # Self-signed cert
        timeout=5
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["kind"] == "AdmissionReview"
    assert "response" in data
    assert data["response"]["uid"] == "test-uid-123"
    assert "allowed" in data["response"]


@pytest.mark.integration
def test_pod_validation_success(k8s_client, webhook_server, webhook_configured):
    """Test that a valid pod is accepted by the webhook."""
    
    # Register validator that requires 'app' label
    @validating("test-pod-validator", kind="Pod")
    def validate_pod(labels):
        return "app" in labels
    
    # Create valid pod with required label
    pod = client.V1Pod(
        metadata=client.V1ObjectMeta(
            name="valid-test-pod",
            labels={"app": "myapp"}
        ),
        spec=client.V1PodSpec(
            containers=[
                client.V1Container(
                    name="test",
                    image="nginx:alpine",
                )
            ]
        )
    )
    
    # Should succeed
    core_api = k8s_client["core"]
    try:
        created = core_api.create_namespaced_pod(namespace="default", body=pod)
        assert created.metadata.name == "valid-test-pod"
    finally:
        # Cleanup
        try:
            core_api.delete_namespaced_pod(
                "valid-test-pod", 
                "default",
                grace_period_seconds=0
            )
        except ApiException:
            pass


@pytest.mark.integration
def test_pod_validation_rejection(k8s_client, webhook_server, webhook_configured):
    """Test that an invalid pod is rejected by the webhook."""
    
    # Register validator that requires 'required-label'
    @validating("test-pod-validator", kind="Pod")
    def validate_pod(labels):
        return "required-label" in labels
    
    # Create invalid pod (missing required label)
    pod = client.V1Pod(
        metadata=client.V1ObjectMeta(
            name="invalid-test-pod",
            labels={"app": "myapp"}  # Missing 'required-label'
        ),
        spec=client.V1PodSpec(
            containers=[
                client.V1Container(
                    name="test", 
                    image="nginx:alpine"
                )
            ]
        )
    )
    
    # Should fail
    core_api = k8s_client["core"]
    with pytest.raises(ApiException) as exc_info:
        core_api.create_namespaced_pod(namespace="default", body=pod)
    
    # Verify rejection
    assert exc_info.value.status == 403 or exc_info.value.status == 400
    assert "Validation failed" in str(exc_info.value.body)


@pytest.mark.integration
def test_pod_validation_with_resource_limits(k8s_client, webhook_server, webhook_configured):
    """Test validation of pod resource limits."""
    
    # Register validator that requires resource limits
    @validating("resource-limit-validator", kind="Pod")
    def validate_resources(object):
        containers = object.get("spec", {}).get("containers", [])
        for container in containers:
            resources = container.get("resources", {})
            limits = resources.get("limits", {})
            if not limits.get("memory") or not limits.get("cpu"):
                return False
        return True
    
    # Test 1: Valid pod with limits should succeed
    valid_pod = client.V1Pod(
        metadata=client.V1ObjectMeta(
            name="pod-with-limits",
            labels={"test": "limits"}
        ),
        spec=client.V1PodSpec(
            containers=[
                client.V1Container(
                    name="test",
                    image="nginx:alpine",
                    resources=client.V1ResourceRequirements(
                        limits={"memory": "128Mi", "cpu": "100m"}
                    )
                )
            ]
        )
    )
    
    core_api = k8s_client["core"]
    try:
        created = core_api.create_namespaced_pod(namespace="default", body=valid_pod)
        assert created.metadata.name == "pod-with-limits"
    finally:
        try:
            core_api.delete_namespaced_pod(
                "pod-with-limits",
                "default", 
                grace_period_seconds=0
            )
        except ApiException:
            pass
    
    # Test 2: Invalid pod without limits should fail
    invalid_pod = client.V1Pod(
        metadata=client.V1ObjectMeta(
            name="pod-without-limits",
            labels={"test": "no-limits"}
        ),
        spec=client.V1PodSpec(
            containers=[
                client.V1Container(
                    name="test",
                    image="nginx:alpine"
                    # No resource limits
                )
            ]
        )
    )
    
    with pytest.raises(ApiException) as exc_info:
        core_api.create_namespaced_pod(namespace="default", body=invalid_pod)
    
    assert exc_info.value.status == 403 or exc_info.value.status == 400


@pytest.mark.integration
def test_multiple_validators(k8s_client, webhook_server, webhook_configured):
    """Test that multiple validators are all evaluated."""
    
    # Register first validator - checks for 'app' label
    @validating("label-validator", kind="Pod")
    def validate_labels(labels):
        return "app" in labels
    
    # Register second validator - checks for 'env' label
    @validating("env-validator", kind="Pod")
    def validate_env(labels):
        return "env" in labels
    
    # Pod with both labels should succeed
    valid_pod = client.V1Pod(
        metadata=client.V1ObjectMeta(
            name="multi-valid-pod",
            labels={"app": "myapp", "env": "test"}
        ),
        spec=client.V1PodSpec(
            containers=[
                client.V1Container(name="test", image="nginx:alpine")
            ]
        )
    )
    
    core_api = k8s_client["core"]
    try:
        created = core_api.create_namespaced_pod(namespace="default", body=valid_pod)
        assert created.metadata.name == "multi-valid-pod"
    finally:
        try:
            core_api.delete_namespaced_pod(
                "multi-valid-pod",
                "default",
                grace_period_seconds=0
            )
        except ApiException:
            pass
    
    # Pod missing 'env' label should fail
    invalid_pod = client.V1Pod(
        metadata=client.V1ObjectMeta(
            name="multi-invalid-pod",
            labels={"app": "myapp"}  # Missing 'env'
        ),
        spec=client.V1PodSpec(
            containers=[
                client.V1Container(name="test", image="nginx:alpine")
            ]
        )
    )
    
    with pytest.raises(ApiException) as exc_info:
        core_api.create_namespaced_pod(namespace="default", body=invalid_pod)
    
    assert exc_info.value.status == 403 or exc_info.value.status == 400
