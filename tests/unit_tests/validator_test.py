import pytest
import re
from kube_cerberus.registry import REGISTRY
from kube_cerberus.validator import validating


@pytest.fixture(autouse=True)
def clean_registry():
    """Automatically clean the registry before each test"""
    REGISTRY.validating_hooks.clear()
    yield
    REGISTRY.validating_hooks.clear()


@pytest.fixture
def pod_request_factory():
    """Factory for creating Pod requests with different configurations"""
    def _create_pod_request(
        name="test-pod",
        namespace="default", 
        labels=None,
        spec=None,
        operation="CREATE"
    ):
        if labels is None:
            labels = {"app": "myapp"}
            
        request = {
            "object": {
                "kind": "Pod",
                "apiVersion": "v1",
                "metadata": {
                    "name": name,
                    "namespace": namespace,
                    "labels": labels
                }
            },
            "operation": operation
        }
        
        if spec:
            request["object"]["spec"] = spec
            
        return request
    
    return _create_pod_request


@pytest.fixture
def basic_pod_request(pod_request_factory):
    """A basic Pod request for testing"""
    return pod_request_factory()


@pytest.fixture
def production_pod_request(pod_request_factory):
    """A Pod request in production namespace with security labels"""
    return pod_request_factory(
        name="secure-pod",
        namespace="production",
        labels={
            "app": "myapp",
            "security-scan": "passed"
        },
        spec={
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 1000
            },
            "containers": [
                {
                    "name": "app",
                    "image": "myapp:latest",
                    "resources": {
                        "limits": {
                            "memory": "512Mi",
                            "cpu": "500m"
                        }
                    }
                }
            ]
        }
    )


@pytest.fixture
def valid_pod_with_env_request(pod_request_factory):
    """A Pod request with valid naming and env label"""
    return pod_request_factory(
        name="valid-pod",
        labels={"env": "test"}
    )


def test_end_to_end_validation_success(basic_pod_request):
    """Test complete end-to-end validation flow with success"""
    @validating("pod-validator", kind="Pod", namespace="default")
    def validate_pod(labels, metadata):
        # Access name from metadata since 'name' alone gets empty dict when missing
        name = metadata.get("name", "")
        return "app" in labels and name.startswith("test-")
        
    # Update the request to match validator conditions
    basic_pod_request["object"]["metadata"]["namespace"] = "default"
    
    result = REGISTRY.validate_request(basic_pod_request)
    assert result is True


def test_end_to_end_validation_failure(basic_pod_request):
    """Test complete end-to-end validation flow with failure"""
    @validating("pod-validator", kind="Pod")
    def validate_pod(labels):
        return "required-label" in labels
        
    # basic_pod_request already has labels without "required-label"
    result = REGISTRY.validate_request(basic_pod_request)
    assert result is False


def test_end_to_end_validation_with_no_validators(basic_pod_request):
    """Test that validation passes when no validators are registered"""
    result = REGISTRY.validate_request(basic_pod_request)
    assert result is True


def test_end_to_end_validation_pre_condition_filter(basic_pod_request):
    """Test that pre-conditions properly filter requests"""
    @validating("service-validator", kind="Service")
    def validate_service():
        return False  # This should not be called for Pod
        
    # New behavior: pre-condition mismatch skips validator
    result = REGISTRY.validate_request(basic_pod_request)
    assert result is True


def test_multiple_validators_all_pass(valid_pod_with_env_request):
    """Test multiple validators where all pass"""
    @validating("validator1", kind="Pod")
    def validate1(metadata):
        name = metadata.get("name", "")
        return name.startswith("valid-")
        
    @validating("validator2", kind="Pod")
    def validate2(labels):
        return "env" in labels
        
    result = REGISTRY.validate_request(valid_pod_with_env_request)
    assert result is True


def test_multiple_validators_one_fails(valid_pod_with_env_request):
    """Test multiple validators where one fails"""
    @validating("validator1", kind="Pod")
    def validate1(metadata):
        name = metadata.get("name", "")
        return name.startswith("valid-")
        
    @validating("validator2", kind="Pod")
    def validate2(labels):
        return "required" in labels  # This will fail
        
    result = REGISTRY.validate_request(valid_pod_with_env_request)
    assert result is False


def test_complex_validation_scenario(production_pod_request, pod_request_factory):
    """Test a complex real-world validation scenario with multiple conditions"""
    @validating("security-validator", kind="Pod", namespace="production")
    def validate_security_requirements(labels, metadata, object):
        # Check for required security labels
        if "security-scan" not in labels:
            return False
        
        # Check for security context
        spec = object.get("spec", {})
        security_context = spec.get("securityContext", {})
        
        # Must run as non-root
        if security_context.get("runAsNonRoot") is not True:
            return False
            
        return True
    
    @validating("resource-validator", kind="Pod")
    def validate_resource_limits(object):
        spec = object.get("spec", {})
        containers = spec.get("containers", [])
        
        # All containers must have resource limits
        for container in containers:
            resources = container.get("resources", {})
            limits = resources.get("limits", {})
            
            if "memory" not in limits or "cpu" not in limits:
                return False
                
        return True
    
    # Test request that should pass all validations (using fixture)
    result = REGISTRY.validate_request(production_pod_request)
    assert result is True
    
    # Test request that should fail security validation (using factory)
    insecure_request = pod_request_factory(
        name="insecure-pod",
        namespace="production",
        labels={"app": "myapp"},  # Missing security-scan label
        spec={
            "securityContext": {"runAsNonRoot": True},
            "containers": [
                {
                    "name": "app",
                    "image": "myapp:latest",
                    "resources": {
                        "limits": {"memory": "512Mi", "cpu": "500m"}
                    }
                }
            ]
        }
    )
    
    # Reset and re-register validators for this test
    REGISTRY.validating_hooks.clear()
    
    @validating("security-validator", kind="Pod", namespace="production")
    def validate_security_requirements_2(labels, metadata, object):
        if "security-scan" not in labels:
            return False
        return True
    
    result = REGISTRY.validate_request(insecure_request)
    assert result is False


@pytest.fixture
def regex_patterns():
    """Common regex patterns for testing"""
    return {
        "kind_pattern": re.compile(r"^(Pod|Deployment|StatefulSet)$"),
        "namespace_pattern": re.compile(r"^(prod|staging)-.*")
    }


@pytest.fixture
def prod_namespace_requests(pod_request_factory):
    """Requests for testing prod namespace scenarios"""
    return {
        "pod_with_owner": pod_request_factory(
            name="test-pod",
            namespace="prod-myapp",
            labels={"owner": "team-a"}
        ),
        "deployment_without_owner": {
            "object": {
                "kind": "Deployment",
                "apiVersion": "apps/v1",  
                "metadata": {
                    "name": "test-deployment",
                    "namespace": "staging-myapp",
                    "labels": {"app": "myapp"}  # Missing owner label
                }
            },
            "operation": "CREATE"
        },
        "service_in_prod": {
            "object": {
                "kind": "Service",  # Not matched by regex
                "apiVersion": "v1",
                "metadata": {
                    "name": "test-service",
                    "namespace": "prod-myapp",
                    "labels": {"app": "myapp"}
                }
            },
            "operation": "CREATE"
        }
    }


def test_validation_with_regex_conditions(regex_patterns, prod_namespace_requests):
    """Test validation with regex-based pre-conditions"""
    # Validator that applies to multiple kinds using regex
    @validating("workload-validator", 
                kind=regex_patterns["kind_pattern"], 
                namespace=regex_patterns["namespace_pattern"])
    def validate_workload(labels, metadata):
        # Require owner label for all workloads in prod/staging
        return "owner" in labels
    
    # Test Pod in prod namespace - should be validated
    result = REGISTRY.validate_request(prod_namespace_requests["pod_with_owner"])
    assert result is True
    
    # Test Deployment in staging namespace without owner - should fail
    # Reset and re-register for this specific test
    REGISTRY.validating_hooks.clear()
    
    @validating("workload-validator", 
                kind=regex_patterns["kind_pattern"], 
                namespace=regex_patterns["namespace_pattern"])
    def validate_workload_2(labels, metadata):
        return "owner" in labels
    
    result = REGISTRY.validate_request(prod_namespace_requests["deployment_without_owner"])
    assert result is False
    
    # Test Service in prod namespace - should pass (validator doesn't apply)
    result = REGISTRY.validate_request(prod_namespace_requests["service_in_prod"])
    assert result is True
