"""
Examples demonstrating all parameters of the @validating decorator.

This file shows how to use the @validating decorator with all possible parameters
and function arguments. Each example includes explanations of what it does.
"""

import re
from kube_cerberus.validator import validating


# =============================================================================
# DECORATOR PARAMETERS EXAMPLES
# =============================================================================

# Example 1: Basic validator with just a name
@validating(name="basic-validator")
def basic_validation() -> bool:
    """
    Simplest validator - applies to all resources, all operations.
    Returns True to allow everything.
    """
    print("Basic validator called - allowing all requests")
    return True


# Example 2: Filter by Kubernetes resource kind (exact match)
@validating(name="pod-validator", kind="Pod")
def validate_pods(object: dict) -> bool:
    """
    Only validates Pod resources.
    Checks if the pod has required labels.
    """
    labels = object.get("metadata", {}).get("labels", {})
    required_label = "app"
    
    if required_label not in labels:
        print(f"Pod missing required label: {required_label}")
        return False
    
    print(f"Pod validation passed for: {labels.get('app')}")
    return True


# Example 3: Filter by namespace (exact match)
@validating(name="production-validator", namespace="production")
def validate_production_resources(object: dict, metadata: dict) -> bool:
    """
    Only validates resources in the 'production' namespace.
    Ensures production resources have proper annotations.
    """
    annotations = metadata.get("annotations", {})
    
    if "owner" not in annotations:
        print("Production resource missing 'owner' annotation")
        return False
    
    if "contact" not in annotations:
        print("Production resource missing 'contact' annotation")
        return False
    
    print(f"Production resource validated for owner: {annotations['owner']}")
    return True


# Example 4: Filter by API version (exact match)
@validating(name="apps-v1-validator", apiVersion="apps/v1")
def validate_apps_v1_resources(object: dict) -> bool:
    """
    Only validates resources with apiVersion 'apps/v1' (Deployments, ReplicaSets, etc.)
    Ensures they have proper resource limits.
    """
    spec = object.get("spec", {})
    template = spec.get("template", {})
    containers = template.get("spec", {}).get("containers", [])
    
    for container in containers:
        resources = container.get("resources", {})
        if "limits" not in resources:
            print(f"Container {container.get('name')} missing resource limits")
            return False
    
    print("All containers have resource limits")
    return True


# Example 5: Filter by operation (exact match)
@validating(name="delete-protector", operation="DELETE")
def protect_from_deletion(object: dict, labels: dict) -> bool:
    """
    Only validates DELETE operations.
    Prevents deletion of resources with 'protected=true' label.
    """
    if labels.get("protected") == "true":
        print(f"Preventing deletion of protected resource: {object.get('metadata', {}).get('name')}")
        return False
    
    print("Delete operation allowed")
    return True


# =============================================================================
# REGEX PATTERN EXAMPLES
# =============================================================================

# Example 6: Multiple kinds using regex
@validating(name="workload-validator", kind=re.compile(r"^(Pod|Deployment|StatefulSet|DaemonSet)$"))
def validate_workloads(object: dict, labels: dict) -> bool:
    """
    Validates multiple workload types using regex pattern.
    Ensures all workloads have environment and version labels.
    """
    required_labels = ["environment", "version"]
    
    for label in required_labels:
        if label not in labels:
            print(f"Workload missing required label: {label}")
            return False
    
    print(f"Workload validation passed for {object.get('kind')}")
    return True


# Example 7: Namespace pattern matching
@validating(name="env-namespace-validator", namespace=re.compile(r"^(dev|test|staging|prod)-.*"))
def validate_environment_namespaces(object: dict, namespace: str) -> bool:
    """
    Validates resources in namespaces matching environment patterns.
    Ensures resources in env namespaces have proper environment labels.
    """
    labels = object.get("metadata", {}).get("labels", {})
    
    # Extract environment from namespace (dev-*, test-*, etc.)
    env_prefix = namespace.split("-")[0]
    
    if labels.get("environment") != env_prefix:
        print(f"Resource in {namespace} must have environment={env_prefix} label")
        return False
    
    print(f"Environment validation passed for namespace: {namespace}")
    return True


# Example 8: API version pattern
@validating(name="core-api-validator", apiVersion=re.compile(r"^v1$|^.*\.k8s\.io/v.*"))
def validate_core_apis(object: dict) -> bool:
    """
    Validates core Kubernetes APIs and k8s.io group APIs.
    Ensures they follow naming conventions.
    """
    name = object.get("metadata", {}).get("name", "")
    
    # Validate naming convention
    if not re.match(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", name):
        print(f"Invalid name format: {name}")
        return False
    
    print(f"Core API resource name validation passed: {name}")
    return True


# Example 9: Operation pattern (CREATE or UPDATE only)
@validating(name="mutation-validator", operation=re.compile(r"^(CREATE|UPDATE)$"))
def validate_mutations(object: dict, operation: str, oldObject: dict) -> bool:
    """
    Only validates CREATE and UPDATE operations (not DELETE or CONNECT).
    Ensures immutable fields aren't changed on updates.
    """
    if operation == "UPDATE":
        # Check immutable fields haven't changed
        old_labels = oldObject.get("metadata", {}).get("labels", {})
        new_labels = object.get("metadata", {}).get("labels", {})
        
        # 'immutable' label cannot be changed
        if old_labels.get("immutable") != new_labels.get("immutable"):
            print("Cannot modify 'immutable' label on existing resource")
            return False
    
    print(f"Mutation validation passed for {operation}")
    return True


# =============================================================================
# FUNCTION PARAMETER EXAMPLES (All possible function arguments)
# =============================================================================

# Example 10: Using all possible function parameters
@validating(name="comprehensive-validator", kind="Service")
def comprehensive_validation(
    object: dict,           # The Kubernetes resource being validated
    oldObject: dict,        # Previous state (for UPDATE/DELETE)
    raw_object: dict,       # Complete admission request
    metadata: dict,         # Resource metadata section
    labels: dict,           # Resource labels
    annotations: dict,      # Resource annotations
    name: str,             # Resource name
    namespace: str,        # Resource namespace
    status: dict,          # Resource status section
    operation: str,        # Admission operation (CREATE/UPDATE/DELETE/CONNECT)
    userInfo: dict         # User making the request
) -> bool:
    """
    Demonstrates all possible function parameters.
    Performs comprehensive validation using all available data.
    """
    print(f"=== Comprehensive Validation for {name} ===")
    print(f"Operation: {operation}")
    print(f"Namespace: {namespace}")
    print(f"User: {userInfo.get('username', 'unknown')}")
    print(f"Kind: {object.get('kind')}")
    print(f"Labels: {labels}")
    print(f"Annotations: {annotations}")
    
    # Example validations using different parameters
    
    # 1. Check user permissions
    username = userInfo.get("username", "")
    if namespace == "kube-system" and not username.startswith("system:"):
        print("Only system users can modify kube-system resources")
        return False
    
    # 2. Validate labels
    if "app" not in labels:
        print("All services must have an 'app' label")
        return False
    
    # 3. Check annotations for specific requirements
    if annotations.get("service.beta.kubernetes.io/aws-load-balancer-type") == "nlb":
        if "service.beta.kubernetes.io/aws-load-balancer-scheme" not in annotations:
            print("NLB services must specify load balancer scheme")
            return False
    
    # 4. For updates, check what changed
    if operation == "UPDATE" and oldObject:
        old_ports = oldObject.get("spec", {}).get("ports", [])
        new_ports = object.get("spec", {}).get("ports", [])
        
        if len(old_ports) != len(new_ports):
            print("Cannot change number of service ports")
            return False
    
    # 5. Check status (if present)
    if status and status.get("loadBalancer", {}).get("ingress"):
        print("Service has external load balancer assigned")
    
    print("Comprehensive validation passed")
    return True


# =============================================================================
# COMPLEX SCENARIOS
# =============================================================================

# Example 11: Multiple filters combined
@validating(
    name="strict-production-pods",
    kind="Pod",
    namespace=re.compile(r"^prod-.*"),
    operation=re.compile(r"^(CREATE|UPDATE)$")
)
def validate_production_pods(object: dict, labels: dict, annotations: dict, userInfo: dict) -> bool:
    """
    Complex validator combining multiple filters:
    - Only Pods
    - Only prod-* namespaces  
    - Only CREATE/UPDATE operations
    
    Enforces strict production requirements.
    """
    # Security: Check user permissions
    username = userInfo.get("username", "")
    allowed_users = ["system:serviceaccount:prod-deploy:deployer", "admin@company.com"]
    
    if username not in allowed_users:
        print(f"User {username} not authorized to deploy to production")
        return False
    
    # Resource requirements
    containers = object.get("spec", {}).get("containers", [])
    for container in containers:
        resources = container.get("resources", {})
        
        # Must have limits
        limits = resources.get("limits", {})
        if not limits.get("memory") or not limits.get("cpu"):
            print(f"Production pod container {container.get('name')} missing resource limits")
            return False
        
        # Must have requests
        requests = resources.get("requests", {})
        if not requests.get("memory") or not requests.get("cpu"):
            print(f"Production pod container {container.get('name')} missing resource requests")
            return False
    
    # Security context requirements
    security_context = object.get("spec", {}).get("securityContext", {})
    if not security_context.get("runAsNonRoot"):
        print("Production pods must run as non-root")
        return False
    
    # Required labels
    required_labels = ["app", "version", "environment", "team"]
    for label in required_labels:
        if label not in labels:
            print(f"Production pod missing required label: {label}")
            return False
    
    # Environment label must match namespace
    if not labels.get("environment", "").startswith("prod"):
        print("Production pod must have environment label starting with 'prod'")
        return False
    
    print(f"Production pod validation passed for {labels.get('app')}")
    return True


# Example 12: User-based validation
@validating(name="user-access-validator")
def validate_user_access(object: dict, namespace: str, userInfo: dict) -> bool:
    """
    Validates based on user information.
    Implements role-based access control.
    """
    username = userInfo.get("username", "")
    groups = userInfo.get("groups", [])
    
    # Admin users can do anything
    if "system:masters" in groups:
        print(f"Admin user {username} - allowing all operations")
        return True
    
    # Developers can only work in dev namespaces
    if any(group.startswith("dev-") for group in groups):
        if not namespace.startswith("dev-"):
            print(f"Developer {username} cannot access namespace {namespace}")
            return False
    
    # Service accounts must match namespace
    if username.startswith("system:serviceaccount:"):
        sa_namespace = username.split(":")[2]
        if sa_namespace != namespace:
            print(f"Service account {username} cannot access different namespace {namespace}")
            return False
    
    print(f"User access validation passed for {username}")
    return True


# Example 13: Resource quota enforcement
@validating(name="resource-quota-validator", kind=re.compile(r"^(Pod|Deployment|StatefulSet)$"))
def validate_resource_quotas(object: dict, namespace: str) -> bool:
    """
    Validates resource requests against namespace quotas.
    Prevents resource exhaustion.
    """
    # Define namespace resource limits
    namespace_limits = {
        "small": {"cpu": "2", "memory": "4Gi"},
        "medium": {"cpu": "8", "memory": "16Gi"},
        "large": {"cpu": "32", "memory": "64Gi"}
    }
    
    # Determine namespace size category
    size_category = "small"  # default
    for category in namespace_limits:
        if category in namespace:
            size_category = category
            break
    
    limits = namespace_limits[size_category]
    
    # Extract resource requests
    containers = []
    if object.get("kind") == "Pod":
        containers = object.get("spec", {}).get("containers", [])
    else:
        # For Deployments/StatefulSets, look in template
        containers = object.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
    
    total_cpu = 0
    total_memory = 0
    
    for container in containers:
        requests = container.get("resources", {}).get("requests", {})
        
        # Parse CPU (assume millicores if no unit)
        cpu_str = requests.get("cpu", "0")
        if cpu_str.endswith("m"):
            cpu_millicores = int(cpu_str[:-1])
        else:
            cpu_millicores = int(float(cpu_str) * 1000)
        total_cpu += cpu_millicores
        
        # Parse memory (convert to MB)
        memory_str = requests.get("memory", "0")
        if memory_str.endswith("Gi"):
            memory_mb = int(float(memory_str[:-2]) * 1024)
        elif memory_str.endswith("Mi"):
            memory_mb = int(memory_str[:-2])
        else:
            memory_mb = int(memory_str) // (1024 * 1024)  # bytes to MB
        total_memory += memory_mb
    
    # Convert limits to same units for comparison
    limit_cpu_millicores = int(float(limits["cpu"]) * 1000)
    limit_memory_mb = int(float(limits["memory"][:-2]) * 1024)  # Gi to MB
    
    if total_cpu > limit_cpu_millicores:
        print(f"Resource request exceeds CPU limit: {total_cpu}m > {limit_cpu_millicores}m")
        return False
    
    if total_memory > limit_memory_mb:
        print(f"Resource request exceeds memory limit: {total_memory}Mi > {limit_memory_mb}Mi")
        return False
    
    print(f"Resource quota validation passed for {namespace} ({size_category})")
    return True


if __name__ == "__main__":
    print("This file contains examples of the @validating decorator.")
    print("Import these examples or copy them to your own validation files.")
    print(f"Total examples: 13")
