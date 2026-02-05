"""
Validator module containing the @validating decorator and helper functions.

This module provides the @validating decorator used to register Kubernetes admission
validation functions, along with supporting helper functions.
"""

from typing import Any, Callable
import re
import inspect

# Import required classes from registry module
from .registry import REGISTRY, MutatingHook, Mutator, Validator, ValidatingHook


def create_condition_check(field_path: list[str], expected_value: str | re.Pattern):
    """Create a condition check that returns True on match and None on mismatch."""

    def check(request: dict[str, Any]) -> bool | None:
        # Navigate through nested dict using field_path
        current = request
        for field in field_path:
            if isinstance(current, dict):
                current = current.get(field, {})
            else:
                current = {}
                break

        actual_value = current if isinstance(current, str) else ""

        if isinstance(expected_value, re.Pattern):
            if not actual_value:
                return None
            return True if expected_value.match(actual_value) else None

        if not actual_value:
            return None
        return True if actual_value == expected_value else None

    return check


def create_pre_conditions(
    kind: str | re.Pattern | None,
    namespace: str | re.Pattern | None,
    apiVersion: str | re.Pattern | None,
    operation: str | re.Pattern | None,
) -> list:
    """Create pre-conditions based on provided parameters."""
    pre_conditions = []

    condition_mappings: list[tuple[str | re.Pattern | None, list[str]]] = [
        (kind, ["object", "kind"]),
        (namespace, ["object", "metadata", "namespace"]),
        (apiVersion, ["object", "apiVersion"]),
        (operation, ["operation"]),
    ]

    for value, path in condition_mappings:
        if value is not None:
            pre_conditions.append(create_condition_check(path, value))

    return pre_conditions


def extract_fields_from_signature(f: Callable) -> dict[str, list[str]]:
    """Extract the fields that need to be passed to the function based on signature."""
    sig = inspect.signature(f)
    extract_fields = {}

    # Mapping of parameter names to their paths in the request
    field_mappings = {
        "labels": ["object", "metadata", "labels"],
        "annotations": ["object", "metadata", "annotations"],
        "name": ["object", "metadata", "name"],
        "namespace": ["object", "metadata", "namespace"],
        "status": ["object", "status"],
        "metadata": ["object", "metadata"],
        "object": ["object"],  # The Kubernetes resource being validated
        "oldObject": ["oldObject"],  # The previous state (for DELETE/UPDATE)
        "operation": ["operation"],  # The admission operation (CREATE, UPDATE, DELETE, CONNECT)
        "userInfo": ["userInfo"],  # Information about the user making the request
        "raw_object": [],  # Special case - pass the entire request
    }
    
    for param_name in sig.parameters:
        if param_name in field_mappings:
            extract_fields[param_name] = field_mappings[param_name]
    
    return extract_fields


def validating(
    name: str,
    kind: str | re.Pattern | None = None,
    namespace: str | re.Pattern | None = None,
    apiVersion: str | re.Pattern | None = None,
    operation: str | re.Pattern | None = None,
):
    """
    Decorator to register a Kubernetes admission validation function.
    
    This decorator registers a function as a validation hook that will be called
    during Kubernetes admission control. The function will only be invoked if
    all pre-conditions (kind, namespace, apiVersion, operation) match the incoming request.
    
    Args:
        name: Unique name for this validator. Must be unique across all validators.
        kind: Optional filter - only validate resources of this kind. Can be:
            - str: Exact match (e.g., "Pod", "Service")
            - re.Pattern: Regex pattern (e.g., re.compile(r"^(Pod|Service)$"))
            - None: Accept all kinds
        namespace: Optional filter - only validate resources in this namespace. Can be:
            - str: Exact match (e.g., "default", "kube-system")
            - re.Pattern: Regex pattern (e.g., re.compile(r"^prod-.*"))
            - None: Accept all namespaces
        apiVersion: Optional filter - only validate resources with this API version. Can be:
            - str: Exact match (e.g., "v1", "apps/v1")
            - re.Pattern: Regex pattern
            - None: Accept all API versions
        operation: Optional filter - only validate specific operations. Can be:
            - str: Exact match (e.g., "CREATE", "UPDATE", "DELETE", "CONNECT")
            - re.Pattern: Regex pattern (e.g., re.compile(r"^(CREATE|UPDATE)$"))
            - None: Accept all operations
    
    The decorated function can accept any combination of these parameters:
        - object: The Kubernetes resource being validated (dict)
        - oldObject: Previous state of the resource for UPDATE/DELETE (dict)
        - raw_object: The complete admission request (dict)
        - metadata: The resource's metadata section (dict)
        - labels: The resource's labels (dict)
        - annotations: The resource's annotations (dict)
        - name: The resource's name (str)
        - namespace: The resource's namespace (str)
        - status: The resource's status section (dict)
        - operation: The admission operation being performed (str)
        - userInfo: Information about the user making the request (dict)
    
    Returns:
        The decorated function, unchanged. The function must return a boolean:
        - True: Allow the request
        - False: Deny the request
    
    Raises:
        Exception: If a validator with the same name already exists
    
    Examples:
        @validating("pod-validator", kind="Pod", namespace="production")
        def validate_production_pods(object: dict, labels: dict) -> bool:
            return "app" in labels and labels["app"] != "forbidden"
        
        @validating("update-tracker", operation="UPDATE")
        def track_updates(object: dict, oldObject: dict, operation: str) -> bool:
            print(f"Resource updated: {object.get('metadata', {}).get('name')}")
            return True
        
        @validating("delete-protector", operation="DELETE", kind="Service")
        def protect_critical_services(object: dict, labels: dict) -> bool:
            return labels.get("critical") != "true"
        
        @validating("create-only", operation=re.compile(r"^(CREATE|UPDATE)$"))
        def validate_mutations(object: dict, operation: str) -> bool:
            if operation == "CREATE":
                return "owner" in object.get("metadata", {}).get("labels", {})
            return True  # Allow updates
        
        @validating("user-based-validator")
        def validate_by_user(object: dict, userInfo: dict) -> bool:
            username = userInfo.get("username", "")
            # Only allow admins to create resources in kube-system
            if object.get("metadata", {}).get("namespace") == "kube-system":
                return username == "admin"
            return True
        
        @validating("service-account-validator", kind="Pod")
        def validate_service_accounts(object: dict, userInfo: dict) -> bool:
            # Block certain service accounts from creating pods
            blocked_users = ["system:serviceaccount:default:malicious"]
            return userInfo.get("username", "") not in blocked_users
    """
    def inner(f):
        # Create pre-conditions and extract fields
        pre_conditions = create_pre_conditions(kind, namespace, apiVersion, operation)
        extract_fields = extract_fields_from_signature(f)

        # Create a validator with the decorated function and pre-conditions
        validator = Validator(
            pre_conditions=pre_conditions,
            user_function=f,
            name=name,
            extract_fields=extract_fields,
            kind_filter=kind,
            namespace_filter=namespace,
            api_version_filter=apiVersion,
            operation_filter=operation,
        )

        # Check if hook exists, if it does throw an exception
        if name in REGISTRY.validating_hooks:
            raise Exception(f"Duplicate hook name: {name}")

        # Create new hook and add it
        hook = ValidatingHook(name=name, validators=[validator])
        REGISTRY.add_validating_webhook(hook)

        return f

    return inner


def mutating(
    name: str,
    kind: str | re.Pattern | None = None,
    namespace: str | re.Pattern | None = None,
    apiVersion: str | re.Pattern | None = None,
    operation: str | re.Pattern | None = None,
):
    """
    Decorator to register a Kubernetes admission mutating function.

    The decorated function must return the mutated Kubernetes object (dict).
    Async functions are supported.
    """

    def inner(f):
        pre_conditions = create_pre_conditions(kind, namespace, apiVersion, operation)
        extract_fields = extract_fields_from_signature(f)

        mutator = Mutator(
            pre_conditions=pre_conditions,
            user_function=f,
            name=name,
            extract_fields=extract_fields,
            kind_filter=kind,
            namespace_filter=namespace,
            api_version_filter=apiVersion,
            operation_filter=operation,
        )

        if name in REGISTRY.mutating_hooks:
            raise Exception(f"Duplicate hook name: {name}")

        hook = MutatingHook(name=name, mutators=[mutator])
        REGISTRY.add_mutating_webhook(hook)
        return f

    return inner
