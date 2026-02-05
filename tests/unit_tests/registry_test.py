import pytest
import re
import types
from unittest.mock import Mock
from kube_cerberus.registry import (
    Registry, 
    Validator, 
    ValidatingHook, 
    REGISTRY,
    create_field_cache,
    validate_request_structure
)
from kube_cerberus.validator import (
    create_condition_check,
    create_pre_conditions,
    extract_fields_from_signature,
    validating
)


def test_create_field_cache_with_raw_object():
    """Test that raw_object returns the entire request as immutable"""
    request = {"object": {"kind": "Pod"}, "operation": "CREATE"}
    field_cache, get_cached_field = create_field_cache(request)
    
    result = get_cached_field("raw_object", [])
    
    assert isinstance(result, types.MappingProxyType)
    assert dict(result) == request


def test_create_field_cache_with_nested_path():
    """Test extracting nested fields from request"""
    request = {
        "object": {
            "metadata": {
                "name": "test-pod",
                "labels": {"app": "test"}
            }
        }
    }
    field_cache, get_cached_field = create_field_cache(request)
    
    result = get_cached_field("labels", ["object", "metadata", "labels"])
    
    assert isinstance(result, types.MappingProxyType)
    assert dict(result) == {"app": "test"}


def test_create_field_cache_missing_path():
    """Test that missing paths return empty immutable dict"""
    request = {"object": {"kind": "Pod"}}
    field_cache, get_cached_field = create_field_cache(request)
    
    result = get_cached_field("missing", ["object", "missing", "path"])
    
    assert isinstance(result, types.MappingProxyType)
    assert dict(result) == {}


def test_create_field_cache_caching_behavior():
    """Test that repeated calls use cached values"""
    request = {"object": {"metadata": {"name": "test"}}}
    field_cache, get_cached_field = create_field_cache(request)
    
    # First call
    result1 = get_cached_field("metadata", ["object", "metadata"])
    # Second call should return same cached object
    result2 = get_cached_field("metadata", ["object", "metadata"])
    
    assert result1 is result2
def test_valid_request_structure():
    """Test that valid request structure passes validation"""
    request = {
        "object": {
            "kind": "Pod",
            "apiVersion": "v1",
            "metadata": {"name": "test-pod"}
        }
    }
    
    # Should not raise any exception
    validate_request_structure(request)


def test_invalid_request_not_dict():
    """Test that non-dict request raises ValueError"""
    with pytest.raises(ValueError, match="Request must be a dictionary"):
        validate_request_structure("not a dict")


def test_missing_object_field():
    """Test that missing object field raises ValueError"""
    request = {"operation": "CREATE"}
    
    with pytest.raises(ValueError, match="Request must contain an 'object' field"):
        validate_request_structure(request)


def test_object_field_not_dict():
    """Test that non-dict object field raises ValueError"""
    request = {"object": "not a dict"}
    
    with pytest.raises(ValueError, match="Request 'object' field must be a dictionary"):
        validate_request_structure(request)


def test_missing_kind_field():
    """Test that missing kind field raises ValueError"""
    request = {"object": {"apiVersion": "v1"}}
    
    with pytest.raises(ValueError, match="Request object must contain a 'kind' field"):
        validate_request_structure(request)


def test_missing_api_version_field():
    """Test that missing apiVersion field raises ValueError"""
    request = {"object": {"kind": "Pod"}}
    
    with pytest.raises(ValueError, match="Request object must contain an 'apiVersion' field"):
        validate_request_structure(request)


def test_invalid_metadata_field():
    """Test that non-dict metadata field raises ValueError"""
    request = {
        "object": {
            "kind": "Pod",
            "apiVersion": "v1",
            "metadata": "not a dict"
        }
    }
    
    with pytest.raises(ValueError, match="Request object 'metadata' field must be a dictionary"):
        validate_request_structure(request)
def test_registry_initialization():
    """Test that registry initializes with empty hooks"""
    registry = Registry()
    assert registry.validating_hooks == {}


def test_add_validating_webhook():
    """Test adding a validating webhook"""
    registry = Registry()
    hook = ValidatingHook(name="test-hook", validators=[])
    registry.add_validating_webhook(hook)
    
    assert "test-hook" in registry.validating_hooks
    assert registry.validating_hooks["test-hook"] == hook


def test_add_duplicate_webhook_raises_exception():
    """Test that adding duplicate webhook raises exception"""
    registry = Registry()
    hook1 = ValidatingHook(name="test-hook", validators=[])
    hook2 = ValidatingHook(name="test-hook", validators=[])
    
    registry.add_validating_webhook(hook1)
    
    with pytest.raises(Exception, match="Duplicate hook.name=test-hook"):
        registry.add_validating_webhook(hook2)


def test_check_pre_conditions_success():
    """Test that pre-conditions pass when all return True"""
    registry = Registry()
    pre_condition1 = Mock(return_value=True)
    pre_condition2 = Mock(return_value=True)
    
    validator = Validator(
        pre_conditions=[pre_condition1, pre_condition2],
        user_function=Mock(),
        name="test",
        extract_fields={}
    )
    
    request = {"test": "data"}
    result = registry._check_pre_conditions(validator, request)
    
    assert result is True
    pre_condition1.assert_called_once_with(request)
    pre_condition2.assert_called_once_with(request)


def test_check_pre_conditions_failure():
    """Test that pre-conditions fail when any return False"""
    registry = Registry()
    pre_condition1 = Mock(return_value=True)
    pre_condition2 = Mock(return_value=False)
    
    validator = Validator(
        pre_conditions=[pre_condition1, pre_condition2],
        user_function=Mock(),
        name="test",
        extract_fields={}
    )
    
    request = {"test": "data"}
    result = registry._check_pre_conditions(validator, request)
    
    assert result is False
    pre_condition1.assert_called_once_with(request)
    pre_condition2.assert_called_once_with(request)


def test_check_pre_conditions_skip_on_none():
    """Test that None pre-condition result causes validator skip."""
    registry = Registry()
    pre_condition = Mock(return_value=None)
    validator = Validator(
        pre_conditions=[pre_condition],
        user_function=Mock(),
        name="test",
        extract_fields={},
    )

    request = {"test": "data"}
    result = registry._check_pre_conditions(validator, request)

    assert result is None


def test_extract_validator_kwargs():
    """Test extracting kwargs for validator"""
    registry = Registry()
    validator = Validator(
        pre_conditions=[],
        user_function=Mock(),
        name="test",
        extract_fields={"labels": ["object", "metadata", "labels"]}
    )
    
    get_cached_field = Mock(return_value={"app": "test"})
    
    kwargs = registry._extract_validator_kwargs(validator, get_cached_field)
    
    assert kwargs == {"labels": {"app": "test"}}
    get_cached_field.assert_called_once_with("labels", ["object", "metadata", "labels"])


def test_run_validator_success():
    """Test running validator successfully"""
    registry = Registry()
    user_function = Mock(return_value=True)
    validator = Validator(
        pre_conditions=[],
        user_function=user_function,
        name="test",
        extract_fields={}
    )
    
    kwargs = {"test": "data"}
    result = registry._run_validator(validator, kwargs)
    
    assert result.allowed is True
    assert result.message == ""
    user_function.assert_called_once_with(**kwargs)


def test_run_validator_false_result():
    """Test running validator that returns False"""
    registry = Registry()
    user_function = Mock(return_value=False)
    validator = Validator(
        pre_conditions=[],
        user_function=user_function,
        name="test",
        extract_fields={}
    )
    
    kwargs = {"test": "data"}
    result = registry._run_validator(validator, kwargs)
    
    assert result.allowed is False
    assert "Validation failed" in result.message


def test_run_validator_non_bool_result():
    """Test running validator that returns non-bool"""
    registry = Registry()
    user_function = Mock(return_value="not a bool")
    validator = Validator(
        pre_conditions=[],
        user_function=user_function,
        name="test",
        extract_fields={}
    )
    
    kwargs = {"test": "data"}
    result = registry._run_validator(validator, kwargs)
    
    assert result.allowed is False
    assert "invalid result type" in result.message


def test_run_validator_tuple_result_with_message():
    """Test tuple validator return with custom failure message."""
    registry = Registry()
    user_function = Mock(return_value=(False, "pod missing label"))
    validator = Validator(
        pre_conditions=[],
        user_function=user_function,
        name="test",
        extract_fields={},
    )

    result = registry._run_validator(validator, {})
    assert result.allowed is False
    assert result.message == "pod missing label"


def test_validate_request_success():
    """Test successful request validation"""
    registry = Registry()
    request = {
        "object": {"kind": "Pod", "apiVersion": "v1"},
        "operation": "CREATE"
    }
    
    user_function = Mock(return_value=True)
    validator = Validator(
        pre_conditions=[],
        user_function=user_function,
        name="test",
        extract_fields={}
    )
    hook = ValidatingHook(name="test-hook", validators=[validator])
    registry.add_validating_webhook(hook)
    
    result = registry.validate_request(request)
    
    assert result is True


def test_validate_request_pre_condition_failure():
    """Test request validation with pre-condition failure"""
    registry = Registry()
    request = {
        "object": {"kind": "Pod", "apiVersion": "v1"},
        "operation": "CREATE"
    }
    
    pre_condition = Mock(return_value=False)
    validator = Validator(
        pre_conditions=[pre_condition],
        user_function=Mock(),
        name="test",
        extract_fields={}
    )
    hook = ValidatingHook(name="test-hook", validators=[validator])
    registry.add_validating_webhook(hook)
    
    result = registry.validate_request(request)
    
    assert result is False


def test_validate_request_validator_failure():
    """Test request validation with validator failure"""
    registry = Registry()
    request = {
        "object": {"kind": "Pod", "apiVersion": "v1"},
        "operation": "CREATE"
    }
    
    user_function = Mock(return_value=False)
    validator = Validator(
        pre_conditions=[],
        user_function=user_function,
        name="test",
        extract_fields={}
    )
    hook = ValidatingHook(name="test-hook", validators=[validator])
    registry.add_validating_webhook(hook)
    
    result = registry.validate_request(request)
    
    assert result is False


def test_validate_request_invalid_structure():
    """Test request validation with invalid structure"""
    registry = Registry()
    request = {"invalid": "structure"}
    
    with pytest.raises(ValueError):
        registry.validate_request(request)
def test_condition_check_string_match():
    """Test condition check with string match"""
    check_func = create_condition_check(["object", "kind"], "Pod")
    request = {"object": {"kind": "Pod"}}
    
    assert check_func(request) is True


def test_condition_check_string_mismatch():
    """Test condition check with string mismatch"""
    check_func = create_condition_check(["object", "kind"], "Pod")
    request = {"object": {"kind": "Service"}}
    
    assert check_func(request) is None


def test_condition_check_regex_match():
    """Test condition check with regex match"""
    pattern = re.compile(r"^Pod|Service$")
    check_func = create_condition_check(["object", "kind"], pattern)
    request = {"object": {"kind": "Pod"}}
    
    assert check_func(request) is True


def test_condition_check_regex_mismatch():
    """Test condition check with regex mismatch"""
    pattern = re.compile(r"^Pod$")
    check_func = create_condition_check(["object", "kind"], pattern)
    request = {"object": {"kind": "Service"}}
    
    assert check_func(request) is None


def test_condition_check_missing_field():
    """Test condition check with missing field"""
    check_func = create_condition_check(["object", "missing"], "value")
    request = {"object": {"kind": "Pod"}}
    
    assert check_func(request) is None


def test_condition_check_non_string_field():
    """Test condition check with non-string field"""
    check_func = create_condition_check(["object", "spec"], "value")
    request = {"object": {"spec": {"replicas": 3}}}
    
    assert check_func(request) is None


def test_create_pre_conditions_all_none():
    """Test creating pre-conditions with all None values"""
    pre_conditions = create_pre_conditions(None, None, None, None)
    
    assert pre_conditions == []


def test_create_pre_conditions_with_values():
    """Test creating pre-conditions with actual values"""
    pre_conditions = create_pre_conditions(
        kind="Pod",
        namespace="default", 
        apiVersion="v1",
        operation="CREATE"
    )
    
    assert len(pre_conditions) == 4
    
    # Test that all conditions are callable
    for condition in pre_conditions:
        assert callable(condition)


def test_create_pre_conditions_partial_values():
    """Test creating pre-conditions with some None values"""
    pre_conditions = create_pre_conditions(
        kind="Pod",
        namespace=None,
        apiVersion="v1", 
        operation=None
    )
    
    assert len(pre_conditions) == 2


def test_extract_fields_single_param():
    """Test extracting fields from function with single parameter"""
    def test_func(labels):
        return True
        
    fields = extract_fields_from_signature(test_func)
    
    assert fields == {"labels": ["object", "metadata", "labels"]}


def test_extract_fields_multiple_params():
    """Test extracting fields from function with multiple parameters"""
    def test_func(labels, annotations, name):
        return True
        
    fields = extract_fields_from_signature(test_func)
    
    expected = {
        "labels": ["object", "metadata", "labels"],
        "annotations": ["object", "metadata", "annotations"],
        "name": ["object", "metadata", "name"]
    }
    assert fields == expected


def test_extract_fields_unknown_param():
    """Test extracting fields with unknown parameter names"""
    def test_func(unknown_param):
        return True
        
    fields = extract_fields_from_signature(test_func)
    
    assert fields == {}


def test_extract_fields_raw_object():
    """Test extracting raw_object field"""
    def test_func(raw_object):
        return True
        
    fields = extract_fields_from_signature(test_func)
    
    assert fields == {"raw_object": []}
def test_validating_decorator_basic():
    """Test basic validating decorator functionality"""
    # Reset the global registry
    REGISTRY.validating_hooks.clear()
    
    @validating("test-validator")
    def test_function():
        return True
        
    assert "test-validator" in REGISTRY.validating_hooks
    hook = REGISTRY.validating_hooks["test-validator"]
    assert hook.name == "test-validator"
    assert len(hook.validators) == 1
    assert hook.validators[0].name == "test-validator"
    assert hook.validators[0].user_function == test_function


def test_validating_decorator_with_conditions():
    """Test validating decorator with pre-conditions"""
    # Reset the global registry
    REGISTRY.validating_hooks.clear()
    
    @validating("test-validator", kind="Pod", namespace="default")
    def test_function():
        return True
        
    hook = REGISTRY.validating_hooks["test-validator"]
    validator = hook.validators[0]
    
    # Should have 2 pre-conditions (kind and namespace)
    assert len(validator.pre_conditions) == 2


def test_validating_decorator_with_regex_conditions():
    """Test validating decorator with regex pre-conditions"""
    # Reset the global registry
    REGISTRY.validating_hooks.clear()
    
    kind_pattern = re.compile(r"^Pod|Service$")
    
    @validating("test-validator", kind=kind_pattern)
    def test_function():
        return True
        
    hook = REGISTRY.validating_hooks["test-validator"]
    validator = hook.validators[0]
    
    assert len(validator.pre_conditions) == 1


def test_validating_decorator_duplicate_name():
    """Test that duplicate validator names raise exception"""
    # Reset the global registry
    REGISTRY.validating_hooks.clear()
    
    @validating("test-validator")
    def test_function1():
        return True
        
    with pytest.raises(Exception, match="Duplicate hook name: test-validator"):
        @validating("test-validator")
        def test_function2():
            return True


def test_validating_decorator_field_extraction():
    """Test that decorator extracts fields from function signature"""
    # Reset the global registry
    REGISTRY.validating_hooks.clear()
    
    @validating("test-validator")
    def test_function(labels, annotations, object):
        return True
        
    hook = REGISTRY.validating_hooks["test-validator"]
    validator = hook.validators[0]
    
    expected_fields = {
        "labels": ["object", "metadata", "labels"],
        "annotations": ["object", "metadata", "annotations"],
        "object": ["object"]
    }
    assert validator.extract_fields == expected_fields


def test_validating_decorator_returns_original_function():
    """Test that decorator returns the original function unchanged"""
    # Reset the global registry
    REGISTRY.validating_hooks.clear()
    
    def original_function():
        return "test result"
        
    decorated = validating("test-validator")(original_function)
    
    assert decorated == original_function
    assert decorated() == "test result"
