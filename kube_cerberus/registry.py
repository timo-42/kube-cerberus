from typing import Any, Callable
from dataclasses import dataclass
import types


def create_field_cache(request: dict[str, Any]) -> tuple[dict[str, types.MappingProxyType], Any]:
    """Create a cache for extracted fields to avoid re-computation"""
    field_cache = {}
    
    def get_cached_field(field_name: str, field_path: list[str]):
        cache_key = field_name
        if cache_key not in field_cache:
            if field_name == "raw_object":
                # Special case: pass the entire request as immutable 'raw_object'
                field_cache[cache_key] = types.MappingProxyType(request)
            else:
                # Navigate to the specific field
                current = request
                for path_part in field_path:
                    current = current.get(path_part, {})
                # If we ended up with a dict, make it immutable; otherwise use empty immutable dict
                if isinstance(current, dict):
                    field_cache[cache_key] = types.MappingProxyType(current)
                else:
                    field_cache[cache_key] = types.MappingProxyType({})
        return field_cache[cache_key]
    
    return field_cache, get_cached_field


def validate_request_structure(request: dict[str, Any]) -> None:
    """Validate the structure of the incoming request"""
    if not isinstance(request, dict):
        raise ValueError("Request must be a dictionary")
    
    if "object" not in request:
        raise ValueError("Request must contain an 'object' field")
    
    if not isinstance(request["object"], dict):
        raise ValueError("Request 'object' field must be a dictionary")
    
    # Validate that object has required Kubernetes fields
    obj = request["object"]
    if "kind" not in obj:
        raise ValueError("Request object must contain a 'kind' field")
    
    if "apiVersion" not in obj:
        raise ValueError("Request object must contain an 'apiVersion' field")
    
    # Validate metadata structure if present
    if "metadata" in obj and not isinstance(obj["metadata"], dict):
        raise ValueError("Request object 'metadata' field must be a dictionary")


@dataclass
class Validator:
    pre_conditions: list[
        Callable[[dict[str, Any]], bool]
    ]  # add list of kind=Pod,namespace=.. conditions, which must be true, before running user code
    user_function: Callable[..., bool]
    name: str
    extract_fields: dict[str, list[str]]  # field name -> path to extract from request


@dataclass
class ValidatingHook:
    name: str
    validators: list[Validator]


class Registry:
    def __init__(self):
        self.validating_hooks: dict[str, ValidatingHook] = {}

    def add_validating_webhook(self, hook: ValidatingHook):
        if hook.name in self.validating_hooks:
            raise Exception(f"Duplicate hook.name={hook.name}")
        self.validating_hooks[hook.name] = hook

    def _check_pre_conditions(self, validator: Validator, request: dict[str, Any]) -> bool:
        """Check all pre-conditions for a validator"""
        for pre_condition in validator.pre_conditions:
            if not pre_condition(request):
                print(f"Pre-condition failed for {validator.name}")
                return False
        return True

    def _extract_validator_kwargs(self, validator: Validator, get_cached_field) -> dict[str, Any]:
        """Extract kwargs for a validator using the field cache"""
        kwargs = {}
        for field_name, field_path in validator.extract_fields.items():
            kwargs[field_name] = get_cached_field(field_name, field_path)
        return kwargs

    def _run_validator(self, validator: Validator, kwargs: dict[str, Any]) -> bool:
        """Run a single validator and return the result"""
        response = validator.user_function(**kwargs)
        if not isinstance(response, bool):
            print("no bool returned, assuming False")
            return False

        if response == False:
            print(f"{validator.name} returned false")
            return False
        return True

    def validate_request(self, request: dict[str, Any]) -> bool:
        """Evaluate all validating hooks against the request"""
        # Validate input request structure
        validate_request_structure(request)
        
        field_cache, get_cached_field = create_field_cache(request)
        
        for hook in self.validating_hooks.values():
            for validator in hook.validators:
                # Check pre-conditions first
                if not self._check_pre_conditions(validator, request):
                    return False

                # Extract kwargs for the validator
                kwargs = self._extract_validator_kwargs(validator, get_cached_field)

                # Run the validator
                if not self._run_validator(validator, kwargs):
                    return False
        
        return True


REGISTRY = Registry()
