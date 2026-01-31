# TODO: Known Issues and Future Improvements

## Pre-condition Skip Behavior

**Issue:** When a validator's pre-conditions don't match the incoming request (e.g., a Service validator checking a Pod), the validation currently returns `False` instead of skipping the validator.

**Current behavior:**
```python
@validating("service-validator", kind="Service")
def validate_service():
    return True

# When validating a Pod, this returns False instead of skipping
result = registry.validate_request(pod_request)  # Returns False
```

**Expected behavior:**
Validators whose pre-conditions don't match should be skipped entirely, allowing validation to continue with other validators. Only validators with matching pre-conditions should affect the validation result.

**Impact:**
- Mixed resource type validations fail unexpectedly
- Requires registering validators very carefully to avoid cross-resource failures
- Tests show this behavior in `tests/unit_tests/validator_test.py:test_end_to_end_validation_pre_condition_filter`

**Proposed fix:**
Modify `Registry._check_pre_conditions()` to return a tri-state:
- `True`: Pre-conditions match, run validator
- `False`: Pre-conditions explicitly fail, reject request
- `None` or `"skip"`: Pre-conditions don't match, skip this validator

Then update `validate_request()` to skip validators that return `None/skip` instead of failing validation.

**Priority:** Medium - Affects flexibility but can be worked around by careful validator design

---

## Future Enhancements

### 1. Mutating Webhook Support
Add support for mutating admission webhooks that can modify resources before they're created/updated.

**API Design:**
```python
@mutating(name="add-labels", kind="Pod")
def add_default_labels(object: dict) -> dict:
    object.setdefault("metadata", {}).setdefault("labels", {})
    object["metadata"]["labels"]["added-by"] = "cerberus"
    return object
```

### 2. Validation Message Details
Allow validators to return detailed failure reasons that are included in admission responses.

**API Design:**
```python
@validating("pod-validator", kind="Pod")
def validate_pod(labels) -> tuple[bool, str]:
    if "app" not in labels:
        return False, "Pod must have 'app' label"
    return True, ""
```

### 3. Async Validator Support
Support async validators for operations that need to make external API calls.

```python
@validating("external-validator", kind="Pod")
async def validate_with_api(object: dict) -> bool:
    result = await external_service.check(object)
    return result.is_valid
```

### 4. Webhook Configuration Generator
Add CLI tool to generate Kubernetes ValidatingWebhookConfiguration YAML from registered validators.

```bash
cerberus generate-webhook --url https://webhook.example.com:8443 > webhook-config.yaml
```

### 5. Prometheus Metrics
Add built-in metrics for monitoring webhook performance:
- Request count by kind/operation
- Validation latency
- Rejection rate
- Error rate

### 6. Structured Logging
Replace print statements with proper structured logging using Python's logging module.
