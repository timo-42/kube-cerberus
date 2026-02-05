import base64
import json
import logging

import pytest

from kube_cerberus.cli import main as cli_main
from kube_cerberus.registry import REGISTRY, Registry, Validator, ValidatingHook
from kube_cerberus.validator import mutating, validating
from kube_cerberus.webhook_config import generate_webhook_configuration_yaml


def _pod_request() -> dict:
    return {
        "object": {
            "kind": "Pod",
            "apiVersion": "v1",
            "metadata": {
                "name": "test-pod",
                "namespace": "default",
                "labels": {"app": "demo"},
            },
            "spec": {"containers": [{"name": "app", "image": "nginx:alpine"}]},
        },
        "operation": "CREATE",
        "userInfo": {"username": "dev-user"},
    }


@pytest.fixture(autouse=True)
def clean_registry():
    REGISTRY.validating_hooks.clear()
    REGISTRY.mutating_hooks.clear()
    REGISTRY.metrics = type(REGISTRY.metrics)()
    yield
    REGISTRY.validating_hooks.clear()
    REGISTRY.mutating_hooks.clear()
    REGISTRY.metrics = type(REGISTRY.metrics)()


def test_validation_message_details_are_returned_in_admission_response():
    @validating("pod-label-validator", kind="Pod")
    def validate_pod(labels):
        if "required" not in labels:
            return False, "Pod must include 'required' label"
        return True, ""

    review = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "uid-1",
            "operation": "CREATE",
            "object": _pod_request()["object"],
        },
    }

    response = REGISTRY.process_admission_review(review)
    assert response["response"]["allowed"] is False
    assert response["response"]["status"]["message"] == "Pod must include 'required' label"


def test_async_validator_is_supported():
    @validating("async-validator", kind="Pod")
    async def validate_async(labels):
        return "app" in labels

    assert REGISTRY.validate_request(_pod_request()) is True


def test_pre_condition_mismatch_skips_validator():
    @validating("service-only", kind="Service")
    def validate_service():
        return False

    assert REGISTRY.validate_request(_pod_request()) is True


def test_explicit_pre_condition_failure_rejects_request():
    registry = Registry()

    def always_reject(_request):
        return False

    validator = Validator(
        pre_conditions=[always_reject],
        user_function=lambda: True,
        name="explicit-reject",
        extract_fields={},
    )
    registry.add_validating_webhook(
        ValidatingHook(name="explicit-reject", validators=[validator])
    )

    assert registry.validate_request(_pod_request()) is False


def test_mutating_hook_changes_object():
    @mutating("add-managed-label", kind="Pod")
    def add_label(object):
        mutated = dict(object)
        metadata = dict(mutated.get("metadata", {}))
        labels = dict(metadata.get("labels", {}))
        labels["managed-by"] = "cerberus"
        metadata["labels"] = labels
        mutated["metadata"] = metadata
        return mutated

    result = REGISTRY.mutate_request_detailed(_pod_request())
    assert result.allowed is True
    assert result.mutated_object["metadata"]["labels"]["managed-by"] == "cerberus"


def test_async_mutator_is_supported():
    @mutating("async-mutator", kind="Pod")
    async def async_mutate(object):
        mutated = dict(object)
        metadata = dict(mutated.get("metadata", {}))
        metadata["annotations"] = {"mutated": "true"}
        mutated["metadata"] = metadata
        return mutated

    result = REGISTRY.mutate_request_detailed(_pod_request())
    assert result.allowed is True
    assert result.mutated_object["metadata"]["annotations"]["mutated"] == "true"


def test_mutating_admission_review_returns_json_patch():
    @mutating("add-label", kind="Pod")
    def add_label(object):
        mutated = dict(object)
        metadata = dict(mutated.get("metadata", {}))
        labels = dict(metadata.get("labels", {}))
        labels["added-by"] = "cerberus"
        metadata["labels"] = labels
        mutated["metadata"] = metadata
        return mutated

    review = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "uid-2",
            "operation": "CREATE",
            "object": _pod_request()["object"],
        },
    }
    response = REGISTRY.process_mutating_admission_review(review)

    assert response["response"]["allowed"] is True
    assert response["response"]["patchType"] == "JSONPatch"
    patch = json.loads(base64.b64decode(response["response"]["patch"]).decode("utf-8"))
    assert any(op["path"] == "/metadata/labels/added-by" for op in patch)


def test_metrics_include_request_rejection_and_error_counts():
    registry = Registry()

    validator = Validator(
        pre_conditions=[],
        user_function=lambda: False,
        name="always-fail",
        extract_fields={},
    )
    registry.add_validating_webhook(ValidatingHook(name="always-fail", validators=[validator]))

    assert registry.validate_request(_pod_request()) is False

    with pytest.raises(ValueError):
        registry.validate_request({"invalid": "request"})

    metrics = registry.metrics_text()
    assert 'kube_cerberus_requests_total{kind="Pod",operation="CREATE"} 1' in metrics
    assert 'kube_cerberus_rejections_total{kind="Pod",operation="CREATE"} 1' in metrics
    assert 'kube_cerberus_errors_total{kind="unknown",operation="unknown"} 1' in metrics


def test_non_bool_validator_result_uses_structured_logging(caplog):
    caplog.set_level(logging.WARNING)

    validator = Validator(
        pre_conditions=[],
        user_function=lambda: "not-a-bool",
        name="bad-validator",
        extract_fields={},
    )
    registry = Registry()
    registry.add_validating_webhook(ValidatingHook(name="bad-validator", validators=[validator]))

    assert registry.validate_request(_pod_request()) is False
    assert "returned invalid type" in caplog.text


def test_generate_webhook_configuration_yaml_includes_both_modes():
    @validating("validate-pod", kind="Pod", operation="CREATE", apiVersion="v1")
    def validate_pod():
        return True

    @mutating("mutate-pod", kind="Pod", operation="UPDATE", apiVersion="v1")
    def mutate_pod(object):
        return object

    output = generate_webhook_configuration_yaml(
        registry=REGISTRY,
        url="https://webhook.example.com:8443",
        name="cerberus",
        mode="both",
    )

    assert "kind: ValidatingWebhookConfiguration" in output
    assert "kind: MutatingWebhookConfiguration" in output
    assert "url: https://webhook.example.com:8443" in output
    assert "- pods" in output


def test_cli_generate_webhook_outputs_yaml(capsys):
    @validating("validate-pod", kind="Pod")
    def validate_pod():
        return True

    exit_code = cli_main(
        [
            "generate-webhook",
            "--url",
            "https://webhook.example.com:8443",
            "--name",
            "cerberus",
            "--mode",
            "validating",
        ]
    )

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "ValidatingWebhookConfiguration" in captured.out
