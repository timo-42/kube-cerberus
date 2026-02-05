from __future__ import annotations

import asyncio
import base64
import copy
import inspect
import json
import logging
import threading
import time
import types
from dataclasses import dataclass, field
from typing import Any, Callable, Literal


logger = logging.getLogger(__name__)

PreConditionState = Literal["match", "reject", "skip"]


def create_field_cache(
    request: dict[str, Any],
) -> tuple[dict[str, Any], Callable[[str, list[str]], Any]]:
    """Create a cache for extracted fields to avoid re-computation."""
    field_cache: dict[str, Any] = {}

    def get_cached_field(field_name: str, field_path: list[str]) -> Any:
        cache_key = field_name
        if cache_key not in field_cache:
            if field_name == "raw_object":
                # Pass the entire request as immutable raw input.
                field_cache[cache_key] = types.MappingProxyType(request)
            else:
                current: Any = request
                for path_part in field_path:
                    if isinstance(current, dict):
                        current = current.get(path_part, {})
                    else:
                        current = {}
                        break

                if isinstance(current, dict):
                    field_cache[cache_key] = types.MappingProxyType(current)
                else:
                    field_cache[cache_key] = current
        return field_cache[cache_key]

    return field_cache, get_cached_field


def validate_request_structure(request: dict[str, Any]) -> None:
    """Validate the structure of the incoming request."""
    if not isinstance(request, dict):
        raise ValueError("Request must be a dictionary")

    if "object" not in request:
        raise ValueError("Request must contain an 'object' field")

    if not isinstance(request["object"], dict):
        raise ValueError("Request 'object' field must be a dictionary")

    obj = request["object"]
    if "kind" not in obj:
        raise ValueError("Request object must contain a 'kind' field")

    if "apiVersion" not in obj:
        raise ValueError("Request object must contain an 'apiVersion' field")

    if "metadata" in obj and not isinstance(obj["metadata"], dict):
        raise ValueError("Request object 'metadata' field must be a dictionary")


@dataclass
class Validator:
    pre_conditions: list[Callable[[dict[str, Any]], Any]]
    user_function: Callable[..., Any]
    name: str
    extract_fields: dict[str, list[str]]
    kind_filter: Any = None
    namespace_filter: Any = None
    api_version_filter: Any = None
    operation_filter: Any = None


@dataclass
class Mutator:
    pre_conditions: list[Callable[[dict[str, Any]], Any]]
    user_function: Callable[..., Any]
    name: str
    extract_fields: dict[str, list[str]]
    kind_filter: Any = None
    namespace_filter: Any = None
    api_version_filter: Any = None
    operation_filter: Any = None


@dataclass
class ValidatingHook:
    name: str
    validators: list[Validator]


@dataclass
class MutatingHook:
    name: str
    mutators: list[Mutator]


@dataclass
class ValidationResult:
    allowed: bool
    message: str = ""


@dataclass
class MutationResult:
    allowed: bool
    mutated_object: dict[str, Any]
    message: str = ""


@dataclass
class RegistryMetrics:
    request_count: dict[tuple[str, str], int] = field(default_factory=dict)
    rejection_count: dict[tuple[str, str], int] = field(default_factory=dict)
    error_count: dict[tuple[str, str], int] = field(default_factory=dict)
    latency_sum: dict[tuple[str, str], float] = field(default_factory=dict)
    latency_count: dict[tuple[str, str], int] = field(default_factory=dict)

    def observe(
        self,
        *,
        kind: str,
        operation: str,
        allowed: bool,
        errored: bool,
        latency_seconds: float,
    ) -> None:
        label = (kind, operation)
        self.request_count[label] = self.request_count.get(label, 0) + 1
        self.latency_sum[label] = self.latency_sum.get(label, 0.0) + latency_seconds
        self.latency_count[label] = self.latency_count.get(label, 0) + 1

        if errored:
            self.error_count[label] = self.error_count.get(label, 0) + 1
        elif not allowed:
            self.rejection_count[label] = self.rejection_count.get(label, 0) + 1

    @staticmethod
    def _escape(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')

    def _render_metric(self, metric_name: str, values: dict[tuple[str, str], Any]) -> list[str]:
        lines = []
        for (kind, operation), value in sorted(values.items()):
            escaped_kind = self._escape(kind)
            escaped_operation = self._escape(operation)
            lines.append(
                f'{metric_name}{{kind="{escaped_kind}",operation="{escaped_operation}"}} {value}'
            )
        return lines

    def render_prometheus(self) -> str:
        lines = [
            "# HELP kube_cerberus_requests_total Total admission requests processed.",
            "# TYPE kube_cerberus_requests_total counter",
            *self._render_metric("kube_cerberus_requests_total", self.request_count),
            "# HELP kube_cerberus_rejections_total Total requests rejected by hooks.",
            "# TYPE kube_cerberus_rejections_total counter",
            *self._render_metric("kube_cerberus_rejections_total", self.rejection_count),
            "# HELP kube_cerberus_errors_total Total request processing errors.",
            "# TYPE kube_cerberus_errors_total counter",
            *self._render_metric("kube_cerberus_errors_total", self.error_count),
            "# HELP kube_cerberus_validation_latency_seconds_total Total validation latency in seconds.",
            "# TYPE kube_cerberus_validation_latency_seconds_total counter",
            *self._render_metric("kube_cerberus_validation_latency_seconds_total", self.latency_sum),
            "# HELP kube_cerberus_validation_latency_seconds_count Total validation latency samples.",
            "# TYPE kube_cerberus_validation_latency_seconds_count counter",
            *self._render_metric("kube_cerberus_validation_latency_seconds_count", self.latency_count),
        ]
        return "\n".join(lines) + "\n"


def _json_pointer_escape(path: str) -> str:
    return path.replace("~", "~0").replace("/", "~1")


def _create_json_patch(
    source: Any,
    target: Any,
    path: str = "",
) -> list[dict[str, Any]]:
    if source == target:
        return []

    if isinstance(source, dict) and isinstance(target, dict):
        patch = []
        for key in sorted(source.keys() - target.keys()):
            child_path = f"{path}/{_json_pointer_escape(key)}"
            patch.append({"op": "remove", "path": child_path})
        for key in sorted(target.keys() - source.keys()):
            child_path = f"{path}/{_json_pointer_escape(key)}"
            patch.append({"op": "add", "path": child_path, "value": target[key]})
        for key in sorted(source.keys() & target.keys()):
            child_path = f"{path}/{_json_pointer_escape(key)}"
            patch.extend(_create_json_patch(source[key], target[key], child_path))
        return patch

    if isinstance(source, list) and isinstance(target, list):
        return [{"op": "replace", "path": path or "", "value": target}]

    return [{"op": "replace", "path": path or "", "value": target}]


class Registry:
    def __init__(self):
        self.validating_hooks: dict[str, ValidatingHook] = {}
        self.mutating_hooks: dict[str, MutatingHook] = {}
        self.metrics = RegistryMetrics()

    def add_validating_webhook(self, hook: ValidatingHook):
        if hook.name in self.validating_hooks:
            raise Exception(f"Duplicate hook.name={hook.name}")
        self.validating_hooks[hook.name] = hook

    def add_mutating_webhook(self, hook: MutatingHook):
        if hook.name in self.mutating_hooks:
            raise Exception(f"Duplicate hook.name={hook.name}")
        self.mutating_hooks[hook.name] = hook

    @staticmethod
    def _normalize_pre_condition_result(result: Any) -> PreConditionState:
        if result is True:
            return "match"
        if result is False:
            return "reject"
        if result is None:
            return "skip"

        if isinstance(result, str):
            value = result.strip().lower()
            if value in {"match", "allow", "pass", "true"}:
                return "match"
            if value in {"skip", "none", "ignore"}:
                return "skip"
            if value in {"reject", "deny", "false"}:
                return "reject"
            return "reject"

        return "match" if bool(result) else "reject"

    def _check_pre_conditions(
        self,
        hook_or_name: Validator | Mutator | str,
        pre_conditions_or_request: list[Callable[[dict[str, Any]], Any]] | dict[str, Any],
        request: dict[str, Any] | None = None,
    ) -> bool | None:
        """Return True=run, False=reject, None=skip."""
        if request is None:
            hook = hook_or_name
            if not isinstance(hook, (Validator, Mutator)):
                raise TypeError("hook must be Validator or Mutator when request is omitted")
            hook_name = hook.name
            pre_conditions = hook.pre_conditions
            request = pre_conditions_or_request
            if not isinstance(request, dict):
                raise TypeError("request must be a dictionary")
        else:
            hook_name = str(hook_or_name)
            pre_conditions = pre_conditions_or_request
            if not isinstance(pre_conditions, list):
                raise TypeError("pre_conditions must be a list")

        skipped = False
        for pre_condition in pre_conditions:
            try:
                state = self._normalize_pre_condition_result(pre_condition(request))
            except Exception:
                logger.exception("Pre-condition raised for hook '%s'", hook_name)
                return False

            if state == "reject":
                logger.info("Pre-condition rejected request for hook '%s'", hook_name)
                return False
            if state == "skip":
                skipped = True

        if skipped:
            return None
        return True

    def _extract_validator_kwargs(
        self,
        hook: Validator | Mutator,
        get_cached_field: Callable[[str, list[str]], Any],
    ) -> dict[str, Any]:
        kwargs = {}
        for field_name, field_path in hook.extract_fields.items():
            kwargs[field_name] = get_cached_field(field_name, field_path)
        return kwargs

    @staticmethod
    def _run_coroutine_sync(awaitable: Any) -> Any:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(awaitable)

        result: dict[str, Any] = {}
        error: dict[str, BaseException] = {}

        def _runner() -> None:
            loop = asyncio.new_event_loop()
            try:
                result["value"] = loop.run_until_complete(awaitable)
            except BaseException as exc:  # noqa: BLE001
                error["error"] = exc
            finally:
                loop.close()

        thread = threading.Thread(target=_runner, daemon=True)
        thread.start()
        thread.join()

        if "error" in error:
            raise error["error"]
        return result.get("value")

    def _execute_user_function(self, user_function: Callable[..., Any], kwargs: dict[str, Any]) -> Any:
        response = user_function(**kwargs)
        if inspect.isawaitable(response):
            return self._run_coroutine_sync(response)
        return response

    def _run_validator(self, validator: Validator, kwargs: dict[str, Any]) -> ValidationResult:
        try:
            response = self._execute_user_function(validator.user_function, kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Validator '%s' raised an exception", validator.name)
            return ValidationResult(
                allowed=False,
                message=f"Validation error in '{validator.name}': {exc}",
            )

        if isinstance(response, bool):
            if response:
                return ValidationResult(allowed=True)
            return ValidationResult(
                allowed=False,
                message=f"Validation failed by '{validator.name}'",
            )

        if (
            isinstance(response, tuple)
            and len(response) == 2
            and isinstance(response[0], bool)
            and isinstance(response[1], str)
        ):
            allowed, message = response
            if allowed:
                return ValidationResult(allowed=True)
            return ValidationResult(
                allowed=False,
                message=message or f"Validation failed by '{validator.name}'",
            )

        logger.warning(
            "Validator '%s' returned invalid type '%s'",
            validator.name,
            type(response).__name__,
        )
        return ValidationResult(
            allowed=False,
            message=f"Validator '{validator.name}' returned invalid result type",
        )

    def _run_mutator(
        self,
        mutator: Mutator,
        kwargs: dict[str, Any],
        current_object: dict[str, Any],
    ) -> MutationResult:
        try:
            response = self._execute_user_function(mutator.user_function, kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Mutator '%s' raised an exception", mutator.name)
            return MutationResult(
                allowed=False,
                mutated_object=current_object,
                message=f"Mutation error in '{mutator.name}': {exc}",
            )

        if not isinstance(response, dict):
            logger.warning(
                "Mutator '%s' returned invalid type '%s'",
                mutator.name,
                type(response).__name__,
            )
            return MutationResult(
                allowed=False,
                mutated_object=current_object,
                message=f"Mutator '{mutator.name}' must return a dictionary",
            )

        return MutationResult(allowed=True, mutated_object=response)

    @staticmethod
    def _request_labels(request: dict[str, Any]) -> tuple[str, str]:
        obj = request.get("object", {})
        kind = obj.get("kind", "unknown") if isinstance(obj, dict) else "unknown"
        operation = request.get("operation", "unknown")
        return str(kind), str(operation)

    def validate_request_detailed(self, request: dict[str, Any]) -> ValidationResult:
        """Evaluate all validating hooks and return detailed result."""
        kind, operation = self._request_labels(request)
        start = time.perf_counter()
        allowed = False
        errored = False

        try:
            validate_request_structure(request)
            _, get_cached_field = create_field_cache(request)

            for hook in self.validating_hooks.values():
                for validator in hook.validators:
                    pre_condition_result = self._check_pre_conditions(
                        validator.name,
                        validator.pre_conditions,
                        request,
                    )
                    if pre_condition_result is None:
                        continue
                    if pre_condition_result is False:
                        return ValidationResult(
                            allowed=False,
                            message=f"Validation pre-condition rejected by '{validator.name}'",
                        )

                    kwargs = self._extract_validator_kwargs(validator, get_cached_field)
                    validator_result = self._run_validator(validator, kwargs)
                    if not validator_result.allowed:
                        return validator_result

            allowed = True
            return ValidationResult(allowed=True)
        except Exception:  # noqa: BLE001
            errored = True
            raise
        finally:
            self.metrics.observe(
                kind=kind,
                operation=operation,
                allowed=allowed,
                errored=errored,
                latency_seconds=time.perf_counter() - start,
            )

    def validate_request(self, request: dict[str, Any]) -> bool:
        """Evaluate all validating hooks against the request."""
        return self.validate_request_detailed(request).allowed

    def validate(self, request: dict[str, Any]) -> bool:
        """Alias for validate_request() for backward compatibility."""
        return self.validate_request(request)

    def mutate_request_detailed(self, request: dict[str, Any]) -> MutationResult:
        """Apply all matching mutating hooks to a request object."""
        kind, operation = self._request_labels(request)
        start = time.perf_counter()
        allowed = False
        errored = False

        try:
            validate_request_structure(request)
            current_request = copy.deepcopy(request)

            for hook in self.mutating_hooks.values():
                for mutator in hook.mutators:
                    pre_condition_result = self._check_pre_conditions(
                        mutator.name,
                        mutator.pre_conditions,
                        current_request,
                    )
                    if pre_condition_result is None:
                        continue
                    if pre_condition_result is False:
                        return MutationResult(
                            allowed=False,
                            mutated_object=current_request["object"],
                            message=f"Mutation pre-condition rejected by '{mutator.name}'",
                        )

                    _, get_cached_field = create_field_cache(current_request)
                    kwargs = self._extract_validator_kwargs(mutator, get_cached_field)
                    mutation_result = self._run_mutator(
                        mutator,
                        kwargs,
                        current_request["object"],
                    )
                    if not mutation_result.allowed:
                        return mutation_result
                    current_request["object"] = mutation_result.mutated_object

            allowed = True
            return MutationResult(allowed=True, mutated_object=current_request["object"])
        except Exception:  # noqa: BLE001
            errored = True
            raise
        finally:
            self.metrics.observe(
                kind=kind,
                operation=operation,
                allowed=allowed,
                errored=errored,
                latency_seconds=time.perf_counter() - start,
            )

    def mutate_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """Apply mutators and return the mutated object."""
        result = self.mutate_request_detailed(request)
        if not result.allowed:
            raise ValueError(result.message or "Mutation failed")
        return result.mutated_object

    def mutate(self, request: dict[str, Any]) -> dict[str, Any]:
        """Alias for mutate_request() for backward compatibility."""
        return self.mutate_request(request)

    def process_admission_review(self, admission_review: dict[str, Any]) -> dict[str, Any]:
        """Process a validating AdmissionReview request."""
        request = admission_review.get("request", {})
        uid = request.get("uid", "")

        admission_request = {
            "object": request.get("object", {}),
            "oldObject": request.get("oldObject"),
            "operation": request.get("operation", ""),
            "userInfo": request.get("userInfo", {}),
        }

        try:
            result = self.validate_request_detailed(admission_request)
            response = {
                "apiVersion": "admission.k8s.io/v1",
                "kind": "AdmissionReview",
                "response": {
                    "uid": uid,
                    "allowed": result.allowed,
                },
            }

            if not result.allowed:
                response["response"]["status"] = {
                    "message": result.message or "Validation failed",
                }

            return response
        except Exception as exc:  # noqa: BLE001
            return {
                "apiVersion": "admission.k8s.io/v1",
                "kind": "AdmissionReview",
                "response": {
                    "uid": uid,
                    "allowed": False,
                    "status": {
                        "message": f"Validation error: {exc}",
                    },
                },
            }

    def process_mutating_admission_review(self, admission_review: dict[str, Any]) -> dict[str, Any]:
        """Process a mutating AdmissionReview request and return JSONPatch response."""
        request = admission_review.get("request", {})
        uid = request.get("uid", "")
        request_object = request.get("object", {})

        admission_request = {
            "object": request_object,
            "oldObject": request.get("oldObject"),
            "operation": request.get("operation", ""),
            "userInfo": request.get("userInfo", {}),
        }

        try:
            result = self.mutate_request_detailed(admission_request)
            response = {
                "apiVersion": "admission.k8s.io/v1",
                "kind": "AdmissionReview",
                "response": {
                    "uid": uid,
                    "allowed": result.allowed,
                },
            }

            if not result.allowed:
                response["response"]["status"] = {
                    "message": result.message or "Mutation failed",
                }
                return response

            patch = _create_json_patch(request_object, result.mutated_object)
            encoded_patch = base64.b64encode(
                json.dumps(patch, separators=(",", ":")).encode("utf-8")
            ).decode("utf-8")

            response["response"]["patchType"] = "JSONPatch"
            response["response"]["patch"] = encoded_patch
            return response
        except Exception as exc:  # noqa: BLE001
            return {
                "apiVersion": "admission.k8s.io/v1",
                "kind": "AdmissionReview",
                "response": {
                    "uid": uid,
                    "allowed": False,
                    "status": {
                        "message": f"Mutation error: {exc}",
                    },
                },
            }

    def metrics_text(self) -> str:
        """Render metrics in Prometheus exposition format."""
        return self.metrics.render_prometheus()


REGISTRY = Registry()
