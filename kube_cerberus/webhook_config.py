"""Webhook configuration generation utilities."""

from __future__ import annotations

import re
from typing import Any, Iterable

from .registry import Mutator, Registry, Validator


def _pluralize_kind(kind: str) -> str:
    normalized = kind.strip().lower()
    if normalized.endswith("s"):
        return f"{normalized}es"
    if normalized.endswith("y") and len(normalized) > 1 and normalized[-2] not in "aeiou":
        return f"{normalized[:-1]}ies"
    return f"{normalized}s"


def _as_string_filter(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _to_operations(value: Any) -> set[str]:
    filter_value = _as_string_filter(value)
    if filter_value is None:
        return {"*"}
    return {filter_value.upper()}


def _to_resources(value: Any) -> set[str]:
    filter_value = _as_string_filter(value)
    if filter_value is None:
        return {"*"}
    return {_pluralize_kind(filter_value)}


def _to_groups_and_versions(value: Any) -> tuple[set[str], set[str]]:
    filter_value = _as_string_filter(value)
    if filter_value is None:
        return {"*"}, {"*"}

    if "/" in filter_value:
        group, version = filter_value.split("/", 1)
        return {group}, {version}

    return {""}, {filter_value}


def _collect_rule_values(hooks: Iterable[Validator | Mutator]) -> dict[str, list[str]]:
    operations: set[str] = set()
    api_groups: set[str] = set()
    api_versions: set[str] = set()
    resources: set[str] = set()

    for hook in hooks:
        operations.update(_to_operations(hook.operation_filter))
        resources.update(_to_resources(hook.kind_filter))
        groups, versions = _to_groups_and_versions(hook.api_version_filter)
        api_groups.update(groups)
        api_versions.update(versions)

    if not operations:
        operations = {"*"}
    if not api_groups:
        api_groups = {"*"}
    if not api_versions:
        api_versions = {"*"}
    if not resources:
        resources = {"*"}

    return {
        "operations": sorted(operations),
        "api_groups": sorted(api_groups),
        "api_versions": sorted(api_versions),
        "resources": sorted(resources),
    }


def _render_list(values: list[str], indent: int) -> list[str]:
    space = " " * indent
    return [f"{space}- {value}" for value in values]


def _render_webhook_config(
    *,
    config_kind: str,
    name: str,
    url: str,
    ca_bundle: str | None,
    rule_values: dict[str, list[str]],
) -> str:
    webhook_name = re.sub(r"[^a-z0-9.-]", "-", name.lower()).strip("-")
    webhook_name = webhook_name or "cerberus-webhook"

    lines = [
        "apiVersion: admissionregistration.k8s.io/v1",
        f"kind: {config_kind}",
        "metadata:",
        f"  name: {webhook_name}",
        "webhooks:",
        f"  - name: {webhook_name}.kube-cerberus.local",
        "    admissionReviewVersions:",
        "      - v1",
        "    sideEffects: None",
        "    failurePolicy: Fail",
        "    timeoutSeconds: 10",
        "    clientConfig:",
        f"      url: {url}",
    ]

    if ca_bundle:
        lines.append(f"      caBundle: {ca_bundle}")

    lines.extend(
        [
            "    rules:",
            "      - operations:",
            *_render_list(rule_values["operations"], 10),
            "        apiGroups:",
            *_render_list(rule_values["api_groups"], 10),
            "        apiVersions:",
            *_render_list(rule_values["api_versions"], 10),
            "        resources:",
            *_render_list(rule_values["resources"], 10),
        ]
    )
    return "\n".join(lines)


def generate_webhook_configuration_yaml(
    *,
    registry: Registry,
    url: str,
    name: str = "cerberus-webhook",
    mode: str = "validating",
    ca_bundle: str | None = None,
) -> str:
    """
    Generate Kubernetes webhook configuration YAML from registered hooks.

    Args:
        registry: Registry containing registered hooks.
        url: Webhook URL reachable by Kubernetes API server.
        name: Base metadata.name for generated resources.
        mode: One of validating, mutating, or both.
        ca_bundle: Optional base64-encoded CA bundle.
    """
    normalized_mode = mode.strip().lower()
    if normalized_mode not in {"validating", "mutating", "both"}:
        raise ValueError("mode must be one of: validating, mutating, both")

    documents: list[str] = []

    if normalized_mode in {"validating", "both"}:
        validators = [
            validator
            for hook in registry.validating_hooks.values()
            for validator in hook.validators
        ]
        validating_rules = _collect_rule_values(validators)
        documents.append(
            _render_webhook_config(
                config_kind="ValidatingWebhookConfiguration",
                name=f"{name}-validating",
                url=url,
                ca_bundle=ca_bundle,
                rule_values=validating_rules,
            )
        )

    if normalized_mode in {"mutating", "both"}:
        mutators = [mutator for hook in registry.mutating_hooks.values() for mutator in hook.mutators]
        mutating_rules = _collect_rule_values(mutators)
        documents.append(
            _render_webhook_config(
                config_kind="MutatingWebhookConfiguration",
                name=f"{name}-mutating",
                url=url,
                ca_bundle=ca_bundle,
                rule_values=mutating_rules,
            )
        )

    return "\n---\n".join(documents) + "\n"
