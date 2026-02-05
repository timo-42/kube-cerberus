"""Pytest fixtures for integration tests."""

import os
import subprocess
import time
import base64
import datetime
import ipaddress
import shutil
import sys
from pathlib import Path
from typing import Any, Dict

import pytest
from kubernetes import client, config
from kubernetes.client.rest import ApiException

from tests.integration_tests.webhook_server import WebhookServer
from kube_cerberus.registry import REGISTRY


CLUSTER_NAME = "cerberus-test"


def _first_line(text: str) -> str:
    cleaned = (text or "").strip()
    if not cleaned:
        return ""
    return cleaned.splitlines()[0]


def _running_on_github_actions() -> bool:
    return os.environ.get("GITHUB_ACTIONS", "").lower() == "true"


def _skip_or_fail(reason: str) -> None:
    if _running_on_github_actions():
        pytest.fail(reason)
    pytest.skip(f"Skipping integration tests: {reason}")


def _ensure_integration_runtime() -> None:
    for binary in ("docker", "kind", "kubectl"):
        if shutil.which(binary) is None:
            _skip_or_fail(f"required binary '{binary}' is not installed.")

    try:
        docker_info = subprocess.run(
            ["docker", "info"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        _skip_or_fail(f"unable to run docker ({exc}).")

    if docker_info.returncode != 0:
        reason = _first_line(docker_info.stderr) or _first_line(docker_info.stdout)
        if not reason:
            reason = "docker info failed"
        _skip_or_fail(f"Docker is unavailable ({reason}).")


def _webhook_host() -> str:
    override = os.environ.get("KIND_WEBHOOK_HOST")
    if override:
        return override

    if sys.platform == "darwin":
        return "host.docker.internal"

    try:
        nodes_result = subprocess.run(
            ["kind", "get", "nodes", "--name", CLUSTER_NAME],
            check=True,
            capture_output=True,
            text=True,
        )
        nodes = [line for line in nodes_result.stdout.splitlines() if line]
        if nodes:
            inspect_result = subprocess.run(
                [
                    "docker",
                    "inspect",
                    "-f",
                    "{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}",
                    nodes[0],
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            gateway = inspect_result.stdout.strip()
            if gateway:
                return gateway
    except Exception:
        pass

    try:
        result = subprocess.run(
            [
                "docker",
                "network",
                "inspect",
                "kind",
                "--format",
                "{{(index .IPAM.Config 0).Gateway}}",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        gateway = result.stdout.strip()
        if gateway:
            return gateway
    except Exception:
        pass

    return "host.docker.internal"


@pytest.fixture(scope="session")
def kind_cluster():
    """
    Create and manage a kind cluster for tests.

    The cluster is created once at session start and reused for all tests.
    Cleanup is manual via 'make test-integration-teardown' to allow reusing
    cluster across multiple test runs for speed.
    """
    cluster_name = CLUSTER_NAME
    test_dir = Path(__file__).parent
    setup_script = test_dir / "scripts" / "setup_kind.sh"

    _ensure_integration_runtime()

    # Setup cluster
    env = os.environ.copy()
    env["CLUSTER_NAME"] = cluster_name

    try:
        subprocess.run(
            ["bash", str(setup_script)],
            check=True,
            env=env,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        error_text = (e.stderr or e.stdout or "").lower()
        if "permission denied while trying to connect to the docker api" in error_text:
            _skip_or_fail("Docker socket is not accessible for kind.")
        pytest.fail(f"Failed to setup kind cluster: {e.stderr}")

    # Load kubeconfig
    try:
        config.load_kube_config(context=f"kind-{cluster_name}")
    except Exception as e:
        pytest.fail(f"Failed to load kubeconfig: {e}")

    yield {"name": cluster_name, "context": f"kind-{cluster_name}"}

    # Note: Cleanup is manual via make test-integration-teardown
    # This allows reusing cluster across multiple test runs for speed


@pytest.fixture(scope="session")
def webhook_certs(tmp_path_factory, kind_cluster):
    """Generate self-signed certificates for webhook server."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    cert_dir = tmp_path_factory.mktemp("certs")

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generate certificate
    webhook_host = _webhook_host()
    alt_names = []
    alt_names.extend(
        [
            x509.DNSName("localhost"),
            x509.DNSName("webhook-server"),
            x509.DNSName("host.docker.internal"),
        ]
    )
    try:
        alt_names.append(x509.IPAddress(ipaddress.ip_address(webhook_host)))
    except ValueError:
        alt_names.append(x509.DNSName(webhook_host))
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cerberus Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "webhook-server"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(alt_names),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Write files
    key_file = cert_dir / "server.key"
    cert_file = cert_dir / "server.crt"

    with open(key_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Get CA bundle (self-signed, so cert is CA)
    ca_bundle_pem = cert.public_bytes(serialization.Encoding.PEM)
    ca_bundle_b64 = base64.b64encode(ca_bundle_pem).decode("utf-8")

    return {
        "cert_file": str(cert_file),
        "key_file": str(key_file),
        "ca_bundle_pem": ca_bundle_pem.decode(),
        "ca_bundle_b64": ca_bundle_b64,
    }


@pytest.fixture(scope="session")
def webhook_server(webhook_certs):
    """Start webhook server for tests."""
    server = WebhookServer(
        host="0.0.0.0",
        port=8443,
        cert_file=webhook_certs["cert_file"],
        key_file=webhook_certs["key_file"],
    )

    server.start()
    time.sleep(2)  # Give server time to start

    yield server

    server.stop()


@pytest.fixture(scope="function", autouse=True)
def clean_registry():
    """Clean registry before each test."""
    REGISTRY.validating_hooks.clear()
    yield
    REGISTRY.validating_hooks.clear()


@pytest.fixture(scope="session")
def k8s_client(kind_cluster):
    """Get Kubernetes API client."""
    return {
        "core": client.CoreV1Api(),
        "apps": client.AppsV1Api(),
        "admission": client.AdmissionregistrationV1Api(),
    }


@pytest.fixture(scope="function")
def webhook_configured(k8s_client, webhook_certs):
    """
    Deploy ValidatingWebhookConfiguration.

    This fixture is function-scoped and cleans up after each test.
    """
    admission_api = k8s_client["admission"]
    webhook_name = "cerberus-test-webhook"

    # Create webhook configuration
    webhook_config = client.V1ValidatingWebhookConfiguration(
        metadata=client.V1ObjectMeta(name=webhook_name),
        webhooks=[
            client.V1ValidatingWebhook(
                name="test.cerberus.k8s.io",
                client_config=client.AdmissionregistrationV1WebhookClientConfig(
                    url=f"https://{_webhook_host()}:8443",
                    ca_bundle=webhook_certs["ca_bundle_b64"],
                ),
                rules=[
                    client.V1RuleWithOperations(
                        operations=["CREATE", "UPDATE"],
                        api_groups=[""],
                        api_versions=["v1"],
                        resources=["pods"],
                    )
                ],
                admission_review_versions=["v1"],
                side_effects="None",
                timeout_seconds=10,
                failure_policy="Fail",
            )
        ],
    )

    try:
        admission_api.create_validating_webhook_configuration(webhook_config)
    except ApiException as e:
        if e.status == 409:  # Already exists
            admission_api.patch_validating_webhook_configuration(
                webhook_name, webhook_config
            )
        else:
            raise

    time.sleep(3)  # Wait for webhook to be ready

    yield webhook_config

    # Cleanup
    try:
        admission_api.delete_validating_webhook_configuration(webhook_name)
    except ApiException:
        pass  # Already deleted
