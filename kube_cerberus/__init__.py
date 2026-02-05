"""
Kubernetes Admission Control Registry Package

This package provides a Kubernetes admission validation system with decorators
for registering validation functions.
"""

from .registry import Registry
from .validator import mutating, validating
from .webhook_config import generate_webhook_configuration_yaml

__all__ = [
    "Registry",
    "validating",
    "mutating",
    "generate_webhook_configuration_yaml",
]
