"""
Kubernetes Admission Control Registry Package

This package provides a Kubernetes admission validation system with decorators
for registering validation functions.
"""

from .registry import Registry
from .validator import validating

__all__ = [
    'Registry',
    'validating'
]