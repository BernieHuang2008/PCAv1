from __future__ import annotations

from .encoding import validate_namespace
from .errors import PCAValidationError

EXAMPLE_NAMESPACE = "EXAMPLE"
HARDCODED_NAMESPACE: str | None = EXAMPLE_NAMESPACE


def set_hardcoded_namespace(namespace: str | None) -> None:
    if namespace is not None and namespace != EXAMPLE_NAMESPACE:
        validate_namespace(namespace)
    global HARDCODED_NAMESPACE
    HARDCODED_NAMESPACE = namespace


def resolve_hardcoded_namespace(namespace: str | None, hardcoded_namespace: str | None) -> str:
    configured_namespace = hardcoded_namespace if hardcoded_namespace is not None else HARDCODED_NAMESPACE
    if configured_namespace == EXAMPLE_NAMESPACE:
        if namespace is None:
            raise PCAValidationError("namespace is required when HARDCODED_NAMESPACE is EXAMPLE")
        validate_namespace(namespace)
        return namespace
    if configured_namespace is None:
        raise PCAValidationError("HARDCODED_NAMESPACE must be set to a Namespace or EXAMPLE")
    validate_namespace(configured_namespace)
    return configured_namespace
