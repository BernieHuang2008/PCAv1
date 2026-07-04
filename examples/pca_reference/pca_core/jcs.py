from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

import rfc8785

from .errors import PCAValidationError


def reject_duplicate_object_pairs(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PCAValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def loads_no_duplicates(text: str) -> Any:
    return json.loads(text, object_pairs_hook=reject_duplicate_object_pairs)


def canonicalize(value: Any) -> str:
    return canonicalize_bytes(value).decode("utf-8")


def canonicalize_bytes(value: Any) -> bytes:
    try:
        return rfc8785.dumps(value)
    except rfc8785.CanonicalizationError as exc:
        raise PCAValidationError(f"RFC 8785 JCS canonicalization failed: {exc}") from exc
