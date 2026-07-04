from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from .errors import PCAValidationError

_MAX_SAFE_JSON_INTEGER = 2**53 - 1


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
    return _canonicalize(value)


def canonicalize_bytes(value: Any) -> bytes:
    return canonicalize(value).encode("utf-8")


def _canonicalize(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > _MAX_SAFE_JSON_INTEGER:
            raise PCAValidationError("JSON integers must fit the I-JSON safe integer range")
        return str(value)
    if isinstance(value, float):
        raise PCAValidationError("PCA signed JSON must not contain floating-point numbers")
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(_canonicalize(item) for item in value) + "]"
    if isinstance(value, dict):
        items: list[tuple[str, Any]] = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise PCAValidationError("JSON object keys must be strings")
            try:
                key.encode("ascii")
            except UnicodeEncodeError as exc:
                raise PCAValidationError("PCA signed JSON keys must be ASCII") from exc
            items.append((key, item))
        items.sort(key=lambda pair: pair[0])
        return "{" + ",".join(_canonicalize(key) + ":" + _canonicalize(item) for key, item in items) + "}"
    raise PCAValidationError(f"unsupported JSON value type: {type(value).__name__}")

