"""Canonical JSON serialisation shared by every hash the product binds to.

Approvals are bound to ``plan_hash``, runs to ``configuration_hash``, and the
audit trail is a SHA-256 chain. Every one of those digests is the hash of a
canonical JSON string, so the serialisation rules *are* the compatibility
contract between the Python reference implementation and the TypeScript port
that runs inside the Chrome extension.

The rules:

- object keys sorted by Unicode code point;
- no insignificant whitespace (``,`` and ``:`` separators);
- non-ASCII emitted as raw UTF-8, never ``\\uXXXX`` escapes;
- integers only within +/-(2**53-1), because Python carries larger ones exactly
  and JavaScript does not;
- floats permitted only when they are neither whole-numbered nor rendered in
  exponential notation. Both languages emit the shortest representation that
  round-trips, so ordinary decimals such as ``0.6`` agree exactly. They diverge
  in two places: a whole-number float is ``1.0`` in Python and ``1`` in
  JavaScript — which JavaScript cannot even distinguish from the integer — and
  exponential notation differs in both threshold and format (``1e-05`` versus
  ``1e-7``). ``DeploymentSpec.offload_cpu_target`` is the only float the
  product hashes, and its ``ge=0.1, le=0.9`` bound keeps it clear of both.

Input must be well-formed Unicode. Lone surrogates are not representable in
UTF-8 and are rejected by ``str.encode`` here, whereas ``JSON.stringify``
escapes them; such input is invalid for both implementations rather than a
difference to reconcile.

Changing any rule changes every hash the product issues. The cross-language
golden set in ``tests/fixtures/canonical/`` pins the behaviour; regenerate it
deliberately, never to make a failing test pass.
"""

from __future__ import annotations

import hashlib
import json

__all__ = ["CanonicalisationError", "canonical_digest", "canonical_json"]


class CanonicalisationError(TypeError):
    """A payload cannot be canonicalised compatibly across implementations."""


_MAX_SAFE_INTEGER = 2**53 - 1
_INF = float("inf")


def _validate(payload: object, path: str = "$") -> None:
    # bool is a subclass of int, so it must be settled before the int branch.
    if isinstance(payload, bool) or payload is None:
        return
    if isinstance(payload, float):
        if payload != payload or payload in (_INF, -_INF):
            raise CanonicalisationError(f"Non-finite number at {path}")
        if payload.is_integer():
            raise CanonicalisationError(
                f"Whole-number float at {path} cannot be canonicalised; Python "
                "renders it as '1.0' and JavaScript as '1', and JavaScript "
                "cannot tell the two apart. Use an integer."
            )
        text = repr(payload)
        if "e" in text or "E" in text:
            raise CanonicalisationError(
                f"Float at {path} renders in exponential notation, where Python "
                "and JavaScript differ in both threshold and format. Scale the "
                "value or carry it as a string."
            )
        return
    if isinstance(payload, int):
        if abs(payload) > _MAX_SAFE_INTEGER:
            raise CanonicalisationError(
                f"Integer at {path} exceeds 2**53-1 and cannot survive a "
                "JavaScript round trip. Carry it as a string."
            )
        return
    if isinstance(payload, str):
        return
    if isinstance(payload, dict):
        for key, value in payload.items():
            if not isinstance(key, str):
                raise CanonicalisationError(
                    f"Non-string key at {path}; JSON object keys must be strings "
                    "for the two implementations to sort them identically."
                )
            _validate(value, f"{path}.{key}")
        return
    if isinstance(payload, (list, tuple)):
        for index, value in enumerate(payload):
            _validate(value, f"{path}[{index}]")
        return
    raise CanonicalisationError(f"Unsupported type {type(payload).__name__} at {path}")


def canonical_json(payload: object) -> str:
    """Serialise ``payload`` to the canonical string form."""
    _validate(payload)
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_digest(payload: object) -> str:
    """Return the SHA-256 hex digest of the canonical form of ``payload``."""
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
