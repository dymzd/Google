"""Canonicalisation is the compatibility contract with the extension port.

The golden set in ``fixtures/canonical/golden.json`` is verified from both
sides: here against the Python reference implementation, and by
``extension/scripts/verify-canonical.ts`` against the TypeScript port. A change
that passes only one side is a silent divergence in every ``plan_hash``,
``configuration_hash``, and audit chain entry the two implementations produce.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sgstudio.domain.canonical import (
    CanonicalisationError,
    canonical_digest,
    canonical_json,
)

_GOLDEN = Path(__file__).parent / "fixtures" / "canonical" / "golden.json"


def _cases() -> list[dict[str, object]]:
    document = json.loads(_GOLDEN.read_text(encoding="utf-8"))
    return document["cases"]


@pytest.mark.parametrize("case", _cases(), ids=lambda case: str(case["name"]))
def test_golden_canonical_form(case: dict[str, object]) -> None:
    assert canonical_json(case["payload"]) == case["canonical"]


@pytest.mark.parametrize("case", _cases(), ids=lambda case: str(case["name"]))
def test_golden_digest(case: dict[str, object]) -> None:
    assert canonical_digest(case["payload"]) == case["digest"]


def test_keys_are_sorted_by_code_point() -> None:
    # U+1F600 is above U+FFFF by code point but its leading UTF-16 surrogate is
    # below it. An implementation sorting by code unit would order these the
    # other way round.
    payload = {chr(0x1F600): 1, chr(0xFFFF): 2}
    assert canonical_json(payload).index(chr(0xFFFF)) < canonical_json(payload).index(
        chr(0x1F600)
    )


def test_non_ascii_is_not_escaped() -> None:
    assert canonical_json({"ou": "組織"}) == '{"ou":"組織"}'


def test_whole_number_floats_are_rejected() -> None:
    # Python renders this "1.0" and JavaScript "1", and JavaScript cannot tell
    # the float from the integer to compensate.
    with pytest.raises(CanonicalisationError, match="Whole-number float"):
        canonical_json({"ratio": 1.0})


def test_nested_whole_number_floats_are_rejected() -> None:
    with pytest.raises(CanonicalisationError, match=r"\$\.outer\[1\]\.leaf"):
        canonical_json({"outer": [0, {"leaf": 2.0}]})


def test_decimal_floats_are_accepted() -> None:
    # offload_cpu_target is bounded ge=0.1/le=0.9, so it is always of this shape.
    assert canonical_json({"offload_cpu_target": 0.6}) == '{"offload_cpu_target":0.6}'


def test_exponential_floats_are_rejected() -> None:
    with pytest.raises(CanonicalisationError, match="exponential notation"):
        canonical_json({"tiny": 1e-9})


def test_non_finite_numbers_are_rejected() -> None:
    with pytest.raises(CanonicalisationError, match="Non-finite"):
        canonical_json({"nan": float("nan")})
    with pytest.raises(CanonicalisationError, match="Non-finite"):
        canonical_json({"inf": float("inf")})


def test_integers_beyond_javascript_safe_range_are_rejected() -> None:
    with pytest.raises(CanonicalisationError, match="exceeds"):
        canonical_json({"big": 2**53})


def test_safe_integer_boundary_is_accepted() -> None:
    assert canonical_json({"big": 2**53 - 1}) == '{"big":9007199254740991}'


def test_booleans_are_not_treated_as_integers() -> None:
    assert canonical_json({"flag": True}) == '{"flag":true}'


def test_non_string_keys_are_rejected() -> None:
    with pytest.raises(CanonicalisationError, match="Non-string key"):
        canonical_json({1: "one"})


def test_unsupported_type_is_rejected() -> None:
    with pytest.raises(CanonicalisationError, match="Unsupported type"):
        canonical_json({"when": object()})
