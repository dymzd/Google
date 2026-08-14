"""The planner golden set is the equivalence contract for the port.

`domain/planner.py` is the largest piece of pure domain logic being ported to
the extension. Correctness means producing the same desired-state resources,
the same gates, and the same `configuration_hash` -- approvals bind to that
hash, so a divergence is a plan the other implementation would refuse rather
than a cosmetic difference.

These tests keep the Python side honest. The TypeScript port is verified
against the same file. Regenerate with:

    python backend/tests/fixtures/planner/generate.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sgstudio.domain.models import DeploymentSpec, DiscoverySnapshot
from sgstudio.domain.planner import (
    DesiredStatePlanner,
    canonical_configuration_hash,
    required_apis,
    required_permissions,
)

_GOLDEN = Path(__file__).parent / "fixtures" / "planner" / "golden.json"


def _cases() -> list[dict[str, Any]]:
    return json.loads(_GOLDEN.read_text(encoding="utf-8"))["cases"]


def _rebuild(case: dict[str, Any]) -> tuple[DeploymentSpec, DiscoverySnapshot]:
    return (
        DeploymentSpec.model_validate(case["spec"]),
        DiscoverySnapshot.model_validate(case["snapshot"]),
    )


@pytest.mark.parametrize("case", _cases(), ids=lambda case: str(case["name"]))
def test_configuration_hash_matches_golden(case: dict[str, Any]) -> None:
    spec, _ = _rebuild(case)
    assert canonical_configuration_hash(spec) == case["configuration_hash"]


@pytest.mark.parametrize("case", _cases(), ids=lambda case: str(case["name"]))
def test_plan_matches_golden(case: dict[str, Any]) -> None:
    spec, snapshot = _rebuild(case)
    produced = DesiredStatePlanner().build_plan(spec, snapshot).model_dump(mode="json")
    produced.pop("generated_at", None)
    assert produced == case["plan"]


@pytest.mark.parametrize("case", _cases(), ids=lambda case: str(case["name"]))
def test_required_apis_match_golden(case: dict[str, Any]) -> None:
    spec, _ = _rebuild(case)
    assert sorted(required_apis(spec)) == case["required_apis"]


@pytest.mark.parametrize("case", _cases(), ids=lambda case: str(case["name"]))
def test_required_permissions_match_golden(case: dict[str, Any]) -> None:
    spec, _ = _rebuild(case)
    assert sorted(required_permissions(spec)) == case["required_permissions"]


def test_golden_covers_both_paths_and_the_global_access_states() -> None:
    names = {case["name"] for case in _cases()}
    assert {"path-a-poc-local-ca", "path-a-existing-vpc"} <= names
    assert {
        "path-b-minimal",
        "path-b-global-access-enabled",
        "path-b-global-access-disabled-blocks",
        "path-b-egress-region-pins-region",
        "path-b-cross-project-upstream",
        "path-b-fqdn-matcher-unresolvable",
    } <= names


def test_golden_blocked_case_is_actually_blocked() -> None:
    # Guards against regenerating a golden that silently stopped exercising the
    # Global Access failure the guide names as the common Path B mistake.
    case = next(c for c in _cases() if c["name"] == "path-b-global-access-disabled-blocks")
    gate = next(g for g in case["plan"]["gates"] if g["gate_id"] == "global-access")
    assert gate["status"] == "blocked"
    assert gate["blocking"] is True
