"""The audit chain golden set is the evidence contract with the extension.

Exported evidence is verified by whichever implementation reads it, so the
chain the extension writes into IndexedDB must be byte-identical to the one the
Python implementation would have written. This file keeps the Python side
pinned; `extension/scripts/verify-audit.ts` checks the port against the same
fixture.

Regenerate with:

    python backend/tests/fixtures/audit/generate.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sgstudio.domain.canonical import canonical_json
from sgstudio.storage.repository import StateRepository

_GOLDEN = Path(__file__).parent / "fixtures" / "audit" / "golden.json"


def _document() -> dict[str, Any]:
    return json.loads(_GOLDEN.read_text(encoding="utf-8"))


def _events() -> list[dict[str, Any]]:
    return _document()["events"]


@pytest.mark.parametrize("event", _events(), ids=lambda event: str(event["event_type"]))
def test_payload_serialisation_matches_golden(event: dict[str, Any]) -> None:
    assert canonical_json(event["payload"]) == event["payload_json"]


@pytest.mark.parametrize("event", _events(), ids=lambda event: str(event["event_type"]))
def test_event_hash_matches_golden(event: dict[str, Any]) -> None:
    assert (
        StateRepository._audit_hash(
            event_id=event["event_id"],
            deployment_id=event["deployment_id"],
            event_type=event["event_type"],
            actor=event["actor"],
            payload_json=event["payload_json"],
            created_at=event["created_at"],
            previous_hash=event["previous_hash"],
        )
        == event["event_hash"]
    )


def test_chain_links_are_consistent() -> None:
    previous: str | None = None
    for event in _events():
        assert event["previous_hash"] == previous
        previous = event["event_hash"]
    assert previous == _document()["chain_head_hash"]


def test_golden_covers_non_ascii_actor_and_payload() -> None:
    # This is the case that diverged before canonicalisation was unified: with
    # ensure_ascii=True the payload would serialise to \uXXXX escapes, which
    # JSON.stringify never produces.
    assert any(
        not event["actor"].isascii() or not event["payload_json"].isascii()
        for event in _events()
    )
