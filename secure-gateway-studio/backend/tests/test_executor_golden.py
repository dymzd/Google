"""The executor golden set is the request-sequence contract with the extension.

What the executor produces is a sequence of HTTP requests. A port is correct
when, for the same change and specification, it issues the same requests in the
same order with the same bodies. Plan comparison cannot see a reordered IAM
read/write, a dropped etag, a missing egress policy, or the wrong project in an
upstream network path -- each of which deploys something different.

Regenerate with:

    python backend/tests/fixtures/executor/generate.py
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from sgstudio.domain.models import DeploymentSpec

_FIXTURES = Path(__file__).parent / "fixtures" / "executor"
_GOLDEN = _FIXTURES / "golden.json"


def _load_fixture_module(name: str, path: Path) -> Any:
    """Load a fixture generator by path.

    Both fixture directories contain a `generate.py`. Importing them by bare
    module name makes the second import silently reuse the first, so the module
    is loaded under a unique name instead.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_generate = _load_fixture_module("executor_fixture", _FIXTURES / "generate.py")
RecordingTransport = _generate.RecordingTransport
_change = _generate._change
_FIXED_EXECUTION_ID = _generate._FIXED_EXECUTION_ID
_PINNED_CERTIFICATE = _generate._PINNED_CERTIFICATE
_configuration_hash = _generate.canonical_configuration_hash

from sgstudio.providers.google_executor import GoogleResourceExecutor  # noqa: E402


def _scenarios() -> list[dict[str, Any]]:
    return json.loads(_GOLDEN.read_text(encoding="utf-8"))["scenarios"]


def _ids(scenario: dict[str, Any]) -> str:
    return str(scenario["name"])


@pytest.mark.parametrize("scenario", _scenarios(), ids=_ids)
def test_recorded_requests_match_the_executor(scenario: dict[str, Any]) -> None:
    spec = DeploymentSpec.model_validate(scenario["spec"])
    for operation in scenario["operations"]:
        transport = RecordingTransport(_configuration_hash(spec))
        executor = GoogleResourceExecutor(
            transport, poll_interval_seconds=0, operation_timeout_seconds=5
        )
        # `requestId` is uuid5(execution_id, key) and execution_id is a fresh
        # uuid4 per executor, so it must be pinned to compare against the file.
        executor._execution_id = _FIXED_EXECUTION_ID
        # Issuance generates a fresh key per run; pin the bundle so the recorded
        # secret payload is reproducible.
        executor._certificate = _PINNED_CERTIFICATE
        executor.apply(
            _change(
                operation["change"]["provider"],
                operation["change"]["resource_type"],
                operation["change"]["resource_name"],
            ),
            spec,
        )
        assert transport.calls == operation["requests"], operation["change"]


def test_cross_project_upstream_moves_both_the_network_and_the_binding() -> None:
    # The guide's worked example separates the VPC project from the gateway
    # project. Both the upstream network path and the upstreamAccess binding
    # have to follow it; moving only one produces a deployment that looks
    # applied and cannot route.
    scenario = next(
        item for item in _scenarios() if item["name"] == "path-b-cross-project-upstream"
    )
    application = next(
        operation
        for operation in scenario["operations"]
        if operation["change"]["resource_type"] == "application"
    )
    create = next(request for request in application["requests"] if request["method"] == "POST")
    assert create["body"]["upstreams"][0]["network"]["name"].startswith(
        "projects/shared-network-prj/"
    )

    binding = next(
        operation
        for operation in scenario["operations"]
        if operation["change"]["resource_type"] == "project_iam"
    )
    assert binding["requests"][-1]["url"].endswith("projects/shared-network-prj:setIamPolicy")


def test_iam_writes_preserve_the_returned_etag() -> None:
    # Dropping the etag turns a concurrent policy edit into a silent overwrite.
    for scenario in _scenarios():
        for operation in scenario["operations"]:
            for request in operation["requests"]:
                if request["url"].endswith(":setIamPolicy"):
                    assert request["body"]["policy"]["etag"] == "before-etag"


def test_iam_writes_retain_pre_existing_bindings() -> None:
    for scenario in _scenarios():
        for operation in scenario["operations"]:
            for request in operation["requests"]:
                if request["url"].endswith(":setIamPolicy"):
                    roles = {
                        binding["role"] for binding in request["body"]["policy"]["bindings"]
                    }
                    assert "roles/viewer" in roles


def test_chrome_policy_reads_the_schema_before_writing() -> None:
    # Schemas are discovered, not assumed: a changed schema must surface as a
    # refusal rather than a policy written into a field that no longer exists.
    for scenario in _scenarios():
        for operation in scenario["operations"]:
            if operation["change"]["provider"] != "chromepolicy":
                continue
            urls = [request["url"] for request in operation["requests"]]
            assert "/policySchemas/" in urls[0]
            assert urls[-1].endswith("/policies/orgunits:batchModify")
