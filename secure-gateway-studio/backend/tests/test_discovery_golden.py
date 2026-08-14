"""The discovery golden set pins both halves of the discovery contract.

Discovery turns a live project into the snapshot the planner consumes. Two
things must be reproduced by the port, and they fail differently:

  - the requests issued, because a probe the extension skips is an existing
    resource it will then try to create, and
  - the snapshot assembled, because that is what decides whether a gate passes
    and therefore whether Apply is offered at all.

Regenerate with:

    python backend/tests/fixtures/discovery/generate.py
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from sgstudio.domain.models import DeploymentSpec

_FIXTURES = Path(__file__).parent / "fixtures" / "discovery"
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


_generate = _load_fixture_module("discovery_fixture", _FIXTURES / "generate.py")
SCENARIOS = _generate.SCENARIOS
RecordingTransport = _generate.RecordingTransport

from sgstudio.providers.discovery import GoogleDiscoveryProvider  # noqa: E402

_IDENTITY = "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com"


def _scenarios() -> list[dict[str, Any]]:
    return json.loads(_GOLDEN.read_text(encoding="utf-8"))["scenarios"]


def _settings(name: str) -> tuple[bool | None, str | None]:
    for scenario_name, _, global_access, matcher_ip in SCENARIOS:
        if scenario_name == name:
            return global_access, matcher_ip
    raise KeyError(name)


@pytest.mark.parametrize("scenario", _scenarios(), ids=lambda scenario: str(scenario["name"]))
def test_recorded_requests_and_snapshot_match(scenario: dict[str, Any]) -> None:
    global_access, matcher_ip = _settings(scenario["name"])
    transport = RecordingTransport(global_access=global_access, matcher_ip=matcher_ip)
    provider = GoogleDiscoveryProvider(
        transport,
        cloud_identity=_IDENTITY,
        credential_kind="impersonated",
        quota_project_id="enterprise-secgw-01",
    )

    result = provider.preflight(DeploymentSpec.model_validate(scenario["spec"]))
    snapshot = result.snapshot.model_dump(mode="json")
    for field in (
        "existing_resource_keys",
        "conflicting_resource_keys",
        "enabled_apis",
        "granted_permissions",
    ):
        snapshot[field] = sorted(snapshot[field])

    assert transport.calls == scenario["requests"]
    assert snapshot == scenario["snapshot"]


def test_unresolvable_matcher_reports_unknown_not_disabled() -> None:
    # The gate blocks only on a confirmed False. Collapsing "could not check"
    # into "disabled" would refuse every FQDN matcher, GKE ingress, and non-GCP
    # backend -- all supported Path B targets.
    scenario = next(
        item for item in _scenarios() if item["name"] == "fqdn-matcher-unresolvable"
    )
    assert scenario["snapshot"]["application_global_access"] is None
    assert scenario["snapshot"]["application_forwarding_rule"] is None


def test_global_access_states_are_distinguished() -> None:
    states = {
        item["name"]: item["snapshot"]["application_global_access"] for item in _scenarios()
    }
    assert states["global-access-enabled"] is True
    assert states["global-access-disabled"] is False


def test_access_level_permission_is_never_probed_at_project_scope() -> None:
    # Access levels live on the access policy, not the project. Asking here
    # always returns "not granted" and would block an authorised plan.
    for scenario in _scenarios():
        for request in scenario["requests"]:
            if request["url"].endswith(":testIamPermissions"):
                assert "accesscontextmanager.accessLevels.get" not in request["body"][
                    "permissions"
                ]


def test_cross_project_upstream_probes_the_owning_project() -> None:
    scenario = next(
        item for item in _scenarios() if item["name"] == "cross-project-upstream"
    )
    network_probes = [
        request["url"]
        for request in scenario["requests"]
        if "/global/networks/" in request["url"]
    ]
    assert network_probes
    assert all("projects/shared-network-prj/" in url for url in network_probes)
