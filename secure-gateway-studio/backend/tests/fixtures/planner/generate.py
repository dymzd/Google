"""Regenerate the cross-language planner golden set.

Run from the repository root:

    python secure-gateway-studio/backend/tests/fixtures/planner/generate.py

The planner is pure domain logic and the largest single piece of the port
(`domain/planner.py`, 1,300 lines). Porting it correctly means producing the
same desired-state resources, the same gates, and above all the same
`configuration_hash` -- approvals are bound to that hash, so a divergence is
not a cosmetic difference but a plan the other implementation would refuse.

This file pins spec-to-plan for a representative set of deployments. The
TypeScript port is verified against the same file, exactly as the
canonicalisation golden set works.

`generated_at` is dropped: it is wall-clock and would make every regeneration
a diff. Nothing hashes it -- `canonical_configuration_hash` covers the spec,
not the plan envelope.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_BACKEND_SRC = Path(__file__).resolve().parents[3] / "src"
sys.path.insert(0, str(_BACKEND_SRC))

from sgstudio.domain.models import (  # noqa: E402
    AccessPrincipal,
    BackendKind,
    BackendLocation,
    CertificateStrategy,
    ChromePlatform,
    DeploymentSpec,
    DiscoverySnapshot,
    NetworkStrategy,
    PrincipalType,
)
from sgstudio.domain.planner import (  # noqa: E402
    DesiredStatePlanner,
    canonical_configuration_hash,
    required_apis,
    required_permissions,
)

_PRINCIPALS = [AccessPrincipal(type=PrincipalType.GROUP, value="secure-access@example.com")]


def _base(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "project_id": "enterprise-secgw-01",
        "target_ou_id": "03-test-ou",
        "managed_chrome_access_level": "accessPolicies/123456789/accessLevels/managed_chrome",
        "test_ou_confirmed": True,
        "principals": _PRINCIPALS,
    }
    values.update(overrides)
    return values


def _path_b(**overrides: Any) -> DeploymentSpec:
    values = _base(
        mode="poc",
        backend_kind=BackendKind.DIRECT_HTTPS,
        network_strategy=NetworkStrategy.EXISTING,
        vpc_name="private-app-vpc",
        source_image=None,
        certificate_strategy=CertificateStrategy.PUBLIC_TRUSTED,
        existing_backend_url="https://10.20.0.10:8443",
        existing_backend_location=BackendLocation.GCP,
        existing_backend_connectivity_confirmed=True,
    )
    values.update(overrides)
    return DeploymentSpec(**values)


def _path_a(**overrides: Any) -> DeploymentSpec:
    values = _base(
        mode="poc",
        certificate_strategy=CertificateStrategy.LOCAL_POC,
        source_image=None,
        platforms={ChromePlatform.MACOS, ChromePlatform.WINDOWS},
    )
    values.update(overrides)
    return DeploymentSpec(**values)


CASES: list[tuple[str, DeploymentSpec, DiscoverySnapshot]] = [
    ("path-b-minimal", _path_b(), DiscoverySnapshot()),
    (
        "path-b-global-access-enabled",
        _path_b(),
        DiscoverySnapshot(
            application_global_access=True, application_forwarding_rule="app-ilb-fr"
        ),
    ),
    (
        "path-b-global-access-disabled-blocks",
        _path_b(),
        DiscoverySnapshot(
            application_global_access=False, application_forwarding_rule="app-ilb-fr"
        ),
    ),
    (
        "path-b-egress-region-pins-region",
        _path_b(application_egress_region="asia-east1"),
        DiscoverySnapshot(application_global_access=False),
    ),
    (
        "path-b-cross-project-upstream",
        _path_b(upstream_vpc_project_id="shared-network-prj"),
        DiscoverySnapshot(),
    ),
    (
        "path-b-fqdn-matcher-unresolvable",
        _path_b(existing_backend_url="https://app.corp.internal:8443"),
        DiscoverySnapshot(),
    ),
    ("path-a-poc-local-ca", _path_a(), DiscoverySnapshot()),
    (
        "path-a-existing-vpc",
        _path_a(
            network_strategy=NetworkStrategy.EXISTING,
            vpc_name="shared-vpc",
            subnet_name="offload-subnet",
        ),
        DiscoverySnapshot(private_egress_available=True),
    ),
]


def build() -> dict[str, Any]:
    planner = DesiredStatePlanner()
    cases = []
    for name, spec, snapshot in CASES:
        plan = planner.build_plan(spec, snapshot)
        payload = plan.model_dump(mode="json")
        # Wall-clock; nothing hashes it and keeping it would make every
        # regeneration a diff.
        payload.pop("generated_at", None)
        spec_payload = spec.model_dump(mode="json", exclude_none=True)
        # `platforms` is a set, so model_dump emits it in iteration order.
        # Sorting here is what canonical_configuration_hash already does before
        # hashing, and it keeps this file stable across regenerations.
        spec_payload["platforms"] = sorted(spec_payload["platforms"])
        cases.append(
            {
                "name": name,
                "spec": spec_payload,
                "snapshot": snapshot.model_dump(mode="json"),
                "configuration_hash": canonical_configuration_hash(spec),
                "required_apis": sorted(required_apis(spec)),
                "required_permissions": sorted(required_permissions(spec)),
                "plan": payload,
            }
        )
    return {
        "note": (
            "Generated by generate.py. Verified by backend/tests/test_planner_golden.py "
            "and by the extension planner test. Do not hand-edit."
        ),
        "cases": cases,
    }


def main() -> None:
    target = Path(__file__).with_name("golden.json")
    document = build()
    target.write_text(
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(document['cases'])} planner cases to {target.name}")


if __name__ == "__main__":
    main()
