"""Regenerate the cross-language discovery golden set.

Run from the repository root:

    python secure-gateway-studio/backend/tests/fixtures/discovery/generate.py

Discovery turns a live environment into the `DiscoverySnapshot` the planner
consumes. Two things have to be reproduced by the port, and they fail
differently:

  - the **requests issued**, because a probe the extension skips is an
    existing resource it will try to create, and
  - the **snapshot assembled**, because that is what decides whether a gate
    passes.

Both are recorded here. The transport returns fixed, plausible responses; this
is a description of what discovery asks and concludes, not a network test.

Only the Path B range is covered. Path A is Phase 4.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_BACKEND = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_BACKEND / "src"))

from sgstudio.domain.models import (  # noqa: E402
    AccessPrincipal,
    BackendKind,
    BackendLocation,
    CertificateStrategy,
    DeploymentSpec,
    NetworkStrategy,
    PrincipalType,
)
from sgstudio.domain.planner import required_permissions  # noqa: E402
from sgstudio.providers.discovery import GoogleDiscoveryProvider  # noqa: E402

_PROJECT = "enterprise-secgw-01"
_ACCESS_LEVEL = "accessPolicies/123456789/accessLevels/managed_chrome"
_ENABLED = [
    "accesscontextmanager.googleapis.com",
    "admin.googleapis.com",
    "beyondcorp.googleapis.com",
    "chromemanagement.googleapis.com",
    "chromepolicy.googleapis.com",
    "cloudbilling.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "compute.googleapis.com",
    "iamcredentials.googleapis.com",
    "licensing.googleapis.com",
    "logging.googleapis.com",
    "serviceusage.googleapis.com",
]


class RecordingTransport:
    """Records requests and answers with a fixed, plausible environment."""

    def __init__(self, *, global_access: bool | None, matcher_ip: str | None) -> None:
        self.calls: list[dict[str, Any]] = []
        self._global_access = global_access
        self._matcher_ip = matcher_ip

    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]:
        del accepted_statuses
        self.calls.append(
            {"method": method, "url": url, "params": params, "body": json_body}
        )

        if "serviceusage.googleapis.com" in url:
            return 200, {
                "services": [{"config": {"name": name}} for name in _ENABLED]
            }
        if url.endswith(":testIamPermissions"):
            requested = (json_body or {}).get("permissions", [])
            return 200, {"permissions": list(requested)}
        if "cloudbilling.googleapis.com" in url:
            return 200, {"billingEnabled": True}
        if "admin.googleapis.com" in url and "/orgunits/id%3A" in url:
            return 200, {
                "orgUnitId": "id:03-test-ou",
                "orgUnitPath": "/Secure Gateway Test",
            }
        if "/aggregated/forwardingRules" in url:
            if self._matcher_ip is None or self._global_access is None:
                return 200, {"items": {}}
            return 200, {
                "items": {
                    "regions/asia-east1": {
                        "forwardingRules": [
                            {
                                "name": "app-ilb-fr",
                                "IPAddress": self._matcher_ip,
                                "allowGlobalAccess": self._global_access,
                                "loadBalancingScheme": "INTERNAL_MANAGED",
                                "IPProtocol": "TCP",
                                "ports": ["8443"],
                            }
                        ]
                    }
                }
            }
        if "/global/networks/" in url:
            return 200, {"name": url.rsplit("/", maxsplit=1)[-1]}
        if "accesscontextmanager.googleapis.com" in url:
            return 200, {"name": _ACCESS_LEVEL}
        if "/securityGateways/" in url:
            return 404, {}
        if "chromepolicy" in url:
            return 200, {"resolvedPolicies": []}
        if "chromemanagement" in url or "licensing" in url:
            return 200, {}
        if "admin.googleapis.com" in url:
            return 200, {}
        return 404, {}


def _spec(**overrides: Any) -> DeploymentSpec:
    values: dict[str, Any] = {
        "project_id": _PROJECT,
        "mode": "poc",
        "target_ou_id": "03-test-ou",
        "managed_chrome_access_level": _ACCESS_LEVEL,
        "test_ou_confirmed": True,
        "principals": [
            AccessPrincipal(type=PrincipalType.GROUP, value="secure-access@example.com")
        ],
        "backend_kind": BackendKind.DIRECT_HTTPS,
        "network_strategy": NetworkStrategy.EXISTING,
        "vpc_name": "private-app-vpc",
        "subnet_name": None,
        "source_image": None,
        "certificate_strategy": CertificateStrategy.PUBLIC_TRUSTED,
        "existing_backend_url": "https://10.20.0.10:8443",
        "existing_backend_location": BackendLocation.GCP,
        "existing_backend_connectivity_confirmed": True,
    }
    values.update(overrides)
    return DeploymentSpec(**values)


SCENARIOS: list[tuple[str, DeploymentSpec, bool | None, str | None]] = [
    ("global-access-enabled", _spec(), True, "10.20.0.10"),
    ("global-access-disabled", _spec(), False, "10.20.0.10"),
    # An FQDN matcher cannot be resolved to a forwarding rule without private
    # DNS, which the app deliberately does not do. The snapshot must report
    # "unknown", not "disabled".
    (
        "fqdn-matcher-unresolvable",
        _spec(existing_backend_url="https://app.corp.internal:8443"),
        None,
        None,
    ),
    (
        "cross-project-upstream",
        _spec(upstream_vpc_project_id="shared-network-prj"),
        True,
        "10.20.0.10",
    ),
]


def build() -> dict[str, Any]:
    scenarios = []
    for name, spec, global_access, matcher_ip in SCENARIOS:
        transport = RecordingTransport(global_access=global_access, matcher_ip=matcher_ip)
        provider = GoogleDiscoveryProvider(
            transport,
            # The audit actor is inherited from the credential, never supplied
            # by the browser. Fixed here so the snapshot is deterministic.
            cloud_identity="secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com",
            credential_kind="impersonated",
            quota_project_id=_PROJECT,
        )
        result = provider.preflight(spec)
        snapshot = result.snapshot.model_dump(mode="json")
        # Sets serialise in iteration order; sorting keeps the file stable.
        for field in (
            "existing_resource_keys",
            "conflicting_resource_keys",
            "enabled_apis",
            "granted_permissions",
        ):
            snapshot[field] = sorted(snapshot[field])
        scenarios.append(
            {
                "name": name,
                "spec": {
                    **spec.model_dump(mode="json", exclude_none=True),
                    "platforms": sorted(spec.model_dump(mode="json")["platforms"]),
                },
                "requests": transport.calls,
                "snapshot": snapshot,
                "required_permissions": sorted(required_permissions(spec)),
            }
        )
    return {
        "note": (
            "Generated by generate.py from GoogleDiscoveryProvider against a recording "
            "transport. Verified by backend/tests/test_discovery_golden.py and the "
            "extension discovery test. Do not hand-edit."
        ),
        "scenarios": scenarios,
    }


def main() -> None:
    target = Path(__file__).with_name("golden.json")
    document = build()
    target.write_text(
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    total = sum(len(scenario["requests"]) for scenario in document["scenarios"])
    print(
        f"wrote {len(document['scenarios'])} scenarios and {total} recorded requests "
        f"to {target.name}"
    )


if __name__ == "__main__":
    main()
