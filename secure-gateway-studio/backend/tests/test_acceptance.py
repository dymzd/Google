from __future__ import annotations

import json
from typing import Any

from sgstudio.domain.models import (
    AcceptanceStatus,
    AccessPrincipal,
    BackendKind,
    BackendLocation,
    CertificateStrategy,
    DeploymentSpec,
    NetworkStrategy,
    PrincipalType,
)
from sgstudio.domain.planner import canonical_configuration_hash
from sgstudio.providers.acceptance import GoogleAcceptanceVerifier


def production_spec() -> DeploymentSpec:
    return DeploymentSpec(
        project_id="enterprise-secgw-01",
        ca_pool="projects/enterprise-secgw-01/locations/asia-east1/caPools/enterprise",
        ca_name=(
            "projects/enterprise-secgw-01/locations/asia-east1/caPools/enterprise/"
            "certificateAuthorities/issuing"
        ),
        target_ou_id="03-test-ou",
        managed_chrome_access_level=("accessPolicies/123456789/accessLevels/managed_chrome"),
        source_image=("projects/enterprise-secgw-01/global/images/sgs-nginx-20260730"),
        chrome_enterprise_premium_license_confirmed=True,
        workspace_services_confirmed=True,
        endpoint_verification_confirmed=True,
        test_ou_confirmed=True,
        principals=[
            AccessPrincipal(
                type=PrincipalType.GROUP,
                value="secure-access@example.com",
            )
        ],
    )


class AcceptanceTransport:
    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]:
        del method, json_body, accepted_statuses
        if url.endswith("/listManagedInstances"):
            return 200, {
                "managedInstances": [
                    {
                        "instanceStatus": "RUNNING",
                        "instance": (
                            "https://compute.googleapis.com/compute/v1/projects/"
                            "enterprise-secgw-01/zones/asia-east1-a/instances/"
                            "secure-gateway-http-offload-offload-a1"
                        ),
                    },
                    {
                        "instanceStatus": "RUNNING",
                        "instance": (
                            "https://compute.googleapis.com/compute/v1/projects/"
                            "enterprise-secgw-01/zones/asia-east1-c/instances/"
                            "secure-gateway-http-offload-offload-c1"
                        ),
                    },
                ]
            }
        if url.endswith("/getGuestAttributes"):
            test_id = str((params or {}).get("queryPath", "")).rsplit("/", 1)[-1]
            configuration_hash = canonical_configuration_hash(production_spec())
            evidence: dict[str, Any]
            if test_id == "T01":
                evidence = {
                    "status": 200,
                    "body_sha256": "a" * 64,
                    "configuration_hash": configuration_hash,
                }
            elif test_id == "T02":
                evidence = {
                    "status": 200,
                    "body_sha256": "b" * 64,
                    "configuration_hash": configuration_hash,
                }
            else:
                evidence = {
                    "http_status": 200,
                    "tls_version": "TLSv1.3",
                    "hostname": "demo-server-http.internal",
                    "subject_alt_names": ["demo-server-http.internal"],
                    "body_sha256": "c" * 64,
                    "configuration_hash": configuration_hash,
                }
            return 200, {
                "queryValue": {
                    "items": [
                        {
                            "namespace": "sgstudio",
                            "key": test_id,
                            "value": json.dumps(evidence),
                        }
                    ]
                }
            }
        if "/addresses/" in url:
            return 200, {"address": "10.42.0.10"}
        if "/rrsets/" in url:
            return 200, {
                "name": "demo-server-http.internal.",
                "type": "A",
                "rrdatas": ["10.42.0.10"],
            }
        if "/applications/" in url:
            return 200, {
                "endpointMatchers": [
                    {
                        "hostname": "demo-server-http.internal",
                        "ports": [443],
                    }
                ],
                "upstreams": [
                    {
                        "network": {
                            "name": (
                                "projects/enterprise-secgw-01/global/networks/"
                                "secure-gateway-http-offload-vpc"
                            )
                        }
                    }
                ],
            }
        raise AssertionError(f"Unexpected URL: {url}")


def test_verifier_passes_t01_through_t05_from_runtime_and_control_plane() -> None:
    findings = GoogleAcceptanceVerifier(AcceptanceTransport()).verify(production_spec())

    assert [finding.test_id.value for finding in findings] == [
        "T01",
        "T02",
        "T03",
        "T04",
        "T05",
    ]
    assert all(finding.status is AcceptanceStatus.PASSED for finding in findings)
    assert "private_key" not in "".join(finding.evidence.lower() for finding in findings)


class MissingProbeTransport(AcceptanceTransport):
    def request_json(self, method: str, url: str, **kwargs):
        if url.endswith("/getGuestAttributes"):
            raise ValueError("missing")
        return super().request_json(method, url, **kwargs)


def test_verifier_fails_closed_when_runtime_probes_are_missing() -> None:
    findings = GoogleAcceptanceVerifier(MissingProbeTransport()).verify(production_spec())
    by_test = {finding.test_id.value: finding for finding in findings}

    assert by_test["T01"].status is AcceptanceStatus.FAILED
    assert by_test["T02"].status is AcceptanceStatus.FAILED
    assert by_test["T03"].status is AcceptanceStatus.FAILED
    assert by_test["T04"].status is AcceptanceStatus.PASSED
    assert by_test["T05"].status is AcceptanceStatus.PASSED


def test_direct_https_verifies_only_the_exact_gateway_route() -> None:
    direct = DeploymentSpec(
        **{
            **production_spec().model_dump(),
            "mode": "poc",
            "backend_kind": BackendKind.DIRECT_HTTPS,
            "network_strategy": NetworkStrategy.EXISTING,
            "vpc_name": "secure-gateway-http-offload-vpc",
            "subnet_name": None,
            "source_image": None,
            "certificate_strategy": CertificateStrategy.PUBLIC_TRUSTED,
            "ca_pool": None,
            "ca_name": None,
            "existing_backend_url": "https://demo-server-http.internal",
            "existing_backend_location": BackendLocation.GCP,
            "existing_backend_connectivity_confirmed": True,
        }
    )

    findings = GoogleAcceptanceVerifier(AcceptanceTransport()).verify(direct)

    assert [finding.test_id.value for finding in findings] == ["T05"]
    assert findings[0].status is AcceptanceStatus.PASSED
