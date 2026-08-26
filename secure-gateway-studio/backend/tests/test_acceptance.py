from __future__ import annotations

import json
from typing import Any

import pytest

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
                    "trust_mode": "presented_chain_pinned",
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


class CrossProjectAcceptanceTransport(AcceptanceTransport):
    def request_json(self, method: str, url: str, **kwargs):
        status, payload = super().request_json(method, url, **kwargs)
        if "/applications/" in url:
            payload["upstreams"][0]["network"]["name"] = (
                "projects/shared-network-prj/global/networks/"
                "secure-gateway-http-offload-vpc"
            )
        return status, payload


def test_direct_https_verifies_only_the_exact_gateway_route() -> None:
    direct = DeploymentSpec(
        **{
            **production_spec().model_dump(),
            "mode": "poc",
            "backend_kind": BackendKind.DIRECT_HTTPS,
            "network_strategy": NetworkStrategy.EXISTING,
            "vpc_name": "secure-gateway-http-offload-vpc",
            "upstream_vpc_project_id": "shared-network-prj",
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

    findings = GoogleAcceptanceVerifier(CrossProjectAcceptanceTransport()).verify(direct)

    assert [finding.test_id.value for finding in findings] == ["T05"]
    assert findings[0].status is AcceptanceStatus.PASSED


class ReplicaAcceptanceTransport(AcceptanceTransport):
    def __init__(
        self,
        count: int,
        *,
        non_running: bool = False,
        duplicate_last: bool = False,
        san_shape: object | None = None,
        spec: DeploymentSpec | None = None,
    ) -> None:
        self._count = count
        self._non_running = non_running
        self._duplicate_last = duplicate_last
        self._san_shape = san_shape
        self._spec = spec

    def request_json(self, method: str, url: str, **kwargs):
        if url.endswith("/listManagedInstances"):
            items = [
                {
                    "instanceStatus": (
                        "STAGING" if self._non_running and index == 0 else "RUNNING"
                    ),
                    "instance": (
                        "https://compute.googleapis.com/compute/v1/projects/"
                        "enterprise-secgw-01/zones/asia-east1-a/instances/"
                        f"secure-gateway-http-offload-offload-{index}"
                    ),
                }
                for index in range(self._count)
            ]
            if self._duplicate_last and items:
                items[-1] = dict(items[0])
            return 200, {"managedInstances": items}
        status, payload = super().request_json(method, url, **kwargs)
        if url.endswith("/getGuestAttributes"):
            item = payload["queryValue"]["items"][0]
            evidence = json.loads(item["value"])
            if self._spec is not None:
                evidence["configuration_hash"] = canonical_configuration_hash(
                    self._spec
                )
            if self._san_shape is not None and "subject_alt_names" in evidence:
                evidence["subject_alt_names"] = self._san_shape
            item["value"] = json.dumps(evidence)
        return status, payload


class PaginatedReplicaAcceptanceTransport(ReplicaAcceptanceTransport):
    def __init__(self, variant: str, *, spec: DeploymentSpec) -> None:
        super().__init__(2, spec=spec)
        self.variant = variant
        self.list_bodies: list[dict[str, Any]] = []
        self.probe_paths: list[str] = []

    def request_json(self, method: str, url: str, **kwargs):
        if url.endswith("/listManagedInstances"):
            body = dict(kwargs.get("json_body") or {})
            self.list_bodies.append(body)
            token = body.get("pageToken")
            if self.variant == "null-token":
                return 200, {"managedInstances": [], "nextPageToken": None}
            if self.variant == "repeat-token":
                return 200, {"managedInstances": [], "nextPageToken": "repeat"}
            if self.variant == "page-cap":
                return 200, {
                    "managedInstances": [],
                    "nextPageToken": f"page-{len(self.list_bodies) + 1}",
                }
            if self.variant == "item-cap":
                return 200, {"managedInstances": [{} for _ in range(501)]}
            if token is None:
                return 200, {
                    "managedInstances": [],
                    "nextPageToken": "page-2",
                }
            if self.variant == "later-malformed":
                return 200, {"managedInstances": [None]}
            return super().request_json(method, url, **kwargs)
        if url.endswith("/getGuestAttributes"):
            self.probe_paths.append(str((kwargs.get("params") or {}).get("queryPath", "")))
        return super().request_json(method, url, **kwargs)


def test_production_offload_requires_every_configured_minimum_replica() -> None:
    spec = production_spec().model_copy(
        update={"offload_min_replicas": 5, "offload_max_replicas": 10}
    )

    insufficient = GoogleAcceptanceVerifier(
        ReplicaAcceptanceTransport(2, spec=spec)
    ).verify(spec)
    complete = GoogleAcceptanceVerifier(
        ReplicaAcceptanceTransport(5, spec=spec)
    ).verify(spec)

    insufficient_by_test = {item.test_id.value: item for item in insufficient}
    complete_by_test = {item.test_id.value: item for item in complete}
    assert insufficient_by_test["T02"].status is AcceptanceStatus.FAILED
    assert insufficient_by_test["T03"].status is AcceptanceStatus.FAILED
    assert complete_by_test["T02"].status is AcceptanceStatus.PASSED
    assert complete_by_test["T03"].status is AcceptanceStatus.PASSED


def test_production_offload_rejects_non_running_and_duplicate_entries() -> None:
    spec = production_spec().model_copy(
        update={"offload_min_replicas": 5, "offload_max_replicas": 10}
    )
    for transport in (
        ReplicaAcceptanceTransport(5, non_running=True, spec=spec),
        ReplicaAcceptanceTransport(5, duplicate_last=True, spec=spec),
        ReplicaAcceptanceTransport(6, duplicate_last=True, spec=spec),
    ):
        by_test = {
            item.test_id.value: item
            for item in GoogleAcceptanceVerifier(transport).verify(spec)
        }
        assert by_test["T02"].status is AcceptanceStatus.FAILED
        assert by_test["T03"].status is AcceptanceStatus.FAILED


def test_production_offload_follows_an_empty_first_managed_instance_page() -> None:
    target = production_spec()
    transport = PaginatedReplicaAcceptanceTransport("valid", spec=target)

    by_test = {
        item.test_id.value: item
        for item in GoogleAcceptanceVerifier(transport).verify(target)
    }

    assert by_test["T02"].status is AcceptanceStatus.PASSED
    assert by_test["T03"].status is AcceptanceStatus.PASSED
    assert transport.list_bodies == [
        {"maxResults": 500},
        {"maxResults": 500, "pageToken": "page-2"},
    ]


@pytest.mark.parametrize(
    "variant",
    ["later-malformed", "null-token", "repeat-token", "page-cap", "item-cap"],
)
def test_production_offload_rejects_incomplete_managed_instance_inventory_before_probes(
    variant: str,
) -> None:
    target = production_spec()
    transport = PaginatedReplicaAcceptanceTransport(variant, spec=target)

    by_test = {
        item.test_id.value: item
        for item in GoogleAcceptanceVerifier(transport).verify(target)
    }

    assert by_test["T02"].status is AcceptanceStatus.FAILED
    assert by_test["T03"].status is AcceptanceStatus.FAILED
    assert not {"sgstudio/T02", "sgstudio/T03"}.intersection(transport.probe_paths)


def test_tls_sans_must_be_a_list_of_strings() -> None:
    by_test = {
        item.test_id.value: item
        for item in GoogleAcceptanceVerifier(
            ReplicaAcceptanceTransport(2, san_shape="demo-server-http.internal")
        ).verify(production_spec())
    }

    assert by_test["T03"].status is AcceptanceStatus.FAILED


class WrongTrustModeTransport(AcceptanceTransport):
    def request_json(self, method: str, url: str, **kwargs):
        status, payload = super().request_json(method, url, **kwargs)
        if url.endswith("/getGuestAttributes"):
            item = payload["queryValue"]["items"][0]
            evidence = json.loads(item["value"])
            if "trust_mode" in evidence:
                evidence["trust_mode"] = "public_system_roots"
                item["value"] = json.dumps(evidence)
        return status, payload


def test_tls_evidence_must_match_configured_trust_mode() -> None:
    by_test = {
        item.test_id.value: item
        for item in GoogleAcceptanceVerifier(WrongTrustModeTransport()).verify(
            production_spec()
        )
    }

    assert by_test["T03"].status is AcceptanceStatus.FAILED


class ExtraApplicationShapeTransport(AcceptanceTransport):
    def __init__(self, *, extra_matcher: bool = False, extra_upstream: bool = False):
        self._extra_matcher = extra_matcher
        self._extra_upstream = extra_upstream

    def request_json(self, method: str, url: str, **kwargs):
        status, payload = super().request_json(method, url, **kwargs)
        if "/applications/" in url:
            if self._extra_matcher:
                payload["endpointMatchers"].append(
                    {"hostname": "foreign.internal", "ports": [443]}
                )
            if self._extra_upstream:
                payload["upstreams"].append(
                    {
                        "network": {
                            "name": "projects/foreign/global/networks/foreign"
                        }
                    }
                )
        return status, payload


def test_application_requires_one_exact_matcher_and_upstream() -> None:
    for transport in (
        ExtraApplicationShapeTransport(extra_matcher=True),
        ExtraApplicationShapeTransport(extra_upstream=True),
    ):
        by_test = {
            item.test_id.value: item
            for item in GoogleAcceptanceVerifier(transport).verify(production_spec())
        }
        assert by_test["T05"].status is AcceptanceStatus.FAILED
