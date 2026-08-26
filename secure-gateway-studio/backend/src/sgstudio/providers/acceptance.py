from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlsplit

from sgstudio.domain.canonical import canonical_json
from sgstudio.domain.models import (
    AcceptanceStatus,
    AcceptanceTestId,
    BackendKind,
    CertificateStrategy,
    DeploymentMode,
    DeploymentSpec,
)
from sgstudio.domain.planner import canonical_configuration_hash
from sgstudio.providers.google_rest import (
    GoogleApiError,
    GoogleAuthorizedTransport,
    JsonTransport,
)


@dataclass(frozen=True)
class AcceptanceFinding:
    test_id: AcceptanceTestId
    status: AcceptanceStatus
    summary: str
    evidence: str


class GoogleAcceptanceVerifier:
    """Verify deploy-time acceptance controls without collecting credentials."""

    def __init__(self, transport: JsonTransport) -> None:
        self._transport = transport

    def verify(self, spec: DeploymentSpec) -> list[AcceptanceFinding]:
        if spec.backend_kind is BackendKind.DIRECT_HTTPS:
            return [self._verify_application(spec)]
        if spec.backend_kind is BackendKind.INTERNAL_HTTPS_LB:
            return [
                self._verify_backend(spec),
                self._verify_dns(spec),
                self._verify_application(spec),
            ]
        findings: list[AcceptanceFinding] = []
        if spec.backend_kind is BackendKind.MANAGED_SAMPLE:
            findings.append(self._verify_backend(spec))
        findings.extend(self._verify_offload(spec))
        findings.append(self._verify_dns(spec))
        findings.append(self._verify_application(spec))
        return findings

    def _verify_backend(self, spec: DeploymentSpec) -> AcceptanceFinding:
        try:
            evidence = self._guest_attribute(
                spec,
                zone=spec.zone,
                instance=f"{spec.name}-backend",
                test_id=AcceptanceTestId.T01,
            )
            passed = (
                evidence.get("status") == 200
                and self._has_hash(evidence)
                and self._matches_configuration(evidence, spec)
            )
            return self._finding(
                AcceptanceTestId.T01,
                passed,
                "Managed backend returned HTTP 200 to its local runtime probe",
                "Managed backend runtime probe is missing or invalid",
                evidence,
            )
        except (GoogleApiError, ValueError, KeyError, TypeError):
            return self._failed(
                AcceptanceTestId.T01,
                "Managed backend runtime probe could not be verified",
                "guest-attribute-unavailable",
            )

    def _verify_offload(self, spec: DeploymentSpec) -> list[AcceptanceFinding]:
        try:
            instances = self._offload_instances(spec)
            if not instances:
                raise ValueError("no-offload-instances")
            t02_evidence = [
                {
                    "instance": instance,
                    **self._guest_attribute(
                        spec,
                        zone=zone,
                        instance=instance,
                        test_id=AcceptanceTestId.T02,
                    ),
                }
                for zone, instance in instances
            ]
            t03_evidence = [
                {
                    "instance": instance,
                    **self._guest_attribute(
                        spec,
                        zone=zone,
                        instance=instance,
                        test_id=AcceptanceTestId.T03,
                    ),
                }
                for zone, instance in instances
            ]
            expected_count = (
                spec.offload_min_replicas
                if spec.mode is DeploymentMode.PRODUCTION
                else 1
            )
            expected_trust_mode = (
                "public_system_roots"
                if spec.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED
                else "presented_chain_pinned"
            )
            t02_passed = len(t02_evidence) >= expected_count and all(
                item.get("status") == 200
                and self._has_hash(item)
                and self._matches_configuration(item, spec)
                for item in t02_evidence
            )
            t03_passed = len(t03_evidence) >= expected_count and all(
                item.get("http_status") == 200
                and item.get("hostname") == spec.private_hostname
                and item.get("trust_mode") == expected_trust_mode
                and item.get("tls_version") in {"TLSv1.2", "TLSv1.3"}
                and isinstance(item.get("subject_alt_names"), list)
                and all(
                    isinstance(name, str)
                    for name in item["subject_alt_names"]
                )
                and spec.private_hostname in item["subject_alt_names"]
                and self._has_hash(item)
                and self._matches_configuration(item, spec)
                for item in t03_evidence
            )
            return [
                self._finding(
                    AcceptanceTestId.T02,
                    t02_passed,
                    "Every offload instance reached the HTTP backend with status 200",
                    "One or more offload-to-backend runtime probes failed",
                    {"instances": t02_evidence},
                ),
                self._finding(
                    AcceptanceTestId.T03,
                    t03_passed,
                    (
                        "Every offload instance passed the configured trust-mode, "
                        "hostname-validating TLS, and HTTP checks"
                    ),
                    "One or more TLS termination runtime probes failed",
                    {"instances": t03_evidence},
                ),
            ]
        except (GoogleApiError, ValueError, KeyError, TypeError):
            return [
                self._failed(
                    AcceptanceTestId.T02,
                    "Offload-to-backend runtime probes could not be verified",
                    "guest-attribute-unavailable",
                ),
                self._failed(
                    AcceptanceTestId.T03,
                    "TLS termination runtime probes could not be verified",
                    "guest-attribute-unavailable",
                ),
            ]

    def _offload_instances(self, spec: DeploymentSpec) -> list[tuple[str, str]]:
        if spec.mode is DeploymentMode.POC:
            return [(spec.zone, f"{spec.name}-offload")]
        url = (
            f"https://compute.googleapis.com/compute/v1/projects/"
            f"{spec.project_id}/regions/{spec.region}/instanceGroupManagers/"
            f"{spec.name}-offload-mig/listManagedInstances"
        )
        managed: list[Any] = []
        seen_tokens: set[str] = set()
        page_token: str | None = None
        complete = False
        page_size = 500
        page_limit = 100
        for _ in range(page_limit):
            body: dict[str, Any] = {"maxResults": page_size}
            if page_token is not None:
                body["pageToken"] = page_token
            _, payload = self._transport.request_json("POST", url, json_body=body)
            page_items = payload.get("managedInstances")
            if not isinstance(page_items, list):
                raise ValueError("invalid-managed-instance-response")
            if len(page_items) > page_size:
                raise ValueError("managed-instance-page-limit")
            managed.extend(page_items)
            if len(managed) > page_size * page_limit:
                raise ValueError("managed-instance-item-limit")
            if "nextPageToken" not in payload or payload["nextPageToken"] == "":
                complete = True
                break
            next_token = payload["nextPageToken"]
            if not isinstance(next_token, str) or next_token in seen_tokens:
                raise ValueError("invalid-managed-instance-page-token")
            seen_tokens.add(next_token)
            page_token = next_token
        if not complete:
            raise ValueError("managed-instance-pagination-incomplete")

        instances: set[tuple[str, str]] = set()
        for item in managed:
            if not isinstance(item, dict) or item.get("instanceStatus") != "RUNNING":
                raise ValueError("managed-instance-not-running")
            instance_url = item.get("instance")
            if not isinstance(instance_url, str):
                raise ValueError("invalid-managed-instance-name")
            parsed = urlsplit(instance_url)
            parts = parsed.path.split("/")
            if (
                parsed.scheme != "https"
                or parsed.hostname not in {"compute.googleapis.com", "www.googleapis.com"}
                or parsed.port is not None
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
                or len(parts) != 9
                or parts[1:4] != ["compute", "v1", "projects"]
                or parts[4] != spec.project_id
                or parts[5] != "zones"
                or parts[7] != "instances"
                or not parts[6]
                or not parts[8]
                or "%" in parts[6]
                or "%" in parts[8]
            ):
                raise ValueError("invalid-managed-instance-name")
            identity = (parts[6], parts[8])
            if identity in instances:
                raise ValueError("duplicate-managed-instance")
            instances.add(identity)
        return sorted(instances)

    def _guest_attribute(
        self,
        spec: DeploymentSpec,
        *,
        zone: str,
        instance: str,
        test_id: AcceptanceTestId,
    ) -> dict[str, Any]:
        _, payload = self._transport.request_json(
            "GET",
            (
                f"https://compute.googleapis.com/compute/v1/projects/"
                f"{spec.project_id}/zones/{zone}/instances/{instance}/"
                "getGuestAttributes"
            ),
            params={"queryPath": f"sgstudio/{test_id.value}"},
        )
        value = payload.get("variableValue")
        query_value = payload.get("queryValue")
        if not isinstance(value, str) and isinstance(query_value, dict):
            items = query_value.get("items")
            if isinstance(items, list):
                match = next(
                    (
                        item
                        for item in items
                        if isinstance(item, dict)
                        and item.get("namespace") == "sgstudio"
                        and item.get("key") == test_id.value
                    ),
                    None,
                )
                if isinstance(match, dict):
                    value = match.get("value")
        if not isinstance(value, str):
            raise ValueError("guest-attribute-value-missing")
        decoded = json.loads(value)
        if not isinstance(decoded, dict):
            raise ValueError("guest-attribute-value-invalid")
        return decoded

    def _verify_dns(self, spec: DeploymentSpec) -> AcceptanceFinding:
        try:
            _, address = self._transport.request_json(
                "GET",
                (
                    f"https://compute.googleapis.com/compute/v1/projects/"
                    f"{spec.project_id}/regions/{spec.region}/addresses/"
                    f"{spec.name}-offload-ip"
                ),
            )
            expected = address.get("address")
            if not isinstance(expected, str):
                raise ValueError("internal-address-missing")
            record_name = quote(f"{spec.private_hostname}.", safe="")
            _, record = self._transport.request_json(
                "GET",
                (
                    f"https://dns.googleapis.com/dns/v1/projects/{spec.project_id}/"
                    f"managedZones/{spec.name}-zone/rrsets/{record_name}/A"
                ),
            )
            rrdatas = record.get("rrdatas")
            passed = (
                record.get("name") == f"{spec.private_hostname}."
                and record.get("type") == "A"
                and isinstance(rrdatas, list)
                and rrdatas == [expected]
            )
            return self._finding(
                AcceptanceTestId.T04,
                passed,
                "Private DNS A record exactly matches the reserved internal address",
                "Private DNS does not exactly match the reserved internal address",
                {
                    "hostname": spec.private_hostname,
                    "expected_address": expected,
                    "rrdatas": rrdatas if isinstance(rrdatas, list) else [],
                },
            )
        except (GoogleApiError, ValueError, KeyError, TypeError):
            return self._failed(
                AcceptanceTestId.T04,
                "Private DNS configuration could not be verified",
                "dns-verification-unavailable",
            )

    def _verify_application(self, spec: DeploymentSpec) -> AcceptanceFinding:
        try:
            _, payload = self._transport.request_json(
                "GET",
                (
                    f"https://beyondcorp.googleapis.com/v1/projects/"
                    f"{spec.project_id}/locations/global/securityGateways/"
                    f"{spec.gateway_id}/applications/{spec.name}-app"
                ),
            )
            matchers = payload.get("endpointMatchers", payload.get("endpoint_matchers"))
            exact = (
                isinstance(matchers, list)
                and len(matchers) == 1
                and isinstance(matchers[0], dict)
                and matchers[0].get("hostname") == spec.application_hostname
                and matchers[0].get("ports") == [spec.application_port]
            )
            upstreams = payload.get("upstreams")
            network_name = (
                spec.vpc_name
                if spec.network_strategy.value == "existing"
                else f"{spec.name}-vpc"
            )
            expected_network = (
                f"projects/{spec.upstream_project_id}/global/networks/{network_name}"
            )
            upstream_exact = False
            if isinstance(upstreams, list) and len(upstreams) == 1:
                upstream = upstreams[0]
                if isinstance(upstream, dict):
                    network = upstream.get("network")
                    policy = upstream.get("egressPolicy", upstream.get("egress_policy"))
                    expected_policy = (
                        {"regions": [spec.application_egress_region]}
                        if spec.application_egress_region
                        else None
                    )
                    upstream_exact = (
                        isinstance(network, dict)
                        and network.get("name") == expected_network
                        and policy == expected_policy
                    )
            exact = exact and upstream_exact
            return self._finding(
                AcceptanceTestId.T05,
                exact,
                "Secure Gateway application exactly matches the private HTTPS endpoint",
                "Secure Gateway application matcher is missing or does not match exactly",
                {
                    "application": f"{spec.name}-app",
                    "hostname": spec.application_hostname,
                    "port": spec.application_port,
                    "network": expected_network,
                    "egress_region": spec.application_egress_region,
                    "exact_match": exact,
                },
            )
        except (GoogleApiError, ValueError, KeyError, TypeError):
            return self._failed(
                AcceptanceTestId.T05,
                "Secure Gateway application matcher could not be verified",
                "application-verification-unavailable",
            )

    @staticmethod
    def _has_hash(evidence: dict[str, Any]) -> bool:
        value = evidence.get("body_sha256")
        return (
            isinstance(value, str)
            and len(value) == 64
            and all(character in "0123456789abcdef" for character in value)
        )

    @staticmethod
    def _matches_configuration(
        evidence: dict[str, Any],
        spec: DeploymentSpec,
    ) -> bool:
        expected = canonical_configuration_hash(spec)
        return evidence.get("configuration_hash") == expected

    @classmethod
    def _finding(
        cls,
        test_id: AcceptanceTestId,
        passed: bool,
        passed_summary: str,
        failed_summary: str,
        evidence: dict[str, Any],
    ) -> AcceptanceFinding:
        return AcceptanceFinding(
            test_id=test_id,
            status=(AcceptanceStatus.PASSED if passed else AcceptanceStatus.FAILED),
            summary=passed_summary if passed else failed_summary,
            evidence=canonical_json(evidence),
        )

    @classmethod
    def _failed(
        cls,
        test_id: AcceptanceTestId,
        summary: str,
        reason: str,
    ) -> AcceptanceFinding:
        return cls._finding(
            test_id,
            False,
            summary,
            summary,
            {"reason": reason},
        )


def create_google_acceptance_verifier(
    *, require_impersonation: bool = False
) -> GoogleAcceptanceVerifier:
    return GoogleAcceptanceVerifier(
        GoogleAuthorizedTransport.from_adc(require_impersonation=require_impersonation)
    )
