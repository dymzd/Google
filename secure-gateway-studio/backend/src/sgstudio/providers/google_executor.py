from __future__ import annotations

import base64
import json
import logging
import re
import time
import uuid
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

from google.auth.exceptions import DefaultCredentialsError, RefreshError

from sgstudio.domain.execution import ProviderExecutionError
from sgstudio.domain.models import (
    BackendKind,
    CertificateStrategy,
    DeploymentSpec,
    NetworkStrategy,
    ResourceChange,
)
from sgstudio.domain.naming import service_account_email
from sgstudio.domain.planner import (
    canonical_configuration_hash,
    certificate_configuration_hash,
    required_apis,
)
from sgstudio.providers.certificates import CertificateBundle, CertificateIssuer
from sgstudio.providers.google_rest import (
    GoogleApiError,
    GoogleAuthorizedTransport,
    JsonTransport,
)
from sgstudio.providers.local_artifacts import CertificateArtifactStore

EXTENSION_ID = "ekajlcmdfcigmdbphhifahdfjbkciflj"
SECURE_GATEWAY_SOURCE_CIDR = "136.124.16.0/20"
LOGGER = logging.getLogger(__name__)
GOOGLE_STATUS_PATTERN = re.compile(r"^[A-Z][A-Z_]{2,63}$")


@dataclass(frozen=True)
class Mutation:
    apply: Callable[[ResourceChange, DeploymentSpec], None]
    rollback: Callable[[ResourceChange, DeploymentSpec], None]


class GoogleResourceExecutor:
    """Direct REST executor with exact IAM/policy restoration and bounded deletion.

    The object is deliberately scoped to one deployment run. Ephemeral certificate
    material and before-images never leave process memory and are not logged.
    """

    def __init__(
        self,
        transport: JsonTransport,
        *,
        artifact_store: CertificateArtifactStore | None = None,
        poll_interval_seconds: float = 1.0,
        operation_timeout_seconds: float = 900.0,
    ) -> None:
        self._transport = transport
        self._artifact_store = artifact_store or CertificateArtifactStore(
            Path.cwd() / ".local" / "artifacts"
        )
        self._poll_interval = poll_interval_seconds
        self._operation_timeout = operation_timeout_seconds
        self._certificate: CertificateBundle | None = None
        self._execution_id = uuid.uuid4()
        self._before: dict[str, dict[str, Any] | None] = {}
        self._created: set[str] = set()
        self._gateway_service_account: str | None = None
        self._mutations = self._build_dispatch()

    def apply(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        mutation = self._mutations.get((change.provider, change.resource_type))
        if mutation is None:
            raise ProviderExecutionError("unsupported-resource-type")
        try:
            mutation.apply(change, spec)
        except ProviderExecutionError:
            raise
        except GoogleApiError as error:
            LOGGER.warning(
                "Google API apply failed: provider=%s resource_type=%s status=%s "
                "host=%s detail=%s",
                change.provider,
                change.resource_type,
                error.status_code,
                error.host,
                error.detail,
            )
            raise ProviderExecutionError(
                self._google_error_code(error, change.provider)
            ) from error
        except Exception as error:
            LOGGER.exception(
                "Provider apply response handling failed: provider=%s resource_type=%s",
                change.provider,
                change.resource_type,
            )
            raise ProviderExecutionError(
                f"invalid-provider-response-{change.resource_type}"
            ) from error

    def rollback(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        mutation = self._mutations.get((change.provider, change.resource_type))
        if mutation is None:
            raise ProviderExecutionError("unsupported-resource-type")
        try:
            mutation.rollback(change, spec)
        except ProviderExecutionError:
            raise
        except GoogleApiError as error:
            if error.status_code == 404:
                return
            LOGGER.warning(
                "Google API rollback failed: provider=%s resource_type=%s status=%s "
                "host=%s detail=%s",
                change.provider,
                change.resource_type,
                error.status_code,
                error.host,
                error.detail,
            )
            raise ProviderExecutionError(
                "rollback-" + self._google_error_code(error, change.provider)
            ) from error
        except Exception as error:
            LOGGER.exception(
                "Provider rollback response handling failed: provider=%s resource_type=%s",
                change.provider,
                change.resource_type,
            )
            raise ProviderExecutionError(
                f"rollback-invalid-response-{change.resource_type}"
            ) from error

    def destroy(
        self, change: ResourceChange, spec: DeploymentSpec
    ) -> str:
        """Delete a server-recorded resource without relying on process-local before-images."""
        try:
            if change.provider == "local" and change.resource_type == "root_certificate_artifact":
                self._artifact_store.remove_root_certificate(spec.name)
                return "deleted"
            if change.provider == "beyondcorp" and change.resource_type == "security_gateway":
                applications = self._request(
                    "GET",
                    f"{self._gateway_resource(spec)}/applications",
                    params={"pageSize": 1},
                    accepted=(200, 404),
                )
                if applications.get("applications"):
                    return "skipped"
                self._delete_url(
                    self._gateway_resource(spec),
                    fallback_host="beyondcorp.googleapis.com",
                )
                return "deleted"
            if change.provider == "dns" and change.resource_type == "record_set":
                self._destroy_dns_record(spec)
                return "deleted"
            url = self._destroy_url(change, spec)
            if url is None:
                return "skipped"
            self._delete_url(url, fallback_host=url.split("/", 3)[2])
            return "deleted"
        except ProviderExecutionError:
            raise
        except GoogleApiError as error:
            raise ProviderExecutionError(
                "teardown-" + self._google_error_code(error, change.provider)
            ) from error
        except Exception as error:
            LOGGER.exception(
                "Provider teardown failed: provider=%s resource_type=%s",
                change.provider,
                change.resource_type,
            )
            raise ProviderExecutionError(
                f"teardown-invalid-response-{change.resource_type}"
            ) from error

    def _delete_url(self, url: str, *, fallback_host: str) -> None:
        status_code, payload = self._transport.request_json(
            "DELETE", url, accepted_statuses=(200, 202, 204, 404)
        )
        if status_code != 404 and payload:
            self._wait(payload, fallback_host=fallback_host)

    def _destroy_url(self, change: ResourceChange, spec: DeploymentSpec) -> str | None:
        project = spec.project_id
        compute = f"https://compute.googleapis.com/compute/v1/projects/{project}"
        key = (change.provider, change.resource_type)
        urls: dict[tuple[str, str], str] = {
            ("compute", "network"): f"{compute}/global/networks/{change.resource_name}",
            ("compute", "subnetwork"): (
                f"{compute}/regions/{spec.region}/subnetworks/{change.resource_name}"
            ),
            ("compute", "router"): (
                f"{compute}/regions/{spec.region}/routers/{change.resource_name}"
            ),
            ("compute", "internal_address"): (
                f"{compute}/regions/{spec.region}/addresses/{change.resource_name}"
            ),
            ("compute", "instance"): (
                f"{compute}/zones/{spec.zone}/instances/{change.resource_name}"
            ),
            ("compute", "instance_template"): (
                f"{compute}/global/instanceTemplates/{change.resource_name}"
            ),
            ("compute", "health_check"): (
                f"{compute}/regions/{spec.region}/healthChecks/{change.resource_name}"
            ),
            ("compute", "instance_group_manager"): (
                f"{compute}/regions/{spec.region}/instanceGroupManagers/"
                f"{change.resource_name}"
            ),
            ("compute", "autoscaler"): (
                f"{compute}/regions/{spec.region}/autoscalers/{change.resource_name}"
            ),
            ("compute", "backend_service"): (
                f"{compute}/regions/{spec.region}/backendServices/{change.resource_name}"
            ),
            ("compute", "forwarding_rule"): (
                f"{compute}/regions/{spec.region}/forwardingRules/{change.resource_name}"
            ),
            ("compute", "firewall_rule"): (
                f"{compute}/global/firewalls/{change.resource_name}"
            ),
            ("dns", "private_zone"): (
                f"https://dns.googleapis.com/dns/v1/projects/{project}/managedZones/"
                f"{change.resource_name}"
            ),
            ("iam", "service_account"): (
                f"https://iam.googleapis.com/v1/projects/{project}/serviceAccounts/"
                f"{quote(f'{change.resource_name}@{project}.iam.gserviceaccount.com', safe='')}"
            ),
            ("secretmanager", "secret"): (
                f"https://secretmanager.googleapis.com/v1/projects/{project}/secrets/"
                f"{change.resource_name}"
            ),
            ("beyondcorp", "application"): (
                f"{self._gateway_resource(spec)}/applications/{change.resource_name}"
            ),
        }
        return urls.get(key)

    def _destroy_dns_record(self, spec: DeploymentSpec) -> None:
        zone = f"{spec.name}-zone"
        fqdn = f"{spec.private_hostname}."
        record_url = (
            f"https://dns.googleapis.com/dns/v1/projects/{spec.project_id}/"
            f"managedZones/{zone}/rrsets/{quote(fqdn, safe='')}/A"
        )
        status_code, record = self._transport.request_json(
            "GET", record_url, accepted_statuses=(200, 404)
        )
        if status_code == 404:
            return
        changes_url = (
            f"https://dns.googleapis.com/dns/v1/projects/{spec.project_id}/"
            f"managedZones/{zone}/changes"
        )
        self._request("POST", changes_url, body={"deletions": [record]})

    def _build_dispatch(self) -> dict[tuple[str, str], Mutation]:
        delete = self._delete_created
        restore = self._restore_before
        return {
            ("accesscontextmanager", "access_level"): Mutation(self._must_reuse, self._no_rollback),
            ("serviceusage", "project_services"): Mutation(
                self._enable_services, self._no_rollback
            ),
            ("compute", "source_image"): Mutation(self._must_reuse, self._no_rollback),
            ("compute", "network"): Mutation(self._create_network, delete),
            ("compute", "subnetwork"): Mutation(self._create_subnetwork, delete),
            ("compute", "router"): Mutation(self._create_router, delete),
            ("compute", "cloud_nat"): Mutation(self._create_nat, restore),
            ("iam", "service_account"): Mutation(self._create_service_account, delete),
            ("compute", "internal_address"): Mutation(self._create_address, delete),
            ("secretmanager", "secret"): Mutation(self._create_secret, delete),
            ("secretmanager", "secret_version"): Mutation(
                self._add_secret_version, self._disable_secret_version
            ),
            ("secretmanager", "secret_iam"): Mutation(
                self._set_secret_iam, self._restore_secret_iam
            ),
            ("compute", "instance"): Mutation(self._create_instance, delete),
            ("compute", "instance_template"): Mutation(self._create_instance_template, delete),
            ("compute", "health_check"): Mutation(self._create_health_check, delete),
            ("compute", "instance_group_manager"): Mutation(
                self._create_instance_group_manager, delete
            ),
            ("compute", "autoscaler"): Mutation(self._create_autoscaler, delete),
            ("compute", "backend_service"): Mutation(self._create_backend_service, delete),
            ("compute", "forwarding_rule"): Mutation(self._create_forwarding_rule, delete),
            ("compute", "offload_refresh"): Mutation(self._refresh_offload, self._no_rollback),
            ("compute", "firewall_rule"): Mutation(self._create_firewall, delete),
            ("dns", "private_zone"): Mutation(self._create_dns_zone, delete),
            ("dns", "record_set"): Mutation(self._create_dns_record, self._delete_dns_record),
            ("beyondcorp", "security_gateway"): Mutation(
                self._create_gateway, self._delete_created
            ),
            ("beyondcorp", "gateway_iam"): Mutation(self._set_gateway_iam, restore),
            ("cloudresourcemanager", "project_iam"): Mutation(self._set_project_iam, restore),
            ("beyondcorp", "application"): Mutation(self._create_application, delete),
            ("beyondcorp", "application_iam"): Mutation(self._set_application_iam, restore),
            ("chromepolicy", "extension_install"): Mutation(
                self._set_chrome_install, self._restore_chrome_policy
            ),
            ("chromepolicy", "extension_configuration"): Mutation(
                self._set_chrome_configuration, self._restore_chrome_policy
            ),
            ("chromepolicy", "service_discovery_proxy"): Mutation(
                self._set_service_discovery_proxy, self._restore_chrome_policy
            ),
            ("local", "root_certificate_artifact"): Mutation(
                self._export_root_certificate, self._remove_root_certificate_artifact
            ),
        }

    @staticmethod
    def _no_rollback(_change: ResourceChange, _spec: DeploymentSpec) -> None:
        # Used only for operations whose safe compensation is either monotonic
        # (API enablement) or performed by the owning mutation (TLS alias restore).
        return

    @staticmethod
    def _google_error_code(error: GoogleApiError, provider: str) -> str:
        code = f"google-api-{error.status_code}-{provider}"
        try:
            payload = json.loads(error.detail)
        except (json.JSONDecodeError, TypeError):
            return code
        status = payload.get("error", {}).get("status") if isinstance(payload, dict) else None
        if isinstance(status, str) and GOOGLE_STATUS_PATTERN.fullmatch(status):
            return f"{code}-{status.lower().replace('_', '-')}"
        return code

    @staticmethod
    def _must_reuse(_change: ResourceChange, _spec: DeploymentSpec) -> None:
        raise ProviderExecutionError("required-shared-resource-not-reused")

    @staticmethod
    def _key(change: ResourceChange) -> str:
        return f"{change.provider}:{change.resource_type}:{change.resource_name}"

    @staticmethod
    def _network_name(spec: DeploymentSpec) -> str:
        return (
            f"{spec.name}-vpc"
            if spec.network_strategy is NetworkStrategy.DEDICATED
            else str(spec.vpc_name)
        )

    @staticmethod
    def _subnet_name(spec: DeploymentSpec) -> str:
        return (
            f"{spec.name}-subnet"
            if spec.network_strategy is NetworkStrategy.DEDICATED
            else str(spec.subnet_name)
        )

    def _request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        body: dict[str, Any] | None = None,
        accepted: tuple[int, ...] = (200,),
    ) -> dict[str, Any]:
        _, payload = self._transport.request_json(
            method,
            url,
            params=params,
            json_body=body,
            accepted_statuses=accepted,
        )
        return payload

    def _wait(self, operation: dict[str, Any], *, fallback_host: str) -> None:
        operation_name = operation.get("name")
        operation_link = operation.get("selfLink")
        is_long_running_operation = (
            "status" in operation
            or "done" in operation
            or (
                isinstance(operation_name, str)
                and (
                    operation_name.startswith("operations/")
                    or "/operations/" in operation_name
                )
            )
            or (
                isinstance(operation_link, str)
                and "/operations/" in operation_link
            )
        )
        if not is_long_running_operation:
            return
        status_value = operation.get("status")
        if (
            isinstance(status_value, str)
            and status_value.lower() == "done"
        ) or operation.get("done") is True:
            self._ensure_operation_success(operation)
            return
        operation_url = operation.get("selfLink")
        if not isinstance(operation_url, str):
            name = operation.get("name")
            if not isinstance(name, str):
                return
            operation_url = (
                name if name.startswith("https://") else f"https://{fallback_host}/v1/{name}"
            )
        # Compute Engine still returns legacy selfLinks on www.googleapis.com.
        # Keep the transport allowlist narrow and normalize that documented API
        # path to the canonical, already-allowlisted Compute endpoint.
        legacy_compute_prefix = "https://www.googleapis.com/compute/"
        if operation_url.startswith(legacy_compute_prefix):
            operation_url = (
                "https://compute.googleapis.com/compute/"
                + operation_url.removeprefix(legacy_compute_prefix)
            )
        deadline = time.monotonic() + self._operation_timeout
        while time.monotonic() < deadline:
            payload = self._request("GET", operation_url)
            polled_status = payload.get("status")
            if (
                isinstance(polled_status, str)
                and polled_status.lower() == "done"
            ) or payload.get("done") is True:
                self._ensure_operation_success(payload)
                return
            time.sleep(self._poll_interval)
        raise ProviderExecutionError("provider-operation-timeout")

    @staticmethod
    def _ensure_operation_success(operation: dict[str, Any]) -> None:
        if operation.get("error"):
            raise ProviderExecutionError("provider-operation-failed")

    def _mark_created(self, change: ResourceChange, url: str) -> None:
        key = self._key(change)
        self._created.add(key)
        self._before[key] = {"delete_url": url}

    def _create(
        self,
        change: ResourceChange,
        *,
        url: str,
        body: dict[str, Any],
        fallback_host: str,
        delete_url: str,
        params: dict[str, str | int] | None = None,
        accepted: tuple[int, ...] = (200,),
    ) -> dict[str, Any]:
        request_params = dict(params or {})
        if "compute.googleapis.com" in url:
            request_params.setdefault(
                "requestId",
                str(uuid.uuid5(self._execution_id, self._key(change))),
            )
        operation = self._request(
            "POST",
            url,
            params=request_params or None,
            body=body,
            accepted=accepted,
        )
        self._mark_created(change, delete_url)
        try:
            self._wait(operation, fallback_host=fallback_host)
        except Exception:
            # A successful create request can be followed by a polling or
            # response-shape failure. Clean up the just-created resource here
            # because the outer executor only rolls back changes whose apply
            # method returned successfully.
            try:
                self._delete_created(change, _spec=None)
            except Exception as cleanup_error:
                raise ProviderExecutionError("provider-operation-cleanup-failed") from cleanup_error
            raise
        return operation

    def _delete_created(
        self,
        change: ResourceChange,
        _spec: DeploymentSpec | None,
    ) -> None:
        key = self._key(change)
        if key not in self._created:
            return
        before = self._before.get(key) or {}
        url = before.get("delete_url")
        if not isinstance(url, str):
            return
        payload = self._request("DELETE", url, accepted=(200, 204, 404))
        if payload:
            self._wait(payload, fallback_host=url.split("/", 3)[2])
        self._created.discard(key)

    def _enable_services(self, _change: ResourceChange, spec: DeploymentSpec) -> None:
        payload = self._request(
            "POST",
            f"https://serviceusage.googleapis.com/v1/projects/{spec.project_id}/services:batchEnable",
            body={"serviceIds": sorted(required_apis(spec))},
        )
        self._wait(payload, fallback_host="serviceusage.googleapis.com")

    def _create_network(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        self._create(
            change,
            url=f"{base}/global/networks",
            body={
                "name": change.resource_name,
                "autoCreateSubnetworks": False,
                "routingConfig": {"routingMode": "REGIONAL"},
                "description": "Managed by Secure Gateway Studio",
            },
            fallback_host="compute.googleapis.com",
            delete_url=f"{base}/global/networks/{change.resource_name}",
        )

    def _create_subnetwork(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        self._create(
            change,
            url=f"{base}/regions/{spec.region}/subnetworks",
            body={
                "name": change.resource_name,
                "ipCidrRange": spec.subnet_cidr,
                "network": f"{base}/global/networks/{self._network_name(spec)}",
                "privateIpGoogleAccess": True,
                "stackType": "IPV4_ONLY",
            },
            fallback_host="compute.googleapis.com",
            delete_url=f"{base}/regions/{spec.region}/subnetworks/{change.resource_name}",
        )

    def _create_router(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        self._create(
            change,
            url=f"{base}/regions/{spec.region}/routers",
            body={
                "name": change.resource_name,
                "network": f"{base}/global/networks/{self._network_name(spec)}",
            },
            fallback_host="compute.googleapis.com",
            delete_url=f"{base}/regions/{spec.region}/routers/{change.resource_name}",
        )

    def _create_nat(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        url = (
            f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}/"
            f"regions/{spec.region}/routers/{spec.name}-router"
        )
        router = self._request("GET", url)
        self._before[self._key(change)] = {
            "restore_url": url,
            "restore_method": "PATCH",
            "body": deepcopy(router),
        }
        router["nats"] = [
            *router.get("nats", []),
            {
                "name": change.resource_name,
                "natIpAllocateOption": "AUTO_ONLY",
                "sourceSubnetworkIpRangesToNat": "LIST_OF_SUBNETWORKS",
                "subnetworks": [
                    {
                        "name": (
                            f"https://compute.googleapis.com/compute/v1/projects/"
                            f"{spec.project_id}/regions/{spec.region}/subnetworks/"
                            f"{self._subnet_name(spec)}"
                        ),
                        "sourceIpRangesToNat": ["ALL_IP_RANGES"],
                    }
                ],
                "logConfig": {"enable": True, "filter": "ERRORS_ONLY"},
            },
        ]
        payload = self._request("PATCH", url, body=router)
        self._wait(payload, fallback_host="compute.googleapis.com")

    def _create_service_account(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        base = f"https://iam.googleapis.com/v1/projects/{spec.project_id}"
        email = quote(f"{change.resource_name}@{spec.project_id}.iam.gserviceaccount.com", safe="")
        self._create(
            change,
            url=f"{base}/serviceAccounts",
            body={
                "accountId": change.resource_name,
                "serviceAccount": {"displayName": f"Secure Gateway Studio {change.resource_name}"},
            },
            fallback_host="iam.googleapis.com",
            delete_url=f"{base}/serviceAccounts/{email}",
        )

    def _create_address(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        self._create(
            change,
            url=f"{base}/regions/{spec.region}/addresses",
            body={
                "name": change.resource_name,
                "addressType": "INTERNAL",
                "subnetwork": (
                    f"{base}/regions/{spec.region}/subnetworks/{self._subnet_name(spec)}"
                ),
            },
            fallback_host="compute.googleapis.com",
            delete_url=f"{base}/regions/{spec.region}/addresses/{change.resource_name}",
        )

    def _create_secret(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        url = f"https://secretmanager.googleapis.com/v1/projects/{spec.project_id}/secrets"
        self._create(
            change,
            url=url,
            params={"secretId": change.resource_name},
            body={
                "replication": {"automatic": {}},
                "labels": {
                    "managed-by": "secure-gateway-studio",
                    "configuration-hash": canonical_configuration_hash(spec)[:32],
                    "certificate-spec-hash": certificate_configuration_hash(spec)[:32],
                },
            },
            fallback_host="secretmanager.googleapis.com",
            delete_url=f"{url}/{change.resource_name}",
        )

    def _issue_certificate(self, spec: DeploymentSpec) -> CertificateBundle:
        if self._certificate is not None:
            return self._certificate
        issuer = CertificateIssuer(self._transport)
        if spec.certificate_strategy is CertificateStrategy.ENTERPRISE_CA:
            certificate_id = f"{spec.name[:40]}-tls-{self._execution_id.hex[:12]}"
            self._certificate = issuer.issue_enterprise_ca(
                hostname=spec.private_hostname,
                ca_pool=str(spec.ca_pool),
                ca_name=str(spec.ca_name),
                certificate_id=certificate_id,
                lifetime_days=spec.certificate_lifetime_days,
            )
        elif spec.certificate_strategy is CertificateStrategy.LOCAL_POC:
            self._certificate = issuer.issue_local_poc(
                hostname=spec.private_hostname,
                lifetime_days=spec.certificate_lifetime_days,
            )
        else:
            raise ValueError("Public certificates must reference an existing secret")
        return self._certificate

    def _add_secret_version(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        bundle = self._issue_certificate(spec)
        secret_url = (
            f"https://secretmanager.googleapis.com/v1/projects/{spec.project_id}/"
            f"secrets/{change.resource_name}"
        )
        try:
            secret_before = self._request("GET", secret_url)
        except Exception:
            self._compensate_unpublished_certificate(bundle)
            raise
        aliases_before = secret_before.get("versionAliases", {})
        if not isinstance(aliases_before, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in aliases_before.items()
        ):
            self._compensate_unpublished_certificate(bundle)
            raise ValueError("Secret Manager returned invalid version aliases")
        labels_before = secret_before.get("labels", {})
        if not isinstance(labels_before, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in labels_before.items()
        ):
            self._compensate_unpublished_certificate(bundle)
            raise ValueError("Secret Manager returned invalid labels")
        labels_after = {
            **labels_before,
            "managed-by": "secure-gateway-studio",
            "configuration-hash": canonical_configuration_hash(spec)[:32],
            "certificate-spec-hash": certificate_configuration_hash(spec)[:32],
        }
        version_name: str | None = None
        try:
            payload = self._request(
                "POST",
                f"{secret_url}:addVersion",
                body={
                    "payload": {"data": base64.b64encode(bundle.secret_payload()).decode("ascii")}
                },
            )
            version_name = payload.get("name")
            if not isinstance(version_name, str) or not version_name:
                raise ValueError("Secret Manager did not return a version name")
            version_id = version_name.rsplit("/", maxsplit=1)[-1]
            if not version_id.isdigit():
                raise ValueError("Secret Manager returned an invalid version name")
            self._set_secret_metadata(
                secret_url,
                {**aliases_before, "active": version_id},
                labels_after,
            )
        except Exception:
            try:
                if version_name is not None:
                    self._set_secret_metadata(
                        secret_url,
                        aliases_before,
                        labels_before,
                    )
                    self._request(
                        "POST",
                        f"https://secretmanager.googleapis.com/v1/{version_name}:disable",
                        body={},
                    )
                self._revoke_issued_certificate(bundle)
            except Exception as cleanup_error:
                raise ProviderExecutionError("certificate-compensation-failed") from cleanup_error
            self._certificate = None
            raise
        self._before[self._key(change)] = {
            "version_name": version_name,
            "issuer_resource_name": bundle.issuer_resource_name,
            "secret_url": secret_url,
            "aliases_before": aliases_before,
            "labels_before": labels_before,
        }

    def _disable_secret_version(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        before = self._before.get(self._key(change)) or {}
        version_name = before.get("version_name")
        secret_url = before.get("secret_url")
        aliases_before = before.get("aliases_before")
        labels_before = before.get("labels_before")
        if (
            isinstance(secret_url, str)
            and isinstance(aliases_before, dict)
            and isinstance(labels_before, dict)
        ):
            self._set_secret_metadata(secret_url, aliases_before, labels_before)
        if isinstance(version_name, str):
            self._request(
                "POST",
                f"https://secretmanager.googleapis.com/v1/{version_name}:disable",
                body={},
            )
        self._revoke_issued_certificate(self._certificate)
        self._certificate = None
        self._refresh_existing_offload(spec)

    def _compensate_unpublished_certificate(self, bundle: CertificateBundle) -> None:
        try:
            self._revoke_issued_certificate(bundle)
        except Exception as cleanup_error:
            raise ProviderExecutionError("certificate-compensation-failed") from cleanup_error
        self._certificate = None

    def _set_secret_metadata(
        self,
        secret_url: str,
        aliases: dict[str, str],
        labels: dict[str, str],
    ) -> None:
        current = self._request("GET", secret_url)
        body: dict[str, Any] = {
            "versionAliases": aliases,
            "labels": labels,
        }
        etag = current.get("etag")
        if isinstance(etag, str) and etag:
            body["etag"] = etag
        self._request(
            "PATCH",
            secret_url,
            params={"updateMask": "version_aliases,labels"},
            body=body,
        )

    def _revoke_issued_certificate(self, bundle: CertificateBundle | None) -> None:
        if bundle is None or bundle.issuer_resource_name is None:
            return
        self._request(
            "POST",
            (f"https://privateca.googleapis.com/v1/{bundle.issuer_resource_name}:revoke"),
            body={
                "reason": "CESSATION_OF_OPERATION",
                "requestId": str(
                    uuid.uuid5(
                        self._execution_id,
                        f"revoke:{bundle.issuer_resource_name}",
                    )
                ),
            },
        )

    @staticmethod
    def _merge_binding(
        policy: dict[str, Any],
        role: str,
        members: list[str],
        condition: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        result = deepcopy(policy)
        if condition is not None:
            result["version"] = max(int(result.get("version", 1)), 3)
        bindings = result.setdefault("bindings", [])
        binding = next(
            (
                item
                for item in bindings
                if item.get("role") == role and item.get("condition") == condition
            ),
            None,
        )
        if binding is None:
            new_binding: dict[str, Any] = {
                "role": role,
                "members": sorted(set(members)),
            }
            if condition is not None:
                new_binding["condition"] = condition
            bindings.append(new_binding)
        else:
            binding["members"] = sorted(set(binding.get("members", [])) | set(members))
        return result

    def _set_iam(
        self,
        change: ResourceChange,
        *,
        get_url: str,
        set_url: str,
        role: str,
        members: list[str],
        get_method: str = "POST",
        condition: dict[str, str] | None = None,
    ) -> None:
        policy = self._request(
            get_method,
            get_url,
            body={} if get_method == "POST" else None,
        )
        self._before[self._key(change)] = {
            "restore_url": set_url,
            "current_url": get_url,
            "current_method": get_method,
            "body": {"policy": deepcopy(policy)},
        }
        updated = self._merge_binding(policy, role, members, condition)
        self._request("POST", set_url, body={"policy": updated})

    def _restore_before(self, change: ResourceChange, _spec: DeploymentSpec) -> None:
        before = self._before.get(self._key(change))
        if not before:
            return
        url = before.get("restore_url")
        method = before.get("restore_method", "POST")
        body = before.get("body")
        if isinstance(url, str) and isinstance(method, str) and isinstance(body, dict):
            for attempt in range(5):
                restore_body = deepcopy(body)
                current_url = before.get("current_url")
                current_method = before.get("current_method", "POST")
                if (
                    isinstance(current_url, str)
                    and isinstance(current_method, str)
                    and isinstance(restore_body.get("policy"), dict)
                ):
                    current = self._request(
                        current_method,
                        current_url,
                        body={} if current_method == "POST" else None,
                    )
                    current_etag = current.get("etag")
                    if isinstance(current_etag, str) and current_etag:
                        restore_body["policy"]["etag"] = current_etag
                    else:
                        restore_body["policy"].pop("etag", None)
                try:
                    payload = self._request(method, url, body=restore_body)
                except GoogleApiError as error:
                    if error.status_code != 409 or attempt == 4:
                        raise
                    time.sleep(max(self._poll_interval, 0.25) * (2**attempt))
                    continue
                if payload.get("name") or payload.get("selfLink"):
                    self._wait(payload, fallback_host=url.split("/", 3)[2])
                return

    def _tls_secret_name(self, spec: DeploymentSpec) -> str:
        if (
            spec.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED
            and spec.public_certificate_secret
        ):
            return spec.public_certificate_secret.rsplit("/", maxsplit=1)[-1]
        return f"{spec.name}-tls"

    def _set_secret_iam(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        resource = (
            f"https://secretmanager.googleapis.com/v1/projects/{spec.project_id}/"
            f"secrets/{self._tls_secret_name(spec)}"
        )
        self._set_iam(
            change,
            get_url=f"{resource}:getIamPolicy",
            set_url=f"{resource}:setIamPolicy",
            role="roles/secretmanager.secretAccessor",
            members=[
                f"serviceAccount:{service_account_email(spec.name, spec.project_id, 'offload')}"
            ],
            get_method="GET",
        )

    def _restore_secret_iam(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        secret_key = f"secretmanager:secret:{self._tls_secret_name(spec)}"
        if secret_key in self._created:
            # The parent Secret is owned by this run and will be deleted later
            # in reverse dependency order. Restoring its child policy first is
            # unnecessary and can turn a successful parent cleanup into a false
            # operator-intervention state.
            return
        self._restore_before(change, spec)

    def _address(self, spec: DeploymentSpec, suffix: str) -> str:
        payload = self._request(
            "GET",
            (
                f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}/"
                f"regions/{spec.region}/addresses/{spec.name}-{suffix}-ip"
            ),
        )
        address = payload.get("address")
        if not isinstance(address, str):
            raise ValueError("Reserved address response is missing address")
        return address

    @staticmethod
    def _package_setup(spec: DeploymentSpec) -> str:
        if spec.mode.value == "production":
            return """command -v python3 >/dev/null
command -v nginx >/dev/null
"""
        return """export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends nginx python3 ca-certificates
"""

    def _backend_startup_script(self, spec: DeploymentSpec) -> str:
        package_setup = self._package_setup(spec)
        configuration_hash = canonical_configuration_hash(spec)
        return f"""#!/bin/bash
set -euo pipefail
{package_setup}
cat >/var/www/html/index.html <<'EOF'
Secure Gateway Studio private backend
EOF
cat >/etc/nginx/conf.d/sgstudio-log.conf <<'EOF'
log_format sgstudio_backend escape=json
  '{{"timestamp":"$time_iso8601","request_id":"$http_x_request_id",'
  '"role":"backend","host":"$host","method":"$request_method","uri":"$uri",'
  '"status":$status,"request_time":$request_time}}';
EOF
cat >/etc/nginx/sites-available/default <<'EOF'
server {{
  listen 80 default_server;
  server_name _;
  server_tokens off;
  root /var/www/html;
  access_log /var/log/nginx/sgstudio-access.log sgstudio_backend;
  location / {{
    try_files $uri $uri/ =404;
  }}
}}
EOF
nginx -t
systemctl enable nginx
systemctl restart nginx
python3 <<'PY'
import hashlib
import json
import urllib.request
from datetime import UTC, datetime

with urllib.request.urlopen("http://127.0.0.1/", timeout=10) as response:
    body = response.read()
    status = response.status
if status != 200:
    raise RuntimeError("backend-self-test-failed")
evidence = json.dumps(
    {{
        "status": status,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "configuration_hash": {configuration_hash!r},
        "observed_at": datetime.now(UTC).isoformat(),
    }},
    separators=(",", ":"),
)
request = urllib.request.Request(
    "http://metadata.google.internal/computeMetadata/v1/instance/"
    "guest-attributes/sgstudio/T01",
    data=evidence.encode(),
    method="PUT",
    headers={{"Metadata-Flavor": "Google"}},
)
with urllib.request.urlopen(request, timeout=10):
    pass
PY
"""

    def _offload_startup_script(self, spec: DeploymentSpec) -> str:
        backend = (
            f"http://{self._address(spec, 'backend')}"
            if spec.backend_kind is BackendKind.MANAGED_SAMPLE
            else str(spec.existing_backend_url)
        )
        secret_version = (
            "latest"
            if spec.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED
            else "active"
        )
        secret = (
            f"projects/{spec.project_id}/secrets/{self._tls_secret_name(spec)}/"
            f"versions/{secret_version}"
        )
        package_setup = self._package_setup(spec)
        configuration_hash = canonical_configuration_hash(spec)
        return f"""#!/bin/bash
set -euo pipefail
umask 077
{package_setup}
python3 <<'PY'
import base64
import json
import os
import urllib.request

token_request = urllib.request.Request(
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    headers={{"Metadata-Flavor": "Google"}},
)
with urllib.request.urlopen(token_request, timeout=10) as response:
    token = json.load(response)["access_token"]
secret_request = urllib.request.Request(
    "https://secretmanager.googleapis.com/v1/{secret}:access",
    headers={{"Authorization": f"Bearer {{token}}"}},
)
with urllib.request.urlopen(secret_request, timeout=20) as response:
    envelope = json.load(response)
document = json.loads(base64.b64decode(envelope["payload"]["data"]))
certificate = document["certificate_pem"] + "".join(
    document["certificate_chain_pem"]
)
for path, value in (
    ("/etc/nginx/tls.crt", certificate),
    ("/etc/nginx/tls.key", document["private_key_pem"]),
):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as output:
        output.write(value)
PY
cat >/etc/nginx/conf.d/sgstudio-log.conf <<'EOF'
log_format sgstudio_offload escape=json
  '{{"timestamp":"$time_iso8601","request_id":"$request_id",'
  '"role":"offload","host":"$host","method":"$request_method","uri":"$uri",'
  '"status":$status,"request_time":$request_time,"tls_protocol":"$ssl_protocol",'
  '"upstream_addr":"$upstream_addr","upstream_status":"$upstream_status",'
  '"upstream_time":"$upstream_response_time"}}';
EOF
cat >/etc/nginx/sites-available/default <<'EOF'
server {{
  listen 443 ssl;
  server_name {spec.private_hostname};
  server_tokens off;
  ssl_certificate /etc/nginx/tls.crt;
  ssl_certificate_key /etc/nginx/tls.key;
  ssl_protocols TLSv1.2 TLSv1.3;
  access_log /var/log/nginx/sgstudio-access.log sgstudio_offload;
  add_header X-Request-ID $request_id always;
  add_header Strict-Transport-Security "max-age=31536000" always;
  location / {{
    proxy_pass {backend};
    proxy_http_version 1.1;
    proxy_connect_timeout 5s;
    proxy_send_timeout 30s;
    proxy_read_timeout 30s;
    proxy_set_header Host $host;
    proxy_set_header Connection "";
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Request-ID $request_id;
  }}
}}
EOF
nginx -t
systemctl enable nginx
systemctl restart nginx
python3 <<'PY'
import hashlib
import json
import socket
import ssl
import time
import urllib.request
from datetime import UTC, datetime

backend = {backend!r}
hostname = {spec.private_hostname!r}

def publish(test_id, payload):
    request = urllib.request.Request(
        "http://metadata.google.internal/computeMetadata/v1/instance/"
        f"guest-attributes/sgstudio/{{test_id}}",
        data=json.dumps(payload, separators=(",", ":")).encode(),
        method="PUT",
        headers={{"Metadata-Flavor": "Google"}},
    )
    with urllib.request.urlopen(request, timeout=10):
        pass

def upstream_check():
    with urllib.request.urlopen(backend, timeout=10) as response:
        body = response.read()
        status = response.status
    if status != 200:
        raise RuntimeError("offload-upstream-test-failed")
    return {{
        "status": status,
        "upstream": backend,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "configuration_hash": {configuration_hash!r},
        "observed_at": datetime.now(UTC).isoformat(),
    }}

def tls_check():
    context = ssl.create_default_context()
    context.load_verify_locations(cafile="/etc/nginx/tls.crt")
    with socket.create_connection(("127.0.0.1", 443), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=hostname) as connection:
            connection.sendall(
                (
                    f"GET / HTTP/1.1\\r\\nHost: {{hostname}}\\r\\n"
                    "Connection: close\\r\\n\\r\\n"
                ).encode()
            )
            response = b""
            while True:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                response += chunk
            negotiated = connection.version()
            peer = connection.getpeercert()
    headers, _, body = response.partition(b"\\r\\n\\r\\n")
    status_line = headers.split(b"\\r\\n", 1)[0].decode("ascii", "replace")
    if " 200 " not in f"{{status_line}} ":
        raise RuntimeError("offload-tls-test-failed")
    return {{
        "http_status": 200,
        "tls_version": negotiated,
        "hostname": hostname,
        "subject_alt_names": [
            value for kind, value in peer.get("subjectAltName", []) if kind == "DNS"
        ],
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "configuration_hash": {configuration_hash!r},
        "observed_at": datetime.now(UTC).isoformat(),
    }}

last_error = None
for _ in range(12):
    try:
        t02 = upstream_check()
        t03 = tls_check()
        publish("T02", t02)
        publish("T03", t03)
        break
    except Exception as error:
        last_error = error
        time.sleep(5)
else:
    raise RuntimeError("offload-runtime-tests-failed") from last_error
PY
"""

    def _create_instance(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        suffix = "backend" if change.resource_name.endswith("-backend") else "offload"
        service_account = service_account_email(spec.name, spec.project_id, suffix)
        script = (
            self._backend_startup_script(spec)
            if suffix == "backend"
            else self._offload_startup_script(spec)
        )
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        network_interface = self._network_interface(spec)
        network_interface["networkIP"] = self._address(spec, suffix)
        self._create(
            change,
            url=f"{base}/zones/{spec.zone}/instances",
            body={
                "name": change.resource_name,
                "machineType": f"zones/{spec.zone}/machineTypes/e2-small",
                "labels": {"managed-by": "secure-gateway-studio", "role": suffix},
                "tags": {"items": [f"{spec.name}-{suffix}"]},
                "disks": [
                    {
                        "boot": True,
                        "autoDelete": True,
                        "initializeParams": {
                            "sourceImage": self._source_image(spec),
                            "diskSizeGb": "20",
                            "diskType": f"zones/{spec.zone}/diskTypes/pd-balanced",
                        },
                    }
                ],
                "networkInterfaces": [network_interface],
                "serviceAccounts": [
                    {
                        "email": service_account,
                        "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                    }
                ],
                "metadata": {
                    "items": [
                        {"key": "startup-script", "value": script},
                        {"key": "enable-guest-attributes", "value": "TRUE"},
                    ]
                },
                "shieldedInstanceConfig": {
                    "enableSecureBoot": True,
                    "enableVtpm": True,
                    "enableIntegrityMonitoring": True,
                },
                # Kept false until the whole run is verified so rollback remains
                # possible. A future lifecycle action may enable it after evidence.
                "deletionProtection": False,
            },
            fallback_host="compute.googleapis.com",
            delete_url=f"{base}/zones/{spec.zone}/instances/{change.resource_name}",
        )
        try:
            self._wait_for_instance_readiness(change, spec, suffix=suffix)
        except Exception:
            # A Compute insert operation only proves that the VM exists. Do not
            # report Apply success until the startup script has published the
            # runtime probes that prove Nginx, TLS, and the upstream are usable.
            try:
                self._delete_created(change, _spec=None)
            except Exception as cleanup_error:
                raise ProviderExecutionError(
                    "provider-operation-cleanup-failed"
                ) from cleanup_error
            raise

    @staticmethod
    def _guest_attribute_items(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
        query_value = payload.get("queryValue")
        items = query_value.get("items") if isinstance(query_value, dict) else None
        if not isinstance(items, list):
            return {}
        evidence: dict[str, dict[str, Any]] = {}
        for item in items:
            if not isinstance(item, dict) or item.get("namespace") != "sgstudio":
                continue
            key = item.get("key")
            value = item.get("value")
            if not isinstance(key, str) or not isinstance(value, str):
                continue
            try:
                decoded = json.loads(value)
            except json.JSONDecodeError:
                continue
            if isinstance(decoded, dict):
                evidence[key] = decoded
        return evidence

    def _wait_for_instance_readiness(
        self,
        change: ResourceChange,
        spec: DeploymentSpec,
        *,
        suffix: str,
    ) -> None:
        expected_hash = canonical_configuration_hash(spec)
        url = (
            f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}/"
            f"zones/{spec.zone}/instances/{change.resource_name}/getGuestAttributes"
        )
        deadline = time.monotonic() + self._operation_timeout
        while time.monotonic() < deadline:
            try:
                payload = self._request("GET", url, params={"queryPath": "sgstudio/"})
            except GoogleApiError as error:
                if error.status_code not in {400, 404}:
                    raise
            else:
                evidence = self._guest_attribute_items(payload)
                if suffix == "backend":
                    t01 = evidence.get("T01", {})
                    ready = (
                        t01.get("status") == 200
                        and t01.get("configuration_hash") == expected_hash
                    )
                else:
                    t02 = evidence.get("T02", {})
                    t03 = evidence.get("T03", {})
                    ready = (
                        t02.get("status") == 200
                        and t02.get("configuration_hash") == expected_hash
                        and t03.get("http_status") == 200
                        and t03.get("configuration_hash") == expected_hash
                        and t03.get("hostname") == spec.private_hostname
                        and t03.get("tls_version") in {"TLSv1.2", "TLSv1.3"}
                        and spec.private_hostname in t03.get("subject_alt_names", [])
                    )
                if ready:
                    return
            time.sleep(max(self._poll_interval, 5.0))
        raise ProviderExecutionError("instance-readiness-timeout")

    def _network_interface(self, spec: DeploymentSpec) -> dict[str, Any]:
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        return {
            "network": f"{base}/global/networks/{self._network_name(spec)}",
            "subnetwork": (f"{base}/regions/{spec.region}/subnetworks/{self._subnet_name(spec)}"),
            "stackType": "IPV4_ONLY",
        }

    @staticmethod
    def _source_image(spec: DeploymentSpec) -> str:
        return (
            spec.source_image
            if spec.source_image
            else "projects/debian-cloud/global/images/family/debian-12"
        )

    def _offload_template_properties(self, spec: DeploymentSpec) -> dict[str, Any]:
        return {
            "machineType": "e2-small",
            "labels": {
                "managed-by": "secure-gateway-studio",
                "role": "offload",
            },
            "tags": {"items": [f"{spec.name}-offload"]},
            "disks": [
                {
                    "boot": True,
                    "autoDelete": True,
                    "initializeParams": {
                        "sourceImage": self._source_image(spec),
                        "diskSizeGb": "20",
                        "diskType": "pd-balanced",
                    },
                }
            ],
            "networkInterfaces": [self._network_interface(spec)],
            "serviceAccounts": [
                {
                    "email": service_account_email(spec.name, spec.project_id, "offload"),
                    "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                }
            ],
            "metadata": {
                "items": [
                    {
                        "key": "startup-script",
                        "value": self._offload_startup_script(spec),
                    },
                    {"key": "enable-guest-attributes", "value": "TRUE"},
                ]
            },
            "shieldedInstanceConfig": {
                "enableSecureBoot": True,
                "enableVtpm": True,
                "enableIntegrityMonitoring": True,
            },
        }

    def _create_instance_template(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        self._create(
            change,
            url=f"{base}/global/instanceTemplates",
            body={
                "name": change.resource_name,
                "description": "Managed by Secure Gateway Studio",
                "properties": self._offload_template_properties(spec),
            },
            fallback_host="compute.googleapis.com",
            delete_url=f"{base}/global/instanceTemplates/{change.resource_name}",
        )

    def _create_health_check(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        self._create(
            change,
            url=f"{base}/regions/{spec.region}/healthChecks",
            body={
                "name": change.resource_name,
                "type": "SSL",
                "sslHealthCheck": {"port": 443},
                "checkIntervalSec": 10,
                "timeoutSec": 5,
                "healthyThreshold": 2,
                "unhealthyThreshold": 3,
            },
            fallback_host="compute.googleapis.com",
            delete_url=(f"{base}/regions/{spec.region}/healthChecks/{change.resource_name}"),
        )

    def _create_instance_group_manager(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        self._create(
            change,
            url=f"{base}/regions/{spec.region}/instanceGroupManagers",
            body={
                "name": change.resource_name,
                "baseInstanceName": f"{spec.name}-offload",
                "targetSize": spec.offload_min_replicas,
                "versions": [
                    {
                        "name": "primary",
                        "instanceTemplate": (
                            f"{base}/global/instanceTemplates/{spec.name}-offload-template"
                        ),
                    }
                ],
                "distributionPolicy": {
                    "targetShape": "EVEN",
                    "zones": [
                        {"zone": f"zones/{spec.zone}"},
                        {"zone": f"zones/{spec.secondary_zone}"},
                    ],
                },
                "namedPorts": [{"name": "https", "port": 443}],
                "updatePolicy": {
                    "type": "PROACTIVE",
                    "minimalAction": "REPLACE",
                    "maxSurge": {"fixed": 1},
                    "maxUnavailable": {"fixed": 0},
                },
            },
            fallback_host="compute.googleapis.com",
            delete_url=(
                f"{base}/regions/{spec.region}/instanceGroupManagers/{change.resource_name}"
            ),
        )
        self._wait_for_manager_stable(spec)

    def _create_autoscaler(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        self._create(
            change,
            url=f"{base}/regions/{spec.region}/autoscalers",
            body={
                "name": change.resource_name,
                "target": (
                    f"{base}/regions/{spec.region}/instanceGroupManagers/{spec.name}-offload-mig"
                ),
                "autoscalingPolicy": {
                    "minNumReplicas": spec.offload_min_replicas,
                    "maxNumReplicas": spec.offload_max_replicas,
                    "coolDownPeriodSec": 90,
                    "cpuUtilization": {
                        "utilizationTarget": spec.offload_cpu_target,
                    },
                    "mode": "ON",
                },
            },
            fallback_host="compute.googleapis.com",
            delete_url=(f"{base}/regions/{spec.region}/autoscalers/{change.resource_name}"),
        )

    def _wait_for_manager_stable(self, spec: DeploymentSpec) -> None:
        manager_url = (
            f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}/"
            f"regions/{spec.region}/instanceGroupManagers/{spec.name}-offload-mig"
        )
        deadline = time.monotonic() + self._operation_timeout
        while time.monotonic() < deadline:
            manager = self._request("GET", manager_url)
            status = manager.get("status")
            current = status.get("currentInstanceStatuses", {}) if isinstance(status, dict) else {}
            if (
                isinstance(status, dict)
                and status.get("isStable") is True
                and isinstance(current, dict)
                and current.get("running", 0) >= spec.offload_min_replicas
            ):
                break
            time.sleep(self._poll_interval)
        else:
            raise ProviderExecutionError("managed-instance-group-not-stable")

    def _refresh_offload(self, _change: ResourceChange, spec: DeploymentSpec) -> None:
        self._perform_offload_refresh(spec)

    def _refresh_existing_offload(self, spec: DeploymentSpec) -> None:
        if spec.mode.value == "production":
            resource_url = (
                f"https://compute.googleapis.com/compute/v1/projects/"
                f"{spec.project_id}/regions/{spec.region}/instanceGroupManagers/"
                f"{spec.name}-offload-mig"
            )
        else:
            resource_url = (
                f"https://compute.googleapis.com/compute/v1/projects/"
                f"{spec.project_id}/zones/{spec.zone}/instances/{spec.name}-offload"
            )
        status_code, _ = self._transport.request_json(
            "GET",
            resource_url,
            accepted_statuses=(200, 404),
        )
        if status_code == 200:
            self._perform_offload_refresh(spec)

    def _perform_offload_refresh(self, spec: DeploymentSpec) -> None:
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        if spec.mode.value == "production":
            manager_url = (
                f"{base}/regions/{spec.region}/instanceGroupManagers/{spec.name}-offload-mig"
            )
            operation = self._request(
                "POST",
                f"{manager_url}/applyUpdatesToInstances",
                body={
                    "allInstances": True,
                    "minimalAction": "RESTART",
                    "mostDisruptiveAllowedAction": "RESTART",
                },
            )
            self._wait(operation, fallback_host="compute.googleapis.com")
            self._wait_for_manager_stable(spec)
            self._wait_for_healthy_backends(spec)
            return

        instance_url = f"{base}/zones/{spec.zone}/instances/{spec.name}-offload"
        stop = self._request(
            "POST",
            f"{instance_url}/stop",
            params={"discardLocalSsd": "false"},
        )
        self._wait(stop, fallback_host="compute.googleapis.com")
        start = self._request("POST", f"{instance_url}/start")
        self._wait(start, fallback_host="compute.googleapis.com")

    def _create_backend_service(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        self._create(
            change,
            url=f"{base}/regions/{spec.region}/backendServices",
            body={
                "name": change.resource_name,
                "protocol": "TCP",
                "loadBalancingScheme": "INTERNAL",
                "timeoutSec": 10,
                "healthChecks": [
                    f"{base}/regions/{spec.region}/healthChecks/{spec.name}-offload-hc"
                ],
                "backends": [
                    {
                        "group": (
                            f"{base}/regions/{spec.region}/instanceGroups/{spec.name}-offload-mig"
                        ),
                    }
                ],
            },
            fallback_host="compute.googleapis.com",
            delete_url=(f"{base}/regions/{spec.region}/backendServices/{change.resource_name}"),
        )

    def _create_forwarding_rule(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        self._create(
            change,
            url=f"{base}/regions/{spec.region}/forwardingRules",
            body={
                "name": change.resource_name,
                "IPAddress": self._address(spec, "offload"),
                "IPProtocol": "TCP",
                "ports": ["443"],
                "loadBalancingScheme": "INTERNAL",
                "allowGlobalAccess": True,
                "network": f"{base}/global/networks/{self._network_name(spec)}",
                "subnetwork": (
                    f"{base}/regions/{spec.region}/subnetworks/{self._subnet_name(spec)}"
                ),
                "backendService": (
                    f"{base}/regions/{spec.region}/backendServices/{spec.name}-offload-bs"
                ),
            },
            fallback_host="compute.googleapis.com",
            delete_url=(f"{base}/regions/{spec.region}/forwardingRules/{change.resource_name}"),
        )
        self._wait_for_healthy_backends(spec)

    def _wait_for_healthy_backends(self, spec: DeploymentSpec) -> None:
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        url = f"{base}/regions/{spec.region}/backendServices/{spec.name}-offload-bs/getHealth"
        group = f"{base}/regions/{spec.region}/instanceGroups/{spec.name}-offload-mig"
        deadline = time.monotonic() + self._operation_timeout
        while time.monotonic() < deadline:
            payload = self._request("POST", url, body={"group": group})
            statuses = payload.get("healthStatus", [])
            healthy = [
                status
                for status in statuses
                if isinstance(status, dict) and status.get("healthState") == "HEALTHY"
            ]
            if len(healthy) >= spec.offload_min_replicas:
                return
            time.sleep(self._poll_interval)
        raise ProviderExecutionError("offload-backends-not-healthy")

    def _create_firewall(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        network = (
            f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}/"
            f"global/networks/{self._network_name(spec)}"
        )
        body: dict[str, Any] = {
            "name": change.resource_name,
            "network": network,
            "direction": "INGRESS",
            "priority": 1000,
            "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}],
            "targetServiceAccounts": [
                service_account_email(spec.name, spec.project_id, "offload")
            ],
            "logConfig": {"enable": True, "metadata": "INCLUDE_ALL_METADATA"},
        }
        if change.resource_name.endswith("gateway-ingress"):
            body["sourceRanges"] = [SECURE_GATEWAY_SOURCE_CIDR]
        elif change.resource_name.endswith("health-check-ingress"):
            body["sourceRanges"] = ["35.191.0.0/16", "130.211.0.0/22"]
        else:
            body["allowed"][0]["ports"] = ["80"]
            body["sourceServiceAccounts"] = [
                service_account_email(spec.name, spec.project_id, "offload")
            ]
            body["targetServiceAccounts"] = [
                service_account_email(spec.name, spec.project_id, "backend")
            ]
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        self._create(
            change,
            url=f"{base}/global/firewalls",
            body=body,
            fallback_host="compute.googleapis.com",
            delete_url=f"{base}/global/firewalls/{change.resource_name}",
        )

    def _create_dns_zone(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        base = f"https://dns.googleapis.com/dns/v1/projects/{spec.project_id}"
        self._create(
            change,
            url=f"{base}/managedZones",
            body={
                "name": change.resource_name,
                "dnsName": f"{spec.private_hostname}.",
                "description": "Managed by Secure Gateway Studio",
                "visibility": "private",
                "privateVisibilityConfig": {
                    "networks": [
                        {
                            "networkUrl": (
                                f"https://compute.googleapis.com/compute/v1/projects/"
                                f"{spec.project_id}/global/networks/"
                                f"{self._network_name(spec)}"
                            )
                        }
                    ]
                },
            },
            fallback_host="dns.googleapis.com",
            delete_url=f"{base}/managedZones/{change.resource_name}",
        )

    def _create_dns_record(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        zone = f"{spec.name}-zone"
        url = (
            f"https://dns.googleapis.com/dns/v1/projects/{spec.project_id}/"
            f"managedZones/{zone}/changes"
        )
        record = {
            "name": f"{spec.private_hostname}.",
            "type": "A",
            "ttl": 60,
            "rrdatas": [self._address(spec, "offload")],
        }
        self._request("POST", url, body={"additions": [record]})
        self._created.add(self._key(change))
        self._before[self._key(change)] = {
            "delete_url": url,
            "dns_record": record,
        }

    def _delete_dns_record(self, change: ResourceChange, _spec: DeploymentSpec) -> None:
        key = self._key(change)
        if key not in self._created:
            return
        before = self._before.get(key) or {}
        url = before.get("delete_url")
        record = before.get("dns_record")
        if isinstance(url, str) and isinstance(record, dict):
            self._request("POST", url, body={"deletions": [record]})
        self._created.discard(key)

    def _create_gateway(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        parent = (
            f"https://beyondcorp.googleapis.com/v1/projects/{spec.project_id}/"
            "locations/global/securityGateways"
        )
        self._create(
            change,
            url=parent,
            params={"security_gateway_id": change.resource_name},
            body={"display_name": change.resource_name, "service_discovery": {}},
            fallback_host="beyondcorp.googleapis.com",
            delete_url=f"{parent}/{change.resource_name}",
        )
        gateway = self._request("GET", f"{parent}/{change.resource_name}")
        account = gateway.get("delegatingServiceAccount")
        if not isinstance(account, str):
            raise ValueError("Gateway response is missing delegatingServiceAccount")
        self._gateway_service_account = account

    def _gateway_resource(self, spec: DeploymentSpec) -> str:
        return (
            f"https://beyondcorp.googleapis.com/v1/projects/{spec.project_id}/"
            f"locations/global/securityGateways/{spec.gateway_id}"
        )

    def _set_gateway_iam(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        resource = self._gateway_resource(spec)
        self._set_iam(
            change,
            get_url=f"{resource}:getIamPolicy",
            set_url=f"{resource}:setIamPolicy",
            role="roles/beyondcorp.serviceDiscoveryUser",
            members=[principal.iam_member for principal in spec.principals],
            get_method="GET",
        )

    def _set_project_iam(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        if not self._gateway_service_account:
            gateway = self._request("GET", self._gateway_resource(spec))
            account = gateway.get("delegatingServiceAccount")
            if not isinstance(account, str):
                raise ValueError("Gateway response is missing delegatingServiceAccount")
            self._gateway_service_account = account
        resource = f"https://cloudresourcemanager.googleapis.com/v1/projects/{spec.project_id}"
        self._set_iam(
            change,
            get_url=f"{resource}:getIamPolicy",
            set_url=f"{resource}:setIamPolicy",
            role="roles/beyondcorp.upstreamAccess",
            members=[f"serviceAccount:{self._gateway_service_account}"],
        )

    def _create_application(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        parent = f"{self._gateway_resource(spec)}/applications"
        upstream: dict[str, Any] = {
            "network": {
                "name": (
                    f"projects/{spec.project_id}/global/networks/"
                    f"{self._network_name(spec)}"
                )
            }
        }
        if (
            spec.backend_kind is BackendKind.DIRECT_HTTPS
            and spec.application_egress_region
        ):
            upstream["egress_policy"] = {
                "regions": [spec.application_egress_region]
            }
        self._create(
            change,
            url=parent,
            params={"application_id": change.resource_name},
            body={
                "display_name": change.resource_name,
                "endpoint_matchers": [
                    {
                        "hostname": spec.application_hostname,
                        "ports": [spec.application_port],
                    }
                ],
                "upstreams": [upstream],
            },
            fallback_host="beyondcorp.googleapis.com",
            delete_url=f"{parent}/{change.resource_name}",
        )

    def _set_application_iam(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        resource = f"{self._gateway_resource(spec)}/applications/{spec.name}-app"
        self._set_iam(
            change,
            get_url=f"{resource}:getIamPolicy",
            set_url=f"{resource}:setIamPolicy",
            role="roles/beyondcorp.sgApplicationUser",
            members=[principal.iam_member for principal in spec.principals],
            get_method="GET",
            condition=(
                {
                    "title": "Managed Chrome required",
                    "description": ("Allow only profiles or browsers managed by this enterprise"),
                    "expression": (
                        f"'{spec.managed_chrome_access_level}' in request.auth.access_levels"
                    ),
                }
                if spec.managed_chrome_access_level
                else None
            ),
        )

    def _chrome_schema(self, spec: DeploymentSpec, schema_name: str) -> dict[str, Any]:
        return self._request(
            "GET",
            (
                f"https://chromepolicy.googleapis.com/v1/customers/{spec.customer_id}/"
                f"policySchemas/{schema_name}"
            ),
        )

    @staticmethod
    def _schema_target_key(schema: dict[str, Any]) -> str:
        keys = schema.get("additionalTargetKeyNames", [])
        for item in keys:
            if isinstance(item, dict) and item.get("key") in {
                "app_id",
                "application_id",
            }:
                return str(item["key"])
        raise ValueError("Chrome app policy schema has no supported app target key")

    @staticmethod
    def _assert_schema_field(schema: dict[str, Any], field: str) -> None:
        definition = schema.get("definition")
        message_types = definition.get("messageType", []) if isinstance(definition, dict) else []
        available = {
            descriptor.get("name")
            for message in message_types
            if isinstance(message, dict)
            for descriptor in message.get("field", [])
            if isinstance(descriptor, dict)
        }
        if field not in available:
            raise ValueError(f"Chrome policy schema no longer exposes {field}")

    def _resolve_chrome_policy(
        self,
        spec: DeploymentSpec,
        schema_name: str,
        app_key: str,
        app_id: str,
    ) -> dict[str, Any] | None:
        payload = self._request(
            "POST",
            f"https://chromepolicy.googleapis.com/v1/customers/{spec.customer_id}/policies:resolve",
            body={
                "policyTargetKey": {
                    "targetResource": f"orgunits/{spec.target_ou_id}",
                    "additionalTargetKeys": {app_key: f"chrome:{app_id}"},
                },
                "policySchemaFilter": schema_name,
            },
        )
        policies = payload.get("resolvedPolicies", [])
        if not isinstance(policies, list):
            return None
        for policy in policies:
            if (
                isinstance(policy, dict)
                and policy.get("sourceKey", {}).get("targetResource")
                == f"orgunits/{spec.target_ou_id}"
            ):
                return deepcopy(policy.get("value"))
        return None

    def _set_chrome_policy(
        self,
        change: ResourceChange,
        spec: DeploymentSpec,
        *,
        schema_name: str,
        field: str,
        value: Any,
        app_id: str = EXTENSION_ID,
    ) -> None:
        schema = self._chrome_schema(spec, schema_name)
        app_key = self._schema_target_key(schema)
        self._assert_schema_field(schema, field)
        previous = self._resolve_chrome_policy(spec, schema_name, app_key, app_id)
        self._before[self._key(change)] = {
            "schema": schema_name,
            "app_key": app_key,
            "app_id": app_id,
            "previous": previous,
        }
        self._request(
            "POST",
            (
                f"https://chromepolicy.googleapis.com/v1/customers/{spec.customer_id}/"
                "policies/orgunits:batchModify"
            ),
            body={
                "requests": [
                    {
                        "policyTargetKey": {
                            "targetResource": f"orgunits/{spec.target_ou_id}",
                            "additionalTargetKeys": {app_key: f"chrome:{app_id}"},
                        },
                        "policyValue": {
                            "policySchema": schema_name,
                            "value": {field: value},
                        },
                        "updateMask": {"paths": [field]},
                    }
                ]
            },
        )

    def _set_chrome_install(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        self._set_chrome_policy(
            change,
            spec,
            schema_name="chrome.users.apps.InstallType",
            field="appInstallType",
            value="FORCED",
            app_id=change.resource_name,
        )

    def _set_chrome_configuration(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        configuration = json.dumps(
            {
                "securityGateway": {
                    "Value": {
                        "authentication": {},
                        "context": {
                            "resource": (
                                f"projects/{spec.project_id}/locations/global/"
                                f"securityGateways/{spec.gateway_id}"
                            )
                        },
                        "serviceDiscovery": {"routes": {}},
                    }
                }
            },
            separators=(",", ":"),
        )
        self._set_chrome_policy(
            change,
            spec,
            schema_name="chrome.users.apps.ManagedConfiguration",
            field="managedConfiguration",
            value=configuration,
        )

    def _resolve_chrome_user_policy(
        self,
        spec: DeploymentSpec,
        schema_name: str,
    ) -> dict[str, Any] | None:
        payload = self._request(
            "POST",
            (
                f"https://chromepolicy.googleapis.com/v1/customers/"
                f"{spec.customer_id}/policies:resolve"
            ),
            body={
                "policyTargetKey": {
                    "targetResource": f"orgunits/{spec.target_ou_id}",
                },
                "policySchemaFilter": schema_name,
            },
        )
        for policy in payload.get("resolvedPolicies", []):
            if (
                isinstance(policy, dict)
                and policy.get("sourceKey", {}).get("targetResource")
                == f"orgunits/{spec.target_ou_id}"
            ):
                return deepcopy(policy.get("value"))
        return None

    def _set_service_discovery_proxy(
        self,
        change: ResourceChange,
        spec: DeploymentSpec,
    ) -> None:
        schema_name = "chrome.users.SimpleProxySettings"
        field = "simpleProxyMode"
        schema = self._chrome_schema(spec, schema_name)
        self._assert_schema_field(schema, field)
        previous = self._resolve_chrome_user_policy(spec, schema_name)
        self._before[self._key(change)] = {
            "schema": schema_name,
            "previous": previous,
        }
        self._request(
            "POST",
            (
                f"https://chromepolicy.googleapis.com/v1/customers/{spec.customer_id}/"
                "policies/orgunits:batchModify"
            ),
            body={
                "requests": [
                    {
                        "policyTargetKey": {
                            "targetResource": f"orgunits/{spec.target_ou_id}",
                        },
                        "policyValue": {
                            "policySchema": schema_name,
                            "value": {
                                field: "PROXY_MODE_ENUM_USER_CONFIGURED",
                            },
                        },
                        "updateMask": {"paths": [field]},
                    }
                ]
            },
        )

    def _export_root_certificate(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        if spec.certificate_strategy is not CertificateStrategy.LOCAL_POC:
            raise ProviderExecutionError("root-certificate-requires-local-poc")
        bundle = self._issue_certificate(spec)
        if len(bundle.certificate_chain_pem) != 1:
            raise ValueError("Local PoC certificate chain is missing its root")
        self._artifact_store.write_root_certificate(spec.name, bundle.certificate_chain_pem[0])
        self._created.add(self._key(change))

    def _remove_root_certificate_artifact(
        self, change: ResourceChange, spec: DeploymentSpec
    ) -> None:
        key = self._key(change)
        if key not in self._created:
            return
        self._artifact_store.remove_root_certificate(spec.name)
        self._created.discard(key)

    def _restore_chrome_policy(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        before = self._before.get(self._key(change)) or {}
        schema = before.get("schema")
        app_key = before.get("app_key")
        app_id = before.get("app_id")
        previous = before.get("previous")
        if not isinstance(schema, str):
            return
        target = {
            "targetResource": f"orgunits/{spec.target_ou_id}",
        }
        if isinstance(app_key, str) and isinstance(app_id, str):
            target["additionalTargetKeys"] = {app_key: f"chrome:{app_id}"}
        base = (
            f"https://chromepolicy.googleapis.com/v1/customers/{spec.customer_id}/policies/orgunits"
        )
        if isinstance(previous, dict):
            values = previous.get("value", {})
            if not isinstance(values, dict):
                raise ValueError("Saved Chrome policy before-image is invalid")
            self._request(
                "POST",
                f"{base}:batchModify",
                body={
                    "requests": [
                        {
                            "policyTargetKey": target,
                            "policyValue": {
                                "policySchema": schema,
                                "value": values,
                            },
                            "updateMask": {"paths": list(values)},
                        }
                    ]
                },
            )
        else:
            self._request(
                "POST",
                f"{base}:batchInherit",
                body={"requests": [{"policyTargetKey": target, "policySchema": schema}]},
            )


def create_google_resource_executor(
    *, artifact_store: CertificateArtifactStore | None = None
) -> GoogleResourceExecutor:
    try:
        transport = GoogleAuthorizedTransport.from_adc()
    except (DefaultCredentialsError, RefreshError) as error:
        raise RuntimeError("Application Default Credentials are unavailable for Apply.") from error
    return GoogleResourceExecutor(transport, artifact_store=artifact_store)
