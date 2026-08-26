from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import re
import time
import uuid
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from google.auth.exceptions import DefaultCredentialsError, RefreshError

from sgstudio.domain.execution import ProviderExecutionError
from sgstudio.domain.iam_policy import (
    IamPolicyEtagMissingError,
    revert_iam_policy_delta,
    validate_iam_policy_v3,
)
from sgstudio.domain.models import (
    BackendKind,
    CertificateStrategy,
    ChangeAction,
    DeploymentPlan,
    DeploymentSpec,
    MutationIdentity,
    NetworkStrategy,
    PublicCertificateBinding,
    ResourceChange,
    RiskLevel,
    RunOperation,
    SourceImageBinding,
)
from sgstudio.domain.naming import service_account_email
from sgstudio.domain.planner import (
    canonical_configuration_hash,
    certificate_configuration_hash,
    required_apis,
)
from sgstudio.providers.certificates import (
    CertificateBundle,
    CertificateIssuanceRejectedError,
    CertificateIssuer,
)
from sgstudio.providers.google_rest import (
    GoogleApiError,
    GoogleAuthorizedTransport,
    JsonTransport,
)
from sgstudio.providers.local_artifacts import CertificateArtifactStore
from sgstudio.providers.mutation_identity import MutationIdentityAuthorizer

EXTENSION_ID = "ekajlcmdfcigmdbphhifahdfjbkciflj"
SECURE_GATEWAY_SOURCE_CIDR = "136.124.16.0/20"
LOGGER = logging.getLogger(__name__)
GOOGLE_STATUS_PATTERN = re.compile(r"^[A-Z][A-Z_]{2,63}$")
GOOGLE_API_HOST_PATTERN = re.compile(r"^[a-z0-9-]+\.googleapis\.com$")
GOOGLE_OPERATION_PATH_PATTERN = re.compile(
    r"^/(?:[A-Za-z0-9._~-]+/)*operations/[A-Za-z0-9._~-]+$"
)
DNS_CHANGE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
AMBIGUOUS_STOP_RECONCILIATION_POLLS = 5
SECRET_METADATA_CONFLICT_ATTEMPTS = 5


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
        execution_id: str | uuid.UUID | None = None,
        mutation_authorizer: MutationIdentityAuthorizer | None = None,
    ) -> None:
        self._transport = transport
        self._artifact_store = artifact_store or CertificateArtifactStore(
            Path.cwd() / ".local" / "artifacts"
        )
        self._poll_interval = poll_interval_seconds
        self._operation_timeout = operation_timeout_seconds
        self._certificate: CertificateBundle | None = None
        self._public_certificate_binding: PublicCertificateBinding | None = None
        self._public_certificate_payload: bytes | None = None
        self._public_certificate_configuration_hash: str | None = None
        self._source_image_binding: SourceImageBinding | None = None
        self._source_image_revalidated = False
        self._enterprise_request: tuple[Any, bytes] | None = None
        self._ownership_metadata: dict[str, dict[str, object]] = {}
        self._execution_id = self._normalise_execution_id(execution_id or uuid.uuid4())
        self._before: dict[str, dict[str, Any] | None] = {}
        self._created: set[str] = set()
        self._gateway_service_account: str | None = None
        self._operation: RunOperation | None = None
        self._operation_checkpoint: dict[str, object] | None = None
        self._checkpoint_writer: Callable[[dict[str, object]], None] | None = None
        self._mutation_authorizer = mutation_authorizer
        self._mutations = self._build_dispatch()

    def authorize_mutation(self, project_id: str) -> MutationIdentity:
        if self._mutation_authorizer is None:
            raise RuntimeError("Mutation identity authorization is unavailable")
        return self._mutation_authorizer.resolve(project_id)

    @staticmethod
    def _normalise_execution_id(value: str | uuid.UUID) -> uuid.UUID:
        if isinstance(value, uuid.UUID):
            return value
        try:
            return uuid.UUID(value)
        except ValueError:
            return uuid.uuid5(uuid.NAMESPACE_URL, f"secure-gateway-studio-run:{value}")

    def bind_run(self, run_id: str) -> None:
        """Bind stable provider request/resource names to the durable deployment run."""
        if (
            self._certificate is not None
            or self._public_certificate_payload is not None
            or self._enterprise_request is not None
            or self._created
            or self._before
        ):
            raise RuntimeError("The executor cannot be rebound after provider work has started")
        self._execution_id = self._normalise_execution_id(run_id)

    def bind_plan(self, plan: DeploymentPlan) -> None:
        """Bind the approval-hashed public certificate identity to this executor."""
        if self._created or self._before or self._public_certificate_payload is not None:
            raise RuntimeError("The executor cannot bind a plan after provider work has started")
        binding = plan.public_certificate_binding
        if (
            self._public_certificate_binding is not None
            and self._public_certificate_binding != binding
        ):
            raise RuntimeError("The executor cannot be rebound to a different plan")
        self._public_certificate_binding = binding
        image_binding = plan.source_image_binding
        if self._source_image_binding is not None and self._source_image_binding != image_binding:
            raise RuntimeError("The executor cannot be rebound to a different source image")
        self._source_image_binding = image_binding

    def prepare_apply(self, spec: DeploymentSpec) -> None:
        """Revalidate an approval-bound TLS version before the first mutation."""
        if (
            spec.mode.value == "production"
            and spec.backend_kind is BackendKind.INTERNAL_HTTPS_LB
        ):
            raise ProviderExecutionError("production-ilb-unsupported-in-0.2.1")
        self._revalidate_source_image(spec)
        consumes_public_tls = (
            spec.backend_kind is not BackendKind.DIRECT_HTTPS
            and spec.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED
        )
        if consumes_public_tls:
            self._revalidate_public_certificate(spec)
            return
        if spec.backend_kind is BackendKind.DIRECT_HTTPS:
            if self._public_certificate_binding is not None:
                raise ProviderExecutionError("certificate-binding-invalid")
            self._public_certificate_payload = None
            self._public_certificate_configuration_hash = None
            return
        if self._public_certificate_binding is not None:
            self._revalidate_managed_certificate(spec)
        else:
            self._public_certificate_payload = None
            self._public_certificate_configuration_hash = None

    def _revalidate_source_image(self, spec: DeploymentSpec) -> None:
        if spec.backend_kind is BackendKind.DIRECT_HTTPS:
            if self._source_image_binding is not None:
                raise ProviderExecutionError("source-image-binding-invalid")
            self._source_image_revalidated = True
            return
        binding = self._source_image_binding
        if binding is None or spec.source_image is None or binding.name != spec.source_image:
            raise ProviderExecutionError("source-image-binding-invalid")
        image_url = f"https://compute.googleapis.com/compute/v1/{spec.source_image}"
        try:
            image = self._request("GET", image_url)
            deprecated = image.get("deprecated")
            state = deprecated.get("state") if isinstance(deprecated, dict) else None
            self_link = image.get("selfLink")
            if (
                image.get("name") != spec.source_image.rsplit("/", maxsplit=1)[-1]
                or str(image.get("id")) != binding.id
                or not isinstance(self_link, str)
                or self_link != binding.self_link
                or state in {"OBSOLETE", "DELETED"}
            ):
                raise ValueError("The source image immutable identity changed")
        except (GoogleApiError, ValueError, TypeError) as error:
            raise ProviderExecutionError("source-image-binding-invalid") from error
        self._source_image_revalidated = True

    def _revalidate_public_certificate(self, spec: DeploymentSpec) -> None:
        """Refresh the approved alias proof immediately before a TLS consumer."""
        binding = self._require_public_certificate_binding(spec)
        access_url = (
            f"https://secretmanager.googleapis.com/v1/projects/{spec.project_id}/"
            f"secrets/{self._tls_secret_name(spec)}/versions/latest:access"
        )
        try:
            envelope = self._request("GET", access_url)
            if envelope.get("name") != binding.secret_version_name:
                raise ValueError("The public TLS secret alias no longer resolves as approved")
            secret_payload = envelope.get("payload")
            encoded = (
                secret_payload.get("data")
                if isinstance(secret_payload, dict)
                else None
            )
            crc_value = (
                secret_payload.get("dataCrc32c")
                if isinstance(secret_payload, dict)
                else None
            )
            if not isinstance(encoded, str) or crc_value is None:
                raise ValueError("Secret Manager response lacks payload integrity metadata")
            decoded = base64.b64decode(encoded, validate=True)
            try:
                expected_crc = int(crc_value)
            except (TypeError, ValueError) as error:
                raise ValueError("Secret Manager payload CRC32C is invalid") from error
            if not 0 <= expected_crc <= 0xFFFFFFFF:
                raise ValueError("Secret Manager payload CRC32C is invalid")
            if self._crc32c(decoded) != expected_crc:
                raise ValueError("Secret Manager payload CRC32C does not match")
            if not hmac.compare_digest(
                hashlib.sha256(decoded).hexdigest(),
                binding.payload_sha256,
            ):
                raise ValueError("The public TLS secret payload changed after approval")
            CertificateIssuer.validate_secret_payload(
                decoded,
                hostname=spec.private_hostname,
                minimum_validity_days=30 if spec.mode.value == "production" else 1,
            )
        except ProviderExecutionError:
            raise
        except (GoogleApiError, ValueError, TypeError, binascii.Error) as error:
            raise ProviderExecutionError("public-certificate-binding-invalid") from error
        self._public_certificate_payload = decoded
        self._public_certificate_configuration_hash = canonical_configuration_hash(spec)

    def _revalidate_managed_certificate(self, spec: DeploymentSpec) -> None:
        """Bind a no-change managed certificate to its approved numeric version."""
        binding = self._require_public_certificate_binding(spec)
        version_id = binding.secret_version_name.rsplit("/", maxsplit=1)[-1]
        secret_url = (
            f"https://secretmanager.googleapis.com/v1/projects/{spec.project_id}/"
            f"secrets/{self._tls_secret_name(spec)}"
        )
        try:
            metadata = self._request("GET", secret_url)
            aliases = self._secret_string_map(metadata, "versionAliases")
            labels = self._secret_string_map(metadata, "labels")
            if (
                aliases.get("active") != version_id
                or labels.get("managed-by") != "secure-gateway-studio"
                or labels.get("certificate-spec-hash")
                != certificate_configuration_hash(spec)[:32]
            ):
                raise ValueError("The managed TLS secret alias no longer matches approval")
            envelope = self._request(
                "GET",
                f"https://secretmanager.googleapis.com/v1/{binding.secret_version_name}:access",
            )
            decoded = self._decode_bound_certificate_payload(
                envelope,
                binding,
                spec,
            )
        except ProviderExecutionError:
            raise
        except (GoogleApiError, ValueError, TypeError, binascii.Error) as error:
            raise ProviderExecutionError("managed-certificate-binding-invalid") from error
        self._public_certificate_payload = decoded
        self._public_certificate_configuration_hash = canonical_configuration_hash(spec)

    def _decode_bound_certificate_payload(
        self,
        envelope: dict[str, Any],
        binding: PublicCertificateBinding,
        spec: DeploymentSpec,
    ) -> bytes:
        if envelope.get("name") != binding.secret_version_name:
            raise ValueError("Secret Manager numeric version identity changed")
        secret_payload = envelope.get("payload")
        encoded = secret_payload.get("data") if isinstance(secret_payload, dict) else None
        crc_value = (
            secret_payload.get("dataCrc32c") if isinstance(secret_payload, dict) else None
        )
        if not isinstance(encoded, str) or crc_value is None:
            raise ValueError("Secret Manager response lacks payload integrity metadata")
        decoded = base64.b64decode(encoded, validate=True)
        expected_crc = int(crc_value)
        if not 0 <= expected_crc <= 0xFFFFFFFF:
            raise ValueError("Secret Manager payload CRC32C is invalid")
        if self._crc32c(decoded) != expected_crc:
            raise ValueError("Secret Manager payload CRC32C does not match")
        if not hmac.compare_digest(hashlib.sha256(decoded).hexdigest(), binding.payload_sha256):
            raise ValueError("The TLS secret payload changed after approval")
        CertificateIssuer.validate_secret_payload(
            decoded,
            hostname=spec.private_hostname,
            minimum_validity_days=30 if spec.mode.value == "production" else 1,
        )
        return decoded

    def _require_public_certificate_binding(
        self,
        spec: DeploymentSpec,
    ) -> PublicCertificateBinding:
        binding = self._public_certificate_binding
        secret_name = self._tls_secret_name(spec)
        expected_prefix = (
            f"projects/{spec.project_id}/secrets/{secret_name}/versions/"
        )
        if binding is None or not binding.secret_version_name.startswith(expected_prefix):
            raise ProviderExecutionError("public-certificate-binding-invalid")
        return binding

    @staticmethod
    def _crc32c(payload: bytes) -> int:
        crc = 0xFFFFFFFF
        for byte in payload:
            crc ^= byte
            for _ in range(8):
                crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
        return (~crc) & 0xFFFFFFFF

    def bind_ownership_metadata(
        self, metadata: dict[str, dict[str, object]]
    ) -> None:
        """Load non-secret exact locators/digests for teardown recovery."""
        self._ownership_metadata = deepcopy(metadata)
        for key, value in metadata.items():
            if value.get("kind") in {
                "privateca_certificate",
                "iam_policy_delta",
            }:
                self._before[key] = deepcopy(value)

    def bind_operation(
        self,
        change: ResourceChange,
        _spec: DeploymentSpec,
        operation: RunOperation,
        checkpoint_writer: Callable[[dict[str, object]], None],
    ) -> None:
        """Bind the durable mutation token/checkpoint before provider work."""
        if operation.resource_key != self._key(change):
            raise ProviderExecutionError("operation-resource-binding-invalid")
        self._operation = operation
        self._operation_checkpoint = deepcopy(operation.checkpoint)
        self._checkpoint_writer = checkpoint_writer
        if operation.checkpoint is not None:
            checkpoint = deepcopy(operation.checkpoint)
            self._before[operation.resource_key] = checkpoint
            self._ownership_metadata[operation.resource_key] = checkpoint

    def _save_checkpoint(self, checkpoint: dict[str, object]) -> None:
        if self._operation is None or self._checkpoint_writer is None:
            resource_key = checkpoint.get("resource_key")
            if not isinstance(resource_key, str):
                raise ProviderExecutionError("durable-operation-context-missing")
            local = deepcopy(checkpoint)
            self._operation_checkpoint = local
            self._before[resource_key] = deepcopy(local)
            self._ownership_metadata[resource_key] = deepcopy(local)
            return
        bound = {
            **deepcopy(checkpoint),
            "schema_version": 1,
            "request_id": self._operation.request_id,
            "resource_key": self._operation.resource_key,
        }
        self._checkpoint_writer(bound)
        self._operation_checkpoint = deepcopy(bound)
        self._before[self._operation.resource_key] = deepcopy(bound)
        self._ownership_metadata[self._operation.resource_key] = deepcopy(bound)

    def _external_request_id(self, purpose: str) -> str:
        if self._operation is not None:
            namespace = uuid.UUID(self._operation.request_id)
            return str(uuid.uuid5(namespace, purpose))
        return str(uuid.uuid5(self._execution_id, purpose))

    def _ownership_token(self, change: ResourceChange) -> str:
        if (
            self._operation is not None
            and self._operation.resource_key == self._key(change)
        ):
            return self._operation.request_id
        return str(uuid.uuid5(self._execution_id, f"ownership:{self._key(change)}"))

    def _named_resource_checkpoint(
        self,
        change: ResourceChange,
        *,
        resource_kind: str,
        resource_url: str,
        marker: str,
        **extra: object,
    ) -> dict[str, object]:
        expected: dict[str, object] = {
            "kind": "named_resource_ownership",
            "phase": "prepared",
            "resource_kind": resource_kind,
            "resource_url": resource_url,
            "ownership_token": self._ownership_token(change),
            "marker": marker,
            "resource_key": self._key(change),
            **deepcopy(extra),
        }
        current = self._operation_checkpoint
        if (
            isinstance(current, dict)
            and current.get("resource_key") != self._key(change)
            and self._operation is None
        ):
            current = None
        if isinstance(current, dict):
            if current.get("kind") != "named_resource_ownership" or any(
                current.get(field) != value
                for field, value in expected.items()
                if field != "phase"
            ):
                raise ProviderExecutionError("named-resource-ownership-checkpoint-mismatch")
            return deepcopy(current)
        self._save_checkpoint(expected)
        return deepcopy(self._operation_checkpoint or expected)

    @staticmethod
    def requires_preclaim(change: ResourceChange, _spec: DeploymentSpec) -> bool:
        """Return whether this approved operation can make an external write."""
        return change.action is ChangeAction.CREATE

    def preclaim_metadata(
        self, change: ResourceChange, spec: DeploymentSpec
    ) -> dict[str, object] | None:
        """Prepare provider-specific non-secret proof before any external write."""
        if (
            change.provider == "privateca"
            and change.resource_type == "certificate"
            and spec.certificate_strategy is CertificateStrategy.ENTERPRISE_CA
        ):
            return self._ensure_enterprise_ownership(change, spec)
        checkpoint = self._operation_checkpoint
        return deepcopy(checkpoint) if isinstance(checkpoint, dict) else None

    def ownership_metadata(
        self,
        change: ResourceChange,
        _spec: DeploymentSpec,
    ) -> dict[str, object] | None:
        """Return durable, non-secret teardown authority captured by Apply."""
        metadata = self._ownership_metadata.get(self._key(change))
        return deepcopy(metadata) if metadata is not None else None

    def apply(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        if (
            spec.backend_kind is not BackendKind.DIRECT_HTTPS
            and spec.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED
            and (
                self._public_certificate_payload is None
                or self._public_certificate_configuration_hash
                != canonical_configuration_hash(spec)
            )
        ):
            raise ProviderExecutionError("public-certificate-not-revalidated")
        mutation = self._mutations.get((change.provider, change.resource_type))
        if mutation is None:
            raise ProviderExecutionError("unsupported-resource-type")
        try:
            if change.provider == "chromepolicy":
                self._assert_target_ou_is_non_root(spec)
            mutation.apply(change, spec)
        except ProviderExecutionError:
            raise
        except GoogleApiError as error:
            LOGGER.warning(
                "Google API apply failed: provider=%s resource_type=%s status=%s host=%s detail=%s",
                change.provider,
                change.resource_type,
                error.status_code,
                error.host,
                error.detail,
            )
            raise ProviderExecutionError(self._google_error_code(error, change.provider)) from error
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
            if change.provider == "chromepolicy":
                self._assert_target_ou_is_non_root(spec)
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

    def destroy(self, change: ResourceChange, spec: DeploymentSpec) -> str:
        """Delete a server-recorded resource without relying on process-local before-images."""
        try:
            if change.provider == "chromepolicy":
                self._assert_target_ou_is_non_root(spec)
            if (change.provider, change.resource_type) in {
                ("iam", "service_account"),
                ("dns", "private_zone"),
                ("dns", "record_set"),
                ("secretmanager", "secret"),
            }:
                ownership = (
                    self._ownership_metadata.get(self._key(change))
                    or self._before.get(self._key(change))
                )
                if not isinstance(ownership, dict) or ownership.get("kind") != (
                    "named_resource_ownership"
                ):
                    return "skipped"
                return self._destroy_named_owned_resource(change, spec, ownership)
            if change.provider == "local" and change.resource_type == "root_certificate_artifact":
                # The path is deployment-scoped rather than run-scoped. A
                # later run may already have replaced it with a newer public
                # root, and a stale teardown has no durable before-image with
                # which to distinguish the two. Retain it instead of deleting
                # another run's trust artifact.
                return "skipped"
            generic_url = self._destroy_url(change, spec)
            if (
                change.provider in {"compute", "beyondcorp"}
                and generic_url is not None
                and not (
                    change.provider == "compute"
                    and change.resource_type in {"cloud_nat", "offload_refresh"}
                )
            ):
                ownership = (
                    self._ownership_metadata.get(self._key(change))
                    or self._before.get(self._key(change))
                )
                if (
                    not isinstance(ownership, dict)
                    or ownership.get("kind") != "generic_created_resource"
                    or ownership.get("phase") != "applied"
                    or ownership.get("resource_url") != generic_url
                ):
                    return "skipped"
                status_code, _, identity = self._read_generic_created_resource(
                    change,
                    generic_url,
                    marker=(
                        ownership.get("ownership_marker")
                        if isinstance(ownership.get("ownership_marker"), str)
                        else None
                    ),
                )
                if status_code == 404:
                    return "deleted"
                if (
                    identity is None
                    or ownership.get("provider_identity_field") != identity[0]
                    or ownership.get("provider_identity") != identity[1]
                ):
                    return "skipped"
                if change.provider == "beyondcorp" and change.resource_type == (
                    "security_gateway"
                ):
                    inventory = self._gateway_application_inventory(generic_url)
                    if inventory == "missing":
                        return "deleted"
                    if inventory == "nonempty":
                        return "skipped"
                self._delete_url(
                    generic_url,
                    fallback_host=generic_url.split("/", 3)[2],
                )
                return "deleted"
            if change.provider == "beyondcorp" and change.resource_type == "security_gateway":
                gateway_url = self._gateway_resource(spec)
                inventory = self._gateway_application_inventory(gateway_url)
                if inventory == "missing":
                    return "deleted"
                if inventory == "nonempty":
                    return "skipped"
                self._delete_url(
                    gateway_url,
                    fallback_host="beyondcorp.googleapis.com",
                )
                return "deleted"
            if change.provider == "compute" and change.resource_type == "cloud_nat":
                self._destroy_cloud_nat(change, spec)
                return "deleted"
            if change.provider == "beyondcorp" and change.resource_type == "gateway_iam":
                resource = self._gateway_resource(spec)
                self._restore_owned_iam(
                    change,
                    current_url=f"{resource}:getIamPolicy",
                    restore_url=f"{resource}:setIamPolicy",
                    current_method="GET",
                )
                return "deleted"
            if change.provider == "beyondcorp" and change.resource_type == "application_iam":
                resource = f"{self._gateway_resource(spec)}/applications/{spec.name}-app"
                self._restore_owned_iam(
                    change,
                    current_url=f"{resource}:getIamPolicy",
                    restore_url=f"{resource}:setIamPolicy",
                    current_method="GET",
                )
                return "deleted"
            if change.provider == "secretmanager" and change.resource_type == "secret_iam":
                resource = (
                    f"https://secretmanager.googleapis.com/v1/projects/{spec.project_id}/"
                    f"secrets/{self._tls_secret_name(spec)}"
                )
                self._restore_owned_iam(
                    change,
                    current_url=f"{resource}:getIamPolicy",
                    restore_url=f"{resource}:setIamPolicy",
                    current_method="GET",
                )
                return "deleted"
            if change.provider == "secretmanager" and change.resource_type == "secret_version":
                return "deleted" if self._destroy_secret_version(change, spec) else "skipped"
            if change.provider == "privateca" and change.resource_type == "certificate":
                ownership = (
                    self._ownership_metadata.get(self._key(change))
                    or self._before.get(self._key(change))
                )
                if not isinstance(ownership, dict):
                    raise ProviderExecutionError(
                        "privateca-certificate-ownership-unverified"
                    )
                certificate_name = ownership.get("certificate_name")
                if not isinstance(certificate_name, str):
                    raise ProviderExecutionError(
                        "privateca-certificate-ownership-unverified"
                    )
                return (
                    "deleted"
                    if self._revoke_certificate_name(certificate_name, ownership)
                    else "skipped"
                )
            if change.provider == "chromepolicy" and change.resource_type in {
                "extension_install",
                "extension_configuration",
                "service_discovery_proxy",
            }:
                self._restore_chrome_policy(change, spec)
                return "deleted"
            if change.provider == "compute" and change.resource_type == "offload_refresh":
                # This is a completed restart action, not a persistent resource.
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
            self._wait(
                payload,
                fallback_host=fallback_host,
                mutation_url=url,
            )

    def _gateway_application_inventory(self, gateway_url: str) -> str:
        """Return missing/empty/nonempty only after bounded, strict pagination.

        A Gateway delete is safe only after every reachable application-list
        page is proven empty. Any malformed item/token, repeated token, or
        pagination limit retains the Gateway for manual reconciliation.
        """
        api_prefix = "https://beyondcorp.googleapis.com/v1/"
        if not gateway_url.startswith(api_prefix):
            raise ProviderExecutionError("teardown-gateway-applications-url-invalid")
        application_name_prefix = (
            f"{gateway_url.removeprefix(api_prefix)}/applications/"
        )
        collection_url = f"{gateway_url}/applications"
        page_token: str | None = None
        seen_tokens: set[str] = set()
        for _ in range(100):
            params: dict[str, str | int] = {"pageSize": 100}
            if page_token is not None:
                params["pageToken"] = page_token
            status_code, payload = self._transport.request_json(
                "GET",
                collection_url,
                params=params,
                accepted_statuses=(200, 404),
            )
            if status_code == 404:
                return "missing"
            unreachable = payload.get("unreachable", [])
            if (
                not isinstance(unreachable, list)
                or any(not isinstance(location, str) or not location for location in unreachable)
            ):
                raise ProviderExecutionError("teardown-gateway-applications-invalid")
            if unreachable:
                raise ProviderExecutionError(
                    "teardown-gateway-applications-unreachable"
                )
            applications = payload.get("applications", [])
            if not isinstance(applications, list):
                raise ProviderExecutionError("teardown-gateway-applications-invalid")
            for application in applications:
                name = application.get("name") if isinstance(application, dict) else None
                suffix = (
                    name.removeprefix(application_name_prefix)
                    if isinstance(name, str) and name.startswith(application_name_prefix)
                    else ""
                )
                if not suffix or "/" in suffix:
                    raise ProviderExecutionError("teardown-gateway-applications-invalid")
            if applications:
                return "nonempty"

            if "nextPageToken" not in payload or payload["nextPageToken"] == "":
                return "empty"
            next_token = payload["nextPageToken"]
            if (
                not isinstance(next_token, str)
                or not next_token.strip()
                or next_token in seen_tokens
            ):
                raise ProviderExecutionError(
                    "teardown-gateway-applications-pagination-invalid"
                )
            seen_tokens.add(next_token)
            page_token = next_token
        raise ProviderExecutionError(
            "teardown-gateway-applications-pagination-limit-exceeded"
        )

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
            ("compute", "instance_group"): (
                f"{compute}/zones/{spec.zone}/instanceGroups/{change.resource_name}"
            ),
            ("compute", "instance_template"): (
                f"{compute}/global/instanceTemplates/{change.resource_name}"
            ),
            ("compute", "health_check"): (
                f"{compute}/regions/{spec.region}/healthChecks/{change.resource_name}"
            ),
            ("compute", "instance_group_manager"): (
                f"{compute}/regions/{spec.region}/instanceGroupManagers/{change.resource_name}"
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
            ("compute", "ssl_certificate"): (
                f"{compute}/regions/{spec.region}/sslCertificates/{change.resource_name}"
            ),
            ("compute", "url_map"): (
                f"{compute}/regions/{spec.region}/urlMaps/{change.resource_name}"
            ),
            ("compute", "target_https_proxy"): (
                f"{compute}/regions/{spec.region}/targetHttpsProxies/{change.resource_name}"
            ),
            ("compute", "firewall_rule"): (f"{compute}/global/firewalls/{change.resource_name}"),
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
            ("beyondcorp", "security_gateway"): (
                f"https://beyondcorp.googleapis.com/v1/projects/{project}/"
                f"locations/global/securityGateways/{change.resource_name}"
            ),
        }
        return urls.get(key)

    def _destroy_named_owned_resource(
        self,
        change: ResourceChange,
        spec: DeploymentSpec,
        ownership: dict[str, object],
    ) -> str:
        token = ownership.get("ownership_token")
        marker = ownership.get("marker")
        resource_url = ownership.get("resource_url")
        if not isinstance(token, str) or not isinstance(resource_url, str):
            return "skipped"
        try:
            uuid.UUID(token)
        except ValueError:
            return "skipped"

        project = spec.project_id
        expected_urls = {
            ("iam", "service_account"): (
                f"https://iam.googleapis.com/v1/projects/{project}/serviceAccounts/"
                f"{quote(f'{change.resource_name}@{project}.iam.gserviceaccount.com', safe='')}"
            ),
            ("dns", "private_zone"): (
                f"https://dns.googleapis.com/dns/v1/projects/{project}/managedZones/"
                f"{change.resource_name}"
            ),
            ("dns", "record_set"): (
                f"https://dns.googleapis.com/dns/v1/projects/{project}/managedZones/"
                f"{spec.name}-zone"
            ),
            ("secretmanager", "secret"): (
                f"https://secretmanager.googleapis.com/v1/projects/{project}/secrets/"
                f"{change.resource_name}"
            ),
        }
        if resource_url != expected_urls.get((change.provider, change.resource_type)):
            return "skipped"

        if change.provider == "dns" and change.resource_type == "record_set":
            fqdn = f"{spec.private_hostname}."
            marker_name = f"_sgs-owner.{fqdn}"
            expected_marker = f'"sgs-owner={token}"'
            address = ownership.get("record_address")
            if (
                marker != expected_marker
                or ownership.get("record_name") != fqdn
                or ownership.get("marker_name") != marker_name
                or not isinstance(address, str)
            ):
                return "skipped"
            record_url = f"{resource_url}/rrsets/{quote(fqdn, safe='')}/A"
            owner_url = f"{resource_url}/rrsets/{quote(marker_name, safe='')}/TXT"
            record_status, record = self._transport.request_json(
                "GET", record_url, accepted_statuses=(200, 404)
            )
            owner_status, owner = self._transport.request_json(
                "GET", owner_url, accepted_statuses=(200, 404)
            )
            if record_status == 404 and owner_status == 404:
                return "deleted"
            expected_owner = {
                "name": marker_name,
                "type": "TXT",
                "ttl": 60,
                "rrdatas": [expected_marker],
            }
            if owner_status == 404 or not self._dns_record_matches(
                owner, expected_owner
            ):
                return "skipped"
            deletions: list[dict[str, object]] = [expected_owner]
            if record_status != 404:
                expected_record = {
                    "name": fqdn,
                    "type": "A",
                    "ttl": 60,
                    "rrdatas": [address],
                }
                if not self._dns_record_matches(record, expected_record):
                    return "skipped"
                deletions.insert(0, expected_record)
            dns_change = self._request(
                "POST",
                f"{resource_url}/changes",
                body={"deletions": deletions},
            )
            self._wait_for_dns_change(
                dns_change,
                collection_url=f"{resource_url}/changes",
            )
            return "deleted"

        status_code, current = self._transport.request_json(
            "GET", resource_url, accepted_statuses=(200, 404)
        )
        if status_code == 404:
            return "deleted"
        if change.provider == "secretmanager":
            labels = current.get("labels")
            owned = (
                marker == token
                and isinstance(labels, dict)
                and labels.get("sgs-owner-token") == token
            )
        else:
            expected_marker = f"Secure Gateway Studio ownership-token={token}"
            owned = marker == expected_marker and current.get("description") == expected_marker
        immutable_id = ownership.get("provider_identity")
        if immutable_id is not None:
            observed = current.get("uniqueId") if change.provider == "iam" else current.get("id")
            owned = owned and str(observed) == str(immutable_id)
        if not owned:
            return "skipped"
        self._delete_url(resource_url, fallback_host=resource_url.split("/", 3)[2])
        return "deleted"

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
        expected_record = {
            "name": f"{spec.private_hostname}.",
            "type": "A",
            "ttl": 60,
            "rrdatas": record.get("rrdatas"),
        }
        if not self._dns_record_matches(record, expected_record):
            raise ProviderExecutionError("dns-record-managed-state-changed")
        dns_change = self._request(
            "POST",
            changes_url,
            body={"deletions": [expected_record]},
        )
        self._wait_for_dns_change(dns_change, collection_url=changes_url)

    def _destroy_cloud_nat(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        self._restore_cloud_nat(change, spec)

    def _destroy_secret_version(self, change: ResourceChange, spec: DeploymentSpec) -> bool:
        expected_secret_url = (
            f"https://secretmanager.googleapis.com/v1/projects/{spec.project_id}/"
            f"secrets/{change.resource_name}"
        )
        checkpoint = (
            self._ownership_metadata.get(self._key(change))
            or self._before.get(self._key(change))
        )
        if (
            not isinstance(checkpoint, dict)
            or checkpoint.get("kind") != "secret_version"
            or checkpoint.get("secret_url") != expected_secret_url
        ):
            raise ProviderExecutionError("secret-version-ownership-metadata-missing")
        version_name = checkpoint.get("version_name")
        try:
            version_name = self._secret_version_name(expected_secret_url, version_name)
        except ProviderExecutionError as error:
            raise ProviderExecutionError(
                "secret-version-ownership-metadata-invalid"
            ) from error
        status_code, _ = self._transport.request_json(
            "GET", expected_secret_url, accepted_statuses=(200, 404)
        )
        if status_code == 404:
            return True
        # Restore the previous alias and labels before destroying the active
        # numeric version. This ordering prevents an ETag conflict, response
        # loss, or worker/process stop from leaving `active` dangling at a
        # DESTROYED version (or removed altogether).
        fresh = self._request("GET", expected_secret_url)
        aliases = self._secret_string_map(fresh, "versionAliases")
        labels = self._secret_string_map(fresh, "labels")
        restored_aliases = self._restore_managed_values(
            aliases,
            checkpoint.get("managed_before_aliases"),
            checkpoint.get("managed_after_aliases"),
            missing_is_managed={"active"},
        )
        restored_labels = self._restore_managed_values(
            labels,
            checkpoint.get("managed_before_labels"),
            checkpoint.get("managed_after_labels"),
        )
        if restored_aliases != aliases or restored_labels != labels:
            self._patch_secret_metadata(
                expected_secret_url,
                fresh,
                restored_aliases,
                restored_labels,
            )
        confirmed = self._request("GET", expected_secret_url)
        confirmed_aliases = self._secret_string_map(confirmed, "versionAliases")
        if confirmed_aliases.get("active") == version_name.rsplit("/", maxsplit=1)[-1]:
            raise ProviderExecutionError("secret-version-active-alias-not-restored")

        version_url = f"https://secretmanager.googleapis.com/v1/{version_name}"
        version_status, version = self._transport.request_json(
            "GET", version_url, accepted_statuses=(200, 404)
        )
        already_destroyed = version_status == 404 or version.get("state") == "DESTROYED"
        if not already_destroyed:
            self._request(
                "POST",
                f"{version_url}:destroy",
                body={},
                accepted=(200, 404),
            )
        return True

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
            ("compute", "cloud_nat"): Mutation(
                self._create_nat, self._restore_cloud_nat
            ),
            ("iam", "service_account"): Mutation(self._create_service_account, delete),
            ("compute", "internal_address"): Mutation(self._create_address, delete),
            ("secretmanager", "secret"): Mutation(self._create_secret, delete),
            ("secretmanager", "secret_version"): Mutation(
                self._add_secret_version, self._disable_secret_version
            ),
            ("privateca", "certificate"): Mutation(
                self._issue_enterprise_certificate_step,
                self._rollback_enterprise_certificate,
            ),
            ("secretmanager", "secret_iam"): Mutation(
                self._set_secret_iam, self._restore_secret_iam
            ),
            ("compute", "instance"): Mutation(self._create_instance, delete),
            ("compute", "instance_group"): Mutation(self._create_instance_group, delete),
            ("compute", "instance_template"): Mutation(self._create_instance_template, delete),
            ("compute", "health_check"): Mutation(self._create_health_check, delete),
            ("compute", "instance_group_manager"): Mutation(
                self._create_instance_group_manager, delete
            ),
            ("compute", "autoscaler"): Mutation(self._create_autoscaler, delete),
            ("compute", "backend_service"): Mutation(self._create_backend_service, delete),
            ("compute", "forwarding_rule"): Mutation(self._create_forwarding_rule, delete),
            ("compute", "ssl_certificate"): Mutation(self._create_ssl_certificate, delete),
            ("compute", "url_map"): Mutation(self._create_url_map, delete),
            ("compute", "target_https_proxy"): Mutation(self._create_target_https_proxy, delete),
            ("compute", "offload_refresh"): Mutation(
                self._refresh_offload, self._rollback_offload_refresh
            ),
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
    def _is_confirmed_iam_etag_conflict(error: GoogleApiError) -> bool:
        if error.status_code != 409:
            return False
        try:
            payload = json.loads(error.detail)
        except (json.JSONDecodeError, TypeError):
            return False
        status = payload.get("error", {}).get("status") if isinstance(payload, dict) else None
        return status == "ABORTED"

    @staticmethod
    def _is_secret_metadata_etag_conflict(error: GoogleApiError) -> bool:
        if error.status_code != 400:
            return False
        try:
            payload = json.loads(error.detail)
        except (json.JSONDecodeError, TypeError):
            return False
        status = payload.get("error", {}).get("status") if isinstance(payload, dict) else None
        return status == "FAILED_PRECONDITION"

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

    def _wait_for_dns_change(
        self,
        change: dict[str, Any],
        *,
        collection_url: str,
    ) -> dict[str, Any]:
        """Wait for the Cloud DNS Change resource returned by changes.create.

        Cloud DNS Changes are not Google long-running Operations.  Their
        `status` is polled through the same managed-zone changes collection,
        and the opaque id must stay bound to the initial response.
        """

        def parse(payload: dict[str, Any]) -> tuple[str, str]:
            change_id = payload.get("id")
            status = payload.get("status")
            if (
                payload.get("kind") != "dns#change"
                or not isinstance(change_id, str)
                or DNS_CHANGE_ID_PATTERN.fullmatch(change_id) is None
                or status not in {"pending", "done"}
            ):
                raise ProviderExecutionError("dns-change-response-invalid")
            return change_id, status

        change_id, status = parse(change)
        if status == "done":
            return change
        poll_url = f"{collection_url}/{quote(change_id, safe='')}"
        deadline = time.monotonic() + self._operation_timeout
        while time.monotonic() < deadline:
            if self._poll_interval > 0:
                time.sleep(self._poll_interval)
            current = self._request("GET", poll_url)
            current_id, current_status = parse(current)
            if current_id != change_id:
                raise ProviderExecutionError("dns-change-identity-mismatch")
            if current_status == "done":
                return current
        raise ProviderExecutionError("dns-change-timeout")

    def _wait(
        self,
        operation: dict[str, Any],
        *,
        fallback_host: str,
        mutation_url: str,
    ) -> dict[str, Any]:
        operation_name = operation.get("name")
        operation_link = operation.get("selfLink")
        is_long_running_operation = (
            "status" in operation
            or "done" in operation
            or (
                isinstance(operation_name, str)
                and (operation_name.startswith("operations/") or "/operations/" in operation_name)
            )
            or (isinstance(operation_link, str) and "/operations/" in operation_link)
        )
        if not is_long_running_operation:
            return operation
        status_value = operation.get("status")
        if "status" in operation and (
            not isinstance(status_value, str)
            or status_value.upper() not in {"PENDING", "RUNNING", "DONE"}
        ):
            raise ProviderExecutionError("provider-operation-status-invalid")
        if "done" in operation and not isinstance(operation.get("done"), bool):
            raise ProviderExecutionError("provider-operation-done-invalid")
        if (isinstance(status_value, str) and status_value.lower() == "done") or operation.get(
            "done"
        ) is True:
            self._ensure_operation_success(operation)
            return operation
        operation_url = operation.get("selfLink")
        if not isinstance(operation_url, str):
            name = operation.get("name")
            if not isinstance(name, str):
                raise ProviderExecutionError("provider-operation-missing-name")
            operation_url = (
                name if name.startswith("https://") else f"https://{fallback_host}/v1/{name}"
            )
        # Compute Engine still returns legacy selfLinks on www.googleapis.com.
        # Keep the transport allowlist narrow and normalize that documented API
        # path to the canonical, already-allowlisted Compute endpoint.
        legacy_compute_prefix = "https://www.googleapis.com/compute/"
        if operation_url.startswith(legacy_compute_prefix):
            operation_url = "https://compute.googleapis.com/compute/" + operation_url.removeprefix(
                legacy_compute_prefix
            )
        self._validate_operation_poll_url(
            operation_url,
            fallback_host=fallback_host,
            mutation_url=mutation_url,
        )
        deadline = time.monotonic() + self._operation_timeout
        while time.monotonic() < deadline:
            payload = self._request("GET", operation_url)
            polled_status = payload.get("status")
            if "status" in payload and (
                not isinstance(polled_status, str)
                or polled_status.upper() not in {"PENDING", "RUNNING", "DONE"}
            ):
                raise ProviderExecutionError("provider-operation-status-invalid")
            if "done" in payload and not isinstance(payload.get("done"), bool):
                raise ProviderExecutionError("provider-operation-done-invalid")
            if (isinstance(polled_status, str) and polled_status.lower() == "done") or payload.get(
                "done"
            ) is True:
                self._ensure_operation_success(payload)
                return payload
            time.sleep(self._poll_interval)
        raise ProviderExecutionError("provider-operation-timeout")

    @staticmethod
    def _validate_operation_poll_url(
        operation_url: str,
        *,
        fallback_host: str,
        mutation_url: str,
    ) -> None:
        """Reject bearer-authenticated polling outside the expected Google LRO origin."""
        expected_host = fallback_host.lower()
        try:
            parsed = urlsplit(operation_url)
            source = urlsplit(mutation_url)
            invalid = (
                not GOOGLE_API_HOST_PATTERN.fullmatch(expected_host)
                or parsed.scheme != "https"
                or parsed.hostname is None
                or parsed.hostname.lower() != expected_host
                or parsed.username is not None
                or parsed.password is not None
                or parsed.port is not None
                or parsed.query
                or parsed.fragment
                or "%" in parsed.path
                or "\\" in parsed.path
                or any(segment in {".", ".."} for segment in parsed.path.split("/"))
                or not GOOGLE_OPERATION_PATH_PATTERN.fullmatch(parsed.path)
                or source.scheme != "https"
                or source.hostname is None
                or source.hostname.lower() != expected_host
                or source.username is not None
                or source.password is not None
                or source.port is not None
                or source.query
                or source.fragment
            )
        except ValueError as error:
            raise ProviderExecutionError("provider-operation-poll-url-invalid") from error
        if invalid or not GoogleResourceExecutor._operation_scope_matches(
            parsed.path,
            mutation_path=source.path,
            expected_host=expected_host,
        ):
            raise ProviderExecutionError("provider-operation-poll-url-invalid")

    @staticmethod
    def _operation_scope_matches(
        operation_path: str,
        *,
        mutation_path: str,
        expected_host: str,
    ) -> bool:
        operation_parts = [part for part in operation_path.split("/") if part]
        mutation_parts = [part for part in mutation_path.split("/") if part]
        if expected_host == "compute.googleapis.com":
            if len(mutation_parts) < 6 or mutation_parts[:3] != [
                "compute",
                "v1",
                "projects",
            ]:
                return False
            if mutation_parts[4] == "global":
                scope = mutation_parts[:5]
            elif mutation_parts[4] in {"regions", "zones"} and len(mutation_parts) >= 7:
                scope = mutation_parts[:6]
            else:
                return False
            return (
                len(operation_parts) == len(scope) + 2
                and operation_parts[:-2] == scope
                and operation_parts[-2] == "operations"
            )

        try:
            project_index = mutation_parts.index("projects")
        except ValueError:
            return operation_parts[:2] == ["v1", "operations"] and len(operation_parts) == 3
        if len(mutation_parts) <= project_index + 1:
            return False
        project = mutation_parts[project_index + 1]
        if (
            len(mutation_parts) > project_index + 3
            and mutation_parts[project_index + 2] == "locations"
        ):
            location = mutation_parts[project_index + 3]
            expected_suffix = [
                "v1",
                "projects",
                project,
                "locations",
                location,
                "operations",
            ]
            return len(operation_parts) == 7 and operation_parts[:-1] == expected_suffix
        if expected_host == "serviceusage.googleapis.com":
            return operation_parts[:2] == ["v1", "operations"] and len(operation_parts) == 3
        expected_suffix = ["v1", "projects", project, "operations"]
        return len(operation_parts) == 5 and operation_parts[:-1] == expected_suffix

    @staticmethod
    def _ensure_operation_success(operation: dict[str, Any]) -> None:
        # A Google operation that carries an `error` member did not succeed,
        # even when a malformed provider response makes that value falsey
        # (`{}`, `[]`, or `""`).  Truthiness here would advance dependent
        # mutations after a failed/undecidable operation.
        if "error" in operation and operation["error"] is not None:
            raise ProviderExecutionError("provider-operation-failed")

    @staticmethod
    def _dns_record_matches(
        current: dict[str, Any],
        expected: dict[str, object],
    ) -> bool:
        if not isinstance(current, dict):
            return False
        if set(current) - {"kind", "name", "type", "ttl", "rrdatas"}:
            return False
        if "kind" in current and current.get("kind") != "dns#resourceRecordSet":
            return False
        ttl = current.get("ttl")
        rrdatas = current.get("rrdatas")
        if (
            not isinstance(current.get("name"), str)
            or not isinstance(current.get("type"), str)
            or type(ttl) is not int
            or not isinstance(rrdatas, list)
            or not all(isinstance(value, str) for value in rrdatas)
        ):
            return False
        canonical = {
            "name": current["name"],
            "type": current["type"],
            "ttl": ttl,
            "rrdatas": rrdatas,
        }
        return canonical == expected

    def _mark_created(self, change: ResourceChange, url: str) -> None:
        key = self._key(change)
        self._created.add(key)
        self._before[key] = {**(self._before.get(key) or {}), "delete_url": url}

    @staticmethod
    def _payload_digest(payload: dict[str, Any]) -> str:
        return hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _provider_payload_contains_expected(
        actual: object,
        expected: object,
        *,
        top_level: bool = True,
    ) -> bool:
        if isinstance(expected, list):
            return (
                isinstance(actual, list)
                and len(actual) == len(expected)
                and all(
                    GoogleResourceExecutor._provider_payload_contains_expected(
                        actual_item,
                        expected_item,
                        top_level=False,
                    )
                    for actual_item, expected_item in zip(actual, expected, strict=True)
                )
            )
        if isinstance(expected, dict):
            allowed_output_fields = {"name", "createTime", "updateTime"}
            is_gateway = top_level and (
                "serviceDiscovery" in expected or "service_discovery" in expected
            )
            is_application = top_level and (
                "endpointMatchers" in expected or "endpoint_matchers" in expected
            )
            if is_gateway:
                allowed_output_fields.update(
                    {"externalIps", "state", "delegatingServiceAccount"}
                )
            if is_application:
                allowed_output_fields.add("schema")
            return (
                isinstance(actual, dict)
                and all(
                    key in expected or (top_level and key in allowed_output_fields)
                    for key in actual
                )
                and all(
                    key in actual
                    and GoogleResourceExecutor._provider_payload_contains_expected(
                        actual[key],
                        value,
                        top_level=False,
                    )
                    for key, value in expected.items()
                )
                and (
                    not is_gateway
                    or (
                        actual.get("state") == "RUNNING"
                        and isinstance(actual.get("delegatingServiceAccount"), str)
                        and bool(str(actual["delegatingServiceAccount"]).strip())
                        and (
                            "externalIps" not in actual
                            or GoogleResourceExecutor._valid_external_ips(
                                actual["externalIps"]
                            )
                        )
                    )
                )
                and (
                    not is_application
                    or actual.get("schema", "SCHEMA_UNSPECIFIED")
                    == "SCHEMA_UNSPECIFIED"
                )
            )
        return type(actual) is type(expected) and actual == expected

    @staticmethod
    def _valid_external_ips(value: object) -> bool:
        if (
            not isinstance(value, list)
            or any(not isinstance(item, str) or not item for item in value)
            or len(set(value)) != len(value)
        ):
            return False
        try:
            for item in value:
                ip_address(item)
        except ValueError:
            return False
        return True

    @staticmethod
    def _generic_provider_identity(
        current: dict[str, Any], provider: str
    ) -> tuple[str, str] | None:
        fields = (
            ("id", "targetId", "selfLink", "creationTimestamp")
            if provider == "compute"
            else ("createTime",)
        )
        for field in fields:
            value = current.get(field)
            if isinstance(value, (str, int)) and str(value):
                return field, str(value)
        return None

    def _read_generic_created_resource(
        self,
        change: ResourceChange,
        resource_url: str,
        *,
        marker: str | None,
    ) -> tuple[int, dict[str, Any], tuple[str, str] | None]:
        status_code, current = self._transport.request_json(
            "GET", resource_url, accepted_statuses=(200, 404)
        )
        if status_code == 404:
            return status_code, current, None
        if marker is not None and current.get("description") != marker:
            return status_code, current, None
        return (
            status_code,
            current,
            self._generic_provider_identity(current, change.provider),
        )

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
        reconcile: Callable[[], bool] | None = None,
        post_create: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        request_body = deepcopy(body)
        marker: str | None = None
        generic_create = change.provider in {"compute", "beyondcorp"}
        if change.provider == "compute":
            ownership_prefix = (
                "Secure Gateway Studio ownership-token="
                f"{self._ownership_token(change)}"
            )
            existing_description = request_body.get("description")
            marker = (
                f"{ownership_prefix}; {existing_description}"
                if isinstance(existing_description, str) and existing_description
                else ownership_prefix
            )
            request_body["description"] = marker
        request_params = dict(params or {})
        if "compute.googleapis.com" in url or "beyondcorp.googleapis.com" in url:
            # Stable across a process restart as well as an in-process retry.
            # Including the intended payload avoids deduplicating a later,
            # genuinely different create for the same resource name.
            request_seed = json.dumps(
                {
                    "execution_id": str(self._execution_id),
                    "resource_key": self._key(change),
                    "url": url,
                    "params": request_params,
                    "body": request_body,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            request_params.setdefault(
                "requestId",
                str(uuid.uuid5(uuid.NAMESPACE_URL, request_seed)),
            )
        checkpoint: dict[str, object] | None = None
        named_checkpoint: dict[str, object] | None = None
        replaying_ambiguous_send = False
        current_checkpoint = self._operation_checkpoint
        if (
            not generic_create
            and isinstance(current_checkpoint, dict)
            and current_checkpoint.get("kind") == "named_resource_ownership"
            and current_checkpoint.get("resource_key") == self._key(change)
        ):
            named_checkpoint = deepcopy(current_checkpoint)
            phase = named_checkpoint.get("phase")
            if phase == "applied":
                if reconcile is None or not reconcile():
                    raise ProviderExecutionError("named-resource-managed-state-changed")
                self._mark_created(change, delete_url)
                return {}
            if phase == "sending":
                if reconcile is not None and reconcile():
                    self._mark_created(change, delete_url)
                    return {}
                raise ProviderExecutionError(
                    "named-resource-provider-response-ambiguous"
                )
            if phase not in {"prepared", "rejected"}:
                raise ProviderExecutionError(
                    "named-resource-ownership-checkpoint-invalid"
                )
        if generic_create:
            expected = {
                "kind": "generic_created_resource",
                "protocol_version": 2,
                "phase": "prepared",
                "resource_key": self._key(change),
                "create_url": url,
                "resource_url": delete_url,
                "create_request_id": request_params.get("requestId"),
                "expected_params_digest": self._payload_digest(request_params),
                "expected_payload_digest": self._payload_digest(request_body),
                "ownership_marker": marker,
            }
            current_checkpoint = self._operation_checkpoint
            if (
                isinstance(current_checkpoint, dict)
                and current_checkpoint.get("resource_key") != self._key(change)
                and self._operation is None
            ):
                current_checkpoint = None
            if isinstance(current_checkpoint, dict):
                if current_checkpoint.get("kind") != "generic_created_resource" or any(
                    current_checkpoint.get(field) != value
                    for field, value in expected.items()
                    if field != "phase"
                ):
                    raise ProviderExecutionError(
                        "generic-resource-ownership-checkpoint-mismatch"
                    )
                checkpoint = deepcopy(current_checkpoint)
                phase = checkpoint.get("phase")
                if phase == "applied":
                    status_code, current, identity = self._read_generic_created_resource(
                        change,
                        delete_url,
                        marker=marker,
                    )
                    if (
                        status_code != 200
                        or identity is None
                        or checkpoint.get("provider_identity_field") != identity[0]
                        or checkpoint.get("provider_identity") != identity[1]
                        or (
                            change.provider == "beyondcorp"
                            and not self._provider_payload_contains_expected(
                                current,
                                request_body,
                            )
                        )
                    ):
                        raise ProviderExecutionError(
                            "generic-resource-managed-state-changed"
                        )
                    if post_create is not None:
                        post_create()
                    self._mark_created(change, delete_url)
                    return {}
                if phase == "sending":
                    status_code, current, identity = self._read_generic_created_resource(
                        change,
                        delete_url,
                        marker=marker,
                    )
                    if status_code == 200 and marker is not None and identity is not None:
                        if post_create is not None:
                            post_create()
                        checkpoint = {
                            **checkpoint,
                            "phase": "applied",
                            "provider_identity_field": identity[0],
                            "provider_identity": identity[1],
                        }
                        self._save_checkpoint(checkpoint)
                        self._mark_created(change, delete_url)
                        return {}
                    if marker is not None:
                        raise ProviderExecutionError(
                            "generic-resource-provider-response-ambiguous"
                        )
                    if (
                        change.provider == "beyondcorp"
                        and status_code == 200
                        and not self._provider_payload_contains_expected(
                            current,
                            request_body,
                        )
                    ):
                        raise ProviderExecutionError(
                            "generic-resource-managed-state-changed"
                        )
                    replaying_ambiguous_send = True
                if (
                    phase not in {"prepared", "rejected"}
                    and not replaying_ambiguous_send
                ):
                    raise ProviderExecutionError(
                        "generic-resource-ownership-checkpoint-invalid"
                    )
            else:
                checkpoint = expected
                self._save_checkpoint(checkpoint)

        accepted_statuses = (
            accepted
            if reconcile is None
            else tuple(dict.fromkeys((*accepted, 409)))
        )
        if checkpoint is not None and not replaying_ambiguous_send:
            self._save_checkpoint({**checkpoint, "phase": "sending"})
        elif named_checkpoint is not None:
            self._save_checkpoint({**named_checkpoint, "phase": "sending"})
        try:
            status_code, operation = self._transport.request_json(
                "POST",
                url,
                params=request_params or None,
                json_body=request_body,
                accepted_statuses=accepted_statuses,
            )
        except GoogleApiError as error:
            if (
                checkpoint is not None
                and not replaying_ambiguous_send
                and error.status_code in {
                400,
                401,
                403,
                404,
                409,
                412,
                }
            ):
                self._save_checkpoint({**checkpoint, "phase": "rejected"})
            elif named_checkpoint is not None and error.status_code in {
                400,
                401,
                403,
                404,
                409,
                412,
            }:
                self._save_checkpoint({**named_checkpoint, "phase": "rejected"})
            raise
        if status_code == 409:
            if reconcile is None or not reconcile():
                raise ProviderExecutionError("named-resource-reconciliation-failed")
            self._mark_created(change, delete_url)
            return operation
        self._mark_created(change, delete_url)
        try:
            terminal = self._wait(
                operation,
                fallback_host=fallback_host,
                mutation_url=url,
            )
            if checkpoint is not None:
                live_status, live_payload, identity = self._read_generic_created_resource(
                    change,
                    delete_url,
                    marker=marker,
                )
                if (
                    change.provider == "beyondcorp"
                    and (
                        live_status != 200
                        or identity is None
                        or not self._provider_payload_contains_expected(
                            live_payload,
                            request_body,
                        )
                    )
                ):
                    raise ProviderExecutionError(
                        "generic-resource-provider-identity-missing"
                    )
                if identity is None and change.provider != "beyondcorp":
                    identity = self._generic_provider_identity(
                        terminal,
                        change.provider,
                    )
                if identity is None:
                    raise ProviderExecutionError(
                        "generic-resource-provider-identity-missing"
                    )
                if post_create is not None:
                    post_create()
                checkpoint = {
                    **checkpoint,
                    "phase": "applied",
                    "provider_identity_field": identity[0],
                    "provider_identity": identity[1],
                }
                self._save_checkpoint(checkpoint)
            self._mark_created(change, delete_url)
        except Exception:
            # A successful create request can be followed by a polling or
            # response-shape failure. Clean up the just-created resource here
            # because the outer executor only rolls back changes whose apply
            # method returned successfully.
            if not replaying_ambiguous_send:
                try:
                    self._delete_created(change, _spec=None)
                except Exception as cleanup_error:
                    raise ProviderExecutionError(
                        "provider-operation-cleanup-failed"
                    ) from cleanup_error
            raise
        return operation

    def _delete_created(
        self,
        change: ResourceChange,
        _spec: DeploymentSpec | None,
    ) -> None:
        key = self._key(change)
        before = self._before.get(key) or {}
        if key not in self._created and before.get("kind") not in {
            "named_resource_ownership",
            "generic_created_resource",
        }:
            return
        if before.get("kind") == "named_resource_ownership":
            phase = before.get("phase")
            if phase in {"prepared", "rejected"}:
                self._created.discard(key)
                return
            if phase not in {"sending", "applied"}:
                raise ProviderExecutionError(
                    "named-resource-ownership-checkpoint-invalid"
                )
            if phase == "sending":
                resource_url = before.get("resource_url")
                if not isinstance(resource_url, str):
                    raise ProviderExecutionError(
                        "named-resource-ownership-checkpoint-invalid"
                    )
                status_code, _ = self._transport.request_json(
                    "GET", resource_url, accepted_statuses=(200, 404)
                )
                if status_code == 404:
                    raise ProviderExecutionError(
                        "named-resource-provider-response-ambiguous"
                    )
            if _spec is None:
                # Cleanup from `_create` happens only before the create method
                # has returned; use its exact URL+marker below. Normal rollback
                # always supplies the specification and revalidates all fields.
                url = before.get("resource_url")
                if not isinstance(url, str):
                    raise ProviderExecutionError("named-resource-ownership-checkpoint-invalid")
                status_code, current = self._transport.request_json(
                    "GET", url, accepted_statuses=(200, 404)
                )
                if status_code == 404:
                    self._created.discard(key)
                    return
                token = before.get("ownership_token")
                marker = before.get("marker")
                if change.provider == "secretmanager":
                    labels = current.get("labels")
                    owned = (
                        isinstance(token, str)
                        and marker == token
                        and isinstance(labels, dict)
                        and labels.get("sgs-owner-token") == token
                    )
                else:
                    owned = (
                        isinstance(token, str)
                        and marker == f"Secure Gateway Studio ownership-token={token}"
                        and current.get("description") == marker
                    )
                if not owned:
                    raise ProviderExecutionError("named-resource-managed-state-changed")
                self._delete_url(url, fallback_host=url.split("/", 3)[2])
                self._created.discard(key)
                return
            outcome = self._destroy_named_owned_resource(change, _spec, before)
            if outcome != "deleted":
                raise ProviderExecutionError("named-resource-managed-state-changed")
            self._created.discard(key)
            return
        if before.get("kind") == "generic_created_resource":
            phase = before.get("phase")
            if phase in {"prepared", "rejected"}:
                self._created.discard(key)
                return
            if phase not in {"sending", "applied"}:
                raise ProviderExecutionError(
                    "generic-resource-ownership-checkpoint-invalid"
                )
            url = before.get("resource_url")
            if not isinstance(url, str):
                raise ProviderExecutionError(
                    "generic-resource-ownership-checkpoint-invalid"
                )
            marker = before.get("ownership_marker")
            status_code, _, identity = self._read_generic_created_resource(
                change,
                url,
                marker=marker if isinstance(marker, str) else None,
            )
            if status_code == 404:
                if before.get("phase") == "sending":
                    raise ProviderExecutionError(
                        "generic-resource-provider-response-ambiguous"
                    )
                self._created.discard(key)
                return
            applied_identity_matches = (
                identity is not None
                and before.get("provider_identity_field") == identity[0]
                and before.get("provider_identity") == identity[1]
            )
            marker_proves_inflight_create = (
                before.get("phase") == "sending"
                and isinstance(marker, str)
                and identity is not None
            )
            if not applied_identity_matches and not marker_proves_inflight_create:
                raise ProviderExecutionError("generic-resource-managed-state-changed")
            self._delete_url(url, fallback_host=url.split("/", 3)[2])
            self._created.discard(key)
            return
        url = before.get("delete_url")
        if not isinstance(url, str):
            return
        payload = self._request("DELETE", url, accepted=(200, 204, 404))
        if payload:
            self._wait(
                payload,
                fallback_host=url.split("/", 3)[2],
                mutation_url=url,
            )
        self._created.discard(key)

    def _enable_services(self, _change: ResourceChange, spec: DeploymentSpec) -> None:
        mutation_url = (
            f"https://serviceusage.googleapis.com/v1/projects/{spec.project_id}/"
            "services:batchEnable"
        )
        payload = self._request(
            "POST",
            mutation_url,
            body={"serviceIds": sorted(required_apis(spec))},
        )
        self._wait(
            payload,
            fallback_host="serviceusage.googleapis.com",
            mutation_url=mutation_url,
        )

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
        proxy_only = change.resource_name.endswith("-proxy-subnet")
        body: dict[str, Any] = {
            "name": change.resource_name,
            "ipCidrRange": spec.proxy_subnet_cidr if proxy_only else spec.subnet_cidr,
            "network": f"{base}/global/networks/{self._network_name(spec)}",
            "privateIpGoogleAccess": not proxy_only,
            "stackType": "IPV4_ONLY",
        }
        if proxy_only:
            body.update({"purpose": "REGIONAL_MANAGED_PROXY", "role": "ACTIVE"})
        self._create(
            change,
            url=f"{base}/regions/{spec.region}/subnetworks",
            body=body,
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
        key = self._key(change)
        managed_nat: dict[str, Any] = {
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
        }
        existing = self._operation_checkpoint
        if isinstance(existing, dict) and existing.get("kind") == "cloud_nat_delta":
            if (
                existing.get("protocol_version") != 3
                or existing.get("router_url") != url
                or existing.get("nat_name") != change.resource_name
                or existing.get("managed_after_nat") != managed_nat
            ):
                raise ProviderExecutionError("cloud-nat-operation-checkpoint-invalid")
            phase = existing.get("phase")
            if phase == "applied":
                self._assert_cloud_nat_managed_state(change, existing)
                return
            if phase == "sending":
                raise ProviderExecutionError("cloud-nat-provider-response-ambiguous")
            if phase not in {"prepared", "rejected"}:
                raise ProviderExecutionError("cloud-nat-operation-checkpoint-invalid")

        router = self._request("GET", url)
        nats = router.get("nats", [])
        if not isinstance(nats, list) or not all(isinstance(nat, dict) for nat in nats):
            raise ProviderExecutionError("cloud-nat-router-state-invalid")
        if any(nat.get("name") == change.resource_name for nat in nats):
            raise ProviderExecutionError("cloud-nat-name-conflict")
        identity = self._generic_provider_identity(router, "compute")
        if identity is None:
            raise ProviderExecutionError("cloud-nat-router-identity-missing")
        fingerprint = router.get("fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint:
            raise ProviderExecutionError("cloud-nat-router-fingerprint-missing")
        snapshot: dict[str, object] = {
            "kind": "cloud_nat_delta",
            "protocol_version": 3,
            "phase": "prepared",
            "resource_key": key,
            "router_url": url,
            "router_identity_field": identity[0],
            "router_identity": identity[1],
            "nat_name": change.resource_name,
            "managed_before_nat": None,
            "managed_after_nat": deepcopy(managed_nat),
            "mutation_request_id": self._external_request_id(
                f"cloud-nat:{key}:patch"
            ),
        }
        self._save_checkpoint(snapshot)
        desired_nats = [*nats, managed_nat]
        self._save_checkpoint({**snapshot, "phase": "sending"})
        try:
            payload = self._request(
                "PATCH",
                url,
                params={"requestId": str(snapshot["mutation_request_id"])},
                body={"nats": desired_nats, "fingerprint": fingerprint},
            )
        except GoogleApiError as error:
            if error.status_code in {400, 401, 403, 404, 409, 412}:
                self._save_checkpoint({**snapshot, "phase": "rejected"})
            raise
        self._wait(
            payload,
            fallback_host="compute.googleapis.com",
            mutation_url=url,
        )
        self._save_checkpoint({**snapshot, "phase": "applied"})

    @staticmethod
    def _cloud_nat_projection(value: dict[str, Any]) -> dict[str, Any]:
        fields = {
            "name",
            "natIpAllocateOption",
            "sourceSubnetworkIpRangesToNat",
            "subnetworks",
            "logConfig",
        }
        return {field: deepcopy(value[field]) for field in fields if field in value}

    def _assert_cloud_nat_managed_state(
        self,
        change: ResourceChange,
        checkpoint: dict[str, object],
    ) -> tuple[dict[str, Any], list[dict[str, Any]], int]:
        router_url = checkpoint.get("router_url")
        expected_nat = checkpoint.get("managed_after_nat")
        if not isinstance(router_url, str) or not isinstance(expected_nat, dict):
            raise ProviderExecutionError("cloud-nat-operation-checkpoint-invalid")
        status_code, router = self._transport.request_json(
            "GET", router_url, accepted_statuses=(200, 404)
        )
        if status_code == 404:
            raise ProviderExecutionError("cloud-nat-router-managed-state-changed")
        identity = self._generic_provider_identity(router, "compute")
        if (
            identity is None
            or checkpoint.get("router_identity_field") != identity[0]
            or checkpoint.get("router_identity") != identity[1]
        ):
            raise ProviderExecutionError("cloud-nat-router-managed-state-changed")
        raw_nats = router.get("nats", [])
        if not isinstance(raw_nats, list) or not all(
            isinstance(nat, dict) for nat in raw_nats
        ):
            raise ProviderExecutionError("cloud-nat-router-state-invalid")
        nats = [deepcopy(nat) for nat in raw_nats]
        matches = [
            index
            for index, nat in enumerate(nats)
            if nat.get("name") == change.resource_name
        ]
        if len(matches) != 1 or self._cloud_nat_projection(nats[matches[0]]) != (
            self._cloud_nat_projection(expected_nat)
        ):
            raise ProviderExecutionError("cloud-nat-managed-state-changed")
        return router, nats, matches[0]

    def _restore_cloud_nat(
        self,
        change: ResourceChange,
        _spec: DeploymentSpec | None,
    ) -> None:
        checkpoint = self._before.get(self._key(change)) or self._ownership_metadata.get(
            self._key(change)
        )
        if not isinstance(checkpoint, dict) or checkpoint.get("kind") != "cloud_nat_delta":
            raise ProviderExecutionError("cloud-nat-ownership-metadata-missing")
        phase = checkpoint.get("phase")
        if phase in {"prepared", "rejected"}:
            return
        if phase != "applied":
            raise ProviderExecutionError("cloud-nat-provider-response-ambiguous")
        router, nats, managed_index = self._assert_cloud_nat_managed_state(
            change, checkpoint
        )
        before_nat = checkpoint.get("managed_before_nat")
        if before_nat is not None and not isinstance(before_nat, dict):
            raise ProviderExecutionError("cloud-nat-operation-checkpoint-invalid")
        nats[managed_index : managed_index + 1] = (
            [deepcopy(before_nat)] if isinstance(before_nat, dict) else []
        )
        router_url = checkpoint.get("router_url")
        if not isinstance(router_url, str):
            raise ProviderExecutionError("cloud-nat-operation-checkpoint-invalid")
        fingerprint = router.get("fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint:
            raise ProviderExecutionError("cloud-nat-router-fingerprint-missing")
        operation = self._request(
            "PATCH",
            router_url,
            params={
                "requestId": self._external_request_id(
                    f"cloud-nat:{self._key(change)}:rollback"
                )
            },
            body={"nats": nats, "fingerprint": fingerprint},
        )
        self._wait(
            operation,
            fallback_host="compute.googleapis.com",
            mutation_url=router_url,
        )

    def _create_service_account(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        base = f"https://iam.googleapis.com/v1/projects/{spec.project_id}"
        email = quote(f"{change.resource_name}@{spec.project_id}.iam.gserviceaccount.com", safe="")
        resource_url = f"{base}/serviceAccounts/{email}"
        token = self._ownership_token(change)
        marker = f"Secure Gateway Studio ownership-token={token}"
        checkpoint = self._named_resource_checkpoint(
            change,
            resource_kind="iam_service_account",
            resource_url=resource_url,
            marker=marker,
        )
        reconciled: dict[str, Any] = {}

        def reconcile() -> bool:
            status_code, current = self._transport.request_json(
                "GET", resource_url, accepted_statuses=(200, 404)
            )
            reconciled.update(current)
            return (
                status_code == 200
                and current.get("email")
                == f"{change.resource_name}@{spec.project_id}.iam.gserviceaccount.com"
                and current.get("displayName")
                == f"Secure Gateway Studio {change.resource_name}"
                and current.get("description") == marker
            )

        created = self._create(
            change,
            url=f"{base}/serviceAccounts",
            body={
                "accountId": change.resource_name,
                "serviceAccount": {
                    "description": marker,
                    "displayName": f"Secure Gateway Studio {change.resource_name}",
                },
            },
            fallback_host="iam.googleapis.com",
            delete_url=resource_url,
            reconcile=reconcile,
        )
        identity = created.get("uniqueId") or reconciled.get("uniqueId")
        self._save_checkpoint(
            {
                **checkpoint,
                "phase": "applied",
                **({"provider_identity": str(identity)} if identity is not None else {}),
            }
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
        resource_url = f"{url}/{change.resource_name}"
        token = self._ownership_token(change)
        checkpoint = self._named_resource_checkpoint(
            change,
            resource_kind="secretmanager_secret",
            resource_url=resource_url,
            marker=token,
        )
        labels = {
            "managed-by": "secure-gateway-studio",
            "configuration-hash": canonical_configuration_hash(spec)[:32],
            "certificate-spec-hash": certificate_configuration_hash(spec)[:32],
            "sgs-owner-token": token,
        }
        reconciled: dict[str, Any] = {}

        def reconcile() -> bool:
            status_code, current = self._transport.request_json(
                "GET", resource_url, accepted_statuses=(200, 404)
            )
            reconciled.update(current)
            current_labels = current.get("labels")
            replication = current.get("replication")
            return (
                status_code == 200
                and isinstance(current_labels, dict)
                and all(current_labels.get(key) == value for key, value in labels.items())
                and isinstance(replication, dict)
                and isinstance(replication.get("automatic"), dict)
            )

        self._create(
            change,
            url=url,
            params={"secretId": change.resource_name},
            body={
                "replication": {"automatic": {}},
                "labels": labels,
            },
            fallback_host="secretmanager.googleapis.com",
            delete_url=resource_url,
            reconcile=reconcile,
        )
        self._save_checkpoint(
            {
                **checkpoint,
                "phase": "applied",
            }
        )

    def _ensure_enterprise_ownership(
        self,
        change: ResourceChange,
        spec: DeploymentSpec,
    ) -> dict[str, object]:
        key = self._key(change)
        existing = self._before.get(key)
        if isinstance(existing, dict) and existing.get("kind") == "privateca_certificate":
            if not spec.ca_name or existing.get("authority_name") != spec.ca_name:
                raise ProviderExecutionError("privateca-certificate-ownership-mismatch")
            certificate_name = existing.get("certificate_name")
            csr_sha256 = existing.get("csr_sha256")
            if not isinstance(certificate_name, str) or not isinstance(csr_sha256, str):
                raise ProviderExecutionError("privateca-certificate-ownership-unverified")
            if self._enterprise_request is not None:
                if hashlib.sha256(self._enterprise_request[1]).hexdigest() != csr_sha256:
                    raise ProviderExecutionError("privateca-certificate-ownership-mismatch")
                return existing

            # Private keys are deliberately not persisted. A prepared phase is
            # proof that no create request was sent, so an absent resource lets
            # us safely replace the abandoned CSR. Once `sending` is durable,
            # absence is ambiguous and the claim must remain for manual review.
            status_code, current = self._transport.request_json(
                "GET",
                f"https://privateca.googleapis.com/v1/{certificate_name}",
                accepted_statuses=(200, 404),
            )
            phase = existing.get("phase")
            if status_code == 404 and phase in {"prepared", "rejected"}:
                self._enterprise_request = CertificateIssuer.prepare_enterprise_request(
                    spec.private_hostname
                )
                replacement = {
                    **existing,
                    "csr_sha256": hashlib.sha256(self._enterprise_request[1]).hexdigest(),
                }
                self._save_checkpoint(replacement)
                return deepcopy(self._operation_checkpoint or replacement)
            if status_code == 404:
                ambiguous = {**existing, "phase": "key_lost_ambiguous"}
                self._save_checkpoint(ambiguous)
                raise ProviderExecutionError(
                    "privateca-certificate-private-key-unrecoverable"
                )

            returned_name = current.get("name")
            returned_csr = current.get("pemCsr")
            returned_authority = current.get("issuerCertificateAuthority")
            if (
                returned_name != certificate_name
                or not isinstance(returned_csr, str)
                or hashlib.sha256(returned_csr.encode("ascii")).hexdigest()
                != csr_sha256
                or returned_authority != spec.ca_name
            ):
                raise ProviderExecutionError("privateca-certificate-ownership-mismatch")
            if not self._revoke_certificate_name(certificate_name, existing):
                raise ProviderExecutionError("privateca-certificate-ownership-mismatch")
            revoked = {**existing, "phase": "key_lost_revoked"}
            self._save_checkpoint(revoked)
            raise ProviderExecutionError(
                "privateca-certificate-private-key-unrecoverable"
            )
        if not spec.ca_name:
            raise ProviderExecutionError("privateca-configuration-missing")
        if self._enterprise_request is None:
            self._enterprise_request = CertificateIssuer.prepare_enterprise_request(
                spec.private_hostname
            )
        _, csr_pem = self._enterprise_request
        metadata: dict[str, object] = {
            "kind": "privateca_certificate",
            "protocol_version": 2,
            "phase": "prepared",
            "resource_key": key,
            "certificate_name": self._enterprise_certificate_name(spec),
            "authority_name": spec.ca_name,
            "csr_sha256": hashlib.sha256(csr_pem).hexdigest(),
            "create_request_id": self._external_request_id(
                f"privateca:create:{self._enterprise_certificate_name(spec)}"
            ),
        }
        self._save_checkpoint(metadata)
        return deepcopy(self._operation_checkpoint or metadata)

    def _issue_certificate(self, spec: DeploymentSpec) -> CertificateBundle:
        if self._certificate is not None:
            return self._certificate
        issuer = CertificateIssuer(
            self._transport,
            poll_interval_seconds=self._poll_interval,
            operation_timeout_seconds=self._operation_timeout,
        )
        if spec.certificate_strategy is CertificateStrategy.ENTERPRISE_CA:
            certificate_change = ResourceChange(
                provider="privateca",
                resource_type="certificate",
                resource_name=f"{spec.name}-certificate",
                action=ChangeAction.CREATE,
                risk=RiskLevel.HIGH,
                summary="Enterprise CA certificate",
                owned_after_apply=True,
                dependencies=[],
            )
            ownership = self._ensure_enterprise_ownership(certificate_change, spec)
            certificate_name = ownership.get("certificate_name")
            request_id = ownership.get("create_request_id")
            if not isinstance(certificate_name, str) or not isinstance(request_id, str):
                raise ProviderExecutionError("privateca-certificate-ownership-unverified")
            certificate_id = certificate_name.rsplit("/", maxsplit=1)[-1]
            self._save_checkpoint({**ownership, "phase": "sending"})
            try:
                self._certificate = issuer.issue_enterprise_ca(
                    hostname=spec.private_hostname,
                    ca_pool=str(spec.ca_pool),
                    ca_name=str(spec.ca_name),
                    certificate_id=certificate_id,
                    lifetime_days=spec.certificate_lifetime_days,
                    request_id=request_id,
                    request=self._enterprise_request,
                )
            except GoogleApiError as error:
                if error.status_code in {400, 401, 403, 404, 412}:
                    self._save_checkpoint({**ownership, "phase": "rejected"})
                raise
            except CertificateIssuanceRejectedError:
                self._save_checkpoint({**ownership, "phase": "rejected"})
                raise
            if (
                self._certificate.issuer_resource_name
                != ownership.get("certificate_name")
                or self._certificate.issuer_certificate_authority
                != ownership.get("authority_name")
                or self._certificate.csr_sha256 != ownership.get("csr_sha256")
            ):
                self._certificate = None
                raise ProviderExecutionError("privateca-certificate-ownership-mismatch")
            self._save_checkpoint({**ownership, "phase": "applied"})
        elif spec.certificate_strategy is CertificateStrategy.LOCAL_POC:
            self._certificate = issuer.issue_local_poc(
                hostname=spec.private_hostname,
                lifetime_days=spec.certificate_lifetime_days,
            )
        else:
            raise ValueError("Public certificates must reference an existing secret")
        return self._certificate

    def _enterprise_certificate_id(self, spec: DeploymentSpec) -> str:
        return f"{spec.name[:40]}-tls-{self._execution_id.hex[:12]}"

    def _enterprise_certificate_name(self, spec: DeploymentSpec) -> str:
        if not spec.ca_pool:
            raise ProviderExecutionError("privateca-configuration-missing")
        return f"{spec.ca_pool}/certificates/{self._enterprise_certificate_id(spec)}"

    def _issue_enterprise_certificate_step(
        self,
        change: ResourceChange,
        spec: DeploymentSpec,
    ) -> None:
        if (
            spec.certificate_strategy is not CertificateStrategy.ENTERPRISE_CA
            or change.resource_name != f"{spec.name}-certificate"
        ):
            raise ProviderExecutionError("privateca-certificate-context-invalid")
        expected_name = self._enterprise_certificate_name(spec)
        ownership = self._ensure_enterprise_ownership(change, spec)
        bundle = self._issue_certificate(spec)
        if bundle.issuer_resource_name != expected_name:
            self._certificate = None
            raise ProviderExecutionError("privateca-certificate-identity-mismatch")
        if ownership.get("certificate_name") != expected_name:
            self._certificate = None
            raise ProviderExecutionError("privateca-certificate-ownership-mismatch")

    def _rollback_enterprise_certificate(
        self,
        change: ResourceChange,
        spec: DeploymentSpec,
    ) -> None:
        before = (
            self._before.get(self._key(change))
            or self._ownership_metadata.get(self._key(change))
            or {}
        )
        certificate_name = before.get("certificate_name")
        if not isinstance(certificate_name, str):
            raise ProviderExecutionError("privateca-certificate-ownership-unverified")
        if before.get("phase") == "key_lost_ambiguous":
            raise ProviderExecutionError("privateca-certificate-provider-response-ambiguous")
        phase = before.get("phase")
        if phase in {"prepared", "rejected"}:
            status_code, _ = self._transport.request_json(
                "GET",
                f"https://privateca.googleapis.com/v1/{certificate_name}",
                accepted_statuses=(200, 404),
            )
            if status_code == 404:
                self._certificate = None
                return
            raise ProviderExecutionError("privateca-certificate-ownership-mismatch")
        if not self._revoke_certificate_name(
            certificate_name,
            before,
            absent_is_ambiguous=phase == "sending",
        ):
            raise ProviderExecutionError("privateca-certificate-ownership-mismatch")
        self._certificate = None

    @staticmethod
    def _secret_string_map(payload: dict[str, Any], field: str) -> dict[str, str]:
        value = payload.get(field, {})
        if not isinstance(value, dict) or not all(
            isinstance(key, str) and isinstance(item, str)
            for key, item in value.items()
        ):
            raise ValueError(f"Secret Manager returned invalid {field}")
        return deepcopy(value)

    @staticmethod
    def _run_owned_secret_payload(bundle: CertificateBundle, ownership_token: str) -> bytes:
        try:
            decoded = json.loads(bundle.secret_payload())
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ProviderExecutionError("secret-version-payload-invalid") from error
        if not isinstance(decoded, dict):
            raise ProviderExecutionError("secret-version-payload-invalid")
        decoded["sgs_ownership_token"] = ownership_token
        return json.dumps(
            decoded,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @staticmethod
    def _secret_version_name(secret_url: str, value: object) -> str:
        api_prefix = "https://secretmanager.googleapis.com/v1/"
        if not secret_url.startswith(api_prefix):
            raise ProviderExecutionError("secret-version-name-invalid")
        resource_name = secret_url.removeprefix(api_prefix)
        expected = re.compile(
            rf"^{re.escape(resource_name)}/versions/[1-9][0-9]*$"
        )
        if not isinstance(value, str) or expected.fullmatch(value) is None:
            raise ProviderExecutionError("secret-version-name-invalid")
        return value

    def _list_secret_version_names(self, secret_url: str) -> list[str]:
        names: list[str] = []
        page_token: str | None = None
        seen_tokens: set[str] = set()
        for _ in range(100):
            params: dict[str, str | int] = {"pageSize": 100}
            if page_token is not None:
                params["pageToken"] = page_token
            payload = self._request("GET", f"{secret_url}/versions", params=params)
            versions = payload.get("versions", [])
            if not isinstance(versions, list):
                raise ValueError("Secret Manager returned an invalid version list")
            for version in versions:
                name = version.get("name") if isinstance(version, dict) else None
                names.append(self._secret_version_name(secret_url, name))
            if "nextPageToken" not in payload or payload["nextPageToken"] == "":
                return names
            next_token = payload["nextPageToken"]
            if (
                not isinstance(next_token, str)
                or next_token in seen_tokens
            ):
                raise ProviderExecutionError("secret-version-pagination-invalid")
            seen_tokens.add(next_token)
            page_token = next_token
        raise ProviderExecutionError("secret-version-pagination-limit-exceeded")

    def _recover_secret_version(
        self,
        checkpoint: dict[str, object],
    ) -> str:
        secret_url = checkpoint.get("secret_url")
        digest = checkpoint.get("payload_sha256")
        ownership_token = checkpoint.get("ownership_token")
        baseline = checkpoint.get("baseline_versions")
        if (
            not isinstance(secret_url, str)
            or not isinstance(digest, str)
            or not isinstance(ownership_token, str)
            or not isinstance(baseline, list)
            or not all(isinstance(item, str) for item in baseline)
        ):
            raise ProviderExecutionError("secret-version-checkpoint-invalid")
        for name in baseline:
            self._secret_version_name(secret_url, name)
        candidates: list[str] = []
        for name in self._list_secret_version_names(secret_url):
            if name in baseline:
                continue
            accessed = self._request(
                "GET",
                f"https://secretmanager.googleapis.com/v1/{name}:access",
            )
            if accessed.get("name") != name:
                raise ProviderExecutionError("secret-version-access-identity-invalid")
            encoded = accessed.get("payload", {}).get("data")
            if not isinstance(encoded, str):
                continue
            try:
                payload = base64.b64decode(encoded, validate=True)
            except ValueError:
                continue
            try:
                decoded = json.loads(payload)
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if (
                hashlib.sha256(payload).hexdigest() == digest
                and isinstance(decoded, dict)
                and decoded.get("sgs_ownership_token") == ownership_token
            ):
                candidates.append(name)
        if len(candidates) != 1:
            raise ProviderExecutionError(
                "secret-version-recovery-not-found"
                if not candidates
                else "secret-version-recovery-ambiguous"
            )
        return candidates[0]

    def _prepared_secret_version_baseline_is_unchanged(
        self,
        checkpoint: dict[str, object],
    ) -> None:
        secret_url = checkpoint.get("secret_url")
        baseline = checkpoint.get("baseline_versions")
        if (
            not isinstance(secret_url, str)
            or not isinstance(baseline, list)
            or not all(isinstance(item, str) for item in baseline)
        ):
            raise ProviderExecutionError("secret-version-checkpoint-invalid")
        validated = [self._secret_version_name(secret_url, item) for item in baseline]
        current = self._list_secret_version_names(secret_url)
        if len(current) != len(set(current)) or set(current) != set(validated):
            raise ProviderExecutionError("secret-version-prepared-state-changed")

    def _revoke_prepared_secret_certificate(
        self,
        checkpoint: dict[str, object],
    ) -> None:
        certificate_name = checkpoint.get("issuer_resource_name")
        if certificate_name is None:
            return
        authority_name = checkpoint.get("issuer_certificate_authority")
        csr_sha256 = checkpoint.get("csr_sha256")
        if (
            not isinstance(certificate_name, str)
            or not certificate_name
            or not isinstance(authority_name, str)
            or not authority_name
            or not isinstance(csr_sha256, str)
            or not csr_sha256
        ):
            raise ProviderExecutionError("secret-version-certificate-ownership-unverified")
        certificate_url = f"https://privateca.googleapis.com/v1/{certificate_name}"
        status_code, _ = self._transport.request_json(
            "GET",
            certificate_url,
            accepted_statuses=(200, 404),
        )
        # The certificate operation completed before this prepared checkpoint.
        # A transient 404 must therefore retain the claim instead of pretending
        # that the externally issued certificate does not exist.
        if status_code == 404:
            raise ProviderExecutionError("secret-version-certificate-not-visible")
        ownership = {
            "kind": "privateca_certificate",
            "certificate_name": certificate_name,
            "authority_name": authority_name,
            "csr_sha256": csr_sha256,
        }
        if not self._revoke_certificate_name(certificate_name, ownership):
            raise ProviderExecutionError("secret-version-certificate-ownership-mismatch")

    @staticmethod
    def _managed_values(
        source: dict[str, str], keys: set[str]
    ) -> dict[str, str | None]:
        return {key: source.get(key) for key in sorted(keys)}

    @staticmethod
    def _restore_managed_values(
        current: dict[str, str],
        before: object,
        after: object,
        *,
        missing_is_managed: set[str] | None = None,
    ) -> dict[str, str]:
        if not isinstance(before, dict) or not isinstance(after, dict):
            raise ProviderExecutionError("secret-metadata-managed-after-missing")
        if set(before) != set(after):
            raise ProviderExecutionError("secret-metadata-checkpoint-invalid")
        restored = deepcopy(current)
        for key in before:
            previous = before[key]
            managed = after[key]
            if previous is not None and not isinstance(previous, str):
                raise ProviderExecutionError("secret-metadata-checkpoint-invalid")
            if managed is not None and not isinstance(managed, str):
                raise ProviderExecutionError("secret-metadata-checkpoint-invalid")
            live = current.get(key)
            if live == managed or (
                live is None
                and missing_is_managed is not None
                and key in missing_is_managed
            ):
                if previous is None:
                    restored.pop(key, None)
                else:
                    restored[key] = previous
            elif live != previous:
                raise ProviderExecutionError("secret-metadata-concurrent-change")
        return restored

    def _patch_secret_metadata(
        self,
        secret_url: str,
        current: dict[str, Any],
        aliases: dict[str, str],
        labels: dict[str, str],
    ) -> None:
        before_aliases = self._secret_string_map(current, "versionAliases")
        before_labels = self._secret_string_map(current, "labels")
        if not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in aliases.items()
        ):
            raise ProviderExecutionError("secret-metadata-checkpoint-invalid")
        if not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in labels.items()
        ):
            raise ProviderExecutionError("secret-metadata-checkpoint-invalid")
        changed_aliases = {
            key
            for key in before_aliases.keys() | aliases.keys()
            if before_aliases.get(key) != aliases.get(key)
        }
        changed_labels = {
            key
            for key in before_labels.keys() | labels.keys()
            if before_labels.get(key) != labels.get(key)
        }
        live = deepcopy(current)
        for attempt in range(SECRET_METADATA_CONFLICT_ATTEMPTS):
            live_aliases = self._secret_string_map(live, "versionAliases")
            live_labels = self._secret_string_map(live, "labels")
            desired_aliases = self._merge_secret_metadata_values(
                before_aliases,
                aliases,
                live_aliases,
                changed_aliases,
            )
            desired_labels = self._merge_secret_metadata_values(
                before_labels,
                labels,
                live_labels,
                changed_labels,
            )
            if desired_aliases == live_aliases and desired_labels == live_labels:
                return
            etag = live.get("etag")
            if not isinstance(etag, str) or not etag:
                raise ProviderExecutionError("secret-metadata-etag-missing")
            try:
                self._request(
                    "PATCH",
                    secret_url,
                    params={"updateMask": "versionAliases,labels"},
                    body={
                        "versionAliases": desired_aliases,
                        "labels": desired_labels,
                        "etag": etag,
                    },
                )
                return
            except GoogleApiError as error:
                if not self._is_secret_metadata_etag_conflict(error):
                    raise
                if attempt + 1 >= SECRET_METADATA_CONFLICT_ATTEMPTS:
                    raise ProviderExecutionError(
                        "secret-metadata-conflict-retry-exhausted"
                    ) from error
                live = self._request("GET", secret_url)
        raise ProviderExecutionError("secret-metadata-conflict-retry-exhausted")

    @staticmethod
    def _merge_secret_metadata_values(
        before: dict[str, str],
        desired: dict[str, str],
        live: dict[str, str],
        changed_keys: set[str],
    ) -> dict[str, str]:
        merged = deepcopy(live)
        for key in changed_keys:
            previous = before.get(key)
            target = desired.get(key)
            current = live.get(key)
            if current not in {previous, target}:
                raise ProviderExecutionError("secret-metadata-concurrent-change")
            if target is None:
                merged.pop(key, None)
            else:
                merged[key] = target
        return merged

    def _add_secret_version(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        key = self._key(change)
        expected_secret_url = (
            f"https://secretmanager.googleapis.com/v1/projects/{spec.project_id}/"
            f"secrets/{change.resource_name}"
        )
        existing = self._operation_checkpoint
        bundle: CertificateBundle | None = None
        if isinstance(existing, dict) and existing.get("kind") == "secret_version":
            checkpoint = deepcopy(existing)
            if checkpoint.get("secret_url") != expected_secret_url:
                raise ProviderExecutionError("secret-version-checkpoint-invalid")
            if checkpoint.get("phase") == "rejected":
                raise ProviderExecutionError("secret-version-add-rejected")
            if checkpoint.get("phase") == "prepared" and checkpoint.get("version_name") is None:
                self._prepared_secret_version_baseline_is_unchanged(checkpoint)
                if checkpoint.get("issuer_resource_name") is not None:
                    self._revoke_prepared_secret_certificate(checkpoint)
                    self._save_checkpoint(
                        {
                            **checkpoint,
                            "phase": "rejected",
                            "rejection_reason": "private-key-lost-before-add-version",
                        }
                    )
                    self._certificate = None
                    raise ProviderExecutionError(
                        "secret-version-prepared-private-key-unrecoverable"
                    )
                # A local PoC certificate has no external issuer resource. It
                # can be regenerated safely because prepared proves addVersion
                # was never sent and the complete version list is unchanged.
                bundle = self._issue_certificate(spec)
                ownership_token = checkpoint.get("ownership_token")
                if not isinstance(ownership_token, str):
                    raise ProviderExecutionError("secret-version-checkpoint-invalid")
                secret_payload = self._run_owned_secret_payload(bundle, ownership_token)
                checkpoint = {
                    **checkpoint,
                    "payload_sha256": hashlib.sha256(secret_payload).hexdigest(),
                    "issuer_resource_name": bundle.issuer_resource_name,
                    "issuer_certificate_authority": bundle.issuer_certificate_authority,
                    "csr_sha256": bundle.csr_sha256,
                }
                self._save_checkpoint(checkpoint)
        else:
            bundle = self._issue_certificate(spec)
            secret_before = self._request("GET", expected_secret_url)
            self._secret_string_map(secret_before, "versionAliases")
            self._secret_string_map(secret_before, "labels")
            ownership_token = self._ownership_token(change)
            secret_payload = self._run_owned_secret_payload(bundle, ownership_token)
            checkpoint = {
                "kind": "secret_version",
                "phase": "prepared",
                "resource_key": key,
                "secret_url": expected_secret_url,
                "payload_sha256": hashlib.sha256(secret_payload).hexdigest(),
                "ownership_token": ownership_token,
                "baseline_versions": self._list_secret_version_names(
                    expected_secret_url
                ),
                "version_name": None,
                "issuer_resource_name": bundle.issuer_resource_name,
                "issuer_certificate_authority": bundle.issuer_certificate_authority,
                "csr_sha256": bundle.csr_sha256,
            }
            self._save_checkpoint(checkpoint)

        version_name = checkpoint.get("version_name")
        if not isinstance(version_name, str):
            if bundle is not None:
                ownership_token = checkpoint.get("ownership_token")
                if not isinstance(ownership_token, str):
                    raise ProviderExecutionError("secret-version-checkpoint-invalid")
                encoded_payload = base64.b64encode(
                    self._run_owned_secret_payload(bundle, ownership_token)
                ).decode("ascii")
                checkpoint = {**checkpoint, "phase": "sending"}
                self._save_checkpoint(checkpoint)
                try:
                    response = self._request(
                        "POST",
                        f"{expected_secret_url}:addVersion",
                        body={"payload": {"data": encoded_payload}},
                    )
                    version_name = response.get("name")
                except GoogleApiError as error:
                    if 400 <= error.status_code < 500 and error.status_code not in {408, 429}:
                        rejected = {
                            **checkpoint,
                            "phase": "rejected",
                            "rejection_status": error.status_code,
                        }
                        self._save_checkpoint(rejected)
                        self._compensate_unpublished_certificate(bundle)
                        raise
                    version_name = self._recover_secret_version(checkpoint)
                except Exception:
                    version_name = self._recover_secret_version(checkpoint)
            else:
                version_name = self._recover_secret_version(checkpoint)
            version_name = self._secret_version_name(expected_secret_url, version_name)
            checkpoint = {
                **checkpoint,
                "phase": "version_added",
                "version_name": version_name,
            }
            self._save_checkpoint(checkpoint)

        version_name = self._secret_version_name(expected_secret_url, version_name)
        version_id = version_name.rsplit("/", maxsplit=1)[-1]
        current = self._request("GET", expected_secret_url)
        aliases = self._secret_string_map(current, "versionAliases")
        labels = self._secret_string_map(current, "labels")
        alias_keys = {"active"}
        label_keys = {
            "managed-by",
            "configuration-hash",
            "certificate-spec-hash",
            "sgs-active-version",
            "sgs-previous-active",
        }
        if checkpoint.get("phase") in {"metadata_prepared", "applied"}:
            managed_aliases = checkpoint.get("managed_after_aliases")
            managed_labels = checkpoint.get("managed_after_labels")
            before_aliases = checkpoint.get("managed_before_aliases")
            before_labels = checkpoint.get("managed_before_labels")
            if not all(
                isinstance(item, dict)
                for item in [managed_aliases, managed_labels, before_aliases, before_labels]
            ):
                raise ProviderExecutionError("secret-metadata-managed-after-missing")
            alias_state = self._managed_values(aliases, alias_keys)
            label_state = self._managed_values(labels, label_keys)
            if alias_state == managed_aliases and label_state == managed_labels:
                self._save_checkpoint({**checkpoint, "phase": "applied"})
                return
            if alias_state != before_aliases or label_state != before_labels:
                raise ProviderExecutionError("secret-metadata-concurrent-change")
        else:
            before_aliases = self._managed_values(aliases, alias_keys)
            before_labels = self._managed_values(labels, label_keys)
            managed_aliases = {"active": version_id}
            managed_labels = {
                "managed-by": "secure-gateway-studio",
                "configuration-hash": canonical_configuration_hash(spec)[:32],
                "certificate-spec-hash": certificate_configuration_hash(spec)[:32],
                "sgs-active-version": version_id,
                "sgs-previous-active": aliases.get("active", "none"),
            }
            checkpoint = {
                **checkpoint,
                "phase": "metadata_prepared",
                "managed_before_aliases": before_aliases,
                "managed_after_aliases": managed_aliases,
                "managed_before_labels": before_labels,
                "managed_after_labels": managed_labels,
            }
            self._save_checkpoint(checkpoint)

        desired_aliases = deepcopy(aliases)
        desired_labels = deepcopy(labels)
        desired_aliases.update(
            {key: value for key, value in managed_aliases.items() if isinstance(value, str)}
        )
        desired_labels.update(
            {key: value for key, value in managed_labels.items() if isinstance(value, str)}
        )
        self._patch_secret_metadata(
            expected_secret_url,
            current,
            desired_aliases,
            desired_labels,
        )
        self._save_checkpoint({**checkpoint, "phase": "applied"})

    def _disable_secret_version(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        before = self._before.get(self._key(change)) or {}
        if before.get("kind") != "secret_version":
            raise ProviderExecutionError("secret-metadata-managed-after-missing")
        if before.get("phase") == "rejected":
            self._certificate = None
            return
        if before.get("phase") == "prepared" and before.get("version_name") is None:
            self._prepared_secret_version_baseline_is_unchanged(before)
            self._revoke_prepared_secret_certificate(before)
            self._save_checkpoint(
                {
                    **before,
                    "phase": "rejected",
                    "rejection_reason": "rolled-back-before-add-version",
                }
            )
            self._certificate = None
            return
        version_name = before.get("version_name")
        secret_url = before.get("secret_url")
        if isinstance(secret_url, str):
            current = self._request("GET", secret_url)
            aliases = self._secret_string_map(current, "versionAliases")
            labels = self._secret_string_map(current, "labels")
            restored_aliases = self._restore_managed_values(
                aliases,
                before.get("managed_before_aliases"),
                before.get("managed_after_aliases"),
            )
            restored_labels = self._restore_managed_values(
                labels,
                before.get("managed_before_labels"),
                before.get("managed_after_labels"),
            )
            if restored_aliases != aliases or restored_labels != labels:
                self._patch_secret_metadata(
                    secret_url,
                    current,
                    restored_aliases,
                    restored_labels,
                )
        if isinstance(version_name, str) and isinstance(secret_url, str):
            version_name = self._secret_version_name(secret_url, version_name)
            self._request(
                "POST",
                f"https://secretmanager.googleapis.com/v1/{version_name}:disable",
                body={},
            )
        self._revoke_issued_certificate(self._certificate)
        self._certificate = None
        self._refresh_existing_offload(spec, before)

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
        self._patch_secret_metadata(secret_url, current, aliases, labels)

    def _revoke_issued_certificate(self, bundle: CertificateBundle | None) -> None:
        if bundle is None or bundle.issuer_resource_name is None:
            return
        ownership: dict[str, object] | None = None
        for candidate in [*self._before.values(), *self._ownership_metadata.values()]:
            if (
                isinstance(candidate, dict)
                and candidate.get("certificate_name") == bundle.issuer_resource_name
            ):
                ownership = candidate
                break
        if ownership is None:
            ownership = {
                "kind": "privateca_certificate",
                "certificate_name": bundle.issuer_resource_name,
                "authority_name": bundle.issuer_certificate_authority,
                "csr_sha256": bundle.csr_sha256,
            }
        self._revoke_certificate_name(bundle.issuer_resource_name, ownership)

    def _restore_owned_iam(
        self,
        change: ResourceChange,
        *,
        current_url: str,
        restore_url: str,
        current_method: str,
    ) -> None:
        key = self._key(change)
        snapshot = self._ownership_metadata.get(key) or self._before.get(key)
        if not isinstance(snapshot, dict) or snapshot.get("kind") != "iam_policy_delta":
            raise ProviderExecutionError("iam-teardown-ownership-metadata-missing")
        if (
            snapshot.get("current_url") != current_url
            or snapshot.get("restore_url") != restore_url
            or snapshot.get("current_method") != current_method
        ):
            raise ProviderExecutionError("iam-teardown-ownership-metadata-invalid")
        body = snapshot.get("body")
        after_policy = snapshot.get("after_policy")
        if (
            not isinstance(body, dict)
            or not isinstance(body.get("policy"), dict)
            or not isinstance(after_policy, dict)
        ):
            raise ProviderExecutionError("iam-teardown-ownership-metadata-invalid")
        self._before[key] = deepcopy(snapshot)
        try:
            self._restore_before(change, _spec=None)
        except GoogleApiError as error:
            if error.status_code != 404:
                raise

    def _revoke_certificate_name(
        self,
        certificate_name: str,
        ownership: dict[str, object],
        *,
        absent_is_ambiguous: bool = False,
    ) -> bool:
        certificate_url = f"https://privateca.googleapis.com/v1/{certificate_name}"
        status_code, current = self._transport.request_json(
            "GET",
            certificate_url,
            accepted_statuses=(200, 404),
        )
        if status_code == 404:
            if absent_is_ambiguous:
                raise ProviderExecutionError(
                    "privateca-certificate-provider-response-ambiguous"
                )
            return True
        returned_name = current.get("name")
        if returned_name != certificate_name:
            raise ProviderExecutionError("privateca-certificate-identity-mismatch")
        csr_sha256 = ownership.get("csr_sha256")
        authority_name = ownership.get("authority_name")
        pem_csr = current.get("pemCsr")
        current_authority = current.get("issuerCertificateAuthority")
        if (
            not isinstance(csr_sha256, str)
            or not csr_sha256
            or not isinstance(authority_name, str)
            or not authority_name
            or not isinstance(pem_csr, str)
            or not pem_csr
            or not isinstance(current_authority, str)
        ):
            raise ProviderExecutionError("privateca-certificate-ownership-unverified")
        if (
            hashlib.sha256(pem_csr.encode("ascii")).hexdigest() != csr_sha256
            or current_authority != authority_name
        ):
            return False
        if current.get("revocationDetails") is not None:
            return True
        request_id = str(
            uuid.uuid5(
                self._execution_id,
                f"privateca:revoke:{certificate_name}",
            )
        )
        status_code, _ = self._transport.request_json(
            "POST",
            f"{certificate_url}:revoke",
            json_body={
                "reason": "CESSATION_OF_OPERATION",
                "requestId": request_id,
            },
            accepted_statuses=(200, 404, 409),
        )
        if status_code == 404:
            return True
        if status_code == 409:
            _, reconciled = self._transport.request_json(
                "GET",
                certificate_url,
                accepted_statuses=(200,),
            )
            if reconciled.get("revocationDetails") is None:
                raise ProviderExecutionError(
                    "privateca-certificate-revoke-reconciliation-failed"
                )
        return True

    @staticmethod
    def _merge_binding(
        policy: dict[str, Any],
        role: str,
        members: list[str],
        condition: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        result = deepcopy(policy)
        # The read always requests v3. Keep that representation for every
        # write so unrelated conditional bindings cannot be collapsed into
        # synthetic roles/..._withcond_ names.
        result["version"] = 3
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

    @staticmethod
    def _validated_fresh_iam_policy(policy: object) -> dict[str, Any]:
        try:
            return validate_iam_policy_v3(policy, require_etag=True)
        except IamPolicyEtagMissingError as error:
            raise ProviderExecutionError("iam-policy-etag-missing") from error

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
        key = self._key(change)
        checkpoint = self._operation_checkpoint
        if (
            isinstance(checkpoint, dict)
            and checkpoint.get("kind") == "iam_policy_delta"
        ):
            if (
                checkpoint.get("current_url") != get_url
                or checkpoint.get("restore_url") != set_url
                or checkpoint.get("current_method") != get_method
            ):
                raise ProviderExecutionError("iam-operation-checkpoint-invalid")
            before_body = checkpoint.get("body")
            after_policy = checkpoint.get("after_policy")
            if (
                not isinstance(before_body, dict)
                or not isinstance(before_body.get("policy"), dict)
                or not isinstance(after_policy, dict)
            ):
                raise ProviderExecutionError("iam-operation-checkpoint-invalid")
            self._before[key] = deepcopy(checkpoint)
            self._ownership_metadata[key] = deepcopy(checkpoint)
            phase = checkpoint.get("phase")
            protocol_version = checkpoint.get("protocol_version")
            if phase == "applied":
                # This phase is written only after a definite successful HTTP
                # response. It is therefore safe to finish the local commit.
                return
            if phase == "sending" or (
                protocol_version != 3 and phase != "applied"
            ):
                # Equality with the intended policy is not proof of ownership:
                # the request may have been lost before Google received it and
                # an administrator may independently have added the same grant.
                raise ProviderExecutionError("iam-provider-response-ambiguous")
            if phase not in {"prepared", "rejected"}:
                raise ProviderExecutionError("iam-operation-checkpoint-invalid")

        for attempt in range(5):
            policy = self._validated_fresh_iam_policy(
                self._request(
                    get_method,
                    get_url,
                    params=(
                        {"options.requestedPolicyVersion": 3}
                        if get_method == "GET"
                        else None
                    ),
                    body=(
                        {"options": {"requestedPolicyVersion": 3}}
                        if get_method == "POST"
                        else None
                    ),
                )
            )
            policy["version"] = 3
            updated = validate_iam_policy_v3(
                self._merge_binding(policy, role, members, condition),
                require_etag=True,
            )
            # A prepared checkpoint proves that no request was in flight.
            # Refresh its exact before/managed-after pair from every freshly
            # read etag before sending, so a confirmed conflict retry retains
            # concurrent administrator edits and rollback owns only this delta.
            snapshot = {
                "kind": "iam_policy_delta",
                "protocol_version": 3,
                "phase": "prepared",
                "attempt": attempt + 1,
                "resource_key": key,
                "restore_url": set_url,
                "current_url": get_url,
                "current_method": get_method,
                "body": {"policy": deepcopy(policy)},
                "after_policy": deepcopy(updated),
            }
            self._save_checkpoint(snapshot)
            if updated == policy:
                self._save_checkpoint({**snapshot, "phase": "applied"})
                return
            self._save_checkpoint({**snapshot, "phase": "sending"})
            try:
                self._request("POST", set_url, body={"policy": updated})
            except GoogleApiError as error:
                # Only definitive client/etag rejections prove that Google did
                # not accept this write. Timeouts, throttling and 5xx responses
                # may be emitted after commit, so retain `sending` and its
                # active intent claim for fail-closed/manual reconciliation.
                if error.status_code in {400, 401, 403, 404, 409, 412}:
                    self._save_checkpoint({**snapshot, "phase": "rejected"})
                if self._is_confirmed_iam_etag_conflict(error) and attempt < 4:
                    time.sleep(max(self._poll_interval, 0.05) * (2**attempt))
                    continue
                raise
            self._save_checkpoint({**snapshot, "phase": "applied"})
            return

    def _restore_before(
        self,
        change: ResourceChange,
        _spec: DeploymentSpec | None,
    ) -> None:
        before = self._before.get(self._key(change))
        if not before:
            return
        rollback_checkpoint = before.get("rollback")
        if isinstance(rollback_checkpoint, dict):
            rollback_phase = rollback_checkpoint.get("phase")
            if rollback_phase == "applied":
                return
            if rollback_phase == "sending":
                raise ProviderExecutionError("iam-rollback-provider-response-ambiguous")
            if rollback_phase not in {"prepared", "rejected"}:
                raise ProviderExecutionError("iam-rollback-checkpoint-invalid")
        url = before.get("restore_url")
        method = before.get("restore_method", "POST")
        body = before.get("body")
        if isinstance(url, str) and isinstance(method, str) and isinstance(body, dict):
            for attempt in range(5):
                restore_body = deepcopy(body)
                rollback: dict[str, object] | None = None
                current_url = before.get("current_url")
                current_method = before.get("current_method", "POST")
                if (
                    isinstance(current_url, str)
                    and isinstance(current_method, str)
                    and isinstance(restore_body.get("policy"), dict)
                ):
                    current = self._validated_fresh_iam_policy(
                        self._request(
                            current_method,
                            current_url,
                            params=(
                                {"options.requestedPolicyVersion": 3}
                                if current_method == "GET"
                                else None
                            ),
                            body=(
                                {"options": {"requestedPolicyVersion": 3}}
                                if current_method == "POST"
                                else None
                            ),
                        )
                    )
                    before_policy = restore_body.get("policy")
                    after_policy = before.get("after_policy")
                    if not isinstance(after_policy, dict):
                        # Legacy snapshots cannot be restored safely: replacing
                        # the current policy would erase post-Apply IAM edits.
                        raise ProviderExecutionError(
                            "iam-restore-after-policy-missing"
                        )
                    restore_body["policy"] = revert_iam_policy_delta(
                        before_policy=before_policy,
                        after_policy=after_policy,
                        current_policy=current,
                    )
                    restore_body["policy"]["etag"] = current["etag"]
                    restore_body["policy"]["version"] = 3
                    restore_body["policy"] = validate_iam_policy_v3(
                        restore_body["policy"],
                        require_etag=True,
                    )
                    normalised_current = deepcopy(current)
                    normalised_current["version"] = 3
                    rollback = {
                        "phase": "prepared",
                        "attempt": attempt + 1,
                        "before_policy": deepcopy(current),
                        "after_policy": deepcopy(restore_body["policy"]),
                    }
                    self._save_checkpoint({**before, "rollback": rollback})
                    if restore_body["policy"] == normalised_current:
                        self._save_checkpoint(
                            {
                                **before,
                                "rollback": {**rollback, "phase": "applied"},
                            }
                        )
                        return
                    self._save_checkpoint(
                        {
                            **before,
                            "rollback": {**rollback, "phase": "sending"},
                        }
                    )
                try:
                    payload = self._request(method, url, body=restore_body)
                except GoogleApiError as error:
                    if (
                        rollback is not None
                        and 400 <= error.status_code < 500
                        and error.status_code not in {408, 429}
                    ):
                        self._save_checkpoint(
                            {
                                **before,
                                "rollback": {**rollback, "phase": "rejected"},
                            }
                        )
                    if not self._is_confirmed_iam_etag_conflict(error) or attempt == 4:
                        raise
                    time.sleep(max(self._poll_interval, 0.25) * (2**attempt))
                    continue
                if payload.get("name") or payload.get("selfLink"):
                    self._wait(
                        payload,
                        fallback_host=url.split("/", 3)[2],
                        mutation_url=url,
                    )
                if rollback is not None:
                    self._save_checkpoint(
                        {
                            **before,
                            "rollback": {**rollback, "phase": "applied"},
                        }
                    )
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
  '"role":"backend","method":"$request_method",'
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
        secret = (
            self._require_public_certificate_binding(spec).secret_version_name
            if spec.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED
            else (
                f"projects/{spec.project_id}/secrets/{self._tls_secret_name(spec)}/"
                "versions/active"
            )
        )
        package_setup = self._package_setup(spec)
        configuration_hash = canonical_configuration_hash(spec)
        pin_presented_chain = (
            spec.certificate_strategy is not CertificateStrategy.PUBLIC_TRUSTED
        )
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
  '"role":"offload","method":"$request_method",'
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
pin_presented_chain = {pin_presented_chain!r}
trust_mode = (
    "presented_chain_pinned" if pin_presented_chain else "public_system_roots"
)

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
    if pin_presented_chain:
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
        "trust_mode": trust_mode,
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

    def _assert_instance_boot_disk_image(
        self,
        spec: DeploymentSpec,
        *,
        instance_name: str,
        zone: str,
    ) -> None:
        binding = self._source_image_binding
        if binding is None or spec.source_image is None or binding.name != spec.source_image:
            raise ProviderExecutionError("source-image-binding-invalid")
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        instance_url = f"{base}/zones/{zone}/instances/{instance_name}"
        instance = self._request("GET", instance_url)
        disks = instance.get("disks")
        if not isinstance(disks, list) or len(disks) != 1 or not isinstance(disks[0], dict):
            raise ProviderExecutionError("instance-boot-disk-identity-invalid")
        attached = disks[0]
        expected_disk_url = f"{base}/zones/{zone}/disks/{instance_name}"
        source = attached.get("source")
        if (
            attached.get("boot") is not True
            or not isinstance(source, str)
            or self._canonical_compute_resource_uri(source)
            != self._canonical_compute_resource_uri(expected_disk_url)
        ):
            raise ProviderExecutionError("instance-boot-disk-identity-invalid")
        disk = self._request("GET", expected_disk_url)
        expected_source = f"https://www.googleapis.com/compute/v1/{spec.source_image}"
        if (
            disk.get("name") != instance_name
            or disk.get("status") != "READY"
            or str(disk.get("sourceImageId")) != binding.id
            or not isinstance(disk.get("sourceImage"), str)
            or self._canonical_compute_resource_uri(str(disk["sourceImage"]))
            != self._canonical_compute_resource_uri(expected_source)
        ):
            raise ProviderExecutionError("instance-boot-disk-identity-invalid")

    def _create_instance(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        if self._source_image_binding is not None:
            self._revalidate_source_image(spec)
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
        if (
            suffix == "offload"
            and spec.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED
        ):
            self._revalidate_public_certificate(spec)
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
            post_create=lambda: self._assert_instance_boot_disk_image(
                spec,
                instance_name=change.resource_name,
                zone=spec.zone,
            ),
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
                raise ProviderExecutionError("provider-operation-cleanup-failed") from cleanup_error
            raise

    def _create_instance_group(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        group_url = f"{base}/zones/{spec.zone}/instanceGroups/{change.resource_name}"
        self._create(
            change,
            url=f"{base}/zones/{spec.zone}/instanceGroups",
            body={
                "name": change.resource_name,
                "description": "Managed by Secure Gateway Studio",
                "namedPorts": [{"name": "http", "port": 80}],
            },
            fallback_host="compute.googleapis.com",
            delete_url=group_url,
        )
        target_instance = f"{base}/zones/{spec.zone}/instances/{spec.name}-backend"
        self._ensure_instance_group_membership(
            change,
            group_url=group_url,
            target_instance=target_instance,
        )

    @staticmethod
    def _canonical_compute_resource_uri(value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in {"compute.googleapis.com", "www.googleapis.com"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.query
            or parsed.fragment
            or not parsed.path.startswith("/compute/v1/projects/")
        ):
            raise ProviderExecutionError("compute-resource-uri-invalid")
        return f"https://www.googleapis.com{parsed.path}"

    def _list_instance_group_members(
        self,
        group_url: str,
    ) -> list[str]:
        members: list[str] = []
        page_token: str | None = None
        seen_tokens: set[str] = set()
        for _ in range(100):
            params: dict[str, str | int] = {"maxResults": 500}
            if page_token is not None:
                params["pageToken"] = page_token
            payload = self._request(
                "POST",
                f"{group_url}/listInstances",
                params=params,
                body={"instanceState": "ALL"},
            )
            items = payload.get("items", [])
            if not isinstance(items, list):
                raise ProviderExecutionError("instance-group-membership-response-invalid")
            for item in items:
                instance = item.get("instance") if isinstance(item, dict) else None
                if not isinstance(instance, str):
                    raise ProviderExecutionError("instance-group-membership-response-invalid")
                members.append(self._canonical_compute_resource_uri(instance))
                if len(members) > 1:
                    raise ProviderExecutionError(
                        "instance-group-membership-managed-state-changed"
                    )
            if "nextPageToken" not in payload or payload["nextPageToken"] == "":
                return members
            next_token = payload["nextPageToken"]
            if (
                not isinstance(next_token, str)
                or not next_token
                or next_token in seen_tokens
            ):
                raise ProviderExecutionError("instance-group-membership-response-invalid")
            seen_tokens.add(next_token)
            page_token = next_token
        raise ProviderExecutionError("instance-group-membership-pagination-limit-exceeded")

    def _ensure_instance_group_membership(
        self,
        change: ResourceChange,
        *,
        group_url: str,
        target_instance: str,
    ) -> None:
        checkpoint = self._operation_checkpoint
        if (
            not isinstance(checkpoint, dict)
            or checkpoint.get("kind") != "generic_created_resource"
            or checkpoint.get("phase") != "applied"
            or checkpoint.get("resource_key") != self._key(change)
            or checkpoint.get("resource_url") != group_url
        ):
            raise ProviderExecutionError("instance-group-membership-checkpoint-invalid")
        expected = {
            "kind": "instance_group_membership",
            "phase": "prepared",
            "group_url": group_url,
            "target_instance": target_instance,
            "request_id": self._external_request_id(
                f"instance-group-membership:{self._key(change)}"
            ),
        }
        membership = checkpoint.get("membership")
        if membership is None:
            membership = expected
            checkpoint = {**checkpoint, "membership": deepcopy(membership)}
            self._save_checkpoint(checkpoint)
        elif not isinstance(membership, dict) or any(
            membership.get(field) != value
            for field, value in expected.items()
            if field != "phase"
        ):
            raise ProviderExecutionError("instance-group-membership-checkpoint-invalid")
        else:
            membership = deepcopy(membership)

        canonical_target = self._canonical_compute_resource_uri(target_instance)
        phase = membership.get("phase")
        if phase in {"sending", "applied"}:
            current_members = self._list_instance_group_members(group_url)
            if current_members == [canonical_target]:
                if phase != "applied":
                    self._save_checkpoint(
                        {**checkpoint, "membership": {**membership, "phase": "applied"}}
                    )
                return
            if current_members:
                raise ProviderExecutionError(
                    "instance-group-membership-managed-state-changed"
                )
            if phase == "applied":
                raise ProviderExecutionError(
                    "instance-group-membership-managed-state-changed"
                )
        elif phase not in {"prepared", "rejected"}:
            raise ProviderExecutionError("instance-group-membership-checkpoint-invalid")

        sending = {**membership, "phase": "sending"}
        self._save_checkpoint({**checkpoint, "membership": sending})
        try:
            payload = self._request(
                "POST",
                f"{group_url}/addInstances",
                params={"requestId": str(membership["request_id"])},
                body={"instances": [{"instance": target_instance}]},
            )
        except GoogleApiError as error:
            if error.status_code in {400, 401, 403, 404, 409, 412}:
                self._save_checkpoint(
                    {**checkpoint, "membership": {**membership, "phase": "rejected"}}
                )
            raise
        self._wait(
            payload,
            fallback_host="compute.googleapis.com",
            mutation_url=f"{group_url}/addInstances",
        )
        if self._list_instance_group_members(group_url) != [canonical_target]:
            raise ProviderExecutionError("instance-group-membership-reconciliation-failed")
        self._save_checkpoint(
            {**checkpoint, "membership": {**membership, "phase": "applied"}}
        )

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
                        t01.get("status") == 200 and t01.get("configuration_hash") == expected_hash
                    )
                else:
                    t02 = evidence.get("T02", {})
                    t03 = evidence.get("T03", {})
                    subject_alt_names = t03.get("subject_alt_names")
                    ready = (
                        t02.get("status") == 200
                        and t02.get("configuration_hash") == expected_hash
                        and t03.get("http_status") == 200
                        and t03.get("configuration_hash") == expected_hash
                        and t03.get("hostname") == spec.private_hostname
                        and t03.get("tls_version") in {"TLSv1.2", "TLSv1.3"}
                        and isinstance(subject_alt_names, list)
                        and all(isinstance(name, str) for name in subject_alt_names)
                        and spec.private_hostname in subject_alt_names
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
        if spec.source_image is None:
            raise ProviderExecutionError("source-image-binding-invalid")
        return spec.source_image

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
        if self._source_image_binding is not None:
            self._revalidate_source_image(spec)
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        properties = self._offload_template_properties(spec)
        if spec.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED:
            self._revalidate_public_certificate(spec)
        self._create(
            change,
            url=f"{base}/global/instanceTemplates",
            body={
                "name": change.resource_name,
                "description": "Managed by Secure Gateway Studio",
                "properties": properties,
            },
            fallback_host="compute.googleapis.com",
            delete_url=f"{base}/global/instanceTemplates/{change.resource_name}",
        )

    def _create_health_check(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        if spec.backend_kind is BackendKind.INTERNAL_HTTPS_LB:
            check_body: dict[str, Any] = {
                "type": "HTTP",
                "httpHealthCheck": {
                    "portSpecification": "USE_SERVING_PORT",
                    "requestPath": "/",
                },
            }
        else:
            check_body = {"type": "SSL", "sslHealthCheck": {"port": 443}}
        self._create(
            change,
            url=f"{base}/regions/{spec.region}/healthChecks",
            body={
                "name": change.resource_name,
                **check_body,
                "checkIntervalSec": 10,
                "timeoutSec": 5,
                "healthyThreshold": 2,
                "unhealthyThreshold": 3,
            },
            fallback_host="compute.googleapis.com",
            delete_url=(f"{base}/regions/{spec.region}/healthChecks/{change.resource_name}"),
        )

    def _tls_material(self, spec: DeploymentSpec) -> tuple[str, str]:
        if spec.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED:
            self._require_public_certificate_binding(spec)
            if self._public_certificate_payload is None:
                raise ProviderExecutionError("public-certificate-not-revalidated")
            raw_document = self._public_certificate_payload
        elif self._certificate is not None:
            certificate = self._certificate.certificate_pem + b"".join(
                self._certificate.certificate_chain_pem
            )
            return (
                certificate.decode("ascii"),
                self._certificate.private_key_pem.decode("ascii"),
            )
        elif (
            self._public_certificate_payload is not None
            and self._public_certificate_configuration_hash
            == canonical_configuration_hash(spec)
        ):
            raw_document = self._public_certificate_payload
        else:
            payload = self._request(
                "GET",
                (
                    "https://secretmanager.googleapis.com/v1/projects/"
                    f"{spec.project_id}/secrets/{self._tls_secret_name(spec)}/"
                    "versions/active:access"
                ),
            )
            encoded = payload.get("payload", {}).get("data")
            if not isinstance(encoded, str):
                raise ValueError("TLS secret response is missing payload data")
            raw_document = base64.b64decode(encoded, validate=True)
        document = json.loads(raw_document)
        certificate_pem = document.get("certificate_pem")
        chain = document.get("certificate_chain_pem")
        private_key_pem = document.get("private_key_pem")
        if (
            not isinstance(certificate_pem, str)
            or not isinstance(private_key_pem, str)
            or not isinstance(chain, list)
            or not all(isinstance(item, str) for item in chain)
        ):
            raise ValueError("TLS secret payload does not match the required contract")
        return certificate_pem + "".join(chain), private_key_pem

    def _create_ssl_certificate(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        if spec.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED:
            self._revalidate_public_certificate(spec)
        certificate, private_key = self._tls_material(spec)
        self._create(
            change,
            url=f"{base}/regions/{spec.region}/sslCertificates",
            body={
                "name": change.resource_name,
                "description": (
                    "Managed by Secure Gateway Studio; certificate configuration "
                    f"{certificate_configuration_hash(spec)}"
                ),
                "certificate": certificate,
                "privateKey": private_key,
            },
            fallback_host="compute.googleapis.com",
            delete_url=(f"{base}/regions/{spec.region}/sslCertificates/{change.resource_name}"),
        )

    def _create_url_map(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        self._create(
            change,
            url=f"{base}/regions/{spec.region}/urlMaps",
            body={
                "name": change.resource_name,
                "defaultService": (
                    f"{base}/regions/{spec.region}/backendServices/{spec.name}-ilb-bs"
                ),
            },
            fallback_host="compute.googleapis.com",
            delete_url=f"{base}/regions/{spec.region}/urlMaps/{change.resource_name}",
        )

    def _create_target_https_proxy(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        self._create(
            change,
            url=f"{base}/regions/{spec.region}/targetHttpsProxies",
            body={
                "name": change.resource_name,
                "urlMap": f"{base}/regions/{spec.region}/urlMaps/{spec.name}-ilb-map",
                "sslCertificates": [
                    f"{base}/regions/{spec.region}/sslCertificates/{spec.name}-ilb-cert"
                ],
            },
            fallback_host="compute.googleapis.com",
            delete_url=(f"{base}/regions/{spec.region}/targetHttpsProxies/{change.resource_name}"),
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
                    "maxSurge": {"fixed": 2},
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
        self._assert_managed_instance_boot_disks(spec)

    def _assert_managed_instance_boot_disks(self, spec: DeploymentSpec) -> None:
        manager_url = (
            f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}/"
            f"regions/{spec.region}/instanceGroupManagers/{spec.name}-offload-mig"
        )
        instances: list[tuple[str, str]] = []
        page_token: str | None = None
        seen_tokens: set[str] = set()
        for _ in range(100):
            params: dict[str, str | int] = {"maxResults": 500}
            if page_token is not None:
                params["pageToken"] = page_token
            payload = self._request(
                "POST",
                f"{manager_url}/listManagedInstances",
                params=params,
            )
            items = payload.get("managedInstances", [])
            if not isinstance(items, list):
                raise ProviderExecutionError("managed-instance-list-invalid")
            for item in items:
                if not isinstance(item, dict) or item.get("instanceStatus") != "RUNNING":
                    raise ProviderExecutionError("managed-instance-list-invalid")
                instance = item.get("instance")
                if not isinstance(instance, str):
                    raise ProviderExecutionError("managed-instance-list-invalid")
                parsed = urlsplit(instance)
                match = re.fullmatch(
                    rf"/compute/v1/projects/{re.escape(spec.project_id)}/zones/"
                    rf"({re.escape(spec.region)}-[a-z])/instances/"
                    rf"({re.escape(spec.name)}-offload-[a-z0-9-]+)",
                    parsed.path,
                )
                if (
                    parsed.scheme != "https"
                    or parsed.hostname not in {"compute.googleapis.com", "www.googleapis.com"}
                    or parsed.username is not None
                    or parsed.password is not None
                    or parsed.port is not None
                    or parsed.query
                    or parsed.fragment
                    or match is None
                ):
                    raise ProviderExecutionError("managed-instance-list-invalid")
                zone, name = match.groups()
                if (
                    zone not in {spec.zone, spec.secondary_zone}
                    or not name.startswith(f"{spec.name}-offload-")
                    or (zone, name) in instances
                ):
                    raise ProviderExecutionError("managed-instance-list-invalid")
                instances.append((zone, name))
                if len(instances) > spec.offload_max_replicas:
                    raise ProviderExecutionError("managed-instance-list-invalid")
            if "nextPageToken" not in payload or payload["nextPageToken"] == "":
                break
            token = payload["nextPageToken"]
            if not isinstance(token, str) or not token or token in seen_tokens:
                raise ProviderExecutionError("managed-instance-list-invalid")
            seen_tokens.add(token)
            page_token = token
        else:
            raise ProviderExecutionError("managed-instance-list-pagination-limit-exceeded")
        if len(instances) < spec.offload_min_replicas:
            raise ProviderExecutionError("managed-instance-count-invalid")
        for zone, name in instances:
            self._assert_instance_boot_disk_image(
                spec,
                instance_name=name,
                zone=zone,
            )

    def _refresh_offload(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        self._perform_offload_refresh(change, spec)

    def _refresh_existing_offload(
        self,
        spec: DeploymentSpec,
        rollback_checkpoint: dict[str, object],
    ) -> None:
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
            self._perform_existing_offload_refresh(
                spec,
                rollback_checkpoint,
            )

    def _offload_refresh_checkpoint(
        self,
        change: ResourceChange,
        spec: DeploymentSpec,
    ) -> dict[str, object]:
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        production = spec.mode.value == "production"
        target_url = (
            f"{base}/regions/{spec.region}/instanceGroupManagers/{spec.name}-offload-mig"
            if production
            else f"{base}/zones/{spec.zone}/instances/{spec.name}-offload"
        )
        expected: dict[str, object] = {
            "kind": "offload_refresh",
            "protocol_version": 2,
            "phase": "prepared",
            "resource_key": self._key(change),
            "mode": spec.mode.value,
            "target_url": target_url,
            "stop_request_id": self._external_request_id(
                f"offload-refresh:{self._key(change)}:stop"
            ),
            "start_request_id": self._external_request_id(
                f"offload-refresh:{self._key(change)}:start"
            ),
        }
        checkpoint = self._operation_checkpoint
        if (
            isinstance(checkpoint, dict)
            and checkpoint.get("resource_key") != self._key(change)
            and self._operation is None
        ):
            checkpoint = None
        if checkpoint is None:
            self._save_checkpoint(expected)
            return deepcopy(self._operation_checkpoint or expected)
        if not isinstance(checkpoint, dict) or any(
            checkpoint.get(field) != value
            for field, value in expected.items()
            if field != "phase"
        ):
            raise ProviderExecutionError("offload-refresh-checkpoint-invalid")
        return deepcopy(checkpoint)

    def _perform_offload_refresh(
        self,
        change: ResourceChange,
        spec: DeploymentSpec,
    ) -> None:
        checkpoint = self._offload_refresh_checkpoint(change, spec)
        phase = checkpoint.get("phase")
        if spec.mode.value == "production":
            manager_url = str(checkpoint["target_url"])
            if phase == "applied":
                self._wait_for_manager_stable(spec)
                self._wait_for_healthy_backends(spec)
                return
            if phase == "update_sending":
                # This Compute method has no requestId field. A lost response
                # cannot be retried or inferred from an already-healthy MIG.
                raise ProviderExecutionError(
                    "offload-refresh-provider-response-ambiguous"
                )
            if phase == "update_rejected":
                raise ProviderExecutionError("offload-refresh-update-rejected")
            if phase != "prepared":
                raise ProviderExecutionError("offload-refresh-checkpoint-invalid")
            self._save_checkpoint({**checkpoint, "phase": "update_sending"})
            try:
                operation = self._request(
                    "POST",
                    f"{manager_url}/applyUpdatesToInstances",
                    body={
                        "allInstances": True,
                        "minimalAction": "RESTART",
                        "mostDisruptiveAllowedAction": "RESTART",
                    },
                )
            except GoogleApiError as error:
                if 400 <= error.status_code < 500 and error.status_code not in {408, 429}:
                    self._save_checkpoint(
                        {
                            **checkpoint,
                            "phase": "update_rejected",
                            "rejection_status": error.status_code,
                        }
                    )
                raise
            self._wait(
                operation,
                fallback_host="compute.googleapis.com",
                mutation_url=f"{manager_url}/applyUpdatesToInstances",
            )
            self._wait_for_manager_stable(spec)
            self._wait_for_healthy_backends(spec)
            self._save_checkpoint({**checkpoint, "phase": "applied"})
            return

        instance_url = str(checkpoint["target_url"])
        if phase == "applied":
            if self._instance_status(instance_url) != "RUNNING":
                raise ProviderExecutionError("offload-refresh-managed-state-changed")
            return
        if phase not in {
            "prepared",
            "stop_sending",
            "stopped",
            "start_sending",
        }:
            raise ProviderExecutionError("offload-refresh-checkpoint-invalid")

        if phase in {"prepared", "stop_sending"}:
            status = self._instance_status(instance_url) if phase == "stop_sending" else "RUNNING"
            if status != "TERMINATED":
                if status == "RUNNING":
                    self._save_checkpoint({**checkpoint, "phase": "stop_sending"})
                    stop = self._request(
                        "POST",
                        f"{instance_url}/stop",
                        params={
                            "discardLocalSsd": "false",
                            "requestId": str(checkpoint["stop_request_id"]),
                        },
                    )
                    self._wait(
                        stop,
                        fallback_host="compute.googleapis.com",
                        mutation_url=f"{instance_url}/stop",
                    )
                elif status not in {"STOPPING", "SUSPENDING"}:
                    raise ProviderExecutionError("offload-refresh-instance-status-invalid")
                self._wait_for_instance_status(instance_url, expected="TERMINATED")
            checkpoint = {**checkpoint, "phase": "stopped"}
            self._save_checkpoint(checkpoint)

        phase = checkpoint.get("phase")
        if phase in {"stopped", "start_sending"}:
            status = (
                self._instance_status(instance_url)
                if phase == "start_sending"
                else "TERMINATED"
            )
            if status != "RUNNING":
                if status == "TERMINATED":
                    self._save_checkpoint({**checkpoint, "phase": "start_sending"})
                    start = self._request(
                        "POST",
                        f"{instance_url}/start",
                        params={"requestId": str(checkpoint["start_request_id"])},
                    )
                    self._wait(
                        start,
                        fallback_host="compute.googleapis.com",
                        mutation_url=f"{instance_url}/start",
                    )
                elif status not in {"PROVISIONING", "STAGING"}:
                    raise ProviderExecutionError("offload-refresh-instance-status-invalid")
                self._wait_for_instance_status(instance_url, expected="RUNNING")
            self._save_checkpoint({**checkpoint, "phase": "applied"})

    def _instance_status(self, instance_url: str) -> str:
        status_code, payload = self._transport.request_json(
            "GET",
            instance_url,
            accepted_statuses=(200, 404),
        )
        status = payload.get("status") if status_code == 200 else None
        if not isinstance(status, str):
            raise ProviderExecutionError("offload-refresh-instance-status-invalid")
        return status

    def _wait_for_instance_status(self, instance_url: str, *, expected: str) -> None:
        deadline = time.monotonic() + self._operation_timeout
        while time.monotonic() < deadline:
            if self._instance_status(instance_url) == expected:
                return
            time.sleep(self._poll_interval)
        raise ProviderExecutionError("offload-refresh-instance-status-timeout")

    def _perform_existing_offload_refresh(
        self,
        spec: DeploymentSpec,
        rollback_checkpoint: dict[str, object],
    ) -> None:
        """Best-effort refresh used while compensating a secret-version mutation."""
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        if spec.mode.value == "production":
            manager_url = (
                f"{base}/regions/{spec.region}/instanceGroupManagers/{spec.name}-offload-mig"
            )
            refresh = rollback_checkpoint.get("offload_refresh_rollback")
            expected = {"phase": "prepared", "target_url": manager_url}
            if refresh is None:
                refresh = expected
                rollback_checkpoint = {
                    **rollback_checkpoint,
                    "offload_refresh_rollback": refresh,
                }
                self._save_checkpoint(rollback_checkpoint)
            if (
                not isinstance(refresh, dict)
                or refresh.get("target_url") != manager_url
                or refresh.get("phase")
                not in {"prepared", "sending", "rejected", "applied"}
            ):
                raise ProviderExecutionError(
                    "secret-version-rollback-refresh-checkpoint-invalid"
                )
            phase = refresh["phase"]
            if phase == "applied":
                return
            if phase == "sending":
                raise ProviderExecutionError(
                    "secret-version-rollback-refresh-outcome-ambiguous"
                )
            sending = {**refresh, "phase": "sending"}
            self._save_checkpoint(
                {
                    **rollback_checkpoint,
                    "offload_refresh_rollback": sending,
                }
            )
            try:
                operation = self._request(
                    "POST",
                    f"{manager_url}/applyUpdatesToInstances",
                    body={
                        "allInstances": True,
                        "minimalAction": "RESTART",
                        "mostDisruptiveAllowedAction": "RESTART",
                    },
                )
            except GoogleApiError as error:
                if 400 <= error.status_code < 500 and error.status_code not in {408, 429}:
                    self._save_checkpoint(
                        {
                            **rollback_checkpoint,
                            "offload_refresh_rollback": {
                                **refresh,
                                "phase": "rejected",
                                "rejection_status": error.status_code,
                            },
                        }
                    )
                raise
            self._wait(
                operation,
                fallback_host="compute.googleapis.com",
                mutation_url=f"{manager_url}/applyUpdatesToInstances",
            )
            self._wait_for_manager_stable(spec)
            self._wait_for_healthy_backends(spec)
            self._save_checkpoint(
                {
                    **rollback_checkpoint,
                    "offload_refresh_rollback": {**refresh, "phase": "applied"},
                }
            )
            return

        instance_url = f"{base}/zones/{spec.zone}/instances/{spec.name}-offload"
        stop_error: Exception | None = None
        try:
            stop = self._request(
                "POST",
                f"{instance_url}/stop",
                params={
                    "discardLocalSsd": "false",
                    "requestId": self._external_request_id(
                        "secret-version-rollback:stop"
                    ),
                },
            )
            self._wait(
                stop,
                fallback_host="compute.googleapis.com",
                mutation_url=f"{instance_url}/stop",
            )
        except Exception as error:
            stop_error = error
        status = self._instance_status(instance_url)
        if status != "RUNNING":
            if status not in {"TERMINATED", "STOPPING", "SUSPENDING"}:
                raise ProviderExecutionError("offload-refresh-instance-status-invalid")
            if status != "TERMINATED":
                self._wait_for_instance_status(instance_url, expected="TERMINATED")
            start = self._request(
                "POST",
                f"{instance_url}/start",
                params={
                    "requestId": self._external_request_id(
                        "secret-version-rollback:start"
                    )
                },
            )
            self._wait(
                start,
                fallback_host="compute.googleapis.com",
                mutation_url=f"{instance_url}/start",
            )
            self._wait_for_instance_status(instance_url, expected="RUNNING")
        if stop_error is not None:
            raise stop_error

    def _rollback_offload_refresh(
        self,
        _change: ResourceChange,
        spec: DeploymentSpec,
    ) -> None:
        checkpoint = self._operation_checkpoint
        if not isinstance(checkpoint, dict) or checkpoint.get("kind") != "offload_refresh":
            raise ProviderExecutionError("offload-refresh-checkpoint-invalid")
        phase = checkpoint.get("phase")
        if spec.mode.value == "production":
            if phase == "applied":
                self._wait_for_manager_stable(spec)
                self._wait_for_healthy_backends(spec)
                return
            if phase in {"prepared", "update_rejected"}:
                return
            if phase == "update_sending":
                raise ProviderExecutionError(
                    "offload-refresh-rollback-outcome-ambiguous"
                )
            raise ProviderExecutionError("offload-refresh-checkpoint-invalid")

        instance_url = checkpoint.get("target_url")
        start_request_id = checkpoint.get("start_request_id")
        if not isinstance(instance_url, str) or not isinstance(start_request_id, str):
            raise ProviderExecutionError("offload-refresh-checkpoint-invalid")
        valid_phases = {
            "prepared",
            "stop_sending",
            "stopped",
            "start_sending",
            "applied",
        }
        if phase not in valid_phases:
            raise ProviderExecutionError("offload-refresh-checkpoint-invalid")

        rollback_phase = checkpoint.get("rollback_phase")
        if rollback_phase is not None:
            if rollback_phase not in {"start_sending", "applied"}:
                raise ProviderExecutionError("offload-refresh-checkpoint-invalid")
            status = self._instance_status(instance_url)
            if rollback_phase == "applied":
                if status != "RUNNING":
                    raise ProviderExecutionError("offload-refresh-rollback-state-unsafe")
                return
            self._finish_offload_refresh_rollback_start(
                checkpoint,
                instance_url,
                start_request_id,
                status=status,
            )
            return

        # A lost stop response can precede the observable RUNNING -> STOPPING
        # transition.  Do not release rollback ownership after a single RUNNING
        # read: observe a short bounded stability window and restart with the
        # durable request ID if the accepted stop becomes visible.
        if phase == "stop_sending":
            for attempt in range(AMBIGUOUS_STOP_RECONCILIATION_POLLS):
                status = self._instance_status(instance_url)
                if status in {"STOPPING", "SUSPENDING"}:
                    self._wait_for_instance_status(instance_url, expected="TERMINATED")
                    status = "TERMINATED"
                if status == "TERMINATED":
                    self._finish_offload_refresh_rollback_start(
                        checkpoint,
                        instance_url,
                        start_request_id,
                        status=status,
                    )
                    return
                if status != "RUNNING":
                    raise ProviderExecutionError("offload-refresh-rollback-state-unsafe")
                if attempt + 1 < AMBIGUOUS_STOP_RECONCILIATION_POLLS:
                    time.sleep(self._poll_interval)
            raise ProviderExecutionError(
                "offload-refresh-rollback-outcome-ambiguous"
            )

        status = self._instance_status(instance_url)
        if status == "RUNNING":
            return
        if phase == "start_sending" and status in {"PROVISIONING", "STAGING"}:
            self._wait_for_instance_status(instance_url, expected="RUNNING")
            return
        if phase in {"stop_sending", "stopped", "start_sending"} and status == "TERMINATED":
            self._finish_offload_refresh_rollback_start(
                checkpoint,
                instance_url,
                start_request_id,
                status=status,
            )
            return
        if phase == "applied" and status == "RUNNING":
            return
        raise ProviderExecutionError("offload-refresh-rollback-state-unsafe")

    def _finish_offload_refresh_rollback_start(
        self,
        checkpoint: dict[str, object],
        instance_url: str,
        start_request_id: str,
        *,
        status: str,
    ) -> None:
        rollback_checkpoint = {**checkpoint, "rollback_phase": "start_sending"}
        self._save_checkpoint(rollback_checkpoint)
        if status == "TERMINATED":
            start = self._request(
                "POST",
                f"{instance_url}/start",
                params={"requestId": start_request_id},
            )
            self._wait(
                start,
                fallback_host="compute.googleapis.com",
                mutation_url=f"{instance_url}/start",
            )
        elif status not in {"RUNNING", "PROVISIONING", "STAGING"}:
            raise ProviderExecutionError("offload-refresh-rollback-state-unsafe")
        if status != "RUNNING":
            self._wait_for_instance_status(instance_url, expected="RUNNING")
        self._save_checkpoint({**checkpoint, "rollback_phase": "applied"})

    def _create_backend_service(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        resource_base = f"https://www.googleapis.com/compute/v1/projects/{spec.project_id}"
        if spec.backend_kind is BackendKind.INTERNAL_HTTPS_LB:
            protocol = "HTTP"
            scheme = "INTERNAL_MANAGED"
            health_check = f"{spec.name}-ilb-hc"
            group = (
                f"{resource_base}/zones/{spec.zone}/instanceGroups/{spec.name}-backend-ig"
            )
            backends = [{"group": group, "balancingMode": "UTILIZATION"}]
            port_name = "http"
        else:
            protocol = "TCP"
            scheme = "INTERNAL"
            health_check = f"{spec.name}-offload-hc"
            group = (
                f"{resource_base}/regions/{spec.region}/instanceGroups/{spec.name}-offload-mig"
            )
            backends = [{"group": group}]
            port_name = None
        body: dict[str, Any] = {
            "name": change.resource_name,
            "protocol": protocol,
            "loadBalancingScheme": scheme,
            "timeoutSec": 10,
            "healthChecks": [f"{base}/regions/{spec.region}/healthChecks/{health_check}"],
            "backends": backends,
        }
        if port_name is not None:
            body["portName"] = port_name
        self._create(
            change,
            url=f"{base}/regions/{spec.region}/backendServices",
            body=body,
            fallback_host="compute.googleapis.com",
            delete_url=(f"{base}/regions/{spec.region}/backendServices/{change.resource_name}"),
        )

    def _create_forwarding_rule(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        internal_application_lb = spec.backend_kind is BackendKind.INTERNAL_HTTPS_LB
        body: dict[str, Any] = {
            "name": change.resource_name,
            "IPAddress": self._address(spec, "offload"),
            "IPProtocol": "TCP",
            "ports": ["443"],
            "loadBalancingScheme": ("INTERNAL_MANAGED" if internal_application_lb else "INTERNAL"),
            "allowGlobalAccess": True,
            "network": f"{base}/global/networks/{self._network_name(spec)}",
            "subnetwork": (f"{base}/regions/{spec.region}/subnetworks/{self._subnet_name(spec)}"),
        }
        if internal_application_lb:
            body["target"] = (
                f"{base}/regions/{spec.region}/targetHttpsProxies/{spec.name}-ilb-proxy"
            )
            body["networkTier"] = "PREMIUM"
        else:
            body["backendService"] = (
                f"{base}/regions/{spec.region}/backendServices/{spec.name}-offload-bs"
            )
        self._create(
            change,
            url=f"{base}/regions/{spec.region}/forwardingRules",
            body=body,
            fallback_host="compute.googleapis.com",
            delete_url=(f"{base}/regions/{spec.region}/forwardingRules/{change.resource_name}"),
        )
        self._wait_for_healthy_backends(spec)

    def _wait_for_healthy_backends(self, spec: DeploymentSpec) -> None:
        base = f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}"
        resource_base = f"https://www.googleapis.com/compute/v1/projects/{spec.project_id}"
        internal_application_lb = spec.backend_kind is BackendKind.INTERNAL_HTTPS_LB
        service_name = (
            f"{spec.name}-ilb-bs" if internal_application_lb else f"{spec.name}-offload-bs"
        )
        url = f"{base}/regions/{spec.region}/backendServices/{service_name}/getHealth"
        group = (
            f"{resource_base}/zones/{spec.zone}/instanceGroups/{spec.name}-backend-ig"
            if internal_application_lb
            else (
                f"{resource_base}/regions/{spec.region}/instanceGroups/{spec.name}-offload-mig"
            )
        )
        deadline = time.monotonic() + self._operation_timeout
        while time.monotonic() < deadline:
            payload = self._request("POST", url, body={"group": group})
            statuses = payload.get("healthStatus", [])
            healthy = [
                status
                for status in statuses
                if isinstance(status, dict) and status.get("healthState") == "HEALTHY"
            ]
            required_healthy = 1 if internal_application_lb else spec.offload_min_replicas
            if len(healthy) >= required_healthy:
                return
            time.sleep(self._poll_interval)
        raise ProviderExecutionError("offload-backends-not-healthy")

    def _create_firewall(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        network = (
            f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}/"
            f"global/networks/{self._network_name(spec)}"
        )
        internal_application_lb = spec.backend_kind is BackendKind.INTERNAL_HTTPS_LB
        target_role = "backend" if internal_application_lb else "offload"
        body: dict[str, Any] = {
            "name": change.resource_name,
            "network": network,
            "direction": "INGRESS",
            "priority": 1000,
            "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}],
            "targetServiceAccounts": [
                service_account_email(spec.name, spec.project_id, target_role)
            ],
            "logConfig": {"enable": True, "metadata": "INCLUDE_ALL_METADATA"},
        }
        if change.resource_name.endswith("ilb-proxy-ingress"):
            body["allowed"][0]["ports"] = ["80"]
            body["sourceRanges"] = [spec.proxy_subnet_cidr]
        elif change.resource_name.endswith("ilb-health-ingress"):
            body["allowed"][0]["ports"] = ["80"]
            body["sourceRanges"] = ["35.191.0.0/16", "130.211.0.0/22"]
        elif change.resource_name.endswith("gateway-ingress"):
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
        resource_url = f"{base}/managedZones/{change.resource_name}"
        token = self._ownership_token(change)
        marker = f"Secure Gateway Studio ownership-token={token}"
        checkpoint = self._named_resource_checkpoint(
            change,
            resource_kind="dns_private_zone",
            resource_url=resource_url,
            marker=marker,
        )
        expected_network = (
            f"https://www.googleapis.com/compute/v1/projects/"
            f"{spec.project_id}/global/networks/{self._network_name(spec)}"
        )
        reconciled: dict[str, Any] = {}

        def reconcile() -> bool:
            status_code, current = self._transport.request_json(
                "GET", resource_url, accepted_statuses=(200, 404)
            )
            reconciled.update(current)
            visibility = current.get("privateVisibilityConfig")
            networks = visibility.get("networks") if isinstance(visibility, dict) else None
            return (
                status_code == 200
                and current.get("name") == change.resource_name
                and current.get("description") == marker
                and current.get("dnsName") == f"{spec.private_hostname}."
                and current.get("visibility") == "private"
                and isinstance(networks, list)
                and len(networks) == 1
                and isinstance(networks[0], dict)
                and networks[0].get("networkUrl") == expected_network
            )

        created = self._create(
            change,
            url=f"{base}/managedZones",
            body={
                "name": change.resource_name,
                "dnsName": f"{spec.private_hostname}.",
                "description": marker,
                "visibility": "private",
                "privateVisibilityConfig": {
                    "networks": [{"networkUrl": expected_network}]
                },
            },
            fallback_host="dns.googleapis.com",
            delete_url=resource_url,
            reconcile=reconcile,
        )
        identity = created.get("id") or reconciled.get("id")
        self._save_checkpoint(
            {
                **checkpoint,
                "phase": "applied",
                **({"provider_identity": str(identity)} if identity is not None else {}),
            }
        )

    def _create_dns_record(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        zone = f"{spec.name}-zone"
        url = (
            f"https://dns.googleapis.com/dns/v1/projects/{spec.project_id}/"
            f"managedZones/{zone}/changes"
        )
        address = self._address(spec, "offload")
        record: dict[str, object] = {
            "name": f"{spec.private_hostname}.",
            "type": "A",
            "ttl": 60,
            "rrdatas": [address],
        }
        token = self._ownership_token(change)
        marker_name = f"_sgs-owner.{spec.private_hostname}."
        marker = f'"sgs-owner={token}"'
        owner_record: dict[str, object] = {
            "name": marker_name,
            "type": "TXT",
            "ttl": 60,
            "rrdatas": [marker],
        }
        resource_url = url.removesuffix("/changes")
        checkpoint = self._named_resource_checkpoint(
            change,
            resource_kind="dns_record_set",
            resource_url=resource_url,
            marker=marker,
            record_name=record["name"],
            record_address=address,
            marker_name=marker_name,
        )
        phase = checkpoint.get("phase")

        def reconcile_records() -> bool:
            record_status, existing = self._transport.request_json(
                "GET",
                f"{resource_url}/rrsets/{quote(str(record['name']), safe='')}/A",
                accepted_statuses=(200, 404),
            )
            owner_status, existing_owner = self._transport.request_json(
                "GET",
                f"{resource_url}/rrsets/{quote(marker_name, safe='')}/TXT",
                accepted_statuses=(200, 404),
            )
            return (
                record_status == 200
                and owner_status == 200
                and self._dns_record_matches(existing, record)
                and self._dns_record_matches(existing_owner, owner_record)
            )

        if phase == "applied":
            if not reconcile_records():
                raise ProviderExecutionError("named-resource-managed-state-changed")
            self._created.add(self._key(change))
            return
        if phase == "sending":
            if not reconcile_records():
                raise ProviderExecutionError(
                    "named-resource-provider-response-ambiguous"
                )
            self._created.add(self._key(change))
            self._save_checkpoint({
                **checkpoint,
                "phase": "applied",
                "delete_url": url,
                "dns_record": record,
                "dns_owner_record": owner_record,
            })
            return
        if phase not in {"prepared", "rejected"}:
            raise ProviderExecutionError(
                "named-resource-ownership-checkpoint-invalid"
            )
        self._save_checkpoint({**checkpoint, "phase": "sending"})
        try:
            status_code, response = self._transport.request_json(
                "POST",
                url,
                params={"clientOperationId": token},
                json_body={"additions": [record, owner_record]},
                accepted_statuses=(200, 409),
            )
        except GoogleApiError as error:
            if error.status_code in {400, 401, 403, 404, 409, 412}:
                self._save_checkpoint({**checkpoint, "phase": "rejected"})
            raise
        if status_code == 200:
            self._wait_for_dns_change(response, collection_url=url)
        if status_code == 409 and not reconcile_records():
            raise ProviderExecutionError("named-resource-reconciliation-failed")
        self._created.add(self._key(change))
        self._save_checkpoint({
            **checkpoint,
            "phase": "applied",
            "delete_url": url,
            "dns_record": record,
            "dns_owner_record": owner_record,
        })

    def _delete_dns_record(self, change: ResourceChange, _spec: DeploymentSpec) -> None:
        key = self._key(change)
        before = self._before.get(key) or {}
        if key not in self._created and before.get("kind") != (
            "named_resource_ownership"
        ):
            return
        if before.get("kind") != "named_resource_ownership":
            raise ProviderExecutionError("named-resource-ownership-checkpoint-invalid")
        phase = before.get("phase")
        if phase in {"prepared", "rejected"}:
            return
        if phase not in {"sending", "applied"}:
            raise ProviderExecutionError(
                "named-resource-ownership-checkpoint-invalid"
            )
        if phase == "sending":
            fqdn = before.get("record_name")
            marker_name = before.get("marker_name")
            resource_url = before.get("resource_url")
            if (
                not isinstance(fqdn, str)
                or not isinstance(marker_name, str)
                or not isinstance(resource_url, str)
            ):
                raise ProviderExecutionError(
                    "named-resource-ownership-checkpoint-invalid"
                )
            record_status, _ = self._transport.request_json(
                "GET",
                f"{resource_url}/rrsets/{quote(fqdn, safe='')}/A",
                accepted_statuses=(200, 404),
            )
            owner_status, _ = self._transport.request_json(
                "GET",
                f"{resource_url}/rrsets/{quote(marker_name, safe='')}/TXT",
                accepted_statuses=(200, 404),
            )
            if record_status == 404 and owner_status == 404:
                raise ProviderExecutionError(
                    "named-resource-provider-response-ambiguous"
                )
        outcome = self._destroy_named_owned_resource(change, _spec, before)
        if outcome != "deleted":
            raise ProviderExecutionError("named-resource-managed-state-changed")
        self._created.discard(key)

    def _create_gateway(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        parent = (
            f"https://beyondcorp.googleapis.com/v1/projects/{spec.project_id}/"
            "locations/global/securityGateways"
        )
        self._create(
            change,
            url=parent,
            params={"securityGatewayId": change.resource_name},
            # The official Private Web Apps task guide prescribes this empty
            # message as the Service Discovery enablement marker for REST/gcloud.
            body={
                "displayName": change.resource_name,
                "serviceDiscovery": {},
                # Current LoggingConfig is an empty enablement marker.
                "logging": {},
            },
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
        # The binding belongs to the project that owns the upstream VPC, which
        # is not necessarily the deployment project. The guide's worked example
        # separates the two.
        resource = (
            f"https://cloudresourcemanager.googleapis.com/v1/projects/{spec.upstream_project_id}"
        )
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
                    f"projects/{spec.upstream_project_id}/global/networks/"
                    f"{self._network_name(spec)}"
                )
            }
        }
        if spec.backend_kind is BackendKind.DIRECT_HTTPS and spec.application_egress_region:
            upstream["egressPolicy"] = {"regions": [spec.application_egress_region]}
        self._create(
            change,
            url=parent,
            params={"applicationId": change.resource_name},
            body={
                "displayName": change.resource_name,
                "endpointMatchers": [
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

    def _assert_target_ou_is_non_root(self, spec: DeploymentSpec) -> None:
        payload = self._request(
            "GET",
            (
                "https://admin.googleapis.com/admin/directory/v1/customer/"
                f"{spec.customer_id}/orgunits/{quote(f'id:{spec.target_ou_id}', safe='')}"
            ),
        )
        raw_id = payload.get("orgUnitId")
        path = payload.get("orgUnitPath")
        if (
            not isinstance(raw_id, str)
            or raw_id.removeprefix("id:") != spec.target_ou_id
            or not isinstance(path, str)
            or not path.startswith("/")
            or path == "/"
        ):
            raise ProviderExecutionError("chrome-policy-target-ou-invalid")

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
        app_key: str | None,
        app_id: str | None,
    ) -> dict[str, Any] | None:
        target = self._chrome_policy_target(spec, app_key, app_id)
        payload = self._list_resolved_chrome_policies(
            spec,
            schema_name=schema_name,
            target=target,
        )
        policies = self._validated_chrome_resolved_policies(
            payload,
            schema_name=schema_name,
            requested_target=target,
        )
        direct = [
            value
            for source, value in policies
            if source == f"orgunits/{spec.target_ou_id}"
        ]
        if len(direct) > 1:
            raise ProviderExecutionError("chrome-policy-direct-policy-duplicate")
        return deepcopy(direct[0]) if direct else None

    def _list_resolved_chrome_policies(
        self,
        spec: DeploymentSpec,
        *,
        schema_name: str,
        target: dict[str, Any],
    ) -> dict[str, Any]:
        policies: list[Any] = []
        seen_tokens: set[str] = set()
        page_token: str | None = None
        for page in range(20):
            body: dict[str, Any] = {
                "policyTargetKey": target,
                "policySchemaFilter": schema_name,
                "pageSize": 1_000,
            }
            if page_token is not None:
                body["pageToken"] = page_token
            payload = self._request(
                "POST",
                (
                    "https://chromepolicy.googleapis.com/v1/customers/"
                    f"{spec.customer_id}/policies:resolve"
                ),
                body=body,
            )
            page_policies = payload.get("resolvedPolicies")
            if not isinstance(page_policies, list) or any(
                not isinstance(item, dict) for item in page_policies
            ):
                raise ProviderExecutionError("chrome-policy-resolve-response-invalid")
            policies.extend(page_policies)
            if len(policies) > 2_000:
                raise ProviderExecutionError("chrome-policy-resolve-item-limit")
            if "nextPageToken" not in payload or payload["nextPageToken"] == "":
                return {"resolvedPolicies": policies}
            next_token = payload["nextPageToken"]
            if not isinstance(next_token, str) or next_token in seen_tokens:
                raise ProviderExecutionError("chrome-policy-resolve-page-token-invalid")
            seen_tokens.add(next_token)
            if page + 1 >= 20:
                raise ProviderExecutionError("chrome-policy-resolve-pagination-incomplete")
            page_token = next_token
        raise ProviderExecutionError("chrome-policy-resolve-pagination-incomplete")

    @staticmethod
    def _validated_chrome_resolved_policies(
        payload: dict[str, Any],
        *,
        schema_name: str,
        requested_target: dict[str, Any],
    ) -> list[tuple[str | None, dict[str, Any]]]:
        policies = payload.get("resolvedPolicies")
        if not isinstance(policies, list):
            raise ProviderExecutionError("chrome-policy-resolve-response-invalid")
        validated: list[tuple[str | None, dict[str, Any]]] = []
        for policy in policies:
            if not isinstance(policy, dict):
                raise ProviderExecutionError("chrome-policy-resolve-response-invalid")
            if policy.get("targetKey") != requested_target:
                raise ProviderExecutionError("chrome-policy-resolve-response-invalid")
            source = (
                GoogleResourceExecutor._validated_chrome_policy_source_key(
                    policy["sourceKey"]
                )
                if "sourceKey" in policy
                else None
            )
            added_source = None
            if "addedSourceKey" in policy:
                added_source = GoogleResourceExecutor._validated_chrome_policy_source_key(
                    policy["addedSourceKey"]
                )
            expected_source_kind = requested_target["targetResource"].partition("/")[0] + "/"
            if (
                (source is not None and not source.startswith(expected_source_kind))
                or (
                    added_source is not None
                    and not added_source.startswith(expected_source_kind)
                )
            ):
                raise ProviderExecutionError("chrome-policy-resolve-response-invalid")
            policy_value = policy.get("value")
            if (
                not isinstance(policy_value, dict)
                or policy_value.get("policySchema") != schema_name
                or not isinstance(policy_value.get("value"), dict)
            ):
                raise ProviderExecutionError("chrome-policy-resolve-response-invalid")
            validated.append((source, deepcopy(policy_value)))
        return validated

    @staticmethod
    def _validated_chrome_policy_source_key(value: Any) -> str:
        if not isinstance(value, dict) or not set(value) <= {
            "targetResource",
            "additionalTargetKeys",
        }:
            raise ProviderExecutionError("chrome-policy-resolve-response-invalid")
        source = value.get("targetResource")
        if (
            not isinstance(source, str)
            or re.fullmatch(r"(?:orgunits|groups)/[A-Za-z0-9_-]+", source) is None
        ):
            raise ProviderExecutionError("chrome-policy-resolve-response-invalid")
        if "additionalTargetKeys" in value:
            additional = value["additionalTargetKeys"]
            if not isinstance(additional, dict) or additional:
                raise ProviderExecutionError("chrome-policy-resolve-response-invalid")
        return source

    @staticmethod
    def _chrome_policy_target(
        spec: DeploymentSpec,
        app_key: str | None,
        app_id: str | None,
    ) -> dict[str, Any]:
        target: dict[str, Any] = {
            "targetResource": f"orgunits/{spec.target_ou_id}",
        }
        if app_key is not None or app_id is not None:
            if not isinstance(app_key, str) or not isinstance(app_id, str):
                raise ProviderExecutionError("chrome-policy-target-invalid")
            target["additionalTargetKeys"] = {app_key: f"chrome:{app_id}"}
        return target

    @staticmethod
    def _chrome_policy_fields(
        policy: dict[str, Any] | None,
        schema_name: str,
    ) -> dict[str, Any]:
        if policy is None:
            return {}
        if policy.get("policySchema") not in {None, schema_name}:
            raise ProviderExecutionError("chrome-policy-managed-state-invalid")
        fields = policy.get("value")
        if not isinstance(fields, dict):
            raise ProviderExecutionError("chrome-policy-managed-state-invalid")
        return deepcopy(fields)

    def _set_chrome_policy(
        self,
        change: ResourceChange,
        spec: DeploymentSpec,
        *,
        schema_name: str,
        field: str,
        value: Any,
        app_id: str | None = EXTENSION_ID,
    ) -> None:
        schema = self._chrome_schema(spec, schema_name)
        app_key = self._schema_target_key(schema) if app_id is not None else None
        self._assert_schema_field(schema, field)
        key = self._key(change)
        target = self._chrome_policy_target(spec, app_key, app_id)
        checkpoint = self._operation_checkpoint
        if isinstance(checkpoint, dict) and checkpoint.get("kind") == (
            "chrome_policy_delta"
        ):
            if (
                checkpoint.get("protocol_version") != 2
                or checkpoint.get("schema") != schema_name
                or checkpoint.get("field") != field
                or checkpoint.get("managed_after") != value
                or checkpoint.get("target") != target
                or checkpoint.get("customer_id") != spec.customer_id
            ):
                raise ProviderExecutionError("chrome-policy-operation-checkpoint-invalid")
            phase = checkpoint.get("phase")
            if phase == "applied":
                current = self._resolve_chrome_policy(
                    spec, schema_name, app_key, app_id
                )
                current_fields = self._chrome_policy_fields(current, schema_name)
                if current_fields.get(field) != value:
                    raise ProviderExecutionError("chrome-policy-managed-state-changed")
                return
            if phase == "sending":
                # Chrome Policy has no idempotency token. Equality with the
                # intended value after a lost response is not proof that SGS
                # wrote it rather than an administrator.
                raise ProviderExecutionError("chrome-policy-provider-response-ambiguous")
            if phase not in {"prepared", "rejected"}:
                raise ProviderExecutionError("chrome-policy-operation-checkpoint-invalid")

        previous = self._resolve_chrome_policy(spec, schema_name, app_key, app_id)
        previous_fields = self._chrome_policy_fields(previous, schema_name)
        snapshot: dict[str, object] = {
            "kind": "chrome_policy_delta",
            "protocol_version": 2,
            "phase": "prepared",
            "resource_key": key,
            "schema": schema_name,
            "field": field,
            "target": target,
            "customer_id": spec.customer_id,
            "app_key": app_key,
            "app_id": app_id,
            "previous_field_present": field in previous_fields,
            "previous_field": deepcopy(previous_fields.get(field)),
            "previous_direct_fields": previous_fields,
            "managed_after": deepcopy(value),
        }
        self._save_checkpoint(snapshot)
        self._save_checkpoint({**snapshot, "phase": "sending"})
        try:
            self._request(
                "POST",
                (
                    f"https://chromepolicy.googleapis.com/v1/customers/{spec.customer_id}/"
                    "policies/orgunits:batchModify"
                ),
                body={
                    "requests": [
                        {
                            "policyTargetKey": target,
                            "policyValue": {
                                "policySchema": schema_name,
                                "value": {field: value},
                            },
                            "updateMask": field,
                        }
                    ]
                },
            )
        except GoogleApiError as error:
            if error.status_code in {400, 401, 403, 404, 409, 412}:
                self._save_checkpoint({**snapshot, "phase": "rejected"})
            raise
        self._save_checkpoint({**snapshot, "phase": "applied"})

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
        target = {
            "targetResource": f"orgunits/{spec.target_ou_id}",
        }
        payload = self._list_resolved_chrome_policies(
            spec,
            schema_name=schema_name,
            target=target,
        )
        policies = self._validated_chrome_resolved_policies(
            payload,
            schema_name=schema_name,
            requested_target=target,
        )
        direct = [
            value
            for source, value in policies
            if source == f"orgunits/{spec.target_ou_id}"
        ]
        if len(direct) > 1:
            raise ProviderExecutionError("chrome-policy-direct-policy-duplicate")
        return deepcopy(direct[0]) if direct else None

    def _set_service_discovery_proxy(
        self,
        change: ResourceChange,
        spec: DeploymentSpec,
    ) -> None:
        self._set_chrome_policy(
            change,
            spec,
            schema_name="chrome.users.SimpleProxySettings",
            field="simpleProxyMode",
            value="PROXY_MODE_ENUM_USER_CONFIGURED",
            app_id=None,
        )

    def _export_root_certificate(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        if spec.certificate_strategy is not CertificateStrategy.LOCAL_POC:
            raise ProviderExecutionError("root-certificate-requires-local-poc")
        raw_payload = self._public_certificate_payload
        if raw_payload is None and self._certificate is not None:
            raw_payload = self._certificate.secret_payload()
        if raw_payload is None:
            secret_name = self._tls_secret_name(spec)
            checkpoint = self._ownership_metadata.get(
                f"secretmanager:secret_version:{secret_name}"
            )
            version_name = checkpoint.get("version_name") if isinstance(checkpoint, dict) else None
            payload_sha256 = (
                checkpoint.get("payload_sha256") if isinstance(checkpoint, dict) else None
            )
            if not isinstance(version_name, str) or not isinstance(payload_sha256, str):
                raise ProviderExecutionError("root-certificate-version-binding-missing")
            try:
                binding = PublicCertificateBinding(
                    secret_version_name=version_name,
                    payload_sha256=payload_sha256,
                )
                envelope = self._request(
                    "GET",
                    f"https://secretmanager.googleapis.com/v1/{version_name}:access",
                )
                raw_payload = self._decode_bound_certificate_payload(envelope, binding, spec)
                ownership_token = checkpoint.get("ownership_token")
                document = json.loads(raw_payload)
                if (
                    not isinstance(ownership_token, str)
                    or not isinstance(document, dict)
                    or document.get("sgs_ownership_token") != ownership_token
                ):
                    raise ValueError("The active certificate ownership marker changed")
            except (GoogleApiError, ValueError, TypeError, binascii.Error) as error:
                raise ProviderExecutionError("root-certificate-version-binding-invalid") from error
        try:
            CertificateIssuer.validate_secret_payload(
                raw_payload,
                hostname=spec.private_hostname,
                minimum_validity_days=1,
            )
            document = json.loads(raw_payload)
            chain = document.get("certificate_chain_pem") if isinstance(document, dict) else None
            if not isinstance(chain, list) or len(chain) != 1 or not isinstance(chain[0], str):
                raise ValueError("Local PoC certificate chain is missing its root")
            root_pem = chain[0].encode("ascii")
        except (UnicodeEncodeError, ValueError, TypeError, json.JSONDecodeError) as error:
            raise ProviderExecutionError("root-certificate-payload-invalid") from error
        self._artifact_store.write_root_certificate(spec.name, root_pem)
        self._created.add(self._key(change))

    def _remove_root_certificate_artifact(
        self, change: ResourceChange, spec: DeploymentSpec
    ) -> None:
        key = self._key(change)
        if key not in self._created:
            return
        # This fixed deployment path can be overwritten by a newer run before
        # an older run rolls back. Without a durable run-bound digest, deletion
        # cannot prove it still owns the bytes currently on disk. The artifact
        # contains only a public certificate, so conservative retention is the
        # safe rollback behavior.
        self._created.discard(key)

    def _restore_chrome_policy(self, change: ResourceChange, spec: DeploymentSpec) -> None:
        before = self._before.get(self._key(change)) or self._ownership_metadata.get(
            self._key(change)
        )
        if not isinstance(before, dict) or before.get("kind") != "chrome_policy_delta":
            raise ProviderExecutionError("chrome-policy-ownership-metadata-missing")
        if before.get("protocol_version") != 2:
            raise ProviderExecutionError("chrome-policy-ownership-metadata-invalid")
        phase = before.get("phase")
        if phase in {"prepared", "rejected"}:
            return
        if phase != "applied":
            raise ProviderExecutionError("chrome-policy-provider-response-ambiguous")
        schema = before.get("schema")
        field = before.get("field")
        target = before.get("target")
        app_key = before.get("app_key")
        app_id = before.get("app_id")
        managed_after = before.get("managed_after")
        if (
            not isinstance(schema, str)
            or not isinstance(field, str)
            or not isinstance(target, dict)
            or target != self._chrome_policy_target(
                spec,
                app_key if isinstance(app_key, str) else None,
                app_id if isinstance(app_id, str) else None,
            )
            or before.get("customer_id") != spec.customer_id
        ):
            raise ProviderExecutionError("chrome-policy-ownership-metadata-invalid")
        current = self._resolve_chrome_policy(
            spec,
            schema,
            app_key if isinstance(app_key, str) else None,
            app_id if isinstance(app_id, str) else None,
        )
        current_fields = self._chrome_policy_fields(current, schema)
        if field not in current_fields or current_fields[field] != managed_after:
            raise ProviderExecutionError("chrome-policy-managed-state-changed")
        base = (
            f"https://chromepolicy.googleapis.com/v1/customers/{spec.customer_id}/policies/orgunits"
        )
        if before.get("previous_field_present") is True:
            self._request(
                "POST",
                f"{base}:batchModify",
                body={
                    "requests": [
                        {
                            "policyTargetKey": target,
                            "policyValue": {
                                "policySchema": schema,
                                "value": {
                                    field: deepcopy(before.get("previous_field")),
                                },
                            },
                            "updateMask": field,
                        }
                    ]
                },
            )
        else:
            previous_fields = before.get("previous_direct_fields")
            if not isinstance(previous_fields, dict) or previous_fields:
                # batchInherit clears the whole direct schema. It is safe only
                # when SGS created the sole direct field and no administrator
                # has since added another direct field.
                raise ProviderExecutionError("chrome-policy-field-inherit-unsafe")
            if set(current_fields) != {field}:
                raise ProviderExecutionError("chrome-policy-field-inherit-unsafe")
            self._request(
                "POST",
                f"{base}:batchInherit",
                body={"requests": [{"policyTargetKey": target, "policySchema": schema}]},
            )


def render_startup_script_for_discovery(
    transport: JsonTransport,
    spec: DeploymentSpec,
    *,
    role: str,
    public_certificate_binding: PublicCertificateBinding | None = None,
) -> str:
    """Render the exact privileged startup script expected by discovery."""
    executor = GoogleResourceExecutor(transport, poll_interval_seconds=0)
    executor._public_certificate_binding = public_certificate_binding
    if role == "backend":
        return executor._backend_startup_script(spec)
    if role == "offload":
        return executor._offload_startup_script(spec)
    raise ValueError("Unknown managed VM role")


def create_google_resource_executor(
    *,
    artifact_store: CertificateArtifactStore | None = None,
    pin_path: Path | None = None,
) -> GoogleResourceExecutor:
    try:
        transport = GoogleAuthorizedTransport.from_adc(require_impersonation=True)
    except (DefaultCredentialsError, RefreshError) as error:
        raise RuntimeError("Application Default Credentials are unavailable for Apply.") from error
    authorizer = MutationIdentityAuthorizer(
        transport,
        pin_path=(
            pin_path
            if pin_path is not None
            else Path.cwd() / ".local" / "secure-gateway-bootstrap-pins.json"
        ),
    )
    return GoogleResourceExecutor(
        transport,
        artifact_store=artifact_store,
        mutation_authorizer=authorizer,
    )
