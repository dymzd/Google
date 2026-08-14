from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

ResourceName = Annotated[
    str,
    StringConstraints(
        pattern=r"^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$",
        strip_whitespace=True,
    ),
]


class DeploymentMode(StrEnum):
    POC = "poc"
    PRODUCTION = "production"


class ProductLocale(StrEnum):
    ENGLISH = "en"
    JAPANESE = "ja"


class ChromePlatform(StrEnum):
    MACOS = "macos"
    WINDOWS = "windows"
    LINUX = "linux"
    CHROMEOS = "chromeos"


class NetworkStrategy(StrEnum):
    DEDICATED = "dedicated"
    EXISTING = "existing"


class CertificateStrategy(StrEnum):
    ENTERPRISE_CA = "enterprise_ca"
    PUBLIC_TRUSTED = "public_trusted"
    LOCAL_POC = "local_poc"


class BackendKind(StrEnum):
    MANAGED_SAMPLE = "managed_sample"
    EXISTING_HTTP = "existing_http"
    DIRECT_HTTPS = "direct_https"
    INTERNAL_HTTPS_LB = "internal_https_lb"


class BackendLocation(StrEnum):
    GCP = "gcp"
    AWS = "aws"
    AZURE = "azure"
    ON_PREM = "on_prem"


class PrincipalType(StrEnum):
    USER = "user"
    GROUP = "group"
    DOMAIN = "domain"


class AccessPrincipal(BaseModel):
    type: PrincipalType
    value: str = Field(min_length=3, max_length=320)

    @model_validator(mode="after")
    def validate_principal_value(self) -> AccessPrincipal:
        value = self.value.strip().lower()
        if self.type in {PrincipalType.USER, PrincipalType.GROUP}:
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
                raise ValueError("User and group principals must be email addresses")
        elif not re.fullmatch(
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
            value,
        ):
            raise ValueError("Domain principals must be valid DNS domains")
        self.value = value
        return self

    @property
    def iam_member(self) -> str:
        return f"{self.type.value}:{self.value}"


class DeploymentSpec(BaseModel):
    schema_version: Literal[1] = 1
    name: ResourceName = "secure-gateway-http-offload"
    locale: ProductLocale = ProductLocale.ENGLISH
    mode: DeploymentMode = DeploymentMode.PRODUCTION
    platforms: set[ChromePlatform] = Field(
        default_factory=lambda: set(ChromePlatform),
        min_length=1,
    )
    network_strategy: NetworkStrategy = NetworkStrategy.DEDICATED
    certificate_strategy: CertificateStrategy = CertificateStrategy.ENTERPRISE_CA
    project_id: str = Field(min_length=6, max_length=30, pattern=r"^[a-z][a-z0-9-]+$")
    region: str = Field(default="asia-east1", pattern=r"^[a-z]+-[a-z]+[0-9]$")
    zone: str = Field(default="asia-east1-c", pattern=r"^[a-z]+-[a-z]+[0-9]-[a-z]$")
    secondary_zone: str = Field(
        default="asia-east1-a",
        pattern=r"^[a-z]+-[a-z]+[0-9]-[a-z]$",
    )
    source_image: str | None = Field(default=None, max_length=250)
    offload_min_replicas: int = Field(default=2, ge=2, le=100)
    offload_max_replicas: int = Field(default=20, ge=2, le=1000)
    offload_cpu_target: float = Field(default=0.6, ge=0.1, le=0.9)
    vpc_name: ResourceName | None = None
    subnet_name: ResourceName | None = None
    subnet_cidr: str = Field(default="10.42.0.0/24", pattern=r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")
    proxy_subnet_cidr: str = Field(
        default="10.42.1.0/24",
        pattern=r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$",
    )
    private_hostname: str = Field(
        default="demo-server-http.internal",
        min_length=4,
        max_length=253,
    )
    gateway_id: ResourceName = "default"
    target_ou_id: str = Field(
        min_length=3,
        max_length=100,
        pattern=r"^[A-Za-z0-9_-]+$",
    )
    customer_id: str = Field(
        default="my_customer",
        min_length=3,
        max_length=100,
        pattern=r"^(?:my_customer|[A-Za-z0-9_-]+)$",
    )
    managed_chrome_access_level: str | None = Field(default=None, max_length=200)
    chrome_enterprise_premium_license_confirmed: bool = False
    workspace_services_confirmed: bool = False
    endpoint_verification_confirmed: bool = False
    test_ou_confirmed: bool = False
    backend_kind: BackendKind = BackendKind.MANAGED_SAMPLE
    existing_backend_url: str | None = None
    existing_backend_location: BackendLocation | None = None
    existing_backend_connectivity_confirmed: bool = False
    application_egress_region: str | None = Field(
        default=None,
        pattern=r"^[a-z]+-[a-z]+[0-9]$",
    )
    # Path B only. The guide's worked example places the upstream VPC in a
    # different project from the gateway, and grants the delegating service
    # account roles/beyondcorp.upstreamAccess in *that* project. Left unset the
    # deployment project is used, which is the single-project case.
    upstream_vpc_project_id: str | None = Field(
        default=None,
        min_length=6,
        max_length=30,
        pattern=r"^[a-z][a-z0-9-]+$",
    )
    ca_pool: str | None = Field(default=None, max_length=500)
    ca_name: str | None = Field(default=None, max_length=500)
    public_certificate_secret: str | None = Field(default=None, max_length=500)
    certificate_lifetime_days: int = Field(default=90, ge=1, le=397)
    principals: list[AccessPrincipal] = Field(default_factory=list, min_length=1)
    allow_external_ips: Literal[False] = False
    require_cloud_nat: bool = True
    require_human_approval: bool = True

    @field_validator("private_hostname")
    @classmethod
    def validate_private_hostname(cls, value: str) -> str:
        hostname = value.strip().lower().removesuffix(".")
        label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        if len(hostname) > 253 or not re.fullmatch(rf"(?:{label}\.)+{label}", hostname):
            raise ValueError("private_hostname must be a valid fully qualified DNS name")
        return hostname

    @model_validator(mode="after")
    def enforce_enterprise_invariants(self) -> DeploymentSpec:
        if self.offload_max_replicas < self.offload_min_replicas:
            raise ValueError(
                "offload_max_replicas must be greater than or equal to offload_min_replicas"
            )
        try:
            backend_network = ipaddress.ip_network(self.subnet_cidr)
            proxy_network = ipaddress.ip_network(self.proxy_subnet_cidr)
        except ValueError as error:
            raise ValueError("Subnet CIDRs must be valid IPv4 networks") from error
        if not backend_network.is_private or not proxy_network.is_private:
            raise ValueError("Subnet CIDRs must use private IPv4 ranges")
        if (
            self.backend_kind is BackendKind.INTERNAL_HTTPS_LB
            and backend_network.overlaps(proxy_network)
        ):
            raise ValueError("ILB proxy-only subnet must not overlap the backend subnet")
        if self.mode is DeploymentMode.PRODUCTION:
            if self.certificate_strategy is CertificateStrategy.LOCAL_POC:
                raise ValueError("Production mode cannot use a local PoC CA")
            if not self.test_ou_confirmed:
                raise ValueError("Production mode requires a confirmed test OU")
            if not self.require_cloud_nat:
                raise ValueError("Production mode requires a private package egress path")
            if not self.require_human_approval:
                raise ValueError("Production mode requires explicit approval before Apply")
            if self.secondary_zone == self.zone:
                raise ValueError("Production mode requires two distinct zones")
            if not self.zone.startswith(f"{self.region}-") or not self.secondary_zone.startswith(
                f"{self.region}-"
            ):
                raise ValueError("Production zones must belong to the selected region")
            if not self.managed_chrome_access_level:
                raise ValueError("Production mode requires a managed Chrome access level")
            if not self.chrome_enterprise_premium_license_confirmed:
                raise ValueError(
                    "Production mode requires Chrome Enterprise Premium license confirmation"
                )
            if not self.workspace_services_confirmed:
                raise ValueError(
                    "Production mode requires Workspace service prerequisites confirmation"
                )
            if not self.endpoint_verification_confirmed:
                raise ValueError("Production mode requires Endpoint Verification confirmation")
            if self.backend_kind is not BackendKind.DIRECT_HTTPS and not self.source_image:
                raise ValueError("Production mode requires an immutable hardened source image")

        if self.source_image and not re.fullmatch(
            r"projects/[a-z][a-z0-9-]{4,61}[a-z0-9]/global/images/"
            r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?",
            self.source_image,
        ):
            raise ValueError("source_image must be a full immutable Compute Engine image name")

        if self.managed_chrome_access_level and not re.fullmatch(
            r"accessPolicies/[0-9]+/accessLevels/[A-Za-z][A-Za-z0-9_]{0,49}",
            self.managed_chrome_access_level,
        ):
            raise ValueError(
                "managed_chrome_access_level must be a full Access Context Manager "
                "access level name"
            )

        if self.network_strategy is NetworkStrategy.EXISTING and not self.vpc_name:
            raise ValueError("Existing VPC strategy requires vpc_name")
        if (
            self.network_strategy is NetworkStrategy.EXISTING
            and self.backend_kind is not BackendKind.DIRECT_HTTPS
            and not self.subnet_name
        ):
            raise ValueError("Managed backend deployment in an existing VPC requires subnet_name")
        if (
            self.backend_kind is BackendKind.DIRECT_HTTPS
            and self.network_strategy is not NetworkStrategy.EXISTING
        ):
            raise ValueError("Direct HTTPS requires the existing VPC that reaches the app")
        if (
            self.upstream_vpc_project_id is not None
            and self.backend_kind is not BackendKind.DIRECT_HTTPS
        ):
            raise ValueError(
                "upstream_vpc_project_id applies only to direct private HTTPS, where "
                "the VPC may belong to another project"
            )

        if (
            self.backend_kind is not BackendKind.DIRECT_HTTPS
            and self.certificate_strategy is CertificateStrategy.ENTERPRISE_CA
            and (
            not self.ca_pool or not self.ca_name
            )
        ):
            raise ValueError("Enterprise CA strategy requires ca_pool and ca_name")
        if (
            self.backend_kind is not BackendKind.DIRECT_HTTPS
            and
            self.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED
            and not self.public_certificate_secret
        ):
            raise ValueError("Public certificate strategy requires public_certificate_secret")
        if (
            self.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED
            and self.public_certificate_secret
            and "/" in self.public_certificate_secret
            and not self.public_certificate_secret.startswith(
                f"projects/{self.project_id}/secrets/"
            )
        ):
            raise ValueError("Public certificate secret must belong to the deployment project")

        if self.backend_kind is BackendKind.EXISTING_HTTP:
            if not self.existing_backend_url:
                raise ValueError("Existing HTTP backend requires existing_backend_url")
            if self.existing_backend_location is None:
                raise ValueError("Existing HTTP backend requires its hosting location")
            if not self.existing_backend_url.startswith("http://"):
                raise ValueError("Existing backend URL must use http:// for HTTP offload")
            parsed = urlsplit(self.existing_backend_url)
            if parsed.username or parsed.password or not parsed.hostname:
                raise ValueError("Existing backend URL must not contain user info")
            if parsed.query or parsed.fragment:
                raise ValueError("Existing backend URL must not contain a query or fragment")
            if re.search(r"[\s{};#]", self.existing_backend_url):
                raise ValueError(
                    "Existing backend URL contains unsafe proxy configuration characters"
                )
            hostname = parsed.hostname.lower()
            if hostname in {"localhost", "metadata", "metadata.google.internal"}:
                raise ValueError("Existing backend URL targets a forbidden host")
            try:
                address = ipaddress.ip_address(hostname)
            except ValueError:
                address = None
            if address is not None:
                allowed_private_ranges = (
                    ipaddress.ip_network("10.0.0.0/8"),
                    ipaddress.ip_network("172.16.0.0/12"),
                    ipaddress.ip_network("192.168.0.0/16"),
                    ipaddress.ip_network("fc00::/7"),
                )
                if not any(address in network for network in allowed_private_ranges):
                    raise ValueError("Existing backend IP must be RFC1918 or IPv6 ULA")
            else:
                label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                if not re.fullmatch(rf"(?:{label}\.)+{label}", hostname):
                    raise ValueError(
                        "Existing backend host must be a private IP or fully qualified DNS name"
                    )
        elif self.backend_kind is BackendKind.DIRECT_HTTPS:
            if not self.existing_backend_url:
                raise ValueError("Direct HTTPS requires existing_backend_url")
            if self.existing_backend_location is None:
                raise ValueError("Direct HTTPS requires its hosting location")
            parsed = urlsplit(self.existing_backend_url)
            if parsed.scheme != "https" or not parsed.hostname:
                raise ValueError("Direct HTTPS URL must use https://")
            if parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ValueError(
                    "Direct HTTPS URL must not contain credentials, query, or fragment"
                )
            if parsed.path not in {"", "/"}:
                raise ValueError("Direct HTTPS URL identifies an endpoint, not an application path")
            if re.search(r"[\s{};#]", self.existing_backend_url):
                raise ValueError("Direct HTTPS URL contains unsafe characters")
            hostname = parsed.hostname.lower()
            if hostname in {"localhost", "metadata", "metadata.google.internal"}:
                raise ValueError("Direct HTTPS URL targets a forbidden host")
            try:
                address = ipaddress.ip_address(hostname)
            except ValueError:
                address = None
            if address is not None:
                allowed_private_ranges = (
                    ipaddress.ip_network("10.0.0.0/8"),
                    ipaddress.ip_network("172.16.0.0/12"),
                    ipaddress.ip_network("192.168.0.0/16"),
                    ipaddress.ip_network("fc00::/7"),
                )
                if not any(address in network for network in allowed_private_ranges):
                    raise ValueError("Direct HTTPS IP must be RFC1918 or IPv6 ULA")
            else:
                label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                if not re.fullmatch(rf"(?:{label}\.)+{label}", hostname):
                    raise ValueError("Direct HTTPS host must be a private IP or FQDN")
            try:
                port = parsed.port or 443
            except ValueError as error:
                raise ValueError("Direct HTTPS URL contains an invalid port") from error
            if not 1 <= port <= 65535:
                raise ValueError("Direct HTTPS port must be between 1 and 65535")
        labels = {principal.iam_member for principal in self.principals}
        if len(labels) != len(self.principals):
            raise ValueError("Duplicate access principals are not allowed")

        return self

    @property
    def upstream_project_id(self) -> str:
        """Project owning the upstream VPC; the deployment project by default."""
        return self.upstream_vpc_project_id or self.project_id

    @property
    def application_hostname(self) -> str:
        if self.backend_kind is BackendKind.DIRECT_HTTPS and self.existing_backend_url:
            return str(urlsplit(self.existing_backend_url).hostname).lower()
        return self.private_hostname

    @property
    def application_port(self) -> int:
        if self.backend_kind is BackendKind.DIRECT_HTTPS and self.existing_backend_url:
            return urlsplit(self.existing_backend_url).port or 443
        return 443


class ChangeAction(StrEnum):
    CREATE = "create"
    UPDATE = "update"
    REUSE = "reuse"
    NO_CHANGE = "no_change"
    CONFLICT = "conflict"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    BLOCKING = "blocking"


class ResourceChange(BaseModel):
    provider: str
    resource_type: str
    resource_name: str
    action: ChangeAction
    risk: RiskLevel
    summary: str
    owned_after_apply: bool
    dependencies: list[str] = Field(default_factory=list)


class DeploymentGate(BaseModel):
    gate_id: str
    title: str
    status: Literal["pass", "pending", "blocked"]
    blocking: bool
    detail: str


class DiscoverySnapshot(BaseModel):
    existing_resource_keys: set[str] = Field(default_factory=set)
    conflicting_resource_keys: set[str] = Field(default_factory=set)
    enabled_apis: set[str] = Field(default_factory=set)
    granted_permissions: set[str] = Field(default_factory=set)
    cloud_identity: str | None = None
    workspace_identity: str | None = None
    private_egress_available: bool | None = None
    billing_enabled: bool | None = None
    managed_chrome_profile_count: int | None = Field(default=None, ge=0)
    profile_only_count: int | None = Field(default=None, ge=0)
    latest_chrome_policy_sync: str | None = None
    endpoint_verification_installed: bool | None = None
    secure_enterprise_browser_installed: bool | None = None
    endpoint_verification_version: str | None = None
    secure_enterprise_browser_version: str | None = None
    chrome_extension_group_conflicts: list[str] = Field(default_factory=list)
    chrome_enterprise_premium_license_count: int | None = Field(default=None, ge=0)
    chrome_root_store_config_count: int | None = Field(default=None, ge=0)
    chrome_root_store_config_names: list[str] = Field(default_factory=list)
    chrome_root_store_enabled: bool | None = None
    # Path B only. True or False when the matcher address resolved to a
    # forwarding rule and its Global Access setting could be read; None when the
    # target is not a discoverable GCP forwarding rule, which is legitimate for
    # GKE ingresses, FQDN matchers, and non-GCP backends.
    application_global_access: bool | None = None
    application_forwarding_rule: str | None = None


class PreflightDiagnostic(BaseModel):
    code: str
    severity: Literal["info", "warning", "error"]
    message: str
    remediation: str | None = None


class PreflightResult(BaseModel):
    snapshot: DiscoverySnapshot
    diagnostics: list[PreflightDiagnostic] = Field(default_factory=list)
    credential_kind: str | None = None
    quota_project_id: str | None = None
    read_only: Literal[True] = True


class ConnectionValidation(BaseModel):
    provider: Literal["google_cloud", "workspace"]
    status: Literal["connected"]
    principal_hint: str
    resource_id: str
    credential_kind: str
    read_only: Literal[True] = True


class SetupOption(BaseModel):
    value: str = Field(min_length=1, max_length=500)
    label: str = Field(min_length=1, max_length=500)
    description: str = Field(default="", max_length=1000)


class DeploymentPlan(BaseModel):
    plan_version: Literal[1] = 1
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    configuration_hash: str
    mode: DeploymentMode
    changes: list[ResourceChange]
    gates: list[DeploymentGate]
    can_apply: bool
    destructive_change_count: int = 0


class PreparedPlan(BaseModel):
    plan_id: str
    specification: DeploymentSpec
    preflight: PreflightResult
    plan: DeploymentPlan
    created_at: datetime
    expires_at: datetime


class ApprovedPlan(BaseModel):
    approval_id: str
    configuration_hash: str
    plan_hash: str
    plan: DeploymentPlan
    specification: DeploymentSpec
    approved_by: str
    approved_at: datetime
    expires_at: datetime
    consumed_at: datetime | None = None


class RunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"
    INTERRUPTED = "interrupted"


class OperationStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    SKIPPED = "skipped"
    INTERRUPTED = "interrupted"


class RunOperation(BaseModel):
    operation_id: str
    resource_key: str
    action: ChangeAction
    status: OperationStatus
    owned_after_apply: bool
    error_code: str | None = None
    started_at: datetime
    completed_at: datetime | None = None


class DeploymentRun(BaseModel):
    run_id: str
    approval_id: str
    configuration_hash: str
    status: RunStatus
    started_at: datetime
    completed_at: datetime | None = None
    operations: list[RunOperation] = Field(default_factory=list)


class DeploymentResource(BaseModel):
    resource_key: str
    summary: str
    provider: str
    resource_type: str
    resource_name: str
    owned: bool
    teardown_action: Literal["delete", "delete_if_empty", "retain"]


class DeploymentDetails(BaseModel):
    run: DeploymentRun
    ownership_run_id: str | None = None
    deployment_name: str
    project_id: str
    gateway_id: str
    backend_kind: BackendKind
    application_hostname: str
    application_port: int
    resources: list[DeploymentResource] = Field(default_factory=list)
    teardown_available: bool


class GatewayLogCategory(StrEnum):
    ACCESS = "access"
    CONNECTION = "connection"
    ADMIN = "admin"
    NGINX = "nginx"


class GatewayLogEntry(BaseModel):
    insert_id: str
    timestamp: datetime | None = None
    severity: str = "DEFAULT"
    category: GatewayLogCategory
    summary: str
    principal: str | None = None
    method: str | None = None
    resource: str | None = None
    request_id: str | None = None
    payload: dict[str, object] = Field(default_factory=dict)


class GatewayLogsResponse(BaseModel):
    run_id: str
    category: GatewayLogCategory
    entries: list[GatewayLogEntry] = Field(default_factory=list)
    logging_enabled: bool | None = None
    data_access_notice: bool = False
    setup_notice: str | None = None


class TeardownOperation(BaseModel):
    resource_key: str
    status: Literal["pending", "running", "succeeded", "failed", "skipped"]
    error_code: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None


class TeardownPlan(BaseModel):
    run_id: str
    plan_hash: str
    confirmation: str
    resources: list[DeploymentResource]
    retained_resources: list[DeploymentResource]
    can_destroy: bool


class TeardownRun(BaseModel):
    teardown_id: str
    source_run_id: str
    plan_hash: str
    status: Literal["pending", "running", "succeeded", "failed", "interrupted"]
    started_at: datetime
    completed_at: datetime | None = None
    operations: list[TeardownOperation] = Field(default_factory=list)


class AcceptanceTestId(StrEnum):
    T01 = "T01"
    T02 = "T02"
    T03 = "T03"
    T04 = "T04"
    T05 = "T05"
    T06 = "T06"
    T07 = "T07"
    T08 = "T08"
    T09 = "T09"


class AcceptanceStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    USER_CONFIRMED = "user_confirmed"
    SKIPPED = "skipped"


class EvidenceSource(StrEnum):
    SYSTEM = "system"
    OPERATOR = "operator"


class AcceptanceResult(BaseModel):
    result_id: str
    run_id: str
    test_id: AcceptanceTestId
    case_key: str = Field(
        default="default",
        min_length=3,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9_-]*$",
    )
    status: AcceptanceStatus
    source: EvidenceSource
    summary: str = Field(min_length=3, max_length=500)
    evidence: str = Field(min_length=3, max_length=4000, repr=False)
    actor: str = Field(min_length=3, max_length=320)
    recorded_at: datetime

    @field_validator("summary", "evidence")
    @classmethod
    def reject_secret_evidence(cls, value: str) -> str:
        normalized = value.strip()
        forbidden = (
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
            r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{16,}",
            r"(?i)\"?(?:access_token|refresh_token|private_key)\"?\s*[:=]",
            r"\bya29\.[A-Za-z0-9_-]+",
        )
        if any(re.search(pattern, normalized) for pattern in forbidden):
            raise ValueError("Acceptance evidence must not contain credentials or keys")
        return normalized


class AcceptanceRequirement(BaseModel):
    test_id: AcceptanceTestId
    case_key: str = Field(
        min_length=3,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9_-]*$",
    )
    operator_confirmable: bool


class AcceptanceReadiness(BaseModel):
    run_id: str
    mode: DeploymentMode
    acceptance_complete: bool
    production_ready: bool
    required_tests: list[AcceptanceTestId]
    operator_confirmable_tests: list[AcceptanceTestId]
    satisfied_tests: list[AcceptanceTestId]
    missing_tests: list[AcceptanceTestId]
    required_cases: list[AcceptanceRequirement]
    operator_confirmable_cases: list[AcceptanceRequirement]
    satisfied_cases: list[AcceptanceRequirement]
    missing_cases: list[AcceptanceRequirement]
    results: list[AcceptanceResult]


class AuditEvent(BaseModel):
    event_id: str
    deployment_id: str | None = None
    event_type: str
    actor: str
    payload: dict[str, str | int | bool | None]
    created_at: datetime
    previous_hash: str | None = None
    event_hash: str | None = None
