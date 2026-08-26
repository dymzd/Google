from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from sgstudio.domain.canonical import canonical_digest
from sgstudio.domain.models import (
    BackendKind,
    CertificateStrategy,
    ChangeAction,
    DeploymentGate,
    DeploymentPlan,
    DeploymentSpec,
    DiscoverySnapshot,
    NetworkStrategy,
    PublicCertificateBinding,
    ResourceChange,
    RiskLevel,
    SourceImageBinding,
)
from sgstudio.domain.naming import service_account_id

REQUIRED_APIS = {
    "accesscontextmanager.googleapis.com",
    "admin.googleapis.com",
    "beyondcorp.googleapis.com",
    "cloudbilling.googleapis.com",
    "compute.googleapis.com",
    "dns.googleapis.com",
    "iap.googleapis.com",
    "logging.googleapis.com",
    "privateca.googleapis.com",
    "serviceusage.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "secretmanager.googleapis.com",
    "chromepolicy.googleapis.com",
    "chromemanagement.googleapis.com",
    "licensing.googleapis.com",
}

DIRECT_HTTPS_APIS = {
    "accesscontextmanager.googleapis.com",
    "admin.googleapis.com",
    "beyondcorp.googleapis.com",
    "cloudbilling.googleapis.com",
    "compute.googleapis.com",
    "serviceusage.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iamcredentials.googleapis.com",
    "chromepolicy.googleapis.com",
    "chromemanagement.googleapis.com",
    "licensing.googleapis.com",
    "logging.googleapis.com",
}

REQUIRED_PERMISSIONS = {
    "accesscontextmanager.accessLevels.get",
    "beyondcorp.securityGateways.create",
    "beyondcorp.securityGateways.delete",
    "beyondcorp.securityGateways.get",
    "beyondcorp.securityGateways.getIamPolicy",
    "beyondcorp.securityGateways.list",
    "beyondcorp.securityGateways.setIamPolicy",
    "beyondcorp.operations.get",
    "beyondcorp.sgApplications.create",
    "beyondcorp.sgApplications.delete",
    "beyondcorp.sgApplications.get",
    "beyondcorp.sgApplications.getIamPolicy",
    "beyondcorp.sgApplications.list",
    "beyondcorp.sgApplications.setIamPolicy",
    "compute.addresses.create",
    "compute.addresses.createInternal",
    "compute.addresses.delete",
    "compute.addresses.deleteInternal",
    "compute.addresses.get",
    "compute.addresses.use",
    "compute.addresses.useInternal",
    "compute.autoscalers.create",
    "compute.autoscalers.delete",
    "compute.autoscalers.get",
    "compute.disks.create",
    "compute.disks.get",
    "compute.firewalls.create",
    "compute.firewalls.delete",
    "compute.firewalls.get",
    "compute.forwardingRules.create",
    "compute.forwardingRules.delete",
    "compute.forwardingRules.get",
    "compute.forwardingRules.list",
    "compute.healthChecks.create",
    "compute.healthChecks.delete",
    "compute.healthChecks.get",
    "compute.globalOperations.get",
    "compute.images.get",
    "compute.images.useReadOnly",
    "compute.instances.create",
    "compute.instances.delete",
    "compute.instances.get",
    "compute.instances.getGuestAttributes",
    "compute.instances.setLabels",
    "compute.instances.setMetadata",
    "compute.instances.setServiceAccount",
    "compute.instances.setTags",
    "compute.instances.start",
    "compute.instances.stop",
    "compute.instanceGroupManagers.create",
    "compute.instanceGroupManagers.delete",
    "compute.instanceGroupManagers.get",
    "compute.instanceGroupManagers.update",
    "compute.instanceGroups.create",
    "compute.instanceGroups.delete",
    "compute.instanceGroups.get",
    "compute.instanceGroups.update",
    "compute.instanceGroups.use",
    "compute.instanceTemplates.create",
    "compute.instanceTemplates.delete",
    "compute.instanceTemplates.get",
    "compute.instanceTemplates.useReadOnly",
    "compute.networks.create",
    "compute.networks.delete",
    "compute.networks.get",
    "compute.networks.updatePolicy",
    "compute.networks.use",
    "compute.routers.create",
    "compute.routers.delete",
    "compute.routers.get",
    "compute.routers.list",
    "compute.routers.update",
    "compute.routes.list",
    "compute.regionOperations.get",
    "compute.regionBackendServices.create",
    "compute.regionBackendServices.delete",
    "compute.regionBackendServices.get",
    "compute.regionBackendServices.use",
    "compute.regionHealthChecks.useReadOnly",
    "compute.regionSslCertificates.create",
    "compute.regionSslCertificates.delete",
    "compute.regionSslCertificates.get",
    "compute.regionTargetHttpsProxies.create",
    "compute.regionTargetHttpsProxies.delete",
    "compute.regionTargetHttpsProxies.get",
    "compute.regionTargetHttpsProxies.use",
    "compute.regionUrlMaps.create",
    "compute.regionUrlMaps.delete",
    "compute.regionUrlMaps.get",
    "compute.regionUrlMaps.use",
    "compute.subnetworks.create",
    "compute.subnetworks.delete",
    "compute.subnetworks.get",
    "compute.subnetworks.use",
    "compute.zoneOperations.get",
    "dns.changes.create",
    "dns.changes.get",
    "dns.managedZones.create",
    "dns.managedZones.delete",
    "dns.managedZones.get",
    "dns.networks.bindPrivateDNSZone",
    "dns.resourceRecordSets.create",
    "dns.resourceRecordSets.delete",
    "dns.resourceRecordSets.get",
    "iam.serviceAccounts.actAs",
    "iam.serviceAccounts.create",
    "iam.serviceAccounts.delete",
    "iam.serviceAccounts.get",
    "logging.logEntries.list",
    "privateca.caPools.use",
    "privateca.certificates.create",
    "privateca.certificates.get",
    "privateca.certificates.update",
    "privateca.operations.get",
    "resourcemanager.projects.get",
    "resourcemanager.projects.getIamPolicy",
    "resourcemanager.projects.setIamPolicy",
    "secretmanager.secrets.create",
    "secretmanager.secrets.delete",
    "secretmanager.secrets.get",
    "secretmanager.secrets.getIamPolicy",
    "secretmanager.secrets.setIamPolicy",
    "secretmanager.secrets.update",
    "secretmanager.versions.add",
    "secretmanager.versions.disable",
    "secretmanager.versions.destroy",
    "secretmanager.versions.get",
    "secretmanager.versions.list",
    "secretmanager.versions.access",
    "serviceusage.services.enable",
    "serviceusage.services.get",
    "serviceusage.services.list",
    "serviceusage.services.use",
    "serviceusage.operations.get",
}


def canonical_configuration_hash(spec: DeploymentSpec) -> str:
    payload = spec.model_dump(mode="json", exclude_none=True)
    payload["platforms"] = sorted(payload["platforms"])
    return canonical_digest(payload)


def canonical_plan_hash(plan: DeploymentPlan) -> str:
    return canonical_digest(plan.model_dump(mode="json"))


def requires_public_certificate_binding(spec: DeploymentSpec) -> bool:
    return (
        spec.backend_kind is not BackendKind.DIRECT_HTTPS
        and spec.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED
    )


def public_certificate_binding_matches_spec(
    spec: DeploymentSpec,
    binding: PublicCertificateBinding | None,
) -> bool:
    if binding is None or spec.backend_kind is BackendKind.DIRECT_HTTPS:
        return False
    if spec.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED:
        if not spec.public_certificate_secret:
            return False
        secret_name = spec.public_certificate_secret.rsplit("/", maxsplit=1)[-1]
    else:
        secret_name = f"{spec.name}-tls"
    prefix = (
        f"projects/{spec.project_id}/secrets/{secret_name}/versions/"
    )
    return binding.secret_version_name.startswith(prefix)


def source_image_binding_matches_spec(
    spec: DeploymentSpec,
    binding: SourceImageBinding | None,
) -> bool:
    return (
        spec.backend_kind is not BackendKind.DIRECT_HTTPS
        and spec.source_image is not None
        and binding is not None
        and binding.name == spec.source_image
        and binding.self_link
        == f"https://www.googleapis.com/compute/v1/{spec.source_image}"
    )


def assert_plan_integrity(
    plan: DeploymentPlan,
    specification: DeploymentSpec,
    *,
    stored_configuration_hash: str | None = None,
    stored_plan_hash: str | None = None,
) -> None:
    """Fail closed unless a stored plan is bound to its exact specification."""

    expected_configuration_hash = canonical_configuration_hash(specification)
    if plan.configuration_hash != expected_configuration_hash:
        raise ValueError("Plan configuration hash does not match its specification")
    if (
        stored_configuration_hash is not None
        and stored_configuration_hash != expected_configuration_hash
    ):
        raise ValueError("Stored configuration hash does not match its specification")
    if stored_plan_hash is not None and stored_plan_hash != canonical_plan_hash(plan):
        raise ValueError("Stored plan hash does not match the canonical plan")
    binding_required = requires_public_certificate_binding(specification)
    if plan.public_certificate_binding is not None and not public_certificate_binding_matches_spec(
        specification,
        plan.public_certificate_binding,
    ):
        raise ValueError("Plan public certificate binding does not match its specification")
    if binding_required and plan.can_apply and plan.public_certificate_binding is None:
        raise ValueError("Applyable public certificate plan lacks an immutable version binding")
    if plan.source_image_binding is not None and not source_image_binding_matches_spec(
        specification,
        plan.source_image_binding,
    ):
        raise ValueError("Plan source image binding does not match its specification")
    if (
        specification.backend_kind is not BackendKind.DIRECT_HTTPS
        and plan.can_apply
        and plan.source_image_binding is None
    ):
        raise ValueError("Applyable managed-VM plan lacks an immutable source image binding")


def _global_access_status(
    spec: DeploymentSpec, snapshot: DiscoverySnapshot
) -> Literal["pass", "pending", "blocked"]:
    if spec.backend_kind is not BackendKind.DIRECT_HTTPS:
        return "pass"
    if not snapshot.application_global_access_discovery_complete:
        return "blocked"
    if spec.application_egress_region is not None:
        return "pass"
    if snapshot.application_global_access is True:
        return "pass"
    if snapshot.application_global_access is False:
        return "blocked"
    return "pending"


def _global_access_detail(spec: DeploymentSpec, snapshot: DiscoverySnapshot) -> str:
    if spec.backend_kind is not BackendKind.DIRECT_HTTPS:
        return "Only direct private HTTPS applications reach a regional load balancer."
    if not snapshot.application_global_access_discovery_complete:
        return (
            "Forwarding-rule discovery did not complete safely, so Global Access "
            "cannot be approved. Retry preflight after the Compute API pagination "
            "response is complete."
        )
    if spec.application_egress_region is not None:
        return (
            "An explicit egress region pins Secure Gateway traffic to "
            f"{spec.application_egress_region}, so Global Access is not required."
        )
    if snapshot.application_global_access is True:
        rule = snapshot.application_forwarding_rule or "the matcher forwarding rule"
        return f"Global Access is enabled on {rule}."
    if snapshot.application_global_access is False:
        rule = snapshot.application_forwarding_rule or "the matcher forwarding rule"
        return (
            f"Global Access is disabled on {rule} and no egress region is set. "
            "A regional internal load balancer refuses traffic arriving from "
            "another region, so Secure Gateway connections will time out. Either "
            "enable Global Access on the frontend, or set an egress region that "
            "matches the load balancer."
        )
    return (
        f"{spec.application_hostname} did not resolve to a forwarding rule in this "
        "project, so Global Access could not be checked. If the target is a "
        "regional internal load balancer, confirm that Global Access is enabled "
        "or set an egress region before Apply."
    )


def required_apis(spec: DeploymentSpec) -> set[str]:
    if spec.backend_kind is BackendKind.DIRECT_HTTPS:
        return set(DIRECT_HTTPS_APIS)
    return set(REQUIRED_APIS)


def certificate_configuration_hash(spec: DeploymentSpec) -> str:
    """Hash only inputs that can change the issued TLS certificate."""
    payload = {
        "certificate_strategy": spec.certificate_strategy.value,
        "private_hostname": spec.private_hostname,
        "certificate_lifetime_days": spec.certificate_lifetime_days,
        "ca_pool": str(spec.ca_pool) if spec.ca_pool else None,
        "ca_name": str(spec.ca_name) if spec.ca_name else None,
        "public_certificate_secret": spec.public_certificate_secret,
    }
    return canonical_digest(payload)


def required_permissions(spec: DeploymentSpec) -> set[str]:
    permissions = set(REQUIRED_PERMISSIONS)
    if spec.backend_kind is BackendKind.DIRECT_HTTPS:
        return {
            permission
            for permission in permissions
            if permission.startswith("beyondcorp.")
            or permission.startswith("resourcemanager.")
            or permission.startswith("serviceusage.")
            or permission.startswith("logging.")
            or permission == "accesscontextmanager.accessLevels.get"
            or permission in {"compute.networks.get", "compute.networks.use"}
        } | {
            # Path B owns no forwarding rule, but resolving the matcher address
            # to one is how the Global Access gate avoids the guide's most
            # common Path B failure. Path A already knows its rule by name and
            # needs only `get`.
            "compute.forwardingRules.list"
        }
    if spec.backend_kind is not BackendKind.INTERNAL_HTTPS_LB:
        permissions -= {
            "compute.instanceGroups.create",
            "compute.instanceGroups.delete",
            "compute.instanceGroups.get",
            "compute.instanceGroups.update",
            "compute.regionSslCertificates.create",
            "compute.regionSslCertificates.delete",
            "compute.regionSslCertificates.get",
            "compute.regionTargetHttpsProxies.create",
            "compute.regionTargetHttpsProxies.delete",
            "compute.regionTargetHttpsProxies.get",
            "compute.regionTargetHttpsProxies.use",
            "compute.regionUrlMaps.create",
            "compute.regionUrlMaps.delete",
            "compute.regionUrlMaps.get",
            "compute.regionUrlMaps.use",
        }
    if spec.network_strategy is NetworkStrategy.EXISTING:
        permissions -= {
            "compute.networks.create",
            "compute.networks.delete",
            "compute.routers.create",
            "compute.routers.delete",
            "compute.routers.update",
        }
        # The ILB path still creates and owns its regional proxy-only subnet
        # in the selected VPC. Other existing-VPC paths reuse the selected
        # subnet and need no subnet mutation authority.
        if spec.backend_kind is not BackendKind.INTERNAL_HTTPS_LB:
            permissions -= {
                "compute.subnetworks.create",
                "compute.subnetworks.delete",
            }
    else:
        # Existing-VPC VM paths must prove an active default-internet-gateway
        # route before relying on an administrator-owned Public NAT.
        permissions.discard("compute.routes.list")
    if spec.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED:
        permissions -= {
            "privateca.caPools.use",
            "privateca.certificates.create",
            "privateca.certificates.get",
            "privateca.certificates.update",
            "privateca.operations.get",
            "secretmanager.secrets.create",
            "secretmanager.secrets.delete",
            "secretmanager.secrets.update",
            "secretmanager.versions.add",
            "secretmanager.versions.disable",
            "secretmanager.versions.destroy",
            "secretmanager.versions.get",
            "secretmanager.versions.list",
        }
    elif spec.certificate_strategy is CertificateStrategy.LOCAL_POC:
        if spec.backend_kind is not BackendKind.INTERNAL_HTTPS_LB:
            permissions.discard("secretmanager.versions.access")
        permissions.discard("privateca.caPools.use")
        permissions.discard("privateca.certificates.create")
        permissions.discard("privateca.certificates.get")
        permissions.discard("privateca.certificates.update")
        permissions.discard("privateca.operations.get")
    if spec.mode.value == "poc":
        production_only_permissions = {
            "compute.autoscalers.create",
            "compute.autoscalers.delete",
            "compute.autoscalers.get",
            "compute.forwardingRules.create",
            "compute.forwardingRules.delete",
            "compute.forwardingRules.get",
            "compute.healthChecks.create",
            "compute.healthChecks.delete",
            "compute.healthChecks.get",
            "compute.instanceTemplates.create",
            "compute.instanceTemplates.delete",
            "compute.instanceTemplates.get",
            "compute.regionBackendServices.create",
            "compute.regionBackendServices.delete",
            "compute.regionBackendServices.get",
            "compute.instanceGroupManagers.create",
            "compute.instanceGroupManagers.delete",
            "compute.instanceGroupManagers.get",
            "compute.instanceGroupManagers.update",
            "compute.instanceGroups.use",
            "compute.regionBackendServices.use",
            "compute.regionHealthChecks.useReadOnly",
        }
        if spec.backend_kind is BackendKind.INTERNAL_HTTPS_LB:
            production_only_permissions -= {
                "compute.forwardingRules.create",
                "compute.forwardingRules.delete",
                "compute.forwardingRules.get",
                "compute.healthChecks.create",
                "compute.healthChecks.delete",
                "compute.healthChecks.get",
                "compute.instanceGroups.create",
                "compute.instanceGroups.delete",
                "compute.instanceGroups.get",
                "compute.instanceGroups.update",
                "compute.instanceGroups.use",
                "compute.regionBackendServices.create",
                "compute.regionBackendServices.delete",
                "compute.regionBackendServices.get",
                "compute.regionBackendServices.use",
                "compute.regionHealthChecks.useReadOnly",
            }
        permissions -= production_only_permissions
    else:
        permissions -= {
            "compute.instances.start",
            "compute.instances.stop",
        }
    return permissions


@dataclass(frozen=True)
class DesiredResource:
    provider: str
    resource_type: str
    name: str
    risk: RiskLevel
    summary: str
    dependencies: tuple[str, ...] = ()
    shared: bool = False
    must_exist: bool = False

    @property
    def key(self) -> str:
        return f"{self.provider}:{self.resource_type}:{self.name}"


class DesiredStatePlanner:
    def build_plan(
        self,
        spec: DeploymentSpec,
        snapshot: DiscoverySnapshot | None = None,
    ) -> DeploymentPlan:
        snapshot = snapshot or DiscoverySnapshot()
        resources = self._desired_resources(spec, snapshot)
        changes = [self._classify(resource, snapshot) for resource in resources]
        gates = self._gates(spec, snapshot, changes)
        can_apply = all(gate.status == "pass" for gate in gates if gate.blocking)

        public_certificate_binding = (
            snapshot.public_certificate_binding
            if public_certificate_binding_matches_spec(
                spec,
                snapshot.public_certificate_binding,
            )
            else None
        )
        source_image_binding = (
            snapshot.source_image_binding
            if source_image_binding_matches_spec(spec, snapshot.source_image_binding)
            else None
        )

        configuration_hash = canonical_configuration_hash(spec)
        return DeploymentPlan(
            configuration_hash=configuration_hash,
            mode=spec.mode,
            changes=changes,
            gates=gates,
            can_apply=can_apply,
            public_certificate_binding=public_certificate_binding,
            source_image_binding=source_image_binding,
        )

    def _classify(
        self,
        resource: DesiredResource,
        snapshot: DiscoverySnapshot,
    ) -> ResourceChange:
        if resource.key in snapshot.conflicting_resource_keys:
            action = ChangeAction.CONFLICT
            risk = RiskLevel.BLOCKING
        elif resource.key in snapshot.existing_resource_keys:
            action = ChangeAction.REUSE if resource.shared else ChangeAction.NO_CHANGE
            risk = RiskLevel.LOW
        elif resource.must_exist:
            action = ChangeAction.CONFLICT
            risk = RiskLevel.BLOCKING
        else:
            action = ChangeAction.CREATE
            risk = resource.risk

        owns_managed_delta = action is ChangeAction.CREATE and (
            resource.provider == "chromepolicy"
            or (
                resource.provider == "cloudresourcemanager"
                and resource.resource_type == "project_iam"
            )
        )
        return ResourceChange(
            provider=resource.provider,
            resource_type=resource.resource_type,
            resource_name=resource.name,
            action=action,
            risk=risk,
            summary=resource.summary,
            # A run owns only mutations it actually performs.  Compatible
            # pre-existing resources are NO_CHANGE/REUSE and must not enter
            # this run's teardown inventory.
            owned_after_apply=action is ChangeAction.CREATE
            and (not resource.shared or owns_managed_delta),
            dependencies=list(resource.dependencies),
        )

    def _desired_resources(
        self,
        spec: DeploymentSpec,
        snapshot: DiscoverySnapshot,
    ) -> list[DesiredResource]:
        prefix = spec.name
        network_name = (
            f"{prefix}-vpc"
            if spec.network_strategy is NetworkStrategy.DEDICATED
            else str(spec.vpc_name)
        )
        offload_account = service_account_id(prefix, "offload")
        backend_account = service_account_id(prefix, "backend")
        tls_secret_name = (
            spec.public_certificate_secret.rsplit("/", maxsplit=1)[-1]
            if spec.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED
            and spec.public_certificate_secret
            else f"{prefix}-tls"
        )
        resources: list[DesiredResource] = [
            DesiredResource(
                "serviceusage",
                "project_services",
                "required-apis",
                RiskLevel.HIGH,
                "Enable the explicit Secure Gateway API allowlist",
                shared=True,
            )
        ]

        if spec.network_strategy is NetworkStrategy.DEDICATED:
            resources.extend(
                [
                    DesiredResource(
                        "compute",
                        "network",
                        f"{prefix}-vpc",
                        RiskLevel.MEDIUM,
                        "Dedicated custom-mode VPC",
                    ),
                    DesiredResource(
                        "compute",
                        "subnetwork",
                        f"{prefix}-subnet",
                        RiskLevel.MEDIUM,
                        f"Private subnet in {spec.region}",
                        (f"compute:network:{prefix}-vpc",),
                    ),
                    DesiredResource(
                        "compute",
                        "router",
                        f"{prefix}-router",
                        RiskLevel.MEDIUM,
                        "Dedicated Cloud Router for private egress",
                        (f"compute:subnetwork:{prefix}-subnet",),
                    ),
                    DesiredResource(
                        "compute",
                        "cloud_nat",
                        f"{prefix}-nat",
                        RiskLevel.MEDIUM,
                        "Private package egress with no VM external IPs",
                        (
                            f"compute:subnetwork:{prefix}-subnet",
                            f"compute:router:{prefix}-router",
                        ),
                    ),
                ]
            )
        else:
            resources.append(
                DesiredResource(
                    "compute",
                    "network",
                    spec.vpc_name or "unresolved",
                    RiskLevel.LOW,
                    "Existing administrator-managed VPC",
                    shared=True,
                    must_exist=True,
                )
            )
            if spec.backend_kind is not BackendKind.DIRECT_HTTPS:
                resources.append(
                    DesiredResource(
                        "compute",
                        "subnetwork",
                        spec.subnet_name or "unresolved",
                        RiskLevel.LOW,
                        "Existing administrator-managed subnet",
                        (f"compute:network:{spec.vpc_name}",),
                        shared=True,
                        must_exist=True,
                    )
                )

        if spec.backend_kind is BackendKind.INTERNAL_HTTPS_LB:
            resources.append(
                DesiredResource(
                    "compute",
                    "subnetwork",
                    f"{prefix}-proxy-subnet",
                    RiskLevel.HIGH,
                    "Regional managed proxy-only subnet for the internal HTTPS load balancer",
                    (f"compute:network:{network_name}",),
                )
            )

        if spec.backend_kind is BackendKind.DIRECT_HTTPS:
            if spec.managed_chrome_access_level:
                resources.append(
                    DesiredResource(
                        "accesscontextmanager",
                        "access_level",
                        spec.managed_chrome_access_level,
                        RiskLevel.HIGH,
                        "Existing access level requiring a managed Chrome profile or browser",
                        shared=True,
                        must_exist=True,
                    )
                )
            resources.extend(
                [
                    DesiredResource(
                        "beyondcorp",
                        "security_gateway",
                        spec.gateway_id,
                        RiskLevel.HIGH,
                        "Service Discovery-enabled Secure Gateway",
                        shared=spec.gateway_id == "default",
                    ),
                    DesiredResource(
                        "beyondcorp",
                        "gateway_iam",
                        f"{spec.gateway_id}-service-discovery-users",
                        RiskLevel.HIGH,
                        "Grant Service Discovery use to the approved principal set",
                        (f"beyondcorp:security_gateway:{spec.gateway_id}",),
                    ),
                    DesiredResource(
                        "cloudresourcemanager",
                        "project_iam",
                        f"{prefix}-upstream-access",
                        RiskLevel.HIGH,
                        "Grant roles/beyondcorp.upstreamAccess to the gateway delegating account",
                        (f"beyondcorp:security_gateway:{spec.gateway_id}",),
                        shared=True,
                    ),
                    DesiredResource(
                        "beyondcorp",
                        "application",
                        f"{prefix}-app",
                        RiskLevel.HIGH,
                        (
                            f"Direct private HTTPS matcher {spec.application_hostname}:"
                            f"{spec.application_port} through VPC {spec.vpc_name}"
                        ),
                        (
                            f"beyondcorp:security_gateway:{spec.gateway_id}",
                            f"compute:network:{spec.vpc_name}",
                            f"cloudresourcemanager:project_iam:{prefix}-upstream-access",
                        ),
                    ),
                    DesiredResource(
                        "beyondcorp",
                        "application_iam",
                        f"{prefix}-app-access",
                        RiskLevel.HIGH,
                        "Grant application access to the approved principal set",
                        (
                            f"beyondcorp:application:{prefix}-app",
                            *(
                                (
                                    "accesscontextmanager:access_level:"
                                    f"{spec.managed_chrome_access_level}",
                                )
                                if spec.managed_chrome_access_level
                                else ()
                            ),
                        ),
                    ),
                    DesiredResource(
                        "chromepolicy",
                        "extension_install",
                        "ekajlcmdfcigmdbphhifahdfjbkciflj",
                        RiskLevel.HIGH,
                        "Force-install the Secure Enterprise Browser extension in the test OU",
                        shared=True,
                    ),
                    DesiredResource(
                        "chromepolicy",
                        "extension_install",
                        "callobklhcbilhphinckomhgkigmfocg",
                        RiskLevel.HIGH,
                        "Force-install Endpoint Verification for managed Chrome signals",
                        shared=True,
                    ),
                    DesiredResource(
                        "chromepolicy",
                        "extension_configuration",
                        "ekajlcmdfcigmdbphhifahdfjbkciflj",
                        RiskLevel.HIGH,
                        "Configure the gateway resource and Service Discovery routes",
                        (f"beyondcorp:security_gateway:{spec.gateway_id}",),
                        shared=True,
                    ),
                    DesiredResource(
                        "chromepolicy",
                        "service_discovery_proxy",
                        spec.target_ou_id,
                        RiskLevel.HIGH,
                        "Override an inherited legacy PAC in the test OU for Service Discovery",
                        (
                            "chromepolicy:extension_configuration:"
                            "ekajlcmdfcigmdbphhifahdfjbkciflj",
                        ),
                        shared=True,
                    ),
                ]
            )
            resources.extend(
                DesiredResource(
                    "chromepolicy",
                    "group_extension_configuration",
                    group_email,
                    RiskLevel.BLOCKING,
                    "A group policy overrides the target OU Secure Gateway configuration",
                    shared=True,
                )
                for group_email in snapshot.chrome_extension_group_conflicts
            )
            return resources

        if spec.backend_kind is BackendKind.INTERNAL_HTTPS_LB:
            if spec.managed_chrome_access_level:
                resources.append(
                    DesiredResource(
                        "accesscontextmanager",
                        "access_level",
                        spec.managed_chrome_access_level,
                        RiskLevel.HIGH,
                        "Existing access level requiring a managed Chrome profile or browser",
                        shared=True,
                        must_exist=True,
                    )
                )
            resources.extend(
                [
                    DesiredResource(
                        "iam",
                        "service_account",
                        backend_account,
                        RiskLevel.LOW,
                        "Dedicated identity for the HTTP backend VM",
                    ),
                    DesiredResource(
                        "compute",
                        "internal_address",
                        f"{prefix}-backend-ip",
                        RiskLevel.MEDIUM,
                        "Stable private address for the sample HTTP backend",
                    ),
                    DesiredResource(
                        "compute",
                        "instance",
                        f"{prefix}-backend",
                        RiskLevel.MEDIUM,
                        "Private HTTP sample backend with no external IP",
                        (
                            f"iam:service_account:{backend_account}",
                            f"compute:internal_address:{prefix}-backend-ip",
                        ),
                    ),
                    DesiredResource(
                        "compute",
                        "instance_group",
                        f"{prefix}-backend-ig",
                        RiskLevel.MEDIUM,
                        "Zonal instance group exposing the sample backend on HTTP port 80",
                        (f"compute:instance:{prefix}-backend",),
                    ),
                    DesiredResource(
                        "compute",
                        "health_check",
                        f"{prefix}-ilb-hc",
                        RiskLevel.MEDIUM,
                        "Regional HTTP health check for the ILB backend",
                        (f"compute:instance_group:{prefix}-backend-ig",),
                    ),
                    DesiredResource(
                        "compute",
                        "firewall_rule",
                        f"{prefix}-ilb-proxy-ingress",
                        RiskLevel.HIGH,
                        "Allow the proxy-only subnet to reach backend TCP 80",
                        (
                            f"compute:subnetwork:{prefix}-proxy-subnet",
                            f"compute:instance:{prefix}-backend",
                        ),
                    ),
                    DesiredResource(
                        "compute",
                        "firewall_rule",
                        f"{prefix}-ilb-health-ingress",
                        RiskLevel.HIGH,
                        "Allow Google health checks to backend TCP 80",
                        (
                            f"compute:health_check:{prefix}-ilb-hc",
                            f"compute:instance:{prefix}-backend",
                        ),
                    ),
                    DesiredResource(
                        "compute",
                        "backend_service",
                        f"{prefix}-ilb-bs",
                        RiskLevel.HIGH,
                        "Regional INTERNAL_MANAGED HTTP backend service",
                        (
                            f"compute:health_check:{prefix}-ilb-hc",
                            f"compute:instance_group:{prefix}-backend-ig",
                        ),
                    ),
                    DesiredResource(
                        "compute",
                        "internal_address",
                        f"{prefix}-offload-ip",
                        RiskLevel.MEDIUM,
                        "Stable private frontend address for the internal HTTPS load balancer",
                    ),
                    DesiredResource(
                        "secretmanager",
                        "secret",
                        tls_secret_name,
                        RiskLevel.HIGH,
                        "TLS material for the internal HTTPS load balancer",
                        shared=spec.certificate_strategy
                        is CertificateStrategy.PUBLIC_TRUSTED,
                        must_exist=spec.certificate_strategy
                        is CertificateStrategy.PUBLIC_TRUSTED,
                    ),
                ]
            )
            if spec.certificate_strategy is not CertificateStrategy.PUBLIC_TRUSTED:
                certificate_dependencies: tuple[str, ...] = ()
                if spec.certificate_strategy is CertificateStrategy.ENTERPRISE_CA:
                    resources.append(
                        DesiredResource(
                            "privateca",
                            "certificate",
                            f"{prefix}-certificate",
                            RiskLevel.HIGH,
                            "Run-scoped TLS certificate issued by Certificate Authority Service",
                        )
                    )
                    certificate_dependencies = (
                        f"privateca:certificate:{prefix}-certificate",
                    )
                resources.append(
                    DesiredResource(
                        "secretmanager",
                        "secret_version",
                        tls_secret_name,
                        RiskLevel.HIGH,
                        "Validated ILB certificate chain and private key payload",
                        (
                            f"secretmanager:secret:{tls_secret_name}",
                            *certificate_dependencies,
                        ),
                    )
                )
            if spec.certificate_strategy is CertificateStrategy.LOCAL_POC:
                resources.append(
                    DesiredResource(
                        "local",
                        "root_certificate_artifact",
                        f"{prefix}-poc-root",
                        RiskLevel.HIGH,
                        "Public root CA for manual Chrome Root Store distribution",
                        (f"secretmanager:secret_version:{tls_secret_name}",),
                    )
                )
            resources.extend(
                [
                    DesiredResource(
                        "compute",
                        "ssl_certificate",
                        f"{prefix}-ilb-cert",
                        RiskLevel.HIGH,
                        "Regional server certificate presented by the internal HTTPS load balancer",
                        (
                            (
                                f"secretmanager:secret:{tls_secret_name}"
                                if spec.certificate_strategy
                                is CertificateStrategy.PUBLIC_TRUSTED
                                else f"secretmanager:secret_version:{tls_secret_name}"
                            ),
                        ),
                    ),
                    DesiredResource(
                        "compute",
                        "url_map",
                        f"{prefix}-ilb-map",
                        RiskLevel.HIGH,
                        "Regional URL map forwarding requests to the HTTP backend service",
                        (f"compute:backend_service:{prefix}-ilb-bs",),
                    ),
                    DesiredResource(
                        "compute",
                        "target_https_proxy",
                        f"{prefix}-ilb-proxy",
                        RiskLevel.HIGH,
                        "Regional HTTPS proxy terminating TLS with the ILB certificate",
                        (
                            f"compute:url_map:{prefix}-ilb-map",
                            f"compute:ssl_certificate:{prefix}-ilb-cert",
                        ),
                    ),
                    DesiredResource(
                        "compute",
                        "forwarding_rule",
                        f"{prefix}-ilb-fr",
                        RiskLevel.HIGH,
                        "Regional internal Application Load Balancer HTTPS frontend",
                        (
                            f"compute:target_https_proxy:{prefix}-ilb-proxy",
                            f"compute:internal_address:{prefix}-offload-ip",
                            f"compute:subnetwork:{prefix}-proxy-subnet",
                        ),
                    ),
                    DesiredResource(
                        "dns",
                        "private_zone",
                        f"{prefix}-zone",
                        RiskLevel.MEDIUM,
                        f"Private DNS authority for {spec.private_hostname}",
                    ),
                    DesiredResource(
                        "dns",
                        "record_set",
                        spec.private_hostname,
                        RiskLevel.MEDIUM,
                        "Private A record pointing to the internal HTTPS load balancer",
                        (
                            f"dns:private_zone:{prefix}-zone",
                            f"compute:internal_address:{prefix}-offload-ip",
                        ),
                    ),
                    DesiredResource(
                        "beyondcorp",
                        "security_gateway",
                        spec.gateway_id,
                        RiskLevel.HIGH,
                        "Service Discovery-enabled Secure Gateway",
                        shared=spec.gateway_id == "default",
                    ),
                    DesiredResource(
                        "beyondcorp",
                        "gateway_iam",
                        f"{spec.gateway_id}-service-discovery-users",
                        RiskLevel.HIGH,
                        "Grant Service Discovery use to the approved principal set",
                        (f"beyondcorp:security_gateway:{spec.gateway_id}",),
                    ),
                    DesiredResource(
                        "cloudresourcemanager",
                        "project_iam",
                        f"{prefix}-upstream-access",
                        RiskLevel.HIGH,
                        "Grant roles/beyondcorp.upstreamAccess to the gateway delegating account",
                        (f"beyondcorp:security_gateway:{spec.gateway_id}",),
                        shared=True,
                    ),
                    DesiredResource(
                        "beyondcorp",
                        "application",
                        f"{prefix}-app",
                        RiskLevel.HIGH,
                        f"HTTPS application matcher {spec.private_hostname}:443",
                        (
                            f"beyondcorp:security_gateway:{spec.gateway_id}",
                            f"compute:forwarding_rule:{prefix}-ilb-fr",
                            f"cloudresourcemanager:project_iam:{prefix}-upstream-access",
                        ),
                    ),
                    DesiredResource(
                        "beyondcorp",
                        "application_iam",
                        f"{prefix}-app-access",
                        RiskLevel.HIGH,
                        "Grant application access to the approved principal set",
                        (
                            f"beyondcorp:application:{prefix}-app",
                            *(
                                (
                                    "accesscontextmanager:access_level:"
                                    f"{spec.managed_chrome_access_level}",
                                )
                                if spec.managed_chrome_access_level
                                else ()
                            ),
                        ),
                    ),
                    DesiredResource(
                        "chromepolicy",
                        "extension_install",
                        "ekajlcmdfcigmdbphhifahdfjbkciflj",
                        RiskLevel.HIGH,
                        "Force-install the Secure Enterprise Browser extension in the test OU",
                        shared=True,
                    ),
                    DesiredResource(
                        "chromepolicy",
                        "extension_install",
                        "callobklhcbilhphinckomhgkigmfocg",
                        RiskLevel.HIGH,
                        "Force-install Endpoint Verification for managed Chrome signals",
                        shared=True,
                    ),
                    DesiredResource(
                        "chromepolicy",
                        "extension_configuration",
                        "ekajlcmdfcigmdbphhifahdfjbkciflj",
                        RiskLevel.HIGH,
                        "Configure the gateway resource and Service Discovery routes",
                        (f"beyondcorp:security_gateway:{spec.gateway_id}",),
                        shared=True,
                    ),
                    DesiredResource(
                        "chromepolicy",
                        "service_discovery_proxy",
                        spec.target_ou_id,
                        RiskLevel.HIGH,
                        "Override an inherited legacy PAC in the test OU for Service Discovery",
                        (
                            "chromepolicy:extension_configuration:"
                            "ekajlcmdfcigmdbphhifahdfjbkciflj",
                        ),
                        shared=True,
                    ),
                ]
            )
            resources.extend(
                DesiredResource(
                    "chromepolicy",
                    "group_extension_configuration",
                    group_email,
                    RiskLevel.BLOCKING,
                    "A group policy overrides the target OU Secure Gateway configuration",
                    shared=True,
                )
                for group_email in snapshot.chrome_extension_group_conflicts
            )
            return resources

        resources.extend(
            [
                *(
                    [
                        DesiredResource(
                            "compute",
                            "source_image",
                            spec.source_image,
                            RiskLevel.HIGH,
                            "Existing immutable hardened image with Nginx and Python",
                            shared=True,
                            must_exist=True,
                        )
                    ]
                    if spec.source_image
                    else []
                ),
                *(
                    [
                        DesiredResource(
                            "accesscontextmanager",
                            "access_level",
                            spec.managed_chrome_access_level,
                            RiskLevel.HIGH,
                            "Existing access level requiring a managed Chrome profile or browser",
                            shared=True,
                            must_exist=True,
                        )
                    ]
                    if spec.managed_chrome_access_level
                    else []
                ),
                DesiredResource(
                    "iam",
                    "service_account",
                    offload_account,
                    RiskLevel.LOW,
                    "Dedicated identity for the HTTPS offload VM",
                ),
                DesiredResource(
                    "compute",
                    "internal_address",
                    f"{prefix}-offload-ip",
                    RiskLevel.MEDIUM,
                    "Stable private address for the HTTPS offload VM",
                ),
            ]
        )
        resources.append(
            DesiredResource(
                "secretmanager",
                "secret",
                tls_secret_name,
                RiskLevel.HIGH,
                "TLS material readable only by the offload identity",
                shared=spec.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED,
                must_exist=spec.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED,
            )
        )
        if spec.certificate_strategy is not CertificateStrategy.PUBLIC_TRUSTED:
            certificate_dependencies: tuple[str, ...] = ()
            if spec.certificate_strategy is CertificateStrategy.ENTERPRISE_CA:
                resources.append(
                    DesiredResource(
                        "privateca",
                        "certificate",
                        f"{prefix}-certificate",
                        RiskLevel.HIGH,
                        "Run-scoped TLS certificate issued by Certificate Authority Service",
                    )
                )
                certificate_dependencies = (
                    f"privateca:certificate:{prefix}-certificate",
                )
            resources.append(
                DesiredResource(
                    "secretmanager",
                    "secret_version",
                    tls_secret_name,
                    RiskLevel.HIGH,
                    "Validated certificate chain and private key payload",
                    (
                        f"secretmanager:secret:{tls_secret_name}",
                        *certificate_dependencies,
                    ),
                )
            )
        if spec.certificate_strategy is CertificateStrategy.LOCAL_POC:
            resources.append(
                DesiredResource(
                    "local",
                    "root_certificate_artifact",
                    f"{prefix}-poc-root",
                    RiskLevel.HIGH,
                    "Public PoC root certificate for Admin console trust upload",
                    (f"secretmanager:secret_version:{tls_secret_name}",),
                )
            )
        resources.append(
            DesiredResource(
                "secretmanager",
                "secret_iam",
                f"{prefix}-tls-accessor",
                RiskLevel.HIGH,
                "Grant Secret Accessor only to the offload service account",
                (
                    f"secretmanager:secret:{tls_secret_name}",
                    f"iam:service_account:{offload_account}",
                ),
            )
        )

        if spec.backend_kind is BackendKind.MANAGED_SAMPLE:
            resources.extend(
                [
                    DesiredResource(
                        "iam",
                        "service_account",
                        backend_account,
                        RiskLevel.LOW,
                        "Dedicated identity for the HTTP backend VM",
                    ),
                    DesiredResource(
                        "compute",
                        "internal_address",
                        f"{prefix}-backend-ip",
                        RiskLevel.MEDIUM,
                        "Stable private address for the sample backend",
                    ),
                    DesiredResource(
                        "compute",
                        "instance",
                        f"{prefix}-backend",
                        RiskLevel.MEDIUM,
                        "Private HTTP sample backend with no external IP",
                        (
                            f"iam:service_account:{backend_account}",
                            f"compute:internal_address:{prefix}-backend-ip",
                        ),
                    ),
                    DesiredResource(
                        "compute",
                        "firewall_rule",
                        f"{prefix}-backend-ingress",
                        RiskLevel.HIGH,
                        "Allow only the offload service identity to backend TCP 80",
                        (
                            f"iam:service_account:{offload_account}",
                            f"iam:service_account:{backend_account}",
                        ),
                    ),
                ]
            )

        if spec.mode.value == "production":
            resources.extend(
                [
                    DesiredResource(
                        "compute",
                        "instance_template",
                        f"{prefix}-offload-template",
                        RiskLevel.MEDIUM,
                        "Hardened private offload VM template",
                        (
                            f"iam:service_account:{offload_account}",
                            f"secretmanager:secret:{tls_secret_name}",
                            f"secretmanager:secret_iam:{prefix}-tls-accessor",
                        ),
                    ),
                    DesiredResource(
                        "compute",
                        "health_check",
                        f"{prefix}-offload-hc",
                        RiskLevel.MEDIUM,
                        "Regional TLS health check for the offload tier",
                    ),
                    DesiredResource(
                        "compute",
                        "instance_group_manager",
                        f"{prefix}-offload-mig",
                        RiskLevel.HIGH,
                        (
                            "Two-zone regional managed instance group with "
                            f"{spec.offload_min_replicas} baseline replicas"
                        ),
                        (f"compute:instance_template:{prefix}-offload-template",),
                    ),
                    DesiredResource(
                        "compute",
                        "autoscaler",
                        f"{prefix}-offload-autoscaler",
                        RiskLevel.HIGH,
                        (
                            "CPU autoscaling for the Nginx offload tier "
                            f"({spec.offload_min_replicas}-"
                            f"{spec.offload_max_replicas} replicas)"
                        ),
                        (f"compute:instance_group_manager:{prefix}-offload-mig",),
                    ),
                    DesiredResource(
                        "compute",
                        "firewall_rule",
                        f"{prefix}-health-check-ingress",
                        RiskLevel.HIGH,
                        "Allow Google load-balancer health checks to offload TCP 443",
                        (
                            f"compute:health_check:{prefix}-offload-hc",
                            f"compute:instance_group_manager:{prefix}-offload-mig",
                        ),
                    ),
                    DesiredResource(
                        "compute",
                        "backend_service",
                        f"{prefix}-offload-bs",
                        RiskLevel.HIGH,
                        "Regional internal TCP load-balancer backend",
                        (
                            f"compute:health_check:{prefix}-offload-hc",
                            f"compute:instance_group_manager:{prefix}-offload-mig",
                        ),
                    ),
                    DesiredResource(
                        "compute",
                        "forwarding_rule",
                        f"{prefix}-offload-fr",
                        RiskLevel.HIGH,
                        "Stable internal HTTPS load-balancer frontend",
                        (
                            f"compute:backend_service:{prefix}-offload-bs",
                            f"compute:internal_address:{prefix}-offload-ip",
                        ),
                    ),
                ]
            )
            offload_dependency = (f"compute:forwarding_rule:{prefix}-offload-fr",)
        else:
            resources.append(
                DesiredResource(
                    "compute",
                    "instance",
                    f"{prefix}-offload",
                    RiskLevel.MEDIUM,
                    "Private Nginx HTTPS-to-HTTP offload VM",
                    (
                        f"iam:service_account:{offload_account}",
                        f"secretmanager:secret:{tls_secret_name}",
                        f"secretmanager:secret_iam:{prefix}-tls-accessor",
                        f"compute:internal_address:{prefix}-offload-ip",
                    ),
                )
            )
            offload_dependency = (f"compute:instance:{prefix}-offload",)

        secret_version_key = f"secretmanager:secret_version:{tls_secret_name}"
        existing_offload_key = (
            f"compute:instance_group_manager:{prefix}-offload-mig"
            if spec.mode.value == "production"
            else f"compute:instance:{prefix}-offload"
        )
        if (
            spec.certificate_strategy is not CertificateStrategy.PUBLIC_TRUSTED
            and secret_version_key not in snapshot.existing_resource_keys
            and existing_offload_key in snapshot.existing_resource_keys
        ):
            resources.append(
                DesiredResource(
                    "compute",
                    "offload_refresh",
                    f"{prefix}-certificate-refresh",
                    RiskLevel.HIGH,
                    "Restart the existing offload tier onto the new active TLS version",
                    (secret_version_key, existing_offload_key),
                    shared=True,
                )
            )

        resources.extend(
            [
                DesiredResource(
                    "compute",
                    "firewall_rule",
                    f"{prefix}-gateway-ingress",
                    RiskLevel.HIGH,
                    "Allow 136.124.16.0/20 to offload TCP 443 only",
                    offload_dependency,
                ),
                DesiredResource(
                    "dns",
                    "private_zone",
                    f"{prefix}-zone",
                    RiskLevel.MEDIUM,
                    f"Private DNS authority for {spec.private_hostname}",
                ),
                DesiredResource(
                    "dns",
                    "record_set",
                    spec.private_hostname,
                    RiskLevel.MEDIUM,
                    "Private A record pointing to the stable offload address",
                    (
                        f"dns:private_zone:{prefix}-zone",
                        f"compute:internal_address:{prefix}-offload-ip",
                    ),
                ),
                DesiredResource(
                    "beyondcorp",
                    "security_gateway",
                    spec.gateway_id,
                    RiskLevel.HIGH,
                    "Service Discovery-enabled Secure Gateway",
                    shared=spec.gateway_id == "default",
                ),
                DesiredResource(
                    "beyondcorp",
                    "gateway_iam",
                    f"{spec.gateway_id}-service-discovery-users",
                    RiskLevel.HIGH,
                    "Grant Service Discovery use to the approved principal set",
                    (f"beyondcorp:security_gateway:{spec.gateway_id}",),
                ),
                DesiredResource(
                    "cloudresourcemanager",
                    "project_iam",
                    f"{prefix}-upstream-access",
                    RiskLevel.HIGH,
                    "Grant roles/beyondcorp.upstreamAccess to the gateway delegating account",
                    (f"beyondcorp:security_gateway:{spec.gateway_id}",),
                    shared=True,
                ),
                DesiredResource(
                    "beyondcorp",
                    "application",
                    f"{prefix}-app",
                    RiskLevel.HIGH,
                    f"HTTPS application matcher {spec.private_hostname}:443",
                    (f"beyondcorp:security_gateway:{spec.gateway_id}",),
                ),
                DesiredResource(
                    "beyondcorp",
                    "application_iam",
                    f"{prefix}-app-access",
                    RiskLevel.HIGH,
                    "Grant application access to the approved principal set",
                    (
                        f"beyondcorp:application:{prefix}-app",
                        *(
                            (
                                "accesscontextmanager:access_level:"
                                f"{spec.managed_chrome_access_level}",
                            )
                            if spec.managed_chrome_access_level
                            else ()
                        ),
                    ),
                ),
                DesiredResource(
                    "chromepolicy",
                    "extension_install",
                    "ekajlcmdfcigmdbphhifahdfjbkciflj",
                    RiskLevel.HIGH,
                    "Force-install the Secure Enterprise Browser extension in the test OU",
                    shared=True,
                ),
                DesiredResource(
                    "chromepolicy",
                    "extension_install",
                    "callobklhcbilhphinckomhgkigmfocg",
                    RiskLevel.HIGH,
                    "Force-install Endpoint Verification for managed Chrome signals",
                    shared=True,
                ),
                DesiredResource(
                    "chromepolicy",
                    "extension_configuration",
                    "ekajlcmdfcigmdbphhifahdfjbkciflj",
                    RiskLevel.HIGH,
                    "Configure the gateway resource and Service Discovery routes",
                    (f"beyondcorp:security_gateway:{spec.gateway_id}",),
                    shared=True,
                ),
                DesiredResource(
                    "chromepolicy",
                    "service_discovery_proxy",
                    spec.target_ou_id,
                    RiskLevel.HIGH,
                    "Override an inherited legacy PAC in the test OU for Service Discovery",
                    (
                        "chromepolicy:extension_configuration:"
                        "ekajlcmdfcigmdbphhifahdfjbkciflj",
                    ),
                    shared=True,
                ),
            ]
        )
        resources.extend(
            DesiredResource(
                "chromepolicy",
                "group_extension_configuration",
                group_email,
                RiskLevel.BLOCKING,
                "A group policy overrides the target OU Secure Gateway configuration",
                shared=True,
            )
            for group_email in snapshot.chrome_extension_group_conflicts
        )
        return resources

    def _gates(
        self,
        spec: DeploymentSpec,
        snapshot: DiscoverySnapshot,
        changes: list[ResourceChange],
    ) -> list[DeploymentGate]:
        missing_apis = sorted(required_apis(spec) - snapshot.enabled_apis)
        conflicts = [
            change.resource_name for change in changes if change.action is ChangeAction.CONFLICT
        ]
        private_egress_status = (
            "pass"
            if spec.backend_kind is BackendKind.DIRECT_HTTPS
            or spec.network_strategy is NetworkStrategy.DEDICATED
            or snapshot.private_egress_available is True
            else "pending"
        )
        missing_permissions = sorted(required_permissions(spec) - snapshot.granted_permissions)
        public_binding_required = requires_public_certificate_binding(spec)
        public_binding_valid = public_certificate_binding_matches_spec(
            spec,
            snapshot.public_certificate_binding,
        )
        source_image_binding_required = spec.backend_kind is not BackendKind.DIRECT_HTTPS
        source_image_binding_valid = source_image_binding_matches_spec(
            spec,
            snapshot.source_image_binding,
        )

        return [
            DeploymentGate(
                gate_id="immutable-image",
                title="Immutable hardened image",
                status=(
                    "pass"
                    if not source_image_binding_required or source_image_binding_valid
                    else "blocked"
                ),
                blocking=source_image_binding_required,
                detail=(
                    "Direct HTTPS creates no Nginx VM, so no source image is required."
                    if not source_image_binding_required
                    else "The approved plan is bound to the immutable Compute image ID."
                    if source_image_binding_valid
                    else "Discovery must bind the exact image name, selfLink, and numeric ID "
                    "before approval."
                ),
            ),
            DeploymentGate(
                gate_id="billing-enabled",
                title="Cloud billing",
                status="pass" if snapshot.billing_enabled is True else "blocked",
                blocking=True,
                detail=(
                    "The deployment project has an active billing association."
                    if snapshot.billing_enabled is True
                    else "Cloud Billing API must confirm an active billing association."
                ),
            ),
            DeploymentGate(
                gate_id="enterprise-license",
                title="Chrome Enterprise Premium license",
                status=(
                    "pass"
                    if (
                        (snapshot.chrome_enterprise_premium_license_count or 0) > 0
                        or spec.chrome_enterprise_premium_license_confirmed
                    )
                    else "blocked"
                    if spec.mode.value == "production"
                    else "pending"
                ),
                blocking=spec.mode.value == "production",
                detail=(
                    "Enterprise License Manager API found "
                    f"{snapshot.chrome_enterprise_premium_license_count} assigned "
                    "Chrome Enterprise Premium license(s)."
                    if snapshot.chrome_enterprise_premium_license_count is not None
                    and snapshot.chrome_enterprise_premium_license_count > 0
                    else "The operator confirmed the required enterprise license."
                    if spec.chrome_enterprise_premium_license_confirmed
                    else "No Chrome Enterprise Premium assignment was detected."
                ),
            ),
            DeploymentGate(
                gate_id="chrome-root-store",
                title="Chrome Root Store trust distribution",
                status=(
                    "pass"
                    if spec.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED
                    or (
                        spec.backend_kind is not BackendKind.DIRECT_HTTPS
                        and spec.certificate_strategy is not CertificateStrategy.LOCAL_POC
                    )
                    else "pending"
                ),
                blocking=False,
                detail=(
                    "The HTTPS application uses a publicly trusted certificate."
                    if spec.backend_kind is BackendKind.DIRECT_HTTPS
                    and spec.certificate_strategy is CertificateStrategy.PUBLIC_TRUSTED
                    else "The selected certificate strategy does not require PoC Root Store "
                    "distribution."
                    if spec.certificate_strategy is not CertificateStrategy.LOCAL_POC
                    and spec.backend_kind is not BackendKind.DIRECT_HTTPS
                    else "Obtain the HTTPS application's issuing root PEM from the app owner, "
                    "upload it in Chrome Root Store, and connect the configuration to the "
                    "test OU. Public APIs cannot attest this handoff; verify it with T07."
                    if spec.backend_kind is BackendKind.DIRECT_HTTPS
                    else "After Apply, upload the generated PoC root in Chrome Root Store "
                    "and connect the configuration to the selected test OU. Public APIs "
                    "cannot attest this handoff; verify it with the platform-specific T07 "
                    "HTTPS test."
                ),
            ),
            DeploymentGate(
                gate_id="workspace-services",
                title="Workspace service prerequisites",
                status=(
                    "pass"
                    if spec.workspace_services_confirmed
                    else "blocked"
                    if spec.mode.value == "production"
                    else "pending"
                ),
                blocking=spec.mode.value == "production",
                detail=(
                    "Additional Google services and Google Cloud access are enabled "
                    "for target users."
                ),
            ),
            DeploymentGate(
                gate_id="managed-chrome-profile",
                title="Managed Chrome profile reporting",
                status=(
                    "pass"
                    if (snapshot.managed_chrome_profile_count or 0) > 0
                    else "pending"
                ),
                blocking=False,
                detail=(
                    f"Chrome Management Profiles API found "
                    f"{snapshot.managed_chrome_profile_count} reporting profile(s), "
                    f"including {snapshot.profile_only_count or 0} profile-managed BYOD "
                    f"profile(s); latest policy sync: "
                    f"{snapshot.latest_chrome_policy_sync or 'not reported'}."
                    if snapshot.managed_chrome_profile_count is not None
                    else "Chrome profile reporting could not be verified by API."
                ),
            ),
            DeploymentGate(
                gate_id="secure-enterprise-browser-client",
                title="Secure Enterprise Browser client",
                status=(
                    "pass"
                    if snapshot.secure_enterprise_browser_installed is True
                    else "pending"
                ),
                blocking=False,
                detail=(
                    "Chrome Management Profiles API reports Secure Enterprise Browser "
                    f"{snapshot.secure_enterprise_browser_version or ''} installed and enabled."
                    if snapshot.secure_enterprise_browser_installed is True
                    else "No enabled Secure Enterprise Browser client was reported yet."
                ),
            ),
            DeploymentGate(
                gate_id="endpoint-verification",
                title="Endpoint Verification signals",
                status=(
                    "pass"
                    if (
                        snapshot.endpoint_verification_installed is True
                        or spec.endpoint_verification_confirmed
                    )
                    else "blocked"
                    if spec.mode.value == "production"
                    else "pending"
                ),
                blocking=spec.mode.value == "production",
                detail=(
                    "Chrome Management Profiles API reports Endpoint Verification "
                    f"{snapshot.endpoint_verification_version or ''} installed and enabled."
                    if snapshot.endpoint_verification_installed is True
                    else "Device signal collection was manually confirmed for the target OU."
                    if spec.endpoint_verification_confirmed
                    else "Apply will force-install Endpoint Verification in the test OU."
                ),
            ),
            DeploymentGate(
                gate_id="no-external-ips",
                title="No external IPs",
                status="pass" if not spec.allow_external_ips else "blocked",
                blocking=True,
                detail="Compute instances must remain private.",
            ),
            DeploymentGate(
                gate_id="private-egress",
                title="Private package egress",
                status=private_egress_status,
                blocking=True,
                detail=(
                    "Direct HTTPS creates no VM and requires no package egress path."
                    if spec.backend_kind is BackendKind.DIRECT_HTTPS
                    else "Cloud NAT is included in the desired state."
                    if spec.network_strategy is NetworkStrategy.DEDICATED
                    else "The existing VPC must provide a verified private egress path."
                ),
            ),
            DeploymentGate(
                gate_id="backend-connectivity",
                title="Existing backend private connectivity",
                status=(
                    "pass"
                    if spec.backend_kind is BackendKind.MANAGED_SAMPLE
                    or spec.existing_backend_connectivity_confirmed
                    else "blocked"
                ),
                blocking=True,
                detail=(
                    "The managed sample backend is created inside the deployment VPC."
                    if spec.backend_kind is BackendKind.MANAGED_SAMPLE
                    else "The operator confirmed that the selected VPC resolves and routes "
                    f"{spec.application_hostname}:{spec.application_port}, permits ingress "
                    "from 136.124.16.0/20, and provides a return path. Secure Gateway connects "
                    "directly to the HTTPS app; no Nginx resources are created."
                    if spec.backend_kind is BackendKind.DIRECT_HTTPS
                    and spec.existing_backend_connectivity_confirmed
                    else "The operator confirmed an existing routed private path from the "
                    f"GCP offload subnet to the {spec.existing_backend_location.value} "
                    "backend. Apply validates the HTTP path with T02; it does not create "
                    "cross-cloud VPN or Interconnect resources."
                    if spec.existing_backend_connectivity_confirmed
                    and spec.existing_backend_location is not None
                    and spec.backend_kind is BackendKind.EXISTING_HTTP
                    else "Establish private routing, DNS, and backend firewall access before "
                    "Apply. For direct HTTPS, allow 136.124.16.0/20 and configure its return "
                    "route. Cross-cloud VPN and Interconnect creation is outside this PoC."
                ),
            ),
            DeploymentGate(
                gate_id="global-access",
                title="Regional load balancer global access",
                status=_global_access_status(spec, snapshot),
                # Blocking only when the forwarding rule was resolved and Global
                # Access is definitively off. An FQDN matcher, a GKE ingress, or
                # a non-GCP backend cannot be resolved, and those are supported
                # Path B targets rather than failures.
                blocking=(
                    spec.backend_kind is BackendKind.DIRECT_HTTPS
                    and (
                        not snapshot.application_global_access_discovery_complete
                        or (
                            spec.application_egress_region is None
                            and snapshot.application_global_access is False
                        )
                    )
                ),
                detail=_global_access_detail(spec, snapshot),
            ),
            DeploymentGate(
                gate_id="test-ou",
                title="Dedicated test OU",
                status="pass" if spec.test_ou_confirmed else "blocked",
                blocking=True,
                detail="Chrome policy changes require prior validation in a test OU.",
            ),
            DeploymentGate(
                gate_id="cloud-identity",
                title="Keyless deployer identity",
                status="pass" if snapshot.cloud_identity else "pending",
                blocking=True,
                detail=(
                    "Impersonate the dedicated service account with the required GCP permissions."
                ),
            ),
            DeploymentGate(
                gate_id="workspace-identity",
                title="Chrome-authorized deployer",
                status="pass" if snapshot.workspace_identity else "pending",
                blocking=True,
                detail=(
                    "Assign the impersonated service account the required direct Chrome admin role."
                ),
            ),
            DeploymentGate(
                gate_id="required-apis",
                title="Required APIs",
                status="pass",
                blocking=True,
                detail=(
                    "All required services are enabled."
                    if not missing_apis
                    else f"{len(missing_apis)} APIs must be enabled during Apply."
                ),
            ),
            DeploymentGate(
                gate_id="apply-permissions",
                title="Apply permissions",
                status="pass" if not missing_permissions else "blocked",
                blocking=True,
                detail=(
                    "The Cloud operator has the required project permissions."
                    if not missing_permissions
                    else f"{len(missing_permissions)} required permissions are missing."
                ),
            ),
            DeploymentGate(
                gate_id="group-policy-discovery",
                title="Group policy discovery",
                status=(
                    "pass"
                    if snapshot.chrome_group_policy_discovery_complete
                    else "blocked"
                ),
                blocking=True,
                detail=(
                    "Higher-priority Chrome group policies were inspected."
                    if snapshot.chrome_group_policy_discovery_complete
                    else "Apply is blocked because higher-priority Chrome group policies "
                    "could not be inspected completely."
                ),
            ),
            DeploymentGate(
                gate_id="public-certificate-binding",
                title="Public certificate immutable version",
                status=(
                    "pass"
                    if not public_binding_required or public_binding_valid
                    else "blocked"
                ),
                blocking=public_binding_required,
                detail=(
                    "The selected topology does not consume an operator-owned TLS secret."
                    if not public_binding_required
                    else "The approved plan is bound to the validated numeric SecretVersion."
                    if public_binding_valid
                    else "Discovery must validate and bind the exact numeric public TLS "
                    "SecretVersion before approval."
                ),
            ),
            DeploymentGate(
                gate_id="resource-conflicts",
                title="Resource conflicts",
                status="pass" if not conflicts else "blocked",
                blocking=True,
                detail=(
                    "No incompatible resource collisions detected."
                    if not conflicts
                    else f"Conflicts: {', '.join(conflicts)}"
                ),
            ),
            DeploymentGate(
                gate_id="human-approval",
                title="Explicit approval",
                status="pending",
                blocking=True,
                detail="An authorized operator must approve the final redacted plan.",
            ),
        ]
