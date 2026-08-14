from pathlib import Path

import pytest
from pydantic import ValidationError

from sgstudio.domain.models import (
    AccessPrincipal,
    BackendKind,
    BackendLocation,
    CertificateStrategy,
    ChromePlatform,
    DeploymentGate,
    DeploymentMode,
    DeploymentPlan,
    DeploymentSpec,
    DiscoverySnapshot,
    NetworkStrategy,
    PrincipalType,
)
from sgstudio.domain.naming import service_account_id
from sgstudio.domain.planner import (
    REQUIRED_APIS,
    REQUIRED_PERMISSIONS,
    DesiredStatePlanner,
    canonical_configuration_hash,
    required_apis,
    required_permissions,
)


def test_deployer_role_manifest_matches_preflight_permissions() -> None:
    manifest = (
        Path(__file__).parents[2] / "infrastructure" / "iam" / "secure-gateway-deployer-role.yaml"
    )
    manifest_permissions = {
        line.removeprefix("  - ").strip()
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if line.startswith("  - ")
    }

    assert manifest_permissions == REQUIRED_PERMISSIONS


def test_poc_bootstrap_role_matches_poc_permissions_not_supplied_by_base_roles() -> None:
    manifest = (
        Path(__file__).parents[2]
        / "infrastructure"
        / "iam"
        / "secure-gateway-poc-deployer-role.yaml"
    )
    manifest_permissions = {
        line.removeprefix("  - ").strip()
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if line.startswith("  - ")
    }
    common = dict(
        mode="poc",
        certificate_strategy="local_poc",
        source_image=None,
        chrome_enterprise_premium_license_confirmed=False,
        workspace_services_confirmed=False,
        endpoint_verification_confirmed=False,
    )
    nginx_spec = production_spec(**common)
    ilb_spec = production_spec(
        **common,
        backend_kind=BackendKind.INTERNAL_HTTPS_LB,
        proxy_subnet_cidr="10.42.1.0/24",
    )
    base_role_permissions = {
        "accesscontextmanager.accessLevels.get",
        "resourcemanager.projects.get",
        "resourcemanager.projects.getIamPolicy",
        "serviceusage.operations.get",
        "serviceusage.services.get",
        "serviceusage.services.list",
        "serviceusage.services.use",
    }

    expected_permissions = (
        required_permissions(nginx_spec) | required_permissions(ilb_spec)
    ) - base_role_permissions

    assert manifest_permissions == expected_permissions


def test_internal_https_lb_plans_managed_tls_offload_without_nginx() -> None:
    spec = production_spec(
        mode="poc",
        backend_kind=BackendKind.INTERNAL_HTTPS_LB,
        certificate_strategy=CertificateStrategy.LOCAL_POC,
        source_image=None,
        proxy_subnet_cidr="10.42.1.0/24",
        chrome_enterprise_premium_license_confirmed=False,
        workspace_services_confirmed=False,
        endpoint_verification_confirmed=False,
    )

    plan = DesiredStatePlanner().build_plan(spec)
    resources = {
        (change.provider, change.resource_type, change.resource_name)
        for change in plan.changes
    }

    assert ("compute", "subnetwork", f"{spec.name}-proxy-subnet") in resources
    assert ("compute", "instance_group", f"{spec.name}-backend-ig") in resources
    assert ("compute", "ssl_certificate", f"{spec.name}-ilb-cert") in resources
    assert ("compute", "url_map", f"{spec.name}-ilb-map") in resources
    assert ("compute", "target_https_proxy", f"{spec.name}-ilb-proxy") in resources
    assert ("compute", "forwarding_rule", f"{spec.name}-ilb-fr") in resources
    assert ("compute", "instance", f"{spec.name}-backend") in resources
    assert ("compute", "instance", f"{spec.name}-offload") not in resources
    assert not any(
        resource_type == "instance_group_manager" for _, resource_type, _ in resources
    )
    assert not any(resource_type == "secret_iam" for _, resource_type, _ in resources)
    ordered_keys = [
        f"{change.provider}:{change.resource_type}:{change.resource_name}"
        for change in plan.changes
    ]
    assert ordered_keys.index(f"compute:firewall_rule:{spec.name}-ilb-health-ingress") < (
        ordered_keys.index(f"compute:forwarding_rule:{spec.name}-ilb-fr")
    )


def test_internal_https_lb_rejects_overlapping_proxy_subnet() -> None:
    with pytest.raises(ValidationError, match="must not overlap"):
        production_spec(
            mode="poc",
            backend_kind=BackendKind.INTERNAL_HTTPS_LB,
            certificate_strategy=CertificateStrategy.LOCAL_POC,
            source_image=None,
            subnet_cidr="10.42.0.0/24",
            proxy_subnet_cidr="10.42.0.128/25",
            chrome_enterprise_premium_license_confirmed=False,
            workspace_services_confirmed=False,
            endpoint_verification_confirmed=False,
        )


def test_internal_address_permissions_cover_create_and_rollback() -> None:
    permissions = required_permissions(
        production_spec(
            mode="poc",
            certificate_strategy="local_poc",
            source_image=None,
            chrome_enterprise_premium_license_confirmed=False,
            workspace_services_confirmed=False,
            endpoint_verification_confirmed=False,
        )
    )

    assert "compute.addresses.createInternal" in permissions
    assert "compute.addresses.deleteInternal" in permissions


def test_instance_permissions_cover_labels_and_network_tags() -> None:
    permissions = required_permissions(
        production_spec(
            mode="poc",
            certificate_strategy="local_poc",
            source_image=None,
            chrome_enterprise_premium_license_confirmed=False,
            workspace_services_confirmed=False,
            endpoint_verification_confirmed=False,
        )
    )

    assert "compute.instances.setLabels" in permissions
    assert "compute.instances.setTags" in permissions


def test_private_dns_permissions_cover_network_binding() -> None:
    permissions = required_permissions(
        production_spec(
            mode="poc",
            certificate_strategy="local_poc",
            source_image=None,
            chrome_enterprise_premium_license_confirmed=False,
            workspace_services_confirmed=False,
            endpoint_verification_confirmed=False,
        )
    )

    assert "dns.networks.bindPrivateDNSZone" in permissions
    assert "dns.resourceRecordSets.get" in permissions


def test_beyondcorp_permissions_cover_long_running_operations() -> None:
    permissions = required_permissions(
        production_spec(
            mode="poc",
            certificate_strategy="local_poc",
            source_image=None,
            chrome_enterprise_premium_license_confirmed=False,
            workspace_services_confirmed=False,
            endpoint_verification_confirmed=False,
        )
    )

    assert "beyondcorp.operations.get" in permissions


def production_spec(**overrides) -> DeploymentSpec:
    values = {
        "project_id": "enterprise-secgw-01",
        "ca_pool": "projects/enterprise-secgw-01/locations/asia-east1/caPools/enterprise",
        "ca_name": (
            "projects/enterprise-secgw-01/locations/asia-east1/caPools/enterprise/"
            "certificateAuthorities/issuing"
        ),
        "target_ou_id": "03-test-ou",
        "managed_chrome_access_level": ("accessPolicies/123456789/accessLevels/managed_chrome"),
        "source_image": ("projects/enterprise-secgw-01/global/images/sgs-nginx-20260730"),
        "chrome_enterprise_premium_license_confirmed": True,
        "workspace_services_confirmed": True,
        "endpoint_verification_confirmed": True,
        "test_ou_confirmed": True,
        "principals": [
            AccessPrincipal(type=PrincipalType.GROUP, value="secure-access@example.com")
        ],
    }
    values.update(overrides)
    if values.get("backend_kind") in {BackendKind.EXISTING_HTTP, "existing_http"}:
        values.setdefault("existing_backend_location", BackendLocation.GCP)
        values.setdefault("existing_backend_connectivity_confirmed", True)
    return DeploymentSpec(**values)


def test_production_rejects_local_poc_ca() -> None:
    with pytest.raises(ValidationError, match="Production mode cannot use a local PoC CA"):
        production_spec(certificate_strategy=CertificateStrategy.LOCAL_POC)


def test_production_requires_managed_chrome_access_level() -> None:
    with pytest.raises(ValidationError, match="requires a managed Chrome access level"):
        production_spec(managed_chrome_access_level=None)


def test_production_requires_an_immutable_image_not_an_image_family() -> None:
    with pytest.raises(ValidationError, match="requires an immutable hardened source image"):
        production_spec(source_image=None)
    with pytest.raises(ValidationError, match="full immutable Compute Engine image"):
        production_spec(source_image="projects/debian-cloud/global/images/family/debian-12")


@pytest.mark.parametrize(
    ("field", "message"),
    [
        (
            "chrome_enterprise_premium_license_confirmed",
            "license confirmation",
        ),
        ("workspace_services_confirmed", "service prerequisites"),
        ("endpoint_verification_confirmed", "Endpoint Verification"),
    ],
)
def test_production_requires_manual_enterprise_prerequisite_confirmations(
    field: str,
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        production_spec(**{field: False})


def test_poc_can_use_local_ca() -> None:
    spec = production_spec(
        mode=DeploymentMode.POC,
        certificate_strategy=CertificateStrategy.LOCAL_POC,
        platforms={
            ChromePlatform.MACOS,
            ChromePlatform.WINDOWS,
            ChromePlatform.LINUX,
            ChromePlatform.CHROMEOS,
        },
    )
    assert spec.certificate_strategy is CertificateStrategy.LOCAL_POC
    plan = DesiredStatePlanner().build_plan(spec)
    root = next(
        change for change in plan.changes if change.resource_type == "root_certificate_artifact"
    )
    assert root.provider == "local"
    assert root.owned_after_apply is True


def test_local_poc_ca_accepts_profile_managed_desktop_chrome_targets() -> None:
    local_spec = production_spec(
        mode=DeploymentMode.POC,
        certificate_strategy=CertificateStrategy.LOCAL_POC,
        platforms={ChromePlatform.MACOS, ChromePlatform.CHROMEOS},
    )

    assert local_spec.platforms == {ChromePlatform.MACOS, ChromePlatform.CHROMEOS}


def test_plan_force_installs_secure_gateway_and_endpoint_verification() -> None:
    plan = DesiredStatePlanner().build_plan(production_spec())
    extension_ids = {
        change.resource_name
        for change in plan.changes
        if change.resource_type == "extension_install"
    }
    assert extension_ids == {
        "ekajlcmdfcigmdbphhifahdfjbkciflj",
        "callobklhcbilhphinckomhgkigmfocg",
    }


def test_plan_overrides_legacy_pac_for_service_discovery() -> None:
    plan = DesiredStatePlanner().build_plan(production_spec())

    proxy_change = next(
        change
        for change in plan.changes
        if change.resource_type == "service_discovery_proxy"
    )

    assert proxy_change.provider == "chromepolicy"
    assert proxy_change.resource_name == "03-test-ou"
    assert proxy_change.owned_after_apply is False
    assert proxy_change.dependencies == [
        "chromepolicy:extension_configuration:ekajlcmdfcigmdbphhifahdfjbkciflj"
    ]


def test_production_uses_two_zone_managed_offload_tier() -> None:
    plan = DesiredStatePlanner().build_plan(production_spec())
    resource_types = {change.resource_type for change in plan.changes}
    assert {
        "instance_template",
        "health_check",
        "instance_group_manager",
        "autoscaler",
        "backend_service",
        "forwarding_rule",
    } <= resource_types
    assert not any(
        change.resource_type == "instance" and change.resource_name.endswith("-offload")
        for change in plan.changes
    )


def test_production_rejects_invalid_autoscaling_range() -> None:
    with pytest.raises(ValidationError, match="offload_max_replicas"):
        production_spec(offload_min_replicas=10, offload_max_replicas=5)


def test_poc_does_not_require_autoscaler_permissions() -> None:
    permissions = required_permissions(
        production_spec(
            mode="poc",
            source_image=None,
            managed_chrome_access_level=None,
            chrome_enterprise_premium_license_confirmed=False,
            workspace_services_confirmed=False,
            endpoint_verification_confirmed=False,
        )
    )

    assert not any(permission.startswith("compute.autoscalers.") for permission in permissions)


def test_profile_api_readiness_marks_byod_and_extensions_verified() -> None:
    snapshot = DiscoverySnapshot(
        managed_chrome_profile_count=1,
        profile_only_count=1,
        latest_chrome_policy_sync="2026-08-03T07:15:16Z",
        endpoint_verification_installed=True,
        endpoint_verification_version="1.140.0",
        secure_enterprise_browser_installed=True,
        secure_enterprise_browser_version="1.26.129",
    )

    plan = DesiredStatePlanner().build_plan(production_spec(), snapshot)
    gates = {gate.gate_id: gate for gate in plan.gates}

    assert gates["managed-chrome-profile"].status == "pass"
    assert gates["secure-enterprise-browser-client"].status == "pass"
    assert gates["endpoint-verification"].status == "pass"
    assert "1.140.0" in gates["endpoint-verification"].detail


def test_api_verified_license_keeps_root_store_as_manual_t07_handoff() -> None:
    spec = production_spec(
        mode="poc",
        certificate_strategy="local_poc",
        source_image=None,
        chrome_enterprise_premium_license_confirmed=False,
        workspace_services_confirmed=False,
        endpoint_verification_confirmed=False,
    )
    snapshot = DiscoverySnapshot(
        chrome_enterprise_premium_license_count=32,
        chrome_root_store_enabled=True,
    )

    plan = DesiredStatePlanner().build_plan(spec, snapshot)
    gates = {gate.gate_id: gate for gate in plan.gates}

    assert gates["enterprise-license"].status == "pass"
    assert "32" in gates["enterprise-license"].detail
    assert gates["chrome-root-store"].status == "pending"
    assert gates["chrome-root-store"].blocking is False
    assert "T07" in gates["chrome-root-store"].detail


def test_group_extension_override_is_a_blocking_resource_conflict() -> None:
    email = "sg-demo@example.com"
    snapshot = DiscoverySnapshot(
        chrome_extension_group_conflicts=[email],
        conflicting_resource_keys={
            f"chromepolicy:group_extension_configuration:{email}"
        },
    )

    plan = DesiredStatePlanner().build_plan(production_spec(), snapshot)
    change = next(
        item
        for item in plan.changes
        if item.resource_type == "group_extension_configuration"
    )
    gates = {gate.gate_id: gate for gate in plan.gates}

    assert change.resource_name == email
    assert change.action.value == "conflict"
    assert gates["resource-conflicts"].status == "blocked"


def test_service_account_ids_are_stable_and_within_google_limit() -> None:
    first = service_account_id("secure-gateway-http-offload", "offload")
    second = service_account_id("secure-gateway-http-offload", "backend")

    assert first == "secure-gateway-cd03d7-offload"
    assert len(first) <= 30
    assert len(second) <= 30
    assert service_account_id("short-poc", "offload") == "short-poc-offload"


def test_runtime_probe_permissions_and_backend_firewall_precede_offload() -> None:
    spec = production_spec()
    plan = DesiredStatePlanner().build_plan(spec)
    keys = [
        f"{change.provider}:{change.resource_type}:{change.resource_name}"
        for change in plan.changes
    ]

    assert "compute.instances.getGuestAttributes" in required_permissions(spec)
    assert keys.index(
        "compute:firewall_rule:secure-gateway-http-offload-backend-ingress"
    ) < keys.index("compute:instance_template:secure-gateway-http-offload-offload-template")


def test_configuration_hash_is_stable_for_platform_set_order() -> None:
    first = production_spec(
        platforms=set(
            [
                ChromePlatform.MACOS,
                ChromePlatform.WINDOWS,
                ChromePlatform.LINUX,
                ChromePlatform.CHROMEOS,
            ]
        )
    )
    second = production_spec(
        platforms=set(
            [
                ChromePlatform.CHROMEOS,
                ChromePlatform.LINUX,
                ChromePlatform.WINDOWS,
                ChromePlatform.MACOS,
            ]
        )
    )

    assert canonical_configuration_hash(first) == canonical_configuration_hash(second)


def test_certificate_rotation_plans_an_explicit_offload_refresh() -> None:
    prefix = "secure-gateway-http-offload"
    snapshot = DiscoverySnapshot(
        existing_resource_keys={
            f"secretmanager:secret:{prefix}-tls",
            f"compute:instance_group_manager:{prefix}-offload-mig",
        }
    )

    plan = DesiredStatePlanner().build_plan(production_spec(), snapshot)

    refresh = next(change for change in plan.changes if change.resource_type == "offload_refresh")
    assert refresh.action.value == "create"
    assert refresh.risk.value == "high"
    assert f"secretmanager:secret_version:{prefix}-tls" in refresh.dependencies


def test_production_rejects_same_primary_and_secondary_zone() -> None:
    with pytest.raises(ValidationError, match="two distinct zones"):
        production_spec(secondary_zone="asia-east1-c")


def test_plan_is_blocked_until_identities_and_approval_are_present() -> None:
    snapshot = DiscoverySnapshot(enabled_apis=REQUIRED_APIS)
    plan = DesiredStatePlanner().build_plan(production_spec(), snapshot)
    assert plan.can_apply is False
    assert {gate.gate_id for gate in plan.gates if gate.status == "pending"} >= {
        "cloud-identity",
        "workspace-identity",
        "human-approval",
    }


def test_plan_is_blocked_when_cloud_billing_is_not_confirmed() -> None:
    plan = DesiredStatePlanner().build_plan(
        production_spec(),
        DiscoverySnapshot(billing_enabled=False),
    )
    billing_gate = next(gate for gate in plan.gates if gate.gate_id == "billing-enabled")
    assert billing_gate.status == "blocked"
    assert plan.can_apply is False


def test_default_gateway_is_shared_and_not_owned() -> None:
    plan = DesiredStatePlanner().build_plan(production_spec())
    gateway = next(change for change in plan.changes if change.resource_type == "security_gateway")
    assert gateway.owned_after_apply is False


def test_conflict_is_blocking() -> None:
    snapshot = DiscoverySnapshot(
        conflicting_resource_keys={
            "compute:instance_group_manager:secure-gateway-http-offload-offload-mig"
        }
    )
    plan = DesiredStatePlanner().build_plan(production_spec(), snapshot)
    conflict_gate = next(gate for gate in plan.gates if gate.gate_id == "resource-conflicts")
    assert conflict_gate.status == "blocked"
    assert plan.can_apply is False


def test_nginx_in_existing_vpc_requires_subnet() -> None:
    with pytest.raises(ValidationError, match="requires subnet_name"):
        production_spec(network_strategy=NetworkStrategy.EXISTING, vpc_name="shared-vpc")


def test_direct_https_uses_existing_vpc_without_nginx_resources() -> None:
    spec = production_spec(
        mode="poc",
        backend_kind=BackendKind.DIRECT_HTTPS,
        network_strategy=NetworkStrategy.EXISTING,
        vpc_name="private-app-vpc",
        source_image=None,
        certificate_strategy=CertificateStrategy.PUBLIC_TRUSTED,
        existing_backend_url="https://app.corp.internal:8443",
        existing_backend_location=BackendLocation.AWS,
        existing_backend_connectivity_confirmed=True,
        application_egress_region="asia-east1",
    )

    plan = DesiredStatePlanner().build_plan(spec, DiscoverySnapshot())
    resource_types = {(change.provider, change.resource_type) for change in plan.changes}

    assert spec.application_hostname == "app.corp.internal"
    assert spec.application_port == 8443
    assert ("beyondcorp", "application") in resource_types
    assert ("compute", "network") in resource_types
    assert ("compute", "instance") not in resource_types
    assert ("compute", "internal_address") not in resource_types
    assert ("compute", "cloud_nat") not in resource_types
    assert ("dns", "private_zone") not in resource_types
    assert ("secretmanager", "secret") not in resource_types
    assert not any(change.resource_type == "subnetwork" for change in plan.changes)
    assert "beyondcorp.googleapis.com" in required_apis(spec)
    assert "privateca.googleapis.com" not in required_apis(spec)
    assert "secretmanager.googleapis.com" not in required_apis(spec)


@pytest.mark.parametrize(
    "url",
    [
        "http://app.corp.internal",
        "https://203.0.113.20",
        "https://app.corp.internal/private/path",
        "https://user:password@app.corp.internal",
    ],
)
def test_direct_https_rejects_nonprivate_or_ambiguous_endpoints(url: str) -> None:
    with pytest.raises(ValidationError):
        production_spec(
            mode="poc",
            backend_kind=BackendKind.DIRECT_HTTPS,
            network_strategy=NetworkStrategy.EXISTING,
            vpc_name="private-app-vpc",
            source_image=None,
            certificate_strategy=CertificateStrategy.PUBLIC_TRUSTED,
            existing_backend_url=url,
            existing_backend_location=BackendLocation.GCP,
            existing_backend_connectivity_confirmed=True,
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://127.0.0.1:8080",
        "http://169.254.169.254/",
        "http://203.0.113.10/",
        "http://10.0.0.8/path?token=unsafe",
        "http://10.0.0.8/;\ninclude /etc/passwd",
    ],
)
def test_existing_backend_rejects_metadata_loopback_and_nonprivate_targets(
    url: str,
) -> None:
    with pytest.raises(ValidationError):
        production_spec(
            backend_kind=BackendKind.EXISTING_HTTP,
            existing_backend_url=url,
        )


def test_existing_backend_connectivity_gate_blocks_unconfirmed_private_path() -> None:
    spec = production_spec(
        backend_kind=BackendKind.EXISTING_HTTP,
        existing_backend_url="http://10.20.0.10:8080",
        existing_backend_location=BackendLocation.AWS,
        existing_backend_connectivity_confirmed=False,
    )
    snapshot = DiscoverySnapshot()

    plan = DesiredStatePlanner().build_plan(spec, snapshot)

    gate = next(item for item in plan.gates if item.gate_id == "backend-connectivity")
    assert gate.status == "blocked"
    assert gate.blocking is True
    assert "Cross-cloud VPN" in gate.detail


def test_existing_backend_connectivity_gate_records_confirmed_provider() -> None:
    spec = production_spec(
        backend_kind=BackendKind.EXISTING_HTTP,
        existing_backend_url="http://10.20.0.10:8080",
        existing_backend_location=BackendLocation.AZURE,
        existing_backend_connectivity_confirmed=True,
    )
    snapshot = DiscoverySnapshot()

    plan = DesiredStatePlanner().build_plan(spec, snapshot)

    gate = next(item for item in plan.gates if item.gate_id == "backend-connectivity")
    assert gate.status == "pass"
    assert "azure backend" in gate.detail


def _global_access_spec(**overrides: object) -> DeploymentSpec:
    """A Path B spec whose matcher is a literal IP, so it can resolve to a rule."""
    base: dict[str, object] = {
        "mode": "poc",
        "backend_kind": BackendKind.DIRECT_HTTPS,
        "network_strategy": NetworkStrategy.EXISTING,
        "vpc_name": "private-app-vpc",
        "source_image": None,
        "certificate_strategy": CertificateStrategy.PUBLIC_TRUSTED,
        "existing_backend_url": "https://10.20.0.10:8443",
        "existing_backend_location": BackendLocation.GCP,
        "existing_backend_connectivity_confirmed": True,
    }
    base.update(overrides)
    return production_spec(**base)  # type: ignore[arg-type]


def _gate(plan: DeploymentPlan, gate_id: str) -> DeploymentGate:
    return next(gate for gate in plan.gates if gate.gate_id == gate_id)


def test_global_access_gate_blocks_when_disabled_and_no_egress_region() -> None:
    # The guide names this as the most common Path B failure: a regional
    # internal load balancer silently refuses cross-region traffic.
    spec = _global_access_spec()
    snapshot = DiscoverySnapshot(
        application_global_access=False,
        application_forwarding_rule="app-ilb-fr",
    )

    plan = DesiredStatePlanner().build_plan(spec, snapshot)
    gate = _gate(plan, "global-access")

    assert gate.status == "blocked"
    assert gate.blocking is True
    # can_apply is False for any unapproved plan, so assert the specific
    # contribution: this gate is one of the reasons Apply is refused.
    assert gate in [item for item in plan.gates if item.blocking and item.status != "pass"]
    assert "app-ilb-fr" in gate.detail
    assert "enable Global Access" in gate.detail


def test_global_access_gate_passes_when_egress_region_pins_the_region() -> None:
    spec = _global_access_spec(application_egress_region="asia-east1")
    snapshot = DiscoverySnapshot(application_global_access=False)

    gate = _gate(DesiredStatePlanner().build_plan(spec, snapshot), "global-access")

    assert gate.status == "pass"
    assert gate.blocking is False
    assert "asia-east1" in gate.detail


def test_global_access_gate_passes_when_enabled_on_the_rule() -> None:
    spec = _global_access_spec()
    snapshot = DiscoverySnapshot(
        application_global_access=True,
        application_forwarding_rule="app-ilb-fr",
    )

    gate = _gate(DesiredStatePlanner().build_plan(spec, snapshot), "global-access")

    assert gate.status == "pass"
    assert gate.blocking is False


def test_global_access_gate_warns_without_blocking_when_unresolvable() -> None:
    # An FQDN matcher, a GKE ingress, or a non-GCP backend cannot be resolved to
    # a forwarding rule. Those are supported Path B targets, so the gate must
    # surface the risk without refusing the deployment.
    spec = _global_access_spec(existing_backend_url="https://app.corp.internal:8443")
    plan = DesiredStatePlanner().build_plan(spec, DiscoverySnapshot())
    gate = _gate(plan, "global-access")

    assert gate.status == "pending"
    assert gate.blocking is False
    # Pending but non-blocking: it must not appear among the reasons Apply is
    # refused, even though it is surfaced to the operator.
    assert gate not in [item for item in plan.gates if item.blocking and item.status != "pass"]
    assert "app.corp.internal" in gate.detail


def test_global_access_gate_is_not_applicable_to_path_a() -> None:
    gate = _gate(
        DesiredStatePlanner().build_plan(production_spec(mode="poc"), DiscoverySnapshot()),
        "global-access",
    )

    assert gate.status == "pass"
    assert gate.blocking is False


def test_path_b_requires_forwarding_rule_list_permission() -> None:
    assert "compute.forwardingRules.list" in required_permissions(_global_access_spec())


def test_cross_project_upstream_vpc_is_expressible() -> None:
    # The guide's worked example places the VPC in a separate project. Until
    # this landed, that example could not be reproduced by the app.
    spec = _global_access_spec(upstream_vpc_project_id="shared-network-prj")

    assert spec.upstream_project_id == "shared-network-prj"
    assert spec.project_id != spec.upstream_project_id


def test_upstream_project_defaults_to_the_deployment_project() -> None:
    spec = _global_access_spec()

    assert spec.upstream_project_id == spec.project_id


def test_cross_project_upstream_is_rejected_outside_direct_https() -> None:
    with pytest.raises(ValidationError, match="only to direct private HTTPS"):
        production_spec(mode="poc", upstream_vpc_project_id="shared-network-prj")
