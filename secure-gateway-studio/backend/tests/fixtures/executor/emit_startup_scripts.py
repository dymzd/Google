"""Emit the VM startup scripts as a TypeScript template module.

Run from the repository root:

    python secure-gateway-studio/backend/tests/fixtures/executor/emit_startup_scripts.py

The offload and sample-backend startup scripts are ~240 lines of shell and
embedded Python that configure Nginx, fetch the TLS bundle from Secret Manager,
and write the T01-T03 self-test results into guest attributes. Retyping them in
TypeScript would produce two subtly different offload configurations, and no
test could see the difference until a deployment behaved oddly in production.

So they are not retyped. This generator asks the Python implementation to build
each script with recognisable sentinel values, replaces those sentinels with
placeholders, and writes the result as a TypeScript module. The Python
implementation stays the single source of truth; CI regenerates and fails on any
diff.

The sentinels are chosen to be unmistakable and to survive the shell and Python
quoting inside the scripts.
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
from sgstudio.providers.google_executor import GoogleResourceExecutor  # noqa: E402

_TARGET = (
    Path(__file__).resolve().parents[4]
    / "extension"
    / "src"
    / "providers"
    / "startup-scripts.generated.ts"
)

# Sentinels that cannot occur naturally in the scripts.
_SENTINELS = {
    "SGSX-BACKEND-URL": "@@BACKEND_URL@@",
    "sgsx-hostname.invalid": "@@PRIVATE_HOSTNAME@@",
    "projects/sgsx-project/secrets/sgsx-secret/versions/active": "@@SECRET_VERSION@@",
    "0" * 64: "@@CONFIGURATION_HASH@@",
}


class _NullTransport:
    def request_json(self, method: str, url: str, **kwargs: Any) -> tuple[int, dict[str, Any]]:
        del method, kwargs
        # The offload script embeds the sample backend's reserved address.
        if "/addresses/" in url:
            return 200, {"address": "SGSX-BACKEND-ADDRESS"}
        return 200, {}


def _spec(**overrides: Any) -> DeploymentSpec:
    values: dict[str, Any] = {
        "project_id": "sgsx-project",
        "name": "sgsx",
        "mode": "poc",
        "target_ou_id": "03-test-ou",
        "test_ou_confirmed": True,
        "private_hostname": "sgsx-hostname.invalid",
        "principals": [
            AccessPrincipal(type=PrincipalType.GROUP, value="secure-access@example.com")
        ],
        "source_image": None,
        "certificate_strategy": CertificateStrategy.PUBLIC_TRUSTED,
        "public_certificate_secret": "projects/sgsx-project/secrets/sgsx-secret",
    }
    values.update(overrides)
    return DeploymentSpec(**values)


def _templatise(script: str, spec: DeploymentSpec, executor: Any) -> str:
    from sgstudio.domain.planner import canonical_configuration_hash

    replacements = {
        canonical_configuration_hash(spec): "@@CONFIGURATION_HASH@@",
        spec.private_hostname: "@@PRIVATE_HOSTNAME@@",
        f"projects/{spec.project_id}/secrets/sgsx-secret/versions/latest": (
            "@@SECRET_VERSION@@"
        ),
        "http://SGSX-BACKEND-ADDRESS": "@@BACKEND_URL@@",
    }
    if spec.existing_backend_url:
        replacements[str(spec.existing_backend_url)] = "@@BACKEND_URL@@"
    del executor
    for value, marker in replacements.items():
        script = script.replace(value, marker)
    return script


def build() -> str:
    executor = GoogleResourceExecutor(_NullTransport(), poll_interval_seconds=0)

    managed = _spec()
    offload = _templatise(executor._offload_startup_script(managed), managed, executor)
    backend = _templatise(executor._backend_startup_script(managed), managed, executor)

    # Production runs on an immutable hardened image that already carries Nginx
    # and Python, so the script verifies their presence rather than installing
    # from a mutable repository at boot. That is a Production requirement, not
    # an optimisation, and it is selected by mode.
    hardened = _spec(
        mode="production",
        source_image="projects/sgsx-project/global/images/sgsx-nginx",
        managed_chrome_access_level=(
            "accessPolicies/123456789/accessLevels/managed_chrome"
        ),
        chrome_enterprise_premium_license_confirmed=True,
        workspace_services_confirmed=True,
        endpoint_verification_confirmed=True,
    )
    offload_hardened = _templatise(
        executor._offload_startup_script(hardened), hardened, executor
    )

    direct = _spec(
        backend_kind=BackendKind.EXISTING_HTTP,
        network_strategy=NetworkStrategy.EXISTING,
        vpc_name="shared-vpc",
        subnet_name="offload-subnet",
        existing_backend_url="http://10.20.0.10:8080",
        existing_backend_location=BackendLocation.GCP,
        existing_backend_connectivity_confirmed=True,
    )
    offload_existing = _templatise(
        executor._offload_startup_script(direct), direct, executor
    )

    header = (
        "/**\n"
        " * Generated from `backend/src/sgstudio/providers/google_executor.py`.\n"
        " * Do not edit.\n"
        " *\n"
        " * Regenerate with:\n"
        " *   python backend/tests/fixtures/executor/emit_startup_scripts.py\n"
        " *\n"
        " * These scripts configure the Nginx offload tier and the sample backend.\n"
        " * Retyping them in TypeScript would produce two subtly different offload\n"
        " * configurations that no test could distinguish, so they are generated from\n"
        " * the Python implementation instead. CI regenerates this file and fails on\n"
        " * any diff.\n"
        " *\n"
        " * Placeholders are substituted by `renderStartupScript`.\n"
        " */\n\n"
    )

    body = (
        f"export const OFFLOAD_MANAGED_SAMPLE = {json.dumps(offload)};\n\n"
        f"export const OFFLOAD_EXISTING_BACKEND = {json.dumps(offload_existing)};\n\n"
        f"export const OFFLOAD_HARDENED = {json.dumps(offload_hardened)};\n\n"
        f"export const SAMPLE_BACKEND = {json.dumps(backend)};\n"
    )
    return header + body


def main() -> None:
    _TARGET.write_text(build(), encoding="utf-8")
    size = len(_TARGET.read_text(encoding="utf-8"))
    print(f"wrote {size} characters of startup-script templates to {_TARGET.name}")


if __name__ == "__main__":
    main()
