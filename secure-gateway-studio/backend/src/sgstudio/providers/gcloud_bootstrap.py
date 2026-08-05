from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class DeployerBootstrapResult:
    project_id: str
    operator_email: str
    service_account_email: str
    custom_role: str
    access_policy_id: str | None
    adc_command: str


class DeployerBootstrapper(Protocol):
    def bootstrap(self, project_id: str) -> DeployerBootstrapResult: ...


class GcloudDeployerBootstrapper:
    """Bootstrap the keyless deployer with the active gcloud user.

    Commands are passed as argument arrays without a shell. The browser-facing
    API validates the project ID and requires an explicit BOOTSTRAP confirmation.
    """

    _account_pattern = re.compile(r"^[^\s@]+@[^\s@]+$")
    _account_id = "secure-gateway-deployer"
    _role_id = "secureGatewayPocDeployer"

    def __init__(
        self,
        *,
        gcloud_path: str | None = None,
        access_policy_id: str | None = None,
    ) -> None:
        self._gcloud = gcloud_path or shutil.which("gcloud") or ""
        if not self._gcloud:
            raise RuntimeError("gcloud CLI is required for automatic deployer setup")
        self._role_file = (
            Path(__file__).resolve().parents[4]
            / "infrastructure"
            / "iam"
            / "secure-gateway-poc-deployer-role.yaml"
        )
        if not self._role_file.is_file():
            raise RuntimeError("The bundled deployer role manifest is unavailable")
        configured_policy = (
            access_policy_id
            if access_policy_id is not None
            else os.getenv("SGSTUDIO_ACCESS_POLICY_ID", "")
        ).strip()
        self._access_policy_id = configured_policy if configured_policy.isdigit() else None

    def bootstrap(self, project_id: str) -> DeployerBootstrapResult:
        operator_email = self._run(
            "auth",
            "list",
            "--filter=status:ACTIVE",
            "--format=value(account)",
        ).strip()
        if not self._account_pattern.fullmatch(operator_email):
            raise RuntimeError("No active gcloud user account was found")

        service_account_email = (
            f"{self._account_id}@{project_id}.iam.gserviceaccount.com"
        )
        if not self._succeeds(
            "iam",
            "service-accounts",
            "describe",
            service_account_email,
            f"--project={project_id}",
        ):
            self._run(
                "iam",
                "service-accounts",
                "create",
                self._account_id,
                f"--project={project_id}",
                "--display-name=Secure Gateway Studio deployer",
                "--quiet",
            )

        role_name = f"projects/{project_id}/roles/{self._role_id}"
        role_action = (
            "update"
            if self._succeeds(
                "iam",
                "roles",
                "describe",
                self._role_id,
                f"--project={project_id}",
            )
            else "create"
        )
        self._run(
            "iam",
            "roles",
            role_action,
            self._role_id,
            f"--project={project_id}",
            f"--file={self._role_file}",
            "--quiet",
        )

        member = f"serviceAccount:{service_account_email}"
        if self._access_policy_id:
            self._run(
                "access-context-manager",
                "policies",
                "add-iam-policy-binding",
                self._access_policy_id,
                f"--member={member}",
                "--role=roles/accesscontextmanager.policyReader",
                "--condition=None",
                "--quiet",
            )

        for role in (
            role_name,
            "roles/browser",
            "roles/serviceusage.serviceUsageConsumer",
        ):
            self._run(
                "projects",
                "add-iam-policy-binding",
                project_id,
                f"--member={member}",
                f"--role={role}",
                "--condition=None",
                "--quiet",
            )

        self._run(
            "iam",
            "service-accounts",
            "add-iam-policy-binding",
            service_account_email,
            f"--project={project_id}",
            f"--member=user:{operator_email}",
            "--role=roles/iam.serviceAccountTokenCreator",
            "--condition=None",
            "--quiet",
        )

        return DeployerBootstrapResult(
            project_id=project_id,
            operator_email=operator_email,
            service_account_email=service_account_email,
            custom_role=role_name,
            access_policy_id=self._access_policy_id,
            adc_command=(
                "gcloud auth application-default login "
                f"--impersonate-service-account={service_account_email}"
            ),
        )

    def _succeeds(self, *arguments: str) -> bool:
        result = subprocess.run(
            [self._gcloud, *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0

    def _run(self, *arguments: str) -> str:
        result = subprocess.run(
            [self._gcloud, *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()[-500:]
            if (
                "Reauthentication failed" in detail
                or "cannot prompt during non-interactive execution" in detail
            ):
                detail = (
                    "The active gcloud user credentials require reauthentication. "
                    "Run `gcloud auth login`, complete browser sign-in, then retry "
                    "automatic deployer setup."
                )
            raise RuntimeError(detail or "gcloud command failed")
        return result.stdout
