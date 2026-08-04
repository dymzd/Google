from __future__ import annotations

import os
import secrets
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from threading import RLock
from typing import Annotated, Literal

from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from google.auth.exceptions import DefaultCredentialsError, RefreshError
from pydantic import BaseModel, ConfigDict, Field

from sgstudio import __version__
from sgstudio.domain import (
    AcceptanceReadiness,
    AcceptanceResult,
    AcceptanceStatus,
    AcceptanceTestId,
    ApprovedPlan,
    AuditEvent,
    ConnectionValidation,
    DeploymentDetails,
    DeploymentSpec,
    DesiredStatePlanner,
    EvidenceSource,
    GatewayLogCategory,
    GatewayLogsResponse,
    PreflightResult,
    PreparedPlan,
    SetupOption,
    TeardownExecutor,
    TeardownPlan,
    TeardownRun,
    build_teardown_plan,
    deployment_details,
)
from sgstudio.domain.execution import DeploymentExecutor
from sgstudio.domain.models import DeploymentRun
from sgstudio.providers import (
    ConnectionValidator,
    DeployerBootstrapper,
    DiscoveryProvider,
    GcloudDeployerBootstrapper,
    GoogleAcceptanceVerifier,
    GoogleApiError,
    GoogleGatewayObservability,
    SetupCatalogProvider,
    create_google_acceptance_verifier,
    create_google_connection_validator,
    create_google_discovery_provider,
    create_google_gateway_observability,
    create_google_setup_catalog_provider,
)
from sgstudio.providers.google_executor import (
    GoogleResourceExecutor,
    create_google_resource_executor,
)
from sgstudio.providers.local_artifacts import CertificateArtifactStore
from sgstudio.storage import StateRepository


class PlanRequest(BaseModel):
    specification: DeploymentSpec


class DraftResponse(BaseModel):
    deployment_id: str


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan_id: str = Field(min_length=36, max_length=36)
    confirmation: Literal["APPROVE"]
    ttl_minutes: int = 30


class CloudConnectionRequest(BaseModel):
    project_id: str = Field(min_length=6, max_length=30, pattern=r"^[a-z][a-z0-9-]+$")


class DeployerBootstrapRequest(CloudConnectionRequest):
    model_config = ConfigDict(extra="forbid")

    confirmation: Literal["BOOTSTRAP"]


class DeployerBootstrapResponse(BaseModel):
    project_id: str
    operator_email: str
    service_account_email: str
    custom_role: str
    access_policy_id: str | None
    adc_command: str


class WorkspaceConnectionRequest(BaseModel):
    customer_id: str = Field(min_length=3, max_length=100)


class ApplyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: str = Field(min_length=36, max_length=36)
    confirmation: Literal["APPLY"]


class EnableGatewayLoggingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirmation: Literal["ENABLE LOGGING"]


class TeardownRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan_hash: str = Field(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")
    confirmation: str = Field(min_length=20, max_length=200)


class IntegrityResponse(BaseModel):
    valid: bool
    event_count: int
    algorithm: Literal["sha256-chain"] = "sha256-chain"
    chain_head_hash: str | None = None


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    version: str
    bind: Literal["loopback"] = "loopback"
    session_nonce: str


class EvidenceBundle(BaseModel):
    schema_version: Literal[2] = 2
    generated_at: datetime
    app_version: str
    integrity: IntegrityResponse
    runs: list[DeploymentRun]
    acceptance: list[AcceptanceReadiness]
    audit_events: list[AuditEvent]


class OperatorAcceptanceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    test_id: AcceptanceTestId
    case_key: str = Field(
        default="default",
        min_length=3,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9_-]*$",
    )
    status: Literal["user_confirmed", "failed", "skipped"]
    summary: str = Field(min_length=3, max_length=500)
    evidence: str = Field(min_length=3, max_length=4000)
    confirmation: Literal["RECORD"]


def _problem(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


def _state_path() -> Path:
    override = os.getenv("SGSTUDIO_STATE_PATH")
    if override:
        return Path(override).expanduser().resolve()
    return (Path.cwd() / ".local" / "secure-gateway-studio.db").resolve()


def _certificate_artifact_store() -> CertificateArtifactStore:
    return CertificateArtifactStore(_state_path().parent / "artifacts")


_repository_instance: StateRepository | None = None
_repository_lock = RLock()


def repository() -> StateRepository:
    global _repository_instance
    with _repository_lock:
        if _repository_instance is None:
            _repository_instance = StateRepository(_state_path())
        return _repository_instance


@lru_cache
def discovery_provider() -> DiscoveryProvider:
    try:
        return create_google_discovery_provider()
    except RuntimeError as error:
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED,
            detail=_problem("adc-unavailable", str(error)),
        ) from error


@lru_cache
def connection_validator() -> ConnectionValidator:
    try:
        return create_google_connection_validator()
    except RuntimeError as error:
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED,
            detail=_problem("adc-unavailable", str(error)),
        ) from error


@lru_cache
def deployer_bootstrapper() -> DeployerBootstrapper:
    try:
        return GcloudDeployerBootstrapper()
    except RuntimeError as error:
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED,
            detail=_problem("gcloud-unavailable", str(error)),
        ) from error


@lru_cache
def setup_catalog_provider() -> SetupCatalogProvider:
    try:
        return create_google_setup_catalog_provider()
    except RuntimeError as error:
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED,
            detail=_problem("adc-unavailable", str(error)),
        ) from error


def resource_executor() -> GoogleResourceExecutor:
    try:
        return create_google_resource_executor(artifact_store=_certificate_artifact_store())
    except RuntimeError as error:
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED,
            detail=_problem("adc-unavailable", str(error)),
        ) from error


@lru_cache
def gateway_observability() -> GoogleGatewayObservability:
    try:
        return create_google_gateway_observability()
    except RuntimeError as error:
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED,
            detail=_problem("adc-unavailable", str(error)),
        ) from error


@lru_cache
def acceptance_verifier() -> GoogleAcceptanceVerifier:
    try:
        return create_google_acceptance_verifier()
    except RuntimeError as error:
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED,
            detail=_problem("adc-unavailable", str(error)),
        ) from error


ALLOWED_ORIGINS = tuple(
    origin.strip()
    for origin in os.getenv(
        "SGSTUDIO_ALLOWED_ORIGINS",
        (
            "http://127.0.0.1:5173,http://localhost:5173,"
            "http://127.0.0.1:4173,http://localhost:4173,"
            "http://127.0.0.1:8787,http://localhost:8787"
        ),
    ).split(",")
    if origin.strip()
)
SESSION_NONCE = secrets.token_urlsafe(32)


def require_local_session(
    origin: str | None = Header(default=None),
    session_nonce: str | None = Header(default=None, alias="X-SGS-Session"),
) -> None:
    if origin is not None and origin not in ALLOWED_ORIGINS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=_problem(
                "origin-rejected",
                "Mutating requests are accepted from configured loopback origins only",
            ),
        )
    if session_nonce is None or not secrets.compare_digest(session_nonce, SESSION_NONCE):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=_problem(
                "session-invalid",
                "The local API session is missing or invalid",
            ),
        )


app = FastAPI(
    title="Secure Gateway Studio API",
    version=__version__,
    docs_url=None,
    redoc_url=None,
    openapi_url="/api/v1/openapi.json",
)


@app.exception_handler(DefaultCredentialsError)
@app.exception_handler(RefreshError)
async def google_authentication_error(
    _request: Request,
    _error: DefaultCredentialsError | RefreshError,
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_428_PRECONDITION_REQUIRED,
        content={
            "detail": _problem(
                "adc-unavailable",
                (
                    "Application Default Credentials are unavailable or require "
                    "reauthentication. Run `gcloud auth application-default login "
                    "--impersonate-service-account=SERVICE_ACCOUNT_EMAIL`."
                ),
            )
        },
    )
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["127.0.0.1", "localhost", "testserver"],
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(ALLOWED_ORIGINS),
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=[
        "Content-Type",
        "Origin",
        "X-Requested-With",
        "X-SGS-Session",
    ],
)


@app.middleware("http")
async def security_headers(request, call_next):
    response: Response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    if request.url.path.startswith("/api/"):
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    else:
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.get("/api/v1/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(version=__version__, session_nonce=SESSION_NONCE)


@app.post(
    "/api/v1/bootstrap/google-cloud/deployer",
    response_model=DeployerBootstrapResponse,
    dependencies=[Depends(require_local_session)],
)
def bootstrap_google_cloud_deployer(
    request: DeployerBootstrapRequest,
    bootstrapper: Annotated[DeployerBootstrapper, Depends(deployer_bootstrapper)],
) -> DeployerBootstrapResponse:
    try:
        result = bootstrapper.bootstrap(request.project_id)
    except RuntimeError as error:
        raise HTTPException(
            status_code=status.HTTP_424_FAILED_DEPENDENCY,
            detail=_problem("deployer-bootstrap-failed", str(error)),
        ) from error
    return DeployerBootstrapResponse(
        project_id=result.project_id,
        operator_email=result.operator_email,
        service_account_email=result.service_account_email,
        custom_role=result.custom_role,
        access_policy_id=result.access_policy_id,
        adc_command=result.adc_command,
    )


@app.post(
    "/api/v1/connections/google-cloud/validate",
    response_model=ConnectionValidation,
    dependencies=[Depends(require_local_session)],
)
def validate_google_cloud_connection(
    request: CloudConnectionRequest,
    validator: Annotated[ConnectionValidator, Depends(connection_validator)],
) -> ConnectionValidation:
    try:
        return validator.validate_cloud(request.project_id)
    except (GoogleApiError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_424_FAILED_DEPENDENCY,
            detail=_problem(
                "cloud-validation-failed",
                "Google Cloud connection validation failed",
            ),
        ) from error


@app.post(
    "/api/v1/connections/workspace/validate",
    response_model=ConnectionValidation,
    dependencies=[Depends(require_local_session)],
)
def validate_workspace_connection(
    request: WorkspaceConnectionRequest,
    validator: Annotated[ConnectionValidator, Depends(connection_validator)],
) -> ConnectionValidation:
    try:
        return validator.validate_workspace(request.customer_id)
    except (GoogleApiError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_424_FAILED_DEPENDENCY,
            detail=_problem(
                "workspace-validation-failed",
                "Workspace connection validation failed",
            ),
        ) from error


@app.post(
    "/api/v1/setup-options/organizational-units",
    response_model=list[SetupOption],
    dependencies=[Depends(require_local_session)],
)
def list_organizational_unit_options(
    request: WorkspaceConnectionRequest,
    provider: Annotated[SetupCatalogProvider, Depends(setup_catalog_provider)],
) -> list[SetupOption]:
    try:
        return provider.list_organizational_units(request.customer_id)
    except (GoogleApiError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_424_FAILED_DEPENDENCY,
            detail=_problem(
                "organizational-units-fetch-failed",
                "Organizational units could not be listed with the current credentials.",
            ),
        ) from error


@app.post(
    "/api/v1/setup-options/groups",
    response_model=list[SetupOption],
    dependencies=[Depends(require_local_session)],
)
def list_group_options(
    request: WorkspaceConnectionRequest,
    provider: Annotated[SetupCatalogProvider, Depends(setup_catalog_provider)],
) -> list[SetupOption]:
    try:
        return provider.list_groups(request.customer_id)
    except (GoogleApiError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_424_FAILED_DEPENDENCY,
            detail=_problem(
                "groups-fetch-failed",
                "Groups could not be listed with the current credentials.",
            ),
        ) from error


@app.post(
    "/api/v1/setup-options/access-levels",
    response_model=list[SetupOption],
    dependencies=[Depends(require_local_session)],
)
def list_access_level_options(
    request: CloudConnectionRequest,
    provider: Annotated[SetupCatalogProvider, Depends(setup_catalog_provider)],
) -> list[SetupOption]:
    try:
        return provider.list_access_levels(request.project_id)
    except (GoogleApiError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_424_FAILED_DEPENDENCY,
            detail=_problem(
                "access-levels-fetch-failed",
                "Access levels could not be listed with the current credentials.",
            ),
        ) from error


@app.post(
    "/api/v1/plans",
    response_model=PreparedPlan,
    dependencies=[Depends(require_local_session)],
)
def create_plan(
    request: PlanRequest,
    provider: Annotated[DiscoveryProvider, Depends(discovery_provider)],
    validator: Annotated[ConnectionValidator, Depends(connection_validator)],
    state_repository: Annotated[StateRepository, Depends(repository)],
) -> PreparedPlan:
    preflight = _trusted_preflight(request.specification, provider, validator)
    plan = DesiredStatePlanner().build_plan(request.specification, preflight.snapshot)
    return state_repository.store_prepared_plan(request.specification, preflight, plan)


@app.post(
    "/api/v1/preflight",
    response_model=PreflightResult,
    dependencies=[Depends(require_local_session)],
)
def run_preflight(
    specification: DeploymentSpec,
    provider: Annotated[DiscoveryProvider, Depends(discovery_provider)],
    validator: Annotated[ConnectionValidator, Depends(connection_validator)],
) -> PreflightResult:
    return _trusted_preflight(specification, provider, validator)


@app.post(
    "/api/v1/approvals",
    response_model=ApprovedPlan,
    dependencies=[Depends(require_local_session)],
)
def approve_plan(
    request: ApprovalRequest,
    state_repository: Annotated[StateRepository, Depends(repository)],
) -> ApprovedPlan:
    try:
        return state_repository.approve_prepared_plan(
            request.plan_id,
            ttl_minutes=request.ttl_minutes,
        )
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error


@app.post(
    "/api/v1/runs",
    response_model=DeploymentRun,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_local_session)],
)
def apply_approved_plan(
    request: ApplyRequest,
    background_tasks: BackgroundTasks,
    state_repository: Annotated[StateRepository, Depends(repository)],
    executor: Annotated[GoogleResourceExecutor, Depends(resource_executor)],
) -> DeploymentRun:
    try:
        approval, run = state_repository.consume_approval_and_create_run(
            request.approval_id,
        )
        background_tasks.add_task(
            DeploymentExecutor(executor, state_repository).execute,
            approval,
            approval.specification,
            actor=approval.approved_by,
            existing_run=run,
        )
        return run
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=_problem("approval-invalid", str(error)),
        ) from error


@app.get("/api/v1/runs/{run_id}", response_model=DeploymentRun)
def get_deployment_run(
    run_id: str,
    state_repository: Annotated[StateRepository, Depends(repository)],
) -> DeploymentRun:
    run = state_repository.get_run(run_id)
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_problem("run-not-found", "Deployment run was not found"),
        )
    return run


@app.get(
    "/api/v1/certificates/local-poc/{deployment_name}",
    dependencies=[Depends(require_local_session)],
)
def download_local_poc_root_certificate(deployment_name: str) -> Response:
    try:
        certificate = _certificate_artifact_store().read_root_certificate(deployment_name)
    except FileNotFoundError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_problem(
                "certificate-artifact-not-found",
                "The local PoC root certificate is available after a successful Apply.",
            ),
        ) from error
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=_problem("invalid-deployment-name", str(error)),
        ) from error
    return Response(
        content=certificate,
        media_type="application/x-pem-file",
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": (f'attachment; filename="{deployment_name}-poc-root.pem"'),
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/api/v1/runs", response_model=list[DeploymentRun])
def list_deployment_runs(
    state_repository: Annotated[StateRepository, Depends(repository)],
    limit: int = 100,
) -> list[DeploymentRun]:
    return state_repository.list_runs(limit=limit)


@app.get(
    "/api/v1/runs/{run_id}/details",
    response_model=DeploymentDetails,
    dependencies=[Depends(require_local_session)],
)
def get_deployment_details(
    run_id: str,
    state_repository: Annotated[StateRepository, Depends(repository)],
) -> DeploymentDetails:
    try:
        return deployment_details(state_repository, run_id)
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_problem("deployment-details-not-found", str(error)),
        ) from error


@app.get(
    "/api/v1/runs/{run_id}/logs",
    response_model=GatewayLogsResponse,
    dependencies=[Depends(require_local_session)],
)
def get_gateway_logs(
    run_id: str,
    observability: Annotated[GoogleGatewayObservability, Depends(gateway_observability)],
    state_repository: Annotated[StateRepository, Depends(repository)],
    category: GatewayLogCategory = GatewayLogCategory.ACCESS,
    hours: int = 24,
    limit: int = 100,
) -> GatewayLogsResponse:
    run = state_repository.get_run(run_id)
    approval = state_repository.get_approval(run.approval_id) if run else None
    if run is None or approval is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_problem("deployment-logs-not-found", "Deployment run was not found"),
        )
    try:
        return observability.list_logs(
            approval.specification,
            run_id=run_id,
            category=category,
            hours=hours,
            limit=limit,
        )
    except GoogleApiError as error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=_problem(
                "cloud-logging-query-failed",
                f"Cloud Logging request failed with status {error.status_code}",
            ),
        ) from error


@app.post(
    "/api/v1/runs/{run_id}/logs/enable",
    dependencies=[Depends(require_local_session)],
)
def enable_gateway_logs(
    run_id: str,
    request: EnableGatewayLoggingRequest,
    observability: Annotated[GoogleGatewayObservability, Depends(gateway_observability)],
    state_repository: Annotated[StateRepository, Depends(repository)],
) -> dict[str, bool]:
    run = state_repository.get_run(run_id)
    approval = state_repository.get_approval(run.approval_id) if run else None
    if run is None or approval is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_problem("deployment-logs-not-found", "Deployment run was not found"),
        )
    try:
        enabled = observability.enable_gateway_logging(approval.specification)
    except GoogleApiError as error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=_problem(
                "gateway-logging-enable-failed",
                f"Secure Gateway logging update failed with status {error.status_code}",
            ),
        ) from error
    state_repository.record_audit_event(
        event_type="gateway.logging_enabled",
        actor=approval.approved_by,
        payload={
            "run_id": run_id,
            "project_id": approval.specification.project_id,
            "gateway_id": approval.specification.gateway_id,
        },
    )
    return {"enabled": enabled}


@app.get(
    "/api/v1/runs/{run_id}/teardown-plan",
    response_model=TeardownPlan,
    dependencies=[Depends(require_local_session)],
)
def get_teardown_plan(
    run_id: str,
    state_repository: Annotated[StateRepository, Depends(repository)],
) -> TeardownPlan:
    try:
        return build_teardown_plan(state_repository, run_id)
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=_problem("teardown-unavailable", str(error)),
        ) from error


@app.post(
    "/api/v1/runs/{run_id}/teardowns",
    response_model=TeardownRun,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_local_session)],
)
def start_teardown(
    run_id: str,
    request: TeardownRequest,
    background_tasks: BackgroundTasks,
    state_repository: Annotated[StateRepository, Depends(repository)],
    executor: Annotated[GoogleResourceExecutor, Depends(resource_executor)],
) -> TeardownRun:
    try:
        plan = build_teardown_plan(state_repository, run_id)
        if not plan.can_destroy:
            raise ValueError("No owned deployment resources are available for teardown")
        if request.plan_hash != plan.plan_hash or request.confirmation != plan.confirmation:
            raise ValueError("Teardown confirmation does not match the current plan")
        run = state_repository.get_run(plan.run_id)
        approval = state_repository.get_approval(run.approval_id) if run else None
        if approval is None:
            raise ValueError("Deployment approval was not found")
        teardown = state_repository.create_teardown_run(
            source_run_id=plan.run_id,
            plan_hash=plan.plan_hash,
            resource_keys=[resource.resource_key for resource in plan.resources],
            actor=approval.approved_by,
        )
        background_tasks.add_task(
            TeardownExecutor(executor, state_repository).execute,
            teardown,
            actor=approval.approved_by,
        )
        return teardown
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=_problem("teardown-invalid", str(error)),
        ) from error


@app.get(
    "/api/v1/teardowns/{teardown_id}",
    response_model=TeardownRun,
    dependencies=[Depends(require_local_session)],
)
def get_teardown(
    teardown_id: str,
    state_repository: Annotated[StateRepository, Depends(repository)],
) -> TeardownRun:
    teardown = state_repository.get_teardown_run(teardown_id)
    if teardown is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_problem("teardown-not-found", "Teardown run was not found"),
        )
    return teardown


@app.get(
    "/api/v1/runs/{run_id}/acceptance",
    response_model=AcceptanceReadiness,
)
def get_acceptance_readiness(
    run_id: str,
    state_repository: Annotated[StateRepository, Depends(repository)],
) -> AcceptanceReadiness:
    try:
        return state_repository.acceptance_readiness(run_id)
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_problem("acceptance-run-not-found", str(error)),
        ) from error


@app.post(
    "/api/v1/runs/{run_id}/acceptance/verify",
    response_model=AcceptanceReadiness,
    dependencies=[Depends(require_local_session)],
)
def verify_system_acceptance(
    run_id: str,
    verifier: Annotated[GoogleAcceptanceVerifier, Depends(acceptance_verifier)],
    state_repository: Annotated[StateRepository, Depends(repository)],
) -> AcceptanceReadiness:
    run = state_repository.get_run(run_id)
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_problem("acceptance-run-not-found", "Deployment run was not found"),
        )
    approval = state_repository.get_approval(run.approval_id)
    if approval is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_problem(
                "acceptance-approval-not-found",
                "Deployment approval was not found",
            ),
        )
    try:
        findings = verifier.verify(approval.specification)
        for finding in findings:
            state_repository.record_acceptance_result(
                run_id=run_id,
                test_id=finding.test_id,
                status=finding.status,
                source=EvidenceSource.SYSTEM,
                summary=finding.summary,
                evidence=finding.evidence,
                actor="system:google-api-verifier",
            )
        return state_repository.acceptance_readiness(run_id)
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=_problem("acceptance-verification-invalid", str(error)),
        ) from error


@app.post(
    "/api/v1/runs/{run_id}/acceptance-results",
    response_model=AcceptanceResult,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_local_session)],
)
def record_operator_acceptance(
    run_id: str,
    request: OperatorAcceptanceRequest,
    state_repository: Annotated[StateRepository, Depends(repository)],
) -> AcceptanceResult:
    try:
        run = state_repository.get_run(run_id)
        if run is None:
            raise ValueError("Deployment run was not found")
        approval = state_repository.get_approval(run.approval_id)
        if approval is None:
            raise ValueError("Deployment approval was not found")
        readiness = state_repository.acceptance_readiness(run_id)
        allowed_cases = {
            (requirement.test_id, requirement.case_key)
            for requirement in readiness.operator_confirmable_cases
        }
        if (request.test_id, request.case_key) not in allowed_cases:
            raise ValueError(
                "The requested acceptance case is not operator-confirmable for this deployment"
            )
        return state_repository.record_acceptance_result(
            run_id=run_id,
            test_id=request.test_id,
            case_key=request.case_key,
            status=AcceptanceStatus(request.status),
            source="operator",
            summary=request.summary,
            evidence=request.evidence,
            actor=approval.approved_by,
        )
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=_problem("acceptance-result-invalid", str(error)),
        ) from error


@app.get("/api/v1/plans/{plan_id}", response_model=PreparedPlan)
def get_prepared_plan(
    plan_id: str,
    state_repository: Annotated[StateRepository, Depends(repository)],
) -> PreparedPlan:
    plan = state_repository.get_prepared_plan(plan_id)
    if plan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_problem("plan-not-found", "Prepared plan was not found"),
        )
    return plan


@app.get("/api/v1/approvals/{approval_id}", response_model=ApprovedPlan)
def get_approved_plan(
    approval_id: str,
    state_repository: Annotated[StateRepository, Depends(repository)],
) -> ApprovedPlan:
    approval = state_repository.get_approval(approval_id)
    if approval is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_problem("approval-not-found", "Approval was not found"),
        )
    return approval


def _trusted_preflight(
    specification: DeploymentSpec,
    provider: DiscoveryProvider,
    validator: ConnectionValidator,
) -> PreflightResult:
    """Produce an entirely server-attested snapshot; client identity flags are ignored."""
    try:
        cloud = validator.validate_cloud(specification.project_id)
        workspace = validator.validate_workspace(
            specification.customer_id,
            specification.target_ou_id,
        )
        result = provider.preflight(specification)
    except (GoogleApiError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_424_FAILED_DEPENDENCY,
            detail=_problem("preflight-validation-failed", "Preflight validation failed"),
        ) from error
    result.snapshot.cloud_identity = cloud.principal_hint
    result.snapshot.workspace_identity = workspace.principal_hint
    result.diagnostics = [
        diagnostic
        for diagnostic in result.diagnostics
        if diagnostic.code != "workspace-oauth-required"
    ]
    return result


@app.post(
    "/api/v1/drafts",
    response_model=DraftResponse,
    dependencies=[Depends(require_local_session)],
)
def save_draft(
    specification: DeploymentSpec,
    state_repository: Annotated[StateRepository, Depends(repository)],
) -> DraftResponse:
    deployment_id = state_repository.save_draft(specification)
    return DraftResponse(deployment_id=deployment_id)


@app.get("/api/v1/drafts/{deployment_id}", response_model=DeploymentSpec)
def get_draft(
    deployment_id: str,
    state_repository: Annotated[StateRepository, Depends(repository)],
) -> DeploymentSpec:
    draft = state_repository.get_draft(deployment_id)
    if draft is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Draft not found")
    return draft


@app.get("/api/v1/evidence/audit-events", response_model=list[AuditEvent])
def list_audit_events(
    state_repository: Annotated[StateRepository, Depends(repository)],
    limit: int = 100,
) -> list[AuditEvent]:
    return state_repository.list_audit_events(limit=limit)


@app.get("/api/v1/evidence/integrity", response_model=IntegrityResponse)
def verify_audit_integrity(
    state_repository: Annotated[StateRepository, Depends(repository)],
) -> IntegrityResponse:
    valid, event_count = state_repository.verify_audit_chain()
    return IntegrityResponse(
        valid=valid,
        event_count=event_count,
        chain_head_hash=state_repository.audit_chain_head(),
    )


@app.get("/api/v1/evidence/export", response_model=EvidenceBundle)
def export_evidence(
    response: Response,
    state_repository: Annotated[StateRepository, Depends(repository)],
) -> EvidenceBundle:
    valid, event_count = state_repository.verify_audit_chain()
    response.headers["Content-Disposition"] = (
        'attachment; filename="secure-gateway-studio-evidence.json"'
    )
    runs = state_repository.list_runs(limit=500)
    return EvidenceBundle(
        generated_at=datetime.now(UTC),
        app_version=__version__,
        integrity=IntegrityResponse(
            valid=valid,
            event_count=event_count,
            chain_head_hash=state_repository.audit_chain_head(),
        ),
        runs=runs,
        acceptance=[state_repository.acceptance_readiness(run.run_id) for run in runs],
        audit_events=state_repository.list_audit_events(limit=500),
    )


_frontend_dist = Path(__file__).resolve().parents[4] / "frontend" / "dist"
if _frontend_dist.is_dir():
    app.mount("/", StaticFiles(directory=_frontend_dist, html=True), name="frontend")
