import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  App,
  connectionErrorText,
  findRecoverableDeploymentRun,
  isTransientPostBootstrapCloudValidationError,
  POST_BOOTSTRAP_VALIDATION_DELAYS_MS,
  specificationsMatch,
  workflowErrorText,
} from "./App";
import {
  AccessStep,
  ApplyStep,
  EnvironmentStep,
  IdentitiesStep,
  isConfigurationReady,
  ReviewStep,
} from "./features/setup/ConfigurationSteps";
import { getMessages } from "./i18n/messages";
import {
  defaultSetupState,
  constrainSetupStateToRuntime,
  isPublicTrustedHostnameCandidate,
  loadSetupState,
  requiresCloudConnectionRevalidation,
  restoreSetupState,
  toDeploymentSpec,
  type SetupState,
} from "./lib/setup-state";
import { useState } from "react";
import {
  ApiError,
  runtimeCapabilities,
  type ApprovedPlan,
  type DeploymentRun,
  type DeploymentSpec,
  type PreparedPlan,
} from "./lib/api";

function restoredPlan(specification: DeploymentSpec, configurationHash: string): PreparedPlan {
  return {
    plan_id: "plan-restored",
    specification,
    preflight: {
      diagnostics: [],
      read_only: true,
      snapshot: {
        managed_chrome_profile_count: null,
        profile_only_count: null,
        latest_chrome_policy_sync: null,
        endpoint_verification_installed: null,
        secure_enterprise_browser_installed: null,
        endpoint_verification_version: null,
        secure_enterprise_browser_version: null,
        chrome_extension_group_conflicts: [],
        chrome_enterprise_premium_license_count: null,
        chrome_root_store_config_count: null,
        chrome_root_store_config_names: [],
        chrome_root_store_enabled: null,
      },
    },
    plan: {
      configuration_hash: configurationHash,
      changes: [],
      gates: [],
      can_apply: true,
    },
    created_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 60_000).toISOString(),
  };
}

function restoredApproval(configurationHash: string): ApprovedPlan {
  return {
    approval_id: "approval-restored",
    configuration_hash: configurationHash,
    plan_hash: "b".repeat(64),
    approved_by: "operator@example.com",
    approved_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 60_000).toISOString(),
  };
}

function stubRestoredWorkflow(plan: PreparedPlan, approval: ApprovedPlan) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
    const url = String(input);
    const payload = url.endsWith("/api/v1/health")
      ? { status: "ok", session_nonce: "workflow-test-nonce" }
      : url.includes("/api/v1/plans/")
        ? plan
        : url.includes("/api/v1/approvals/")
          ? approval
          : { run_id: "unexpected-run" };
    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  });
  vi.stubGlobal("fetch", fetchMock);
  window.localStorage.setItem(
    "sgs.workflow.v1",
    JSON.stringify({
      planId: plan.plan_id,
      approvalId: approval.approval_id,
      runId: "",
    }),
  );
  return fetchMock;
}

describe("Secure Gateway Studio mode screen", () => {
  it("recovers an unfinished Apply instead of preparing a conflicting replacement plan", () => {
    const completed = {
      ...restoredApproval("a".repeat(64)),
    };
    const run = (status: DeploymentRun["status"], startedAt: string): DeploymentRun => ({
      run_id: `run-${status}`,
      approval_id: completed.approval_id,
      configuration_hash: completed.configuration_hash,
      status,
      started_at: startedAt,
      completed_at: status === "succeeded" ? startedAt : null,
      operations: [],
    });

    expect(findRecoverableDeploymentRun([
      run("succeeded", "2026-08-25T00:00:00Z"),
      run("interrupted", "2026-08-26T00:00:00Z"),
    ])?.status).toBe("interrupted");
    expect(findRecoverableDeploymentRun([
      run("rollback_failed", "2026-08-26T00:00:00Z"),
    ])?.status).toBe("rollback_failed");
    expect(findRecoverableDeploymentRun([
      run("failed", "2026-08-26T00:00:00Z"),
    ])?.status).toBe("failed");
    expect(findRecoverableDeploymentRun([
      run("rollback_unavailable", "2026-08-26T00:00:00Z"),
    ])?.status).toBe("rollback_unavailable");
    expect(findRecoverableDeploymentRun([
      run("rolled_back", "2026-08-26T00:00:00Z"),
      run("succeeded", "2026-08-25T00:00:00Z"),
    ])).toBeNull();
  });

  it("treats server-normalized principals and private hostnames as the same approved spec", () => {
    const current = toDeploymentSpec({
      ...defaultSetupState,
      privateHostname: "SECURE-GATEWAY.INTERNAL.",
      principals: [{ id: "p1", type: "group", value: "USERS@EXAMPLE.COM" }],
    }, "en");
    const normalized = {
      ...current,
      private_hostname: "secure-gateway.internal",
      principals: [{ type: "group" as const, value: "users@example.com" }],
    };

    expect(specificationsMatch(normalized, current)).toBe(true);
  });

  it("shows the deployer prerequisite returned while approving instead of a generic validation error", () => {
    const detail =
      "Bootstrap and impersonate the Secure Gateway deployer before continuing.";
    expect(workflowErrorText(
      new ApiError(409, "deployer-project-mismatch", detail),
      getMessages("ja").workflow,
    )).toBe(detail);
  });

  it("shows the actual Cloud connection failure instead of hiding it behind a generic message", () => {
    const detail =
      "The signed-in administrator cannot impersonate secure-gateway-studio-deployer@montreal-436802.iam.gserviceaccount.com.";
    expect(connectionErrorText(
      new ApiError(403, "impersonation-denied", detail),
      "cloud",
      getMessages("ja").workflow,
    )).toBe(detail);
  });

  it("retries only IAM propagation-shaped failures after bootstrap", () => {
    expect(isTransientPostBootstrapCloudValidationError(
      new ApiError(403, "impersonation-denied", "cannot impersonate"),
    )).toBe(true);
    expect(isTransientPostBootstrapCloudValidationError(
      new ApiError(403, "google-api-403", "permission not propagated"),
    )).toBe(true);
    expect(isTransientPostBootstrapCloudValidationError(
      new ApiError(409, "deployer-permissions-not-ready", "role update not propagated"),
    )).toBe(true);
    expect(isTransientPostBootstrapCloudValidationError(
      new ApiError(409, "deployer-dns-readiness-failed", "DNS read not propagated"),
    )).toBe(true);
    expect(isTransientPostBootstrapCloudValidationError(
      new ApiError(409, "deployer-dns-permission-denied", "DNS returned HTTP 403"),
    )).toBe(true);
    expect(isTransientPostBootstrapCloudValidationError(
      new ApiError(409, "deployer-dns-network-failed", "DNS could not be reached"),
    )).toBe(true);
    expect(isTransientPostBootstrapCloudValidationError(
      new ApiError(404, "google-api-404", "project not found"),
    )).toBe(false);
    expect(isTransientPostBootstrapCloudValidationError(
      new ApiError(
        409,
        "deployer-dns-organization-restricted",
        "VPC Service Controls denied the request",
      ),
    )).toBe(false);
    expect(POST_BOOTSTRAP_VALIDATION_DELAYS_MS.reduce<number>(
      (total, milliseconds) => total + milliseconds,
      0,
    )).toBeGreaterThanOrEqual(120_000);
    expect(Math.max(...POST_BOOTSTRAP_VALIDATION_DELAYS_MS)).toBeLessThanOrEqual(30_000);
  });

  beforeEach(() => {
    window.localStorage.clear();
    vi.restoreAllMocks();
  });

  it("switches the complete interface between English and Japanese", () => {
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: /English/ }));
    fireEvent.click(screen.getByRole("menuitemradio", { name: "日本語" }));

    expect(
      screen.getByRole("heading", {
        name: "セキュア ゲートウェイの新規セットアップ",
      }),
    ).toBeInTheDocument();
    expect(window.localStorage.getItem("sgs.locale.v1")).toBe("ja");
  });

  it("defaults to rapid PoC and keeps Production visible but disabled", () => {
    render(<App />);

    expect(
      screen.getByRole("button", { name: /^Rapid proof of concept/ }),
    ).toHaveAttribute("aria-pressed", "true");
    expect(
      screen.getByRole("button", { name: /^Production/ }),
    ).toBeDisabled();
  });

  it("shows the actionable gcloud bootstrap failure returned by the API", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    render(
      <IdentitiesStep
        messages={getMessages("ja")}
        onBootstrapCloud={vi.fn().mockRejectedValue(
          new ApiError(
            424,
            "deployer-bootstrap-failed",
            "The active gcloud user credentials require reauthentication. Run `gcloud auth login`, complete browser sign-in, then retry automatic deployer setup.",
          ),
        )}
        onPatch={vi.fn()}
        onValidateCloud={vi.fn()}
        onValidateWorkspace={vi.fn()}
        state={{ ...defaultSetupState, projectId: "montreal-436802" }}
      />,
    );

    fireEvent.click(
      screen.getByRole("button", { name: "SAと製品用途限定ロールを自動作成" }),
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "gcloud auth login",
    );
  });

  it("allows a local CA for all selected managed Chrome PoC platforms", () => {
    render(<App />);

    const localCa = screen.getByRole("button", { name: /Local PoC CA/ });

    expect(localCa).not.toBeDisabled();
    fireEvent.click(localCa);
    expect(localCa).toHaveAttribute("aria-pressed", "true");

    fireEvent.click(screen.getByRole("checkbox", { name: "macOS" }));
    expect(localCa).toHaveAttribute("aria-pressed", "true");
    expect(
      screen.getByText(/Admin console upload required/),
    ).toBeInTheDocument();
  });

  it("defaults a new rapid PoC to macOS only", () => {
    render(<App />);

    expect(screen.queryByText("proj-secgw-lab-01")).not.toBeInTheDocument();
    expect(screen.queryByText("admin@acme.com")).not.toBeInTheDocument();
    expect(screen.getByRole("checkbox", { name: "macOS" })).toBeChecked();
    for (const platform of ["Windows", "Linux", "ChromeOS"]) {
      expect(screen.getByRole("checkbox", { name: platform })).not.toBeChecked();
    }
    expect(
      screen.getByText(/Each selected platform creates a required T07/),
    ).toBeInTheDocument();
  });

  it("locks the project ID while bootstrap and its post-bootstrap validation are running", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    let finishBootstrap!: (value: {
      project_id: string;
      operator_email: string;
      service_account_email: string;
      service_account_unique_id: string;
      custom_role: string;
      access_policy_id: null;
      adc_command: string;
    }) => void;
    const onBootstrapCloud = vi.fn().mockReturnValue(new Promise((resolve) => {
      finishBootstrap = resolve;
    }));
    let finishValidation!: () => void;
    const onValidateCloud = vi.fn().mockReturnValue(new Promise<void>((resolve) => {
      finishValidation = resolve;
    }));
    render(
      <IdentitiesStep
        messages={getMessages("ja")}
        onBootstrapCloud={onBootstrapCloud}
        onPatch={vi.fn()}
        onValidateCloud={onValidateCloud}
        onValidateWorkspace={vi.fn()}
        state={{ ...defaultSetupState, projectId: "montreal-436802" }}
      />,
    );

    fireEvent.click(
      screen.getByRole("button", { name: "SAと製品用途限定ロールを自動作成" }),
    );
    expect(screen.getByRole("textbox", { name: "Google Cloud プロジェクトID" }))
      .toBeDisabled();

    finishBootstrap({
      project_id: "montreal-436802",
      operator_email: "operator@example.com",
      service_account_email:
        "secure-gateway-studio-deployer@montreal-436802.iam.gserviceaccount.com",
      service_account_unique_id: "223456789012345678901",
      custom_role: "projects/montreal-436802/roles/secureGatewayStudioDeployer",
      access_policy_id: null,
      adc_command: "",
    });
    await waitFor(() => expect(onValidateCloud).toHaveBeenCalledWith(true));
    expect(screen.getByRole("button", { name: "IAM権限の反映を待機中…" }))
      .toBeDisabled();
    finishValidation();
    await waitFor(() => expect(
      screen.getByRole("textbox", { name: "Google Cloud プロジェクトID" }),
    ).toBeEnabled());
    expect(screen.getByRole("textbox", { name: "Google Cloud プロジェクトID" }))
      .toBeEnabled();
  });

  it("allows trusted preflight to report an incomplete restored configuration", () => {
    const onPrepare = vi.fn().mockResolvedValue(undefined);
    render(
      <ReviewStep
        approval={null}
        busy={false}
        error=""
        messages={getMessages("ja")}
        onApprove={vi.fn().mockResolvedValue(undefined)}
        onPatch={vi.fn()}
        onPrepare={onPrepare}
        preparedPlan={null}
        state={{
          ...defaultSetupState,
          currentStep: 5,
          cloudConnection: "connected",
          workspaceConnection: "connected",
          targetOuId: "03-test-ou",
          managedChromeAccessLevel: "NONE",
          testOuConfirmed: true,
          principals: [{ id: "p1", type: "user", value: "user@example.com" }],
        }}
      />,
    );

    const button = screen.getByRole("button", { name: "信頼済み事前確認を実行" });
    expect(button).toBeEnabled();
    fireEvent.click(button);
    expect(onPrepare).toHaveBeenCalledTimes(1);
  });

  it("requires a second explicit confirmation before migrating a 0.2.0 deployer", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    const onBootstrapCloud = vi.fn()
      .mockRejectedValueOnce(new ApiError(
        409,
        "service-account-identity-unpinned",
        "The existing deployer has no immutable ownership pin.",
      ))
      .mockResolvedValueOnce({
        project_id: "enterprise-secgw-01",
        operator_email: "operator@example.com",
        service_account_email:
          "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com",
        service_account_unique_id: "123456789012345678901",
        custom_role: "projects/enterprise-secgw-01/roles/secureGatewayPocDeployer",
        access_policy_id: null,
        adc_command: "",
      });
    render(
      <IdentitiesStep
        messages={getMessages("ja")}
        onBootstrapCloud={onBootstrapCloud}
        onPatch={vi.fn()}
        onValidateCloud={vi.fn().mockResolvedValue(undefined)}
        onValidateWorkspace={vi.fn()}
        state={{ ...defaultSetupState, projectId: "enterprise-secgw-01" }}
      />,
    );

    fireEvent.click(
      screen.getByRole("button", { name: "SAと製品用途限定ロールを自動作成" }),
    );

    await waitFor(() => expect(onBootstrapCloud).toHaveBeenCalledTimes(2));
    expect(onBootstrapCloud).toHaveBeenNthCalledWith(1, false);
    expect(onBootstrapCloud).toHaveBeenNthCalledWith(2, true);
    expect(confirm).toHaveBeenCalledTimes(2);
    expect(String(confirm.mock.calls[1]?.[0])).toContain("不変な数値ID");
  });

  it("requires a deletion-specific confirmation before recreating a pinned deployer", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    const onBootstrapCloud = vi.fn()
      .mockRejectedValueOnce(new ApiError(
        409,
        "service-account-pinned-identity-missing",
        "The pinned deployer service account no longer exists.",
      ))
      .mockResolvedValueOnce({
        project_id: "enterprise-secgw-01",
        operator_email: "operator@example.com",
        service_account_email:
          "secure-gateway-deployer@enterprise-secgw-01.iam.gserviceaccount.com",
        service_account_unique_id: "223456789012345678901",
        custom_role: "projects/enterprise-secgw-01/roles/secureGatewayPocDeployer",
        access_policy_id: null,
        adc_command: "",
      });
    const onValidateCloud = vi.fn().mockResolvedValue(undefined);
    render(
      <IdentitiesStep
        messages={getMessages("ja")}
        onBootstrapCloud={onBootstrapCloud}
        onPatch={vi.fn()}
        onValidateCloud={onValidateCloud}
        onValidateWorkspace={vi.fn()}
        state={{ ...defaultSetupState, projectId: "enterprise-secgw-01" }}
      />,
    );

    fireEvent.click(
      screen.getByRole("button", { name: "SAと製品用途限定ロールを自動作成" }),
    );

    await waitFor(() => expect(onBootstrapCloud).toHaveBeenCalledTimes(2));
    expect(onBootstrapCloud).toHaveBeenNthCalledWith(1, false);
    expect(onBootstrapCloud).toHaveBeenNthCalledWith(2, false, false, true);
    expect(onValidateCloud).toHaveBeenCalledWith(true);
    expect(confirm).toHaveBeenCalledTimes(2);
    expect(String(confirm.mock.calls[1]?.[0])).toContain("旧数値IDを恒久的に廃止");
  });

  it("offers an isolated replacement only after the legacy migration audit fails closed", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    const onBootstrapCloud = vi.fn()
      .mockRejectedValueOnce(new ApiError(
        409,
        "service-account-identity-unpinned",
        "The existing deployer has no immutable ownership pin.",
      ))
      .mockRejectedValueOnce(new ApiError(
        409,
        "legacy-deployer-project-iam-unsafe",
        "The legacy deployer project IAM does not match.",
      ))
      .mockResolvedValueOnce({
        project_id: "enterprise-secgw-01",
        operator_email: "operator@example.com",
        service_account_email:
          "secure-gateway-studio-deployer@enterprise-secgw-01.iam.gserviceaccount.com",
        service_account_unique_id: "223456789012345678901",
        custom_role: "projects/enterprise-secgw-01/roles/secureGatewayStudioDeployer",
        access_policy_id: null,
        adc_command: "",
      });
    const onValidateCloud = vi.fn().mockResolvedValue(undefined);
    render(
      <IdentitiesStep
        messages={getMessages("ja")}
        onBootstrapCloud={onBootstrapCloud}
        onPatch={vi.fn()}
        onValidateCloud={onValidateCloud}
        onValidateWorkspace={vi.fn()}
        state={{ ...defaultSetupState, projectId: "enterprise-secgw-01" }}
      />,
    );

    fireEvent.click(
      screen.getByRole("button", { name: "SAと製品用途限定ロールを自動作成" }),
    );

    await waitFor(() => expect(onBootstrapCloud).toHaveBeenCalledTimes(3));
    expect(onBootstrapCloud).toHaveBeenNthCalledWith(1, false);
    expect(onBootstrapCloud).toHaveBeenNthCalledWith(2, true);
    expect(onBootstrapCloud).toHaveBeenNthCalledWith(3, false, true);
    expect(onValidateCloud).toHaveBeenCalledWith(true);
    expect(confirm).toHaveBeenCalledTimes(3);
    expect(String(confirm.mock.calls[2]?.[0])).toContain("別の予約名");
  });

  it("invalidates a restored plan and approval when a platform changes", async () => {
    const specification = toDeploymentSpec(defaultSetupState, "en");
    const plan = restoredPlan(specification, "a".repeat(64));
    const approval = restoredApproval(plan.plan.configuration_hash);
    const fetchMock = stubRestoredWorkflow(plan, approval);

    render(<App />);
    await waitFor(() =>
      expect(fetchMock.mock.calls.some(([input]) => String(input).includes("/approvals/"))).toBe(
        true,
      ),
    );
    await waitFor(() => expect(window.localStorage.getItem("sgs.workflow.v1")).not.toBeNull());

    fireEvent.click(screen.getByRole("checkbox", { name: "Windows" }));

    await waitFor(() => expect(window.localStorage.getItem("sgs.workflow.v1")).toBeNull());
  });

  it("keeps Apply disabled when a restored approval belongs to a different specification", async () => {
    const savedSetup = { ...defaultSetupState, currentStep: 6 };
    window.localStorage.setItem("sgs.setup.v8", JSON.stringify(savedSetup));
    const staleSpecification = {
      ...toDeploymentSpec(savedSetup, "en"),
      project_id: "different-project",
    };
    const plan = restoredPlan(staleSpecification, "c".repeat(64));
    const approval = restoredApproval(plan.plan.configuration_hash);
    const fetchMock = stubRestoredWorkflow(plan, approval);

    render(<App />);
    await waitFor(() =>
      expect(fetchMock.mock.calls.some(([input]) => String(input).includes("/approvals/"))).toBe(
        true,
      ),
    );

    const applyButton = screen.getByRole("button", { name: /Apply approved changes/ });
    expect(applyButton).toBeDisabled();
    fireEvent.click(applyButton);
    expect(
      fetchMock.mock.calls.some(
        ([input, init]) => String(input).endsWith("/api/v1/runs") && init?.method === "POST",
      ),
    ).toBe(false);
  });

  it("allows an exact approved extension plan to continue when the plan response omits timestamps", async () => {
    const savedSetup = {
      ...defaultSetupState,
      currentStep: 5,
      projectId: "montreal-436802",
      cloudConnection: "connected" as const,
      cloudIdentity: "operator@example.com",
      workspaceConnection: "connected" as const,
      workspaceIdentity: "admin@example.com",
      backendKind: "direct_https" as const,
      networkStrategy: "existing" as const,
      vpcName: "private-app-vpc",
      existingBackendUrl: "https://secgw-backend.internal:443",
      existingBackendConnectivityConfirmed: true,
      privateHostname: "secgw-backend.internal",
      customerId: "C012canonical",
      targetOuId: "03pilot",
      managedChromeAccessLevel: "NONE",
      principals: [{ id: "p1", type: "user" as const, value: "user@example.com" }],
      testOuConfirmed: true,
    };
    expect(isConfigurationReady(savedSetup)).toBe(true);
    window.localStorage.setItem("sgs.setup.v9", JSON.stringify(savedSetup));
    const completePlan = restoredPlan(
      toDeploymentSpec(savedSetup, "en"),
      "e".repeat(64),
    );
    const { created_at: _createdAt, expires_at: _expiresAt, ...extensionPlan } = completePlan;
    const approval = restoredApproval(completePlan.plan.configuration_hash);
    const fetchMock = stubRestoredWorkflow(extensionPlan as PreparedPlan, approval);

    render(<App />);
    await waitFor(() =>
      expect(fetchMock.mock.calls.some(([input]) => String(input).includes("/approvals/"))).toBe(
        true,
      ),
    );

    expect(screen.getByRole("button", { name: "Continue to Apply" })).toBeEnabled();
  });

  it("allows a semantically identical approved Option B plan returned in a different key order", async () => {
    const savedSetup = {
      ...defaultSetupState,
      currentStep: 5,
      projectId: "montreal-436802",
      cloudConnection: "connected" as const,
      cloudIdentity: "operator@example.com",
      workspaceConnection: "connected" as const,
      workspaceIdentity: "admin@test-domain.dev",
      backendKind: "internal_https_lb" as const,
      networkStrategy: "dedicated" as const,
      certificateStrategy: "local_poc" as const,
      sourceImage: "projects/debian-cloud/global/images/debian-12-bookworm-v20260801",
      privateHostname: "secgw-backend.internal",
      customerId: "C012canonical",
      targetOuId: "03ph8a2z3skxigh",
      managedChromeAccessLevel: "NONE",
      principals: [{ id: "p1", type: "group" as const, value: "users@test-domain.dev" }],
      testOuConfirmed: true,
    };
    expect(isConfigurationReady(savedSetup)).toBe(true);
    window.localStorage.setItem("sgs.setup.v9", JSON.stringify(savedSetup));
    const currentSpecification = toDeploymentSpec(savedSetup, "en");
    const extensionRoundTripSpecification = Object.fromEntries(
      Object.entries({
        ...currentSpecification,
        subnet_cidr: "10.42.0.0/24",
        platforms: [...currentSpecification.platforms].sort(),
      })
        .filter(([, value]) => value !== null && value !== undefined)
        .reverse(),
    ) as unknown as DeploymentSpec;
    const plan = restoredPlan(extensionRoundTripSpecification, "f".repeat(64));
    const approval = restoredApproval(plan.plan.configuration_hash);
    const fetchMock = stubRestoredWorkflow(plan, approval);

    render(<App />);
    await waitFor(() =>
      expect(fetchMock.mock.calls.some(([input]) => String(input).includes("/approvals/"))).toBe(
        true,
      ),
    );

    expect(screen.getByRole("button", { name: "Continue to Apply" })).toBeEnabled();
  });

  it("resumes an interrupted Apply and continues polling the same run", async () => {
    const savedSetup = { ...defaultSetupState, currentStep: 6 };
    window.localStorage.setItem("sgs.setup.v8", JSON.stringify(savedSetup));
    const plan = restoredPlan(
      toDeploymentSpec(savedSetup, "en"),
      "d".repeat(64),
    );
    const approval = restoredApproval(plan.plan.configuration_hash);
    const interruptedRun: DeploymentRun = {
      run_id: "run-interrupted",
      approval_id: approval.approval_id,
      configuration_hash: plan.plan.configuration_hash,
      status: "interrupted",
      started_at: "2026-08-04T00:00:00Z",
      completed_at: "2026-08-04T00:00:30Z",
      operations: [],
    };
    let runReads = 0;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      let payload: unknown;
      if (url.endsWith("/api/v1/health")) {
        payload = { status: "ok", session_nonce: "resume-test-nonce" };
      } else if (url.includes("/api/v1/plans/")) {
        payload = plan;
      } else if (url.includes("/api/v1/approvals/")) {
        payload = approval;
      } else if (url.endsWith("/api/v1/runs/run-interrupted/resume")) {
        payload = { ...interruptedRun, status: "running", completed_at: null };
      } else if (url.endsWith("/api/v1/runs/run-interrupted")) {
        runReads += 1;
        payload =
          runReads === 1
            ? interruptedRun
            : { ...interruptedRun, status: "succeeded", completed_at: "2026-08-04T00:01:00Z" };
      } else {
        payload = { detail: "unexpected request" };
      }
      return new Response(JSON.stringify(payload), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    window.localStorage.setItem(
      "sgs.workflow.v1",
      JSON.stringify({
        planId: plan.plan_id,
        approvalId: approval.approval_id,
        runId: interruptedRun.run_id,
      }),
    );

    render(<App />);
    fireEvent.click(
      await screen.findByRole("button", { name: "Resume interrupted Apply" }),
    );

    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(
          ([input, init]) =>
            String(input).endsWith("/api/v1/runs/run-interrupted/resume") &&
            init?.method === "POST" &&
            init.body === JSON.stringify({ confirmation: "RESUME" }),
        ),
      ).toBe(true),
    );
    expect(
      (await screen.findAllByText("Deployment succeeded", {}, { timeout: 3_000 }))
        .length,
    ).toBeGreaterThan(0);
    expect(runReads).toBeGreaterThanOrEqual(2);
  });

  it("makes existing cross-cloud backend connectivity an explicit prerequisite", () => {
    const onPatch = vi.fn();
    render(
      <EnvironmentStep
        messages={getMessages("en")}
        onPatch={onPatch}
        state={{
          ...defaultSetupState,
          backendKind: "existing_http",
          existingBackendLocation: "aws",
        }}
      />,
    );

    expect(
      screen.getByRole("combobox", { name: "Backend hosting location" }),
    ).toHaveValue("aws");
    expect(
      screen.getByText(/does not create AWS\/Azure VPNs/),
    ).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("checkbox", {
        name: /I confirm private routing, DNS, and backend firewall access/,
      }),
    );
    expect(onPatch).toHaveBeenCalledWith({
      existingBackendConnectivityConfirmed: true,
    });
  });

  it("models direct private HTTPS as a separate deployment without Nginx fields", () => {
    const onPatch = vi.fn();
    const directState = {
      ...defaultSetupState,
      backendKind: "direct_https" as const,
      networkStrategy: "existing" as const,
      vpcName: "private-app-vpc",
      upstreamVpcProjectId: "shared-network-prj",
      existingBackendUrl: "https://app.corp.internal:8443",
      existingBackendLocation: "azure" as const,
      existingBackendConnectivityConfirmed: true,
      applicationEgressRegion: "asia-east1",
    };
    render(
      <EnvironmentStep
        messages={getMessages("en")}
        onPatch={onPatch}
        state={directState}
      />,
    );

    expect(
      screen.getByRole("button", {
        name: /^Option A — Connect directly to an existing HTTPS app/,
      }),
    ).toHaveAttribute("aria-pressed", "true");
    expect(
      screen.getByRole("textbox", { name: /Private HTTPS endpoint/ }),
    ).toHaveValue("https://app.corp.internal:8443");
    expect(
      screen.queryByRole("textbox", { name: "Private application hostname" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("textbox", { name: "Existing subnet name" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("textbox", { name: "Upstream VPC project ID (optional)" }),
    ).toHaveValue("shared-network-prj");
    expect(
      screen.getByRole("button", { name: "Use Option B's private sample VM" }),
    ).toBeInTheDocument();

    expect(toDeploymentSpec(directState, "en")).toMatchObject({
      backend_kind: "direct_https",
      network_strategy: "existing",
      existing_backend_url: "https://app.corp.internal:8443",
      application_egress_region: "asia-east1",
      upstream_vpc_project_id: "shared-network-prj",
    });
  });

  it("requires an explicit existing VPC for direct private HTTPS", () => {
    const onPatch = vi.fn();
    render(
      <EnvironmentStep
        messages={getMessages("en")}
        onPatch={onPatch}
        state={{ ...defaultSetupState, vpcName: "" }}
      />,
    );

    fireEvent.click(
      screen.getByRole("button", {
        name: /^Option A — Connect directly to an existing HTTPS app/,
      }),
    );
    const selectionPatch = onPatch.mock.calls.at(-1)?.[0];
    expect(selectionPatch).toMatchObject({
      backendKind: "direct_https",
      networkStrategy: "existing",
    });
    expect(selectionPatch).not.toHaveProperty("vpcName");
    const otherwiseReady = {
      ...defaultSetupState,
      cloudConnection: "connected" as const,
      workspaceConnection: "connected" as const,
      backendKind: "direct_https" as const,
      networkStrategy: "existing" as const,
      existingBackendUrl: "https://app.corp.internal:443",
      existingBackendConnectivityConfirmed: true,
      customerId: "C01abcdef",
      targetOuId: "03pilot",
      managedChromeAccessLevel: "accessPolicies/123/accessLevels/managed",
      principals: [{ id: "p1", type: "user" as const, value: "user@example.com" }],
      testOuConfirmed: true,
    };
    expect(isConfigurationReady({ ...otherwiseReady, vpcName: "" })).toBe(false);
    expect(isConfigurationReady({ ...otherwiseReady, vpcName: "private-app-vpc" })).toBe(true);
    expect(
      isConfigurationReady({
        ...otherwiseReady,
        vpcName: "private-app-vpc",
        upstreamVpcProjectId: "INVALID_PROJECT",
      }),
    ).toBe(false);
    expect(
      toDeploymentSpec({
        ...otherwiseReady,
        vpcName: "private-app-vpc",
        upstreamVpcProjectId: "shared-network-prj",
      }, "en").upstream_vpc_project_id,
    ).toBe("shared-network-prj");
    expect(
      isConfigurationReady({
        ...otherwiseReady,
        vpcName: "private-app-vpc",
        managedChromeAccessLevel: "AUTO_CREATE_CHROME_ANY",
      }),
    ).toBe(false);
    expect(
      isConfigurationReady({
        ...otherwiseReady,
        vpcName: "private-app-vpc",
        managedChromeAccessLevel: "NONE",
      }),
    ).toBe(true);
  });

  it("models internal Application Load Balancer HTTPS offload as Option B", () => {
    const onPatch = vi.fn();
    const ilbState = {
      ...defaultSetupState,
      backendKind: "internal_https_lb" as const,
      deploymentName: "secure-gateway-ilb-https-offload",
      proxySubnetCidr: "10.42.1.0/24",
    };
    const { rerender } = render(
      <EnvironmentStep
        messages={getMessages("en")}
        onPatch={onPatch}
        state={ilbState}
      />,
    );

    expect(
      screen.getByRole("button", {
        name: /^Option B — HTTPS offload with Internal Application Load Balancer/,
      }),
    ).toHaveAttribute("aria-pressed", "true");
    expect(
      screen.getByRole("textbox", { name: "ILB proxy-only subnet CIDR" }),
    ).toHaveValue("10.42.1.0/24");
    expect(screen.queryByText("Backend URL (http://)")).not.toBeInTheDocument();
    expect(
      screen.getByRole("textbox", { name: "Immutable VM image" }),
    ).toBeInTheDocument();
    expect(screen.getAllByText(/Estimated monthly PoC:.*USD/).length).toBeGreaterThanOrEqual(4);
    fireEvent.click(
      screen.getByRole("button", { name: "Create a private sample VM during approved Apply" }),
    );
    expect(onPatch).toHaveBeenLastCalledWith(expect.objectContaining({
      backendKind: "internal_https_lb",
      networkStrategy: "dedicated",
      proxySubnetCidr: "10.42.1.0/24",
    }));
    const otherwiseReadyPocIlb = {
      ...ilbState,
      cloudConnection: "connected" as const,
      workspaceConnection: "connected" as const,
      certificateStrategy: "local_poc" as const,
      targetOuId: "03pilot",
      managedChromeAccessLevel: "NONE",
      principals: [{ id: "p1", type: "user" as const, value: "user@example.com" }],
      testOuConfirmed: true,
    };
    expect(isConfigurationReady(otherwiseReadyPocIlb)).toBe(false);
    expect(
      isConfigurationReady({
        ...otherwiseReadyPocIlb,
        sourceImage:
          "projects/my-image-project/global/images/sgs-nginx-20260730",
      }),
    ).toBe(true);

    expect(toDeploymentSpec(ilbState, "en")).toMatchObject({
      backend_kind: "internal_https_lb",
      proxy_subnet_cidr: "10.42.1.0/24",
      existing_backend_url: null,
    });

    rerender(
      <EnvironmentStep
        messages={getMessages("en")}
        onPatch={onPatch}
        state={{ ...ilbState, mode: "production" }}
      />,
    );
    expect(
      screen.getByRole("textbox", { name: "Immutable VM image" }),
    ).toBeInTheDocument();
    expect(screen.queryByText("Minimum Nginx replicas")).not.toBeInTheDocument();
  });

  it("fills the immutable PoC image immediately when the sample VM action is clicked", async () => {
    const mutableCapabilities = runtimeCapabilities as unknown as {
      recommendedPocSourceImage: boolean;
    };
    const previousCapability = mutableCapabilities.recommendedPocSourceImage;
    mutableCapabilities.recommendedPocSourceImage = true;
    const immutableImage =
      "projects/debian-cloud/global/images/debian-12-bookworm-v20260801";
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      if (String(input).endsWith("/api/v1/health")) {
        return new Response(JSON.stringify({ session_nonce: "sample-image-test" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response(JSON.stringify({
        option: {
          value: immutableImage,
          label: "Google Debian 12",
          description: "Immutable public PoC image · numeric ID 1234567890123456789",
        },
      }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }));

    function Harness() {
      const [state, setState] = useState<SetupState>({
        ...defaultSetupState,
        backendKind: "internal_https_lb" as const,
        cloudConnection: "connected" as const,
        projectId: "enterprise-secgw-01",
      });
      return (
        <EnvironmentStep
          messages={getMessages("ja")}
          onPatch={(patch) => setState((current) => ({ ...current, ...patch }))}
          state={state}
        />
      );
    }

    try {
      render(<Harness />);
      fireEvent.click(screen.getByRole("button", {
        name: "承認済みApplyでプライベートサンプルVMを作成",
      }));
      await waitFor(() => {
        expect(screen.getByRole("textbox", { name: "不変のVMイメージ" }))
          .toHaveValue(immutableImage);
      });
      expect(screen.getByRole("status")).toHaveTextContent(
        `不変のPoCイメージを設定しました${immutableImage}`,
      );
    } finally {
      mutableCapabilities.recommendedPocSourceImage = previousCapability;
    }
  });

  it("moves the legacy Nginx choices into Option C advanced settings", () => {
    render(
      <EnvironmentStep
        messages={getMessages("en")}
        onPatch={vi.fn()}
        state={{ ...defaultSetupState, backendKind: "managed_sample" }}
      />,
    );

    const legacy = screen.getByText(
      "Option C — Legacy Nginx method / advanced settings",
    ).closest("details");
    expect(legacy).toHaveAttribute("open");
    expect(
      within(legacy as HTMLElement).getByRole("button", {
        name: /^Managed sample backend \(Nginx\)/,
      }),
    ).toHaveAttribute("aria-pressed", "true");
    expect(
      screen.getByRole("button", { name: "Create the private sample VM during Apply" }),
    ).toBeInTheDocument();
    expect(screen.getAllByText(/Estimated monthly PoC:.*USD/).length).toBeGreaterThanOrEqual(4);
  });

  it("offers the public root CA handoff after a successful local CA Apply", () => {
    render(
      <ApplyStep
        approval={null}
        busy={false}
        error=""
        messages={getMessages("en")}
        onResume={vi.fn()}
        preparedPlan={null}
        run={{
          run_id: "run-local-ca",
          approval_id: "approval-local-ca",
          configuration_hash: "hash-local-ca",
          status: "succeeded",
          started_at: "2026-08-03T00:00:00Z",
          completed_at: "2026-08-03T00:01:00Z",
          operations: [],
        }}
        state={{
          ...defaultSetupState,
          backendKind: "managed_sample",
          certificateStrategy: "local_poc",
        }}
      />,
    );

    expect(
      screen.getByRole("heading", { name: "Complete managed Chrome trust" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Download public root CA" }),
    ).toBeEnabled();
    expect(
      screen.getByRole("link", { name: "Open Google's CA setup guide" }),
    ).toHaveAttribute(
      "href",
      "https://support.google.com/chrome/a/answer/16073278",
    );
    expect(screen.getByText(/Run-scoped Nginx and\/or sample-backend VM resources/)).toBeInTheDocument();
    expect(screen.getByText(/Created for a dedicated-VPC path with private VMs/)).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(/10\.10\.0\.2|secgw-nat-static-ip|\/ RUNNING/);
  });

  it("hides nonexistent VM and Cloud NAT links for direct HTTPS", () => {
    const { rerender } = render(
      <ApplyStep
        approval={null}
        busy={false}
        error=""
        messages={getMessages("en")}
        onResume={vi.fn()}
        preparedPlan={null}
        run={null}
        state={{
          ...defaultSetupState,
          backendKind: "direct_https",
          networkStrategy: "existing",
          projectId: "service-project-123",
          upstreamVpcProjectId: "host-project-456",
          vpcName: "shared-vpc",
        }}
      />,
    );

    expect(screen.queryByText("Compute Engine VM Instances")).not.toBeInTheDocument();
    expect(screen.queryByText("Cloud NAT")).not.toBeInTheDocument();
    expect(screen.getByText("BeyondCorp Security Gateways")).toBeInTheDocument();
    expect(screen.getByText("VPC Networks & Firewalls")).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /VPC Networks & Firewalls/ }),
    ).toHaveAttribute(
      "href",
      "https://console.cloud.google.com/networking/networks/list?project=host-project-456",
    );
    expect(document.body).not.toHaveTextContent(/RUNNING/);
  });

  it("visualizes live Apply progress from recorded operations", () => {
    render(
      <ApplyStep
        approval={null}
        busy={false}
        error=""
        messages={getMessages("en")}
        onResume={vi.fn()}
        preparedPlan={null}
        run={{
          run_id: "run-progress",
          approval_id: "approval-progress",
          configuration_hash: "hash-progress",
          status: "running",
          started_at: "2026-08-03T00:00:00Z",
          completed_at: null,
          operations: [
            {
              operation_id: "operation-1",
              resource_key: "compute:network:poc-vpc",
              action: "create",
              status: "succeeded",
              error_code: null,
            },
            {
              operation_id: "operation-2",
              resource_key: "compute:subnetwork:poc-subnet",
              action: "create",
              status: "running",
              error_code: null,
            },
          ],
        }}
        state={defaultSetupState}
      />,
    );

    expect(screen.getByRole("progressbar", { name: "Deployment progress" })).toHaveAttribute(
      "aria-valuenow",
      "50",
    );
    expect(screen.getByText("1 of 2 operations complete")).toBeInTheDocument();
    expect(screen.getByText("compute:subnetwork:poc-subnet")).toBeInTheDocument();
  });

  it("shows every failed rollback operation and its error in one render", () => {
    render(
      <ApplyStep
        approval={null}
        busy={false}
        error=""
        messages={getMessages("en")}
        onResume={vi.fn()}
        preparedPlan={null}
        run={{
          run_id: "run-failed-operation",
          approval_id: "approval-failed-operation",
          configuration_hash: "hash-failed-operation",
          status: "rollback_failed",
          started_at: "2026-08-25T00:00:00Z",
          completed_at: "2026-08-25T00:01:00Z",
          operations: [
            {
              operation_id: "operation-1",
              resource_key: "serviceusage:project_services:required-apis",
              action: "create",
              status: "succeeded",
              error_code: null,
            },
            {
              operation_id: "operation-2",
              resource_key: "compute:network:poc-vpc",
              action: "create",
              status: "rollback_failed",
              error_code: "compute.networks.delete: permission denied",
            },
            {
              operation_id: "operation-3",
              resource_key: "compute:subnetwork:poc-subnet",
              action: "create",
              status: "rollback_failed",
              error_code: "compute.subnetworks.delete: permission denied",
            },
          ],
        }}
        state={defaultSetupState}
      />,
    );

    expect(screen.getByText("Failed operations")).toBeInTheDocument();
    expect(screen.getByText("compute:network:poc-vpc")).toBeInTheDocument();
    expect(screen.getByText("compute.networks.delete: permission denied")).toBeInTheDocument();
    expect(screen.getByText("compute:subnetwork:poc-subnet")).toBeInTheDocument();
    expect(screen.getByText("compute.subnetworks.delete: permission denied")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry failed rollback" })).toBeInTheDocument();
  });

  it.each(["failed", "rollback_failed"] as const)(
    "offers ownership-bounded rollback recovery for a resumable %s run",
    (status) => {
      const onResume = vi.fn();
      render(
        <ApplyStep
          approval={null}
          busy={false}
          error=""
          messages={getMessages("en")}
          onResume={onResume}
          preparedPlan={null}
          run={{
            run_id: `run-${status}`,
            approval_id: `approval-${status}`,
            configuration_hash: `hash-${status}`,
            status,
            started_at: "2026-08-25T00:00:00Z",
            completed_at: "2026-08-25T00:01:00Z",
            operations: [],
          }}
          state={defaultSetupState}
        />,
      );

      const button = screen.getByRole("button", { name: "Retry failed rollback" });
      expect(button).toBeEnabled();
      fireEvent.click(button);
      expect(onResume).toHaveBeenCalledTimes(1);
    },
  );

  it("does not offer an endless retry after rollback is terminally unavailable", () => {
    render(
      <ApplyStep
        approval={null}
        busy={false}
        error=""
        messages={getMessages("en")}
        onResume={vi.fn()}
        preparedPlan={null}
        run={{
          run_id: "run-rollback-unavailable",
          approval_id: "approval-rollback-unavailable",
          configuration_hash: "hash-rollback-unavailable",
          status: "rollback_unavailable",
          started_at: "2026-08-25T00:00:00Z",
          completed_at: "2026-08-25T00:01:00Z",
          retry_available: false,
          residual_resources: [
            {
              resource_key: "beyondcorp:security_gateway:default",
              provider: "beyondcorp",
              resource_type: "security_gateway",
              resource_name: "default",
              owned: true,
              shared: false,
            },
            {
              resource_key: "cloudresourcemanager:project_iam:upstream-access",
              provider: "cloudresourcemanager",
              resource_type: "project_iam",
              resource_name: "upstream-access",
              owned: true,
              shared: false,
            },
          ],
          operations: [],
        }}
        state={defaultSetupState}
      />,
    );

    expect(screen.queryByRole("button", { name: "Retry failed rollback" }))
      .not.toBeInTheDocument();
    expect(screen.getByText("Manual cleanup required")).toBeInTheDocument();
    expect(screen.getByText("beyondcorp:security_gateway:default")).toBeInTheDocument();
    expect(screen.getByText("cloudresourcemanager:project_iam:upstream-access"))
      .toBeInTheDocument();
  });

  it("keeps rolling back Apply runs in progress instead of marking them finished", () => {
    render(
      <ApplyStep
        approval={null}
        busy={false}
        error=""
        messages={getMessages("en")}
        onResume={vi.fn()}
        preparedPlan={null}
        run={{
          run_id: "run-rolling-back",
          approval_id: "approval-rolling-back",
          configuration_hash: "hash-rolling-back",
          status: "rolling_back",
          started_at: "2026-08-25T00:00:00Z",
          completed_at: null,
          operations: [
            {
              operation_id: "operation-1",
              resource_key: "compute:network:poc-vpc",
              action: "create",
              status: "succeeded",
              error_code: null,
            },
          ],
        }}
        state={defaultSetupState}
      />,
    );

    expect(screen.getByText("Rolling back applied changes…")).toBeInTheDocument();
    expect(screen.queryByText("1 operations recorded")).not.toBeInTheDocument();
    expect(document.querySelector(".progress-spinner")).toBeInTheDocument();
  });

  it("shows a rolled-back Apply as finished instead of leaving stale partial progress", () => {
    const operations = Array.from({ length: 32 }, (_, index) => ({
      operation_id: `operation-${index + 1}`,
      resource_key: `compute:resource:resource-${index + 1}`,
      action: "create",
      status: index < 2 ? "succeeded" : "pending",
      error_code: null,
    }));

    render(
      <ApplyStep
        approval={null}
        busy={false}
        error=""
        messages={getMessages("en")}
        onResume={vi.fn()}
        preparedPlan={null}
        run={{
          run_id: "run-rolled-back",
          approval_id: "approval-rolled-back",
          configuration_hash: "hash-rolled-back",
          status: "rolled_back",
          started_at: "2026-08-25T00:00:00Z",
          completed_at: "2026-08-25T00:01:00Z",
          operations,
        }}
        state={defaultSetupState}
      />,
    );

    expect(screen.getByRole("progressbar", { name: "Deployment progress" })).toHaveAttribute(
      "aria-valuenow",
      "100",
    );
    expect(screen.getByText("Run finished")).toBeInTheDocument();
    expect(screen.getByText("No operation is running")).toBeInTheDocument();
    expect(screen.queryByText("2 of 32 operations complete")).not.toBeInTheDocument();
    expect(screen.queryByText("Current operation")).not.toBeInTheDocument();
    expect(document.querySelector(".progress-spinner")).not.toBeInTheDocument();
  });

  it("restores validated identities but clears stale errors and approval", () => {
    window.localStorage.setItem(
      "sgs.setup.v6",
      JSON.stringify({
        ...defaultSetupState,
        cloudIdentity: "old-cloud-principal@example.com",
        cloudConnection: "connected",
        cloudConnectionError: "stale cloud error",
        workspaceIdentity: "old-workspace-principal@example.com",
        workspaceConnection: "connected",
        workspaceConnectionError: "stale workspace error",
        customerId: "C012canonical",
        managedChromeAccessLevel: "AUTO_CREATE_CHROME_ANY",
        approvalConfirmed: true,
      }),
    );

    expect(loadSetupState()).toMatchObject({
      cloudIdentity: "old-cloud-principal@example.com",
      cloudConnection: "connected",
      cloudConnectionError: "",
      workspaceIdentity: "old-workspace-principal@example.com",
      workspaceConnection: "connected",
      workspaceConnectionError: "",
      managedChromeAccessLevel: "",
      approvalConfirmed: false,
    });
  });

  it("invalidates a pre-0.2.7 cloud validation contract and returns to identities", () => {
    const legacyConnectedSetup = {
      ...defaultSetupState,
      schemaVersion: 8,
      currentStep: 5,
      cloudIdentity: "secure-gateway-studio-deployer@example.iam.gserviceaccount.com",
      cloudConnection: "connected",
    };
    expect(requiresCloudConnectionRevalidation(legacyConnectedSetup)).toBe(true);
    expect(restoreSetupState(legacyConnectedSetup)).toMatchObject({
      schemaVersion: 9,
      currentStep: 1,
      cloudIdentity: "secure-gateway-studio-deployer@example.iam.gserviceaccount.com",
      cloudConnection: "not_connected",
      cloudConnectionError: "",
    });
  });

  it("normalizes an unsupported extension ILB draft to the supported Nginx path", () => {
    expect(constrainSetupStateToRuntime(defaultSetupState, false)).toMatchObject({
      backendKind: "managed_sample",
      deploymentName: "secure-gateway-http-offload",
      existingBackendConnectivityConfirmed: false,
    });
    expect(constrainSetupStateToRuntime(defaultSetupState, true).backendKind).toBe(
      "internal_https_lb",
    );
    expect(
      constrainSetupStateToRuntime(
        { ...defaultSetupState, mode: "production" },
        true,
      ),
    ).toMatchObject({
      backendKind: "managed_sample",
      deploymentName: "secure-gateway-http-offload",
    });
  });

  it("rejects private and reserved names for public-root TLS", () => {
    expect(isPublicTrustedHostnameCandidate("gateway.customer.dev")).toBe(true);
    expect(isPublicTrustedHostnameCandidate("demo-server-http.internal")).toBe(false);
    expect(isPublicTrustedHostnameCandidate("gateway.example.com")).toBe(false);
    expect(isPublicTrustedHostnameCandidate("localhost")).toBe(false);
  });

  it("requires Workspace revalidation when a saved draft has only the my_customer alias", () => {
    window.localStorage.setItem(
      "sgs.setup.v6",
      JSON.stringify({
        ...defaultSetupState,
        workspaceIdentity: "old-workspace-principal@example.com",
        workspaceConnection: "connected",
        customerId: "my_customer",
      }),
    );

    expect(loadSetupState()).toMatchObject({
      workspaceIdentity: "old-workspace-principal@example.com",
      workspaceConnection: "not_connected",
      customerId: "my_customer",
    });
  });

  it("migrates a saved Production draft back to the supported PoC mode", () => {
    window.localStorage.setItem(
      "sgs.setup.v6",
      JSON.stringify({
        ...defaultSetupState,
        mode: "production",
      }),
    );

    expect(loadSetupState().mode).toBe("poc");
  });

  it("opens a bilingual bottom navigation guide for all seven setup steps", () => {
    render(<App />);

    const primaryNavigation = screen.getByRole("navigation", {
      name: "Primary navigation",
    });
    fireEvent.click(
      within(primaryNavigation).getByRole("button", {
        name: "Secure Gateway Deployer",
      }),
    );
    fireEvent.click(
      within(primaryNavigation).getByRole("button", { name: "Guide" }),
    );

    expect(
      screen.getByRole("heading", {
        name: "What happens in each setup step",
      }),
    ).toBeInTheDocument();
    expect(screen.getByText(/Before final Apply, it changes only the deployer service account/)).toBeInTheDocument();
    expect(screen.getByText(/10\.42\.0\.0\/24 subnet.*blocks overlaps or resource collisions/)).toBeInTheDocument();
    expect(document.body).toHaveTextContent(
      /Google Cloud mutations after bootstrap use the pinned keyless deployer service account/,
    );
    expect(document.body).toHaveTextContent(/Apply only persists the matrix/);
    expect(document.body).toHaveTextContent(/evaluate all safety gates/);
    expect(document.body).toHaveTextContent(
      /approved run-scoped backend hostname and reserved private address/,
    );
    expect(document.body).toHaveTextContent(/Chrome > Connectors > Chrome Root Store/);
    expect(document.body).toHaveTextContent(/tamper-evident cryptographic audit trail/);
    expect(document.body).toHaveTextContent(
      /PoC mode does not prove that selected existing resources are non-production/,
    );
    expect(document.body).toHaveTextContent(
      /restored only when the current value safely matches that run's recorded managed-after state/,
    );
    expect(document.body).toHaveTextContent(
      /POSThttps:\/\/iam\.googleapis\.com\/v1\/projects\/\{projectId\}\/roles/,
    );
    expect(document.body).toHaveTextContent(
      /PATCHhttps:\/\/iam\.googleapis\.com\/v1\/projects\/\{projectId\}\/roles\/\{roleId\}/,
    );
    expect(screen.getAllByText(/^Step [1-7]$/)).toHaveLength(7);
    expect(
      screen.getByRole("heading", { name: "Three independent deployment architectures" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", {
        name: "Secure Gateway + internal HTTPS load balancer + private sample VM",
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", {
        name: "Secure Gateway + existing private HTTPS app",
      }),
    ).toBeInTheDocument();
    expect(
      screen.getAllByText(/AWS, Azure, or on premises/).length,
    ).toBeGreaterThan(0);
    expect(
      screen.getByRole("heading", { name: "What is implemented" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", {
        name: "Regional Nginx availability and autoscaling",
      }),
    ).toBeInTheDocument();
    expect(screen.getByText(/configured minimum number of healthy replicas/)).toBeInTheDocument();
    expect(
      screen.getByText(/external production distribution requires Google OAuth branding/),
    ).toBeInTheDocument();
    expect(screen.queryByText(/Go to Secure Gateway Studio \(unsafe\)/)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /English/ }));
    fireEvent.click(screen.getByRole("menuitemradio", { name: "日本語" }));
    expect(
      screen.getByRole("heading", {
        name: "各セットアップ手順で実行すること",
      }),
    ).toBeInTheDocument();
    expect(screen.getAllByText(/^ステップ [1-7]$/)).toHaveLength(7);
    expect(screen.getByText(/初回準備で明示的に確認したデプロイヤーSA/)).toBeInTheDocument();
    expect(screen.getByText(/10\.42\.0\.0\/24サブネット.*CIDR重複やリソース衝突/)).toBeInTheDocument();
    expect(document.body).toHaveTextContent(/初回準備後のGoogle Cloud変更は/);
    expect(document.body).toHaveTextContent(/Applyはマトリクスの保存だけ/);
    expect(document.body).toHaveTextContent(/すべての安全ゲート/);
    expect(document.body).toHaveTextContent(/予約済みプライベートアドレス/);
    expect(document.body).toHaveTextContent(/Chrome］>［コネクタ］>［Chrome Root Store/);
    expect(document.body).toHaveTextContent(/作成済みサブネットにCloud RouterとCloud NAT/);
    expect(document.body).toHaveTextContent(/PoCモードだけでは、選択した既存リソースが非本番であることを保証しません/);
    expect(document.body).toHaveTextContent(/記録済みmanaged-after状態と安全に一致する場合だけ復元/);
    expect(
      screen.getByRole("heading", { name: "実装済み機能の全体像" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/OAuth ブランド審査とスコープ審査が必要/)).toBeInTheDocument();
    expect(screen.queryByText(/安全ではないページ/)).not.toBeInTheDocument();
  });

  it("includes production Nginx autoscaling limits in the desired state", () => {
    const desired = toDeploymentSpec(
      {
        ...defaultSetupState,
        mode: "production",
        offloadMinReplicas: "4",
        offloadMaxReplicas: "80",
        offloadCpuTarget: "0.55",
      },
      "en",
    );

    expect(desired.offload_min_replicas).toBe(4);
    expect(desired.offload_max_replicas).toBe(80);
    expect(desired.offload_cpu_target).toBe(0.55);
  });

  it("uses the local API before marking administrator connections valid", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/api/v1/health")) {
          return new Response(
            JSON.stringify({
              status: "ok",
              version: "0.1.0",
              bind: "loopback",
              session_nonce: "test-session-nonce",
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        const workspace = url.includes("/workspace/");
        return new Response(
          JSON.stringify({
            provider: workspace ? "workspace" : "google_cloud",
            status: "connected",
            principal_hint: workspace
              ? "admin@example.com"
              : "operator@example.com",
            resource_id: workspace ? "C012canonical" : "enterprise-secgw-01",
            credential_kind: "AuthorizedUserCredentials",
            read_only: true,
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }),
    );
    render(<App />);
    fireEvent.click(
      screen.getByRole("button", { name: "Continue to identities" }),
    );
    fireEvent.change(
      screen.getByRole("textbox", { name: "Google Cloud project ID" }),
      { target: { value: "enterprise-secgw-01" } },
    );

    const cloudCard = screen.getByText("Google Cloud deployer").closest("article");
    const workspaceCard = screen
      .getByText("Workspace and Chrome administrator")
      .closest("article");
    expect(cloudCard).not.toBeNull();
    expect(workspaceCard).not.toBeNull();
    fireEvent.click(
      within(cloudCard as HTMLElement).getByRole("button", {
        name: "Validate connection",
      }),
    );
    fireEvent.click(
      within(workspaceCard as HTMLElement).getByRole("button", {
        name: "Validate connection",
      }),
    );

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Continue" })).not.toBeDisabled();
    });
    expect(
      screen.getByRole("textbox", { name: "Workspace customer ID" }),
    ).toHaveValue("C012canonical");
    const mutationCalls = vi
      .mocked(fetch)
      .mock.calls.filter(([, options]) => options?.method === "POST");
    expect(mutationCalls).toHaveLength(2);
    const sessionHeader = new Headers(mutationCalls[0]?.[1]?.headers).get(
      "X-SGS-Session",
    );
    expect(sessionHeader).toBeTruthy();
    for (const [, options] of mutationCalls) {
      expect(new Headers(options?.headers).get("X-SGS-Session")).toBe(sessionHeader);
    }
  });

  it("loads OU, access level, and group dropdowns from the local API", async () => {
    const onPatch = vi.fn();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        const payload = url.endsWith("/organizational-units")
          ? [
              {
                value: "id:root-ou",
                label: "/",
                description: "/",
              },
              {
                value: "03-test-ou",
                label: "/PoC/Secure Gateway",
                description: "Secure Gateway",
              },
            ]
          : url.endsWith("/access-levels")
            ? [
                {
                  value: "AUTO_CREATE_CHROME_ANY",
                  label: "Create automatically",
                  description: "Unsafe setup sentinel",
                },
                {
                  value: "accessPolicies/123/accessLevels/managed_chrome",
                  label: "Managed Chrome",
                  description: "Managed browser or profile",
                },
              ]
            : [
                {
                  value: "secure-access@example.com",
                  label: "Secure Access",
                  description: "secure-access@example.com",
                },
              ];
        return new Response(JSON.stringify(payload), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }),
    );

    render(
      <AccessStep
        messages={getMessages("en")}
        onPatch={onPatch}
        state={{
          ...defaultSetupState,
          projectId: "enterprise-secgw-01",
          customerId: "C012abcde",
          cloudConnection: "connected",
          workspaceConnection: "connected",
        }}
      />,
    );

    const ouSelect = screen.getByRole("combobox", {
      name: "Dedicated test OU ID",
    });
    expect(
      await screen.findByRole("option", { name: "/PoC/Secure Gateway" }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "/" })).not.toBeInTheDocument();
    expect(
      screen.getByRole("option", { name: "Managed Chrome" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("option", { name: "None — do not require an access level" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("option", { name: "Create automatically" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("option", { name: "Secure Access" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("checkbox", {
        name: "Chrome Enterprise Premium licenses are assigned to the target users",
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("checkbox", {
        name: /Additional Google services and Google Cloud access/,
      }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("checkbox", {
        name: /Endpoint Verification device signal collection/,
      }),
    ).not.toBeInTheDocument();

    fireEvent.change(ouSelect, { target: { value: "03-test-ou" } });
    expect(onPatch).toHaveBeenCalledWith({
      targetOuId: "03-test-ou",
      testOuConfirmed: false,
    });
  });

  it("shows ADC reauthentication instead of false catalog permission errors", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/api/v1/health")) {
          return new Response(
            JSON.stringify({
              status: "ok",
              version: "0.1.0",
              bind: "loopback",
              session_nonce: "test-session-nonce",
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        return new Response(
          JSON.stringify({
            detail: {
              code: "adc-unavailable",
              message: "Application Default Credentials require reauthentication",
            },
          }),
          { status: 428, headers: { "Content-Type": "application/json" } },
        );
      }),
    );

    render(
      <AccessStep
        messages={getMessages("en")}
        onPatch={vi.fn()}
        state={{
          ...defaultSetupState,
          projectId: "enterprise-secgw-01",
          customerId: "C012abcde",
          cloudConnection: "connected",
          workspaceConnection: "connected",
        }}
      />,
    );

    expect(
      await screen.findAllByText(
        /Keyless Application Default Credentials are unavailable/,
      ),
    ).toHaveLength(3);
    expect(
      screen.queryByText(/Grant the service account Policy Editor/),
    ).not.toBeInTheDocument();
  });

  it("opens the functional audit evidence view", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        const payload = url.includes("/audit-events")
          ? [
              {
                event_id: "event-1",
                deployment_id: null,
                event_type: "plan.prepared",
                actor: "operator@example.com",
                payload: {},
                created_at: "2026-07-30T00:00:00Z",
                previous_hash: null,
                event_hash: "abc123",
              },
            ]
          : url.includes("/integrity")
            ? {
                valid: true,
                event_count: 1,
                algorithm: "sha256-chain",
                chain_head_hash: "abc123",
              }
            : [];
        return new Response(JSON.stringify(payload), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }),
    );
    render(<App />);

    fireEvent.click(
      screen.getByRole("button", { name: "Secure Gateway Deployer" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Evidence" }));

    expect(
      await screen.findByRole("heading", { name: "Audit evidence" }),
    ).toBeInTheDocument();
    expect(await screen.findByText("Audit chain verified")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Export evidence/ })).toBeInTheDocument();
  });

  it("runs machine acceptance checks and renders the certification matrix", async () => {
    const requiredCases = [
      ...["T01", "T02", "T03", "T04", "T05"].map((testId) => ({
        test_id: testId,
        case_key: "default",
        operator_confirmable: false,
      })),
      {
        test_id: "T06",
        case_key: "default",
        operator_confirmable: true,
      },
      ...["macos", "windows", "linux", "chromeos"].map((caseKey) => ({
        test_id: "T07",
        case_key: caseKey,
        operator_confirmable: true,
      })),
      {
        test_id: "T08",
        case_key: "default",
        operator_confirmable: true,
      },
      {
        test_id: "T09",
        case_key: "unauthorized_principal",
        operator_confirmable: true,
      },
      {
        test_id: "T09",
        case_key: "unmanaged_browser",
        operator_confirmable: true,
      },
    ];
    const missingReadiness = {
      run_id: "run-acceptance-1",
      mode: "production",
      acceptance_complete: false,
      production_ready: false,
      required_tests: ["T01", "T02", "T03", "T04", "T05", "T06", "T07", "T08", "T09"],
      operator_confirmable_tests: ["T06", "T07", "T08", "T09"],
      satisfied_tests: [],
      missing_tests: ["T01", "T02", "T03", "T04", "T05", "T06", "T07", "T08", "T09"],
      required_cases: requiredCases,
      operator_confirmable_cases: requiredCases.filter(
        (item) => item.operator_confirmable,
      ),
      satisfied_cases: [],
      missing_cases: requiredCases,
      results: [],
    };
    const verifiedReadiness = {
      ...missingReadiness,
      satisfied_tests: ["T01", "T02", "T03", "T04", "T05"],
      missing_tests: ["T06", "T07", "T08", "T09"],
      satisfied_cases: requiredCases.slice(0, 5),
      missing_cases: requiredCases.slice(5),
      results: ["T01", "T02", "T03", "T04", "T05"].map((testId) => ({
        result_id: `result-${testId}`,
        run_id: "run-acceptance-1",
        test_id: testId,
        case_key: "default",
        status: "passed",
        source: "system",
        summary: `${testId} passed`,
        evidence: `{"test_id":"${testId}"}`,
        actor: "system:google-api-verifier",
        recorded_at: "2026-07-30T00:00:00Z",
      })),
    };
    const fetchMock = vi.fn(
      async (input: RequestInfo | URL, options?: RequestInit) => {
        const url = String(input);
        let payload: unknown;
        if (url.endsWith("/api/v1/health")) {
          payload = {
            status: "ok",
            version: "0.1.0",
            bind: "loopback",
            session_nonce: "test-session-nonce",
          };
        } else if (url.includes("/acceptance/verify")) {
          expect(options?.method).toBe("POST");
          expect(new Headers(options?.headers).get("X-SGS-Session")).toBeTruthy();
          payload = verifiedReadiness;
        } else if (url.includes("/acceptance-results")) {
          const requestBody = JSON.parse(String(options?.body)) as Record<
            string,
            unknown
          >;
          expect(requestBody).not.toHaveProperty("actor");
          expect(requestBody.confirmation).toBe("RECORD");
          payload = {
            result_id: "result-operator",
            run_id: "run-acceptance-1",
            test_id: requestBody.test_id,
            case_key: requestBody.case_key,
            status: "user_confirmed",
            source: "operator",
            summary: requestBody.summary,
            evidence: requestBody.evidence,
            actor: "attested-operator@example.com",
            recorded_at: "2026-07-30T00:05:00Z",
          };
        } else if (url.endsWith("/acceptance")) {
          payload = missingReadiness;
        } else if (url.includes("/audit-events")) {
          payload = [];
        } else if (url.includes("/integrity")) {
          payload = {
            valid: true,
            event_count: 0,
            algorithm: "sha256-chain",
            chain_head_hash: null,
          };
        } else {
          payload = [
            {
              run_id: "run-acceptance-1",
              approval_id: "approval-1",
              configuration_hash: "hash-1",
              status: "succeeded",
              started_at: "2026-07-30T00:00:00Z",
              completed_at: "2026-07-30T00:10:00Z",
              operations: [],
            },
          ];
        }
        return new Response(JSON.stringify(payload), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      },
    );
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);

    fireEvent.click(
      screen.getByRole("button", { name: "Secure Gateway Deployer" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Evidence" }));
    expect(
      await screen.findByRole("heading", { name: "Acceptance certification" }),
    ).toBeInTheDocument();
    expect(screen.getByText("0 of 13 required cases satisfied")).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Managed Chrome client diagnostics" }),
    ).toBeInTheDocument();
    expect(screen.getByText("ERR_NAME_NOT_RESOLVED")).toBeInTheDocument();
    expect(screen.getByText("Access Denied (403)")).toBeInTheDocument();
    expect(
      screen.queryByRole("textbox", { name: "Operator" }),
    ).not.toBeInTheDocument();

    fireEvent.change(screen.getByRole("textbox", { name: "Result summary" }), {
      target: { value: "Managed Chrome test passed" },
    });
    fireEvent.change(
      screen.getByRole("textbox", {
        name: "Sanitized evidence or artifact SHA-256",
      }),
      { target: { value: "sha256:abc123" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Record confirmation" }));
    expect(
      await screen.findByText("Acceptance evidence recorded."),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Verify T01–T05" }));

    expect(
      await screen.findByText("5 of 13 required cases satisfied"),
    ).toBeInTheDocument();
    expect(
      screen.getAllByText(
        (_, element) =>
          element?.tagName === "SMALL" &&
          element.textContent?.startsWith("System verified") === true,
      ),
    ).toHaveLength(5);
    expect(
      fetchMock.mock.calls.filter(([input]) =>
        String(input).includes("/audit-events"),
      ),
    ).toHaveLength(3);
    expect(
      fetchMock.mock.calls.filter(([input]) =>
        String(input).includes("/integrity"),
      ),
    ).toHaveLength(3);
  });

  it("hides the extension-only Easy PoC route and provides the local deployer menu", () => {
    render(<App />);

    expect(screen.queryByRole("button", { name: /Easy PoC/i })).not.toBeInTheDocument();

    // Secure Gateway Deployer dropdown trigger
    const sgwDropdownTrigger = screen.getByRole("button", { name: /Secure Gateway Deployer/i });
    expect(sgwDropdownTrigger).toBeInTheDocument();

    // Clicking Secure Gateway Deployer opens the dropdown with the 4 SGW tabs
    fireEvent.click(sgwDropdownTrigger);

    expect(screen.getByRole("button", { name: /新規セットアップ|New setup/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /デプロイ|Deployments/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /エビデンス|Evidence/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /ガイド|Guide/i })).toBeInTheDocument();

    // Clicking a sub-item like Evidence switches to that view
    fireEvent.click(screen.getByRole("button", { name: /エビデンス|Evidence/i }));
    expect(screen.getByRole("heading", { name: /証跡とエビデンス|Evidence/i })).toBeInTheDocument();
  });
});
