import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { getMessages } from "../../i18n/messages";
import * as api from "../../lib/api";
import { DeploymentManager } from "./DeploymentManager";

vi.mock("../../lib/api", async (importOriginal) => {
  const original = await importOriginal<typeof import("../../lib/api")>();
  return {
    ...original,
    getDeploymentDetails: vi.fn(),
    getLatestTeardownRun: vi.fn(),
    getTeardownPlan: vi.fn(),
    getTeardownRun: vi.fn(),
    listAccessLevelOptions: vi.fn(),
    listGatewayLogs: vi.fn(),
    runtimeCapabilities: {
      bootstrapAccessPolicyId: true,
      cepDeployer: true,
      postDeploymentAccessUpdate: true,
      sessionSignOut: true,
      userDataDisclosure: true,
    },
    resumeTeardownRun: vi.fn(),
    startTeardown: vi.fn(),
    updateAccessLevel: vi.fn(),
  };
});

const resource = {
  resource_key: "beyondcorp:application:demo-app",
  summary: "Secure Gateway application route",
  provider: "beyondcorp",
  resource_type: "application",
  resource_name: "demo-app",
  owned: true,
  teardown_action: "delete" as const,
};

const restoredResource: api.DeploymentResource = {
  resource_key: "chrome-policy:orgunit:03pilot:OnFileUploadEnterpriseConnector",
  summary: "Restore shared Chrome connector policy",
  provider: "chrome-policy",
  resource_type: "policy",
  resource_name: "OnFileUploadEnterpriseConnector",
  owned: false,
  teardown_action: "restore",
};

const details: api.DeploymentDetails = {
  run: {
    run_id: "run-123",
    approval_id: "approval-123",
    configuration_hash: "hash",
    status: "succeeded",
    started_at: "2026-08-04T00:00:00Z",
    completed_at: "2026-08-04T00:01:00Z",
    operations: [],
  },
  ownership_run_id: null,
  deployment_name: "secure-gateway-http-offload",
  project_id: "montreal-436802",
  gateway_id: "default",
  backend_kind: "managed_sample",
  application_hostname: "demo.internal",
  application_port: 443,
  resources: [resource, restoredResource],
  managed_chrome_access_level: "accessPolicies/123/accessLevels/managed_chrome",
  policy_principals: ["group:run-owner@example.com"],
  teardown_available: true,
};

const teardownPlan: api.TeardownPlan = {
  run_id: "run-123",
  plan_hash: "a".repeat(64),
  confirmation: "DELETE secure-gateway-http-offload aaaaaaaaaaaa",
  resources: [resource, restoredResource],
  retained_resources: [],
  can_destroy: true,
};

describe("DeploymentManager", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.localStorage.clear();
    (
      api.runtimeCapabilities as { postDeploymentAccessUpdate: boolean }
    ).postDeploymentAccessUpdate = true;
    vi.mocked(api.getDeploymentDetails).mockResolvedValue(details);
    vi.mocked(api.getLatestTeardownRun).mockRejectedValue(
      new Error("no teardown"),
    );
    vi.mocked(api.getTeardownPlan).mockResolvedValue(teardownPlan);
    vi.mocked(api.listGatewayLogs).mockResolvedValue({
      run_id: "run-123",
      category: "access",
      entries: [],
      logging_enabled: null,
      data_access_notice: true,
      setup_notice: null,
    });
    vi.mocked(api.listAccessLevelOptions).mockResolvedValue([
      {
        value: "accessPolicies/123/accessLevels/managed_chrome",
        label: "Managed Chrome",
        description: "Existing level",
      },
      {
        value: "AUTO_CREATE_CHROME_ANY",
        label: "Create automatically",
        description: "Unsafe setup sentinel",
      },
    ]);
    vi.mocked(api.updateAccessLevel).mockResolvedValue({
      success: true,
      access_level: "NONE",
      policy_principals: ["user:new-owner@example.com"],
      run_id: "run-123",
    });
    vi.mocked(api.startTeardown).mockResolvedValue({
      teardown_id: "teardown-123",
      source_run_id: "run-123",
      plan_hash: teardownPlan.plan_hash,
      status: "succeeded",
      started_at: "2026-08-04T00:02:00Z",
      completed_at: "2026-08-04T00:03:00Z",
      operations: [
        {
          resource_key: resource.resource_key,
          status: "succeeded",
          error_code: null,
          started_at: "2026-08-04T00:02:00Z",
          completed_at: "2026-08-04T00:03:00Z",
        },
      ],
    });
  });

  it("shows deployment logs and the owned/shared resource inventory", async () => {
    render(
      <DeploymentManager
        copy={getMessages("en").operations}
        onClose={() => undefined}
        runId="run-123"
      />,
    );

    expect(await screen.findByText("montreal-436802")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Start sample backend/ }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Run GCP diagnosis/ }),
    ).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Resources" }));
    expect(screen.getByText("Shared policy values restored from before-images")).toBeInTheDocument();
    expect(screen.getByText("Restore exact before-image")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Logs" }));
    expect(await screen.findByText(/Data Access audit logs/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Enable Gateway logging/ })).not.toBeInTheDocument();
  });

  it.each([
    [true, "Secure Gateway connection logging is enabled in this deployment project."],
    [
      false,
      "Secure Gateway connection logging is disabled. Connection entries will not be produced; review the gateway in Google Cloud before relying on this view.",
    ],
  ])("shows the freshly verified connection-logging state (%s)", async (enabled, message) => {
    vi.mocked(api.listGatewayLogs).mockImplementation(async (_runId, category) => ({
      run_id: "run-123",
      category,
      entries: [],
      logging_enabled: category === "connection" ? enabled : null,
      data_access_notice: category === "access",
      setup_notice: null,
    }));
    render(
      <DeploymentManager
        copy={getMessages("en").operations}
        onClose={() => undefined}
        runId="run-123"
      />,
    );

    await screen.findByText("montreal-436802");
    fireEvent.click(screen.getByRole("button", { name: "Logs" }));
    await screen.findByText(/Data Access audit logs/);
    fireEvent.click(screen.getByRole("button", { name: "Connections" }));

    expect(await screen.findByText(message)).toBeInTheDocument();
  });

  it("requires the hash-bound exact phrase before teardown", async () => {
    render(
      <DeploymentManager
        copy={getMessages("en").operations}
        onClose={() => undefined}
        runId="run-123"
      />,
    );

    await screen.findByText("montreal-436802");
    fireEvent.click(screen.getByRole("button", { name: "Teardown" }));
    expect(screen.queryByText(/Clean State All|Purge all cloud infrastructure/)).not.toBeInTheDocument();
    const deleteButton = screen.getByRole("button", { name: "Restore and delete run changes" });
    expect(deleteButton).toBeDisabled();
    fireEvent.change(screen.getByPlaceholderText("Type the exact phrase shown above"), {
      target: { value: teardownPlan.confirmation },
    });
    expect(deleteButton).toBeEnabled();
    fireEvent.click(deleteButton);

    expect(await screen.findByText("Teardown completed")).toBeInTheDocument();
    expect(api.startTeardown).toHaveBeenCalledWith(
      "run-123",
      teardownPlan,
      teardownPlan.confirmation,
    );
  });

  it("restores and resumes an interrupted teardown after a page reload", async () => {
    const interrupted: api.TeardownRun = {
      teardown_id: "teardown-interrupted",
      source_run_id: "run-123",
      plan_hash: teardownPlan.plan_hash,
      status: "interrupted",
      started_at: "2026-08-04T00:02:00Z",
      completed_at: "2026-08-04T00:02:30Z",
      operations: [
        {
          resource_key: resource.resource_key,
          status: "running",
          error_code: null,
          started_at: "2026-08-04T00:02:00Z",
          completed_at: null,
        },
      ],
    };
    vi.mocked(api.getLatestTeardownRun).mockResolvedValue(interrupted);
    vi.mocked(api.resumeTeardownRun).mockResolvedValue({
      ...interrupted,
      status: "running",
      completed_at: null,
    });

    render(
      <DeploymentManager
        copy={getMessages("en").operations}
        onClose={() => undefined}
        runId="run-123"
      />,
    );

    await screen.findByText("montreal-436802");
    fireEvent.click(screen.getByRole("button", { name: "Teardown" }));
    expect(
      await screen.findByText(/execution worker or local service stopped during teardown/i),
    ).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "Resume interrupted teardown" }),
    );

    await waitFor(() =>
      expect(api.resumeTeardownRun).toHaveBeenCalledWith(
        "teardown-interrupted",
      ),
    );
    expect(
      (await screen.findAllByText("Restoring and deleting run changes…")).length,
    ).toBeGreaterThan(0);
    expect(api.startTeardown).not.toHaveBeenCalled();
  });

  it("loads local-backend details that omit extension-only access policy fields", async () => {
    (
      api.runtimeCapabilities as { postDeploymentAccessUpdate: boolean }
    ).postDeploymentAccessUpdate = false;
    vi.mocked(api.getDeploymentDetails).mockResolvedValue({
      ...details,
      managed_chrome_access_level: undefined,
      policy_principals: undefined,
    } as unknown as api.DeploymentDetails);

    render(
      <DeploymentManager
        copy={getMessages("en").operations}
        onClose={() => undefined}
        runId="run-123"
      />,
    );

    expect(await screen.findByText("montreal-436802")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Update Access Level Policy" }),
    ).not.toBeInTheDocument();
    expect(api.listAccessLevelOptions).not.toHaveBeenCalled();
  });

  it("uses the server policy principals as the only persisted source", async () => {
    window.localStorage.setItem("sgs.principals.run-123", "user:stale@example.com");
    render(
      <DeploymentManager
        copy={getMessages("en").operations}
        onClose={() => undefined}
        runId="run-123"
      />,
    );

    const principalsInput = await screen.findByRole("textbox", {
      name: "Allowed Principals (Users, Groups, Domains)",
    });
    expect(principalsInput).toHaveValue("group:run-owner@example.com");
    expect(screen.queryByRole("option", { name: /Create automatically/ })).not.toBeInTheDocument();

    fireEvent.change(principalsInput, {
      target: { value: "user:requested@example.com" },
    });
    fireEvent.change(
      screen.getByRole("combobox", { name: "Target Access Level Policy" }),
      { target: { value: "NONE" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Update Access Level Policy" }));

    await waitFor(() =>
      expect(api.updateAccessLevel).toHaveBeenCalledWith(
        "run-123",
        "NONE",
        ["user:requested@example.com"],
      ),
    );
    expect(principalsInput).toHaveValue("user:new-owner@example.com");
    expect(window.localStorage.getItem("sgs.principals.run-123")).toBe(
      "user:stale@example.com",
    );
  });
});
