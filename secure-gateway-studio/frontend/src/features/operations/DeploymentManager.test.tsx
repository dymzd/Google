import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { getMessages } from "../../i18n/messages";
import * as api from "../../lib/api";
import { DeploymentManager } from "./DeploymentManager";

vi.mock("../../lib/api", async (importOriginal) => {
  const original = await importOriginal<typeof import("../../lib/api")>();
  return {
    ...original,
    enableGatewayLogging: vi.fn(),
    getDeploymentDetails: vi.fn(),
    getTeardownPlan: vi.fn(),
    getTeardownRun: vi.fn(),
    listGatewayLogs: vi.fn(),
    startTeardown: vi.fn(),
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
  resources: [resource],
  teardown_available: true,
};

const teardownPlan: api.TeardownPlan = {
  run_id: "run-123",
  plan_hash: "a".repeat(64),
  confirmation: "DELETE secure-gateway-http-offload aaaaaaaaaaaa",
  resources: [resource],
  retained_resources: [],
  can_destroy: true,
};

describe("DeploymentManager", () => {
  beforeEach(() => {
    vi.mocked(api.getDeploymentDetails).mockResolvedValue(details);
    vi.mocked(api.getTeardownPlan).mockResolvedValue(teardownPlan);
    vi.mocked(api.listGatewayLogs).mockResolvedValue({
      run_id: "run-123",
      category: "access",
      entries: [],
      logging_enabled: false,
      data_access_notice: true,
      setup_notice: null,
    });
    vi.mocked(api.enableGatewayLogging).mockResolvedValue({ enabled: true });
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

  it("shows deployment logs and enables gateway logging", async () => {
    render(
      <DeploymentManager
        copy={getMessages("en").operations}
        onClose={() => undefined}
        runId="run-123"
      />,
    );

    expect(await screen.findByText("montreal-436802")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Logs" }));
    expect(await screen.findByText(/Data Access audit logs/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Enable Gateway logging" }));

    await waitFor(() => expect(api.enableGatewayLogging).toHaveBeenCalledWith("run-123"));
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
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    const deleteButton = screen.getByRole("button", { name: "Delete owned resources" });
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
});
