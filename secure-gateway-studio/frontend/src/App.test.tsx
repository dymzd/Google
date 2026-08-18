import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import {
  AccessStep,
  ApplyStep,
  EnvironmentStep,
  IdentitiesStep,
} from "./features/setup/ConfigurationSteps";
import { getMessages } from "./i18n/messages";
import {
  defaultSetupState,
  loadSetupState,
  toDeploymentSpec,
} from "./lib/setup-state";
import { ApiError } from "./lib/api";

describe("Secure Gateway Studio mode screen", () => {
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
      screen.getByRole("button", { name: "SAと最小権限ロールを自動作成" }),
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

    expect(toDeploymentSpec(directState, "en")).toMatchObject({
      backend_kind: "direct_https",
      network_strategy: "existing",
      existing_backend_url: "https://app.corp.internal:8443",
      application_egress_region: "asia-east1",
    });
  });

  it("models internal Application Load Balancer HTTPS offload as Option B", () => {
    const onPatch = vi.fn();
    const ilbState = {
      ...defaultSetupState,
      backendKind: "internal_https_lb" as const,
      deploymentName: "secure-gateway-ilb-https-offload",
      proxySubnetCidr: "10.42.1.0/24",
    };
    render(
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

    expect(toDeploymentSpec(ilbState, "en")).toMatchObject({
      backend_kind: "internal_https_lb",
      proxy_subnet_cidr: "10.42.1.0/24",
      existing_backend_url: null,
    });
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
  });

  it("offers the public root CA handoff after a successful local CA Apply", () => {
    render(
      <ApplyStep
        approval={null}
        busy={false}
        error=""
        messages={getMessages("en")}
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
        state={{ ...defaultSetupState, certificateStrategy: "local_poc" }}
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
  });

  it("visualizes live Apply progress from recorded operations", () => {
    render(
      <ApplyStep
        approval={null}
        busy={false}
        error=""
        messages={getMessages("en")}
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
      approvalConfirmed: false,
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
      within(primaryNavigation).getByRole("button", { name: "Guide" }),
    );

    expect(
      screen.getByRole("heading", {
        name: "What happens in each setup step",
      }),
    ).toBeInTheDocument();
    expect(screen.getAllByText(/^Step [1-7]$/)).toHaveLength(7);
    expect(
      screen.getByRole("heading", { name: "Three independent deployment architectures" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", {
        name: "Secure Gateway + internal HTTPS load balancer + HTTP app",
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

    fireEvent.click(screen.getByRole("button", { name: /English/ }));
    fireEvent.click(screen.getByRole("menuitemradio", { name: "日本語" }));
    expect(
      screen.getByRole("heading", {
        name: "各セットアップ手順で実行すること",
      }),
    ).toBeInTheDocument();
    expect(screen.getAllByText(/^ステップ [1-7]$/)).toHaveLength(7);
    expect(
      screen.getByRole("heading", { name: "実装済み機能の全体像" }),
    ).toBeInTheDocument();
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
            resource_id: workspace ? "my_customer" : "enterprise-secgw-01",
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
      .getByText("Chrome-authorized service account")
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
    expect(fetch).toHaveBeenCalledTimes(3);
    const mutationCalls = vi.mocked(fetch).mock.calls.slice(1);
    for (const [, options] of mutationCalls) {
      expect(new Headers(options?.headers).get("X-SGS-Session")).toBe(
        "test-session-nonce",
      );
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
                value: "03-test-ou",
                label: "/PoC/Secure Gateway",
                description: "Secure Gateway",
              },
            ]
          : url.endsWith("/access-levels")
            ? [
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
    expect(
      screen.getByRole("option", { name: "Managed Chrome" }),
    ).toBeInTheDocument();
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
      screen.queryByText(/Grant the service account Policy Reader/),
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

    fireEvent.click(screen.getByRole("button", { name: "Evidence" }));

    expect(
      await screen.findByRole("heading", { name: "Audit evidence" }),
    ).toBeInTheDocument();
    expect(await screen.findByText("Audit chain verified")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Export evidence/ })).toHaveAttribute(
      "href",
      "/api/v1/evidence/export",
    );
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
          expect(new Headers(options?.headers).get("X-SGS-Session")).toBe(
            "test-session-nonce",
          );
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

  it("provides top-level Easy PoC navigation and a collapsible Secure Gateway Deployer menu", () => {
    render(<App />);

    // Easy PoC button is available at top level
    const easyPocBtn = screen.getByRole("button", { name: /Easy PoC/i });
    expect(easyPocBtn).toBeInTheDocument();

    // Clicking Easy PoC navigates to CEP PoC Deployer page
    fireEvent.click(easyPocBtn);
    expect(screen.getByRole("heading", { name: /Chrome Enterprise Premium/i })).toBeInTheDocument();

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
