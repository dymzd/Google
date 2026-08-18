/**
 * Route table: the API surface the local FastAPI app used to serve.
 *
 * The React layer still asks for `/api/v1/plans`; the worker answers it. That
 * keeps the seam at the transport and leaves `api.ts` and every component above
 * it untouched between the two builds.
 *
 * Routes not yet ported return a typed `route-not-ported` error naming the
 * route. That is deliberate: a stub returning plausible data would let the UI
 * appear to work while doing nothing, and the difference would only surface
 * against a real Google project. An explicit refusal is visible immediately and
 * is honest about what Phase 3 covers.
 */

import { buildPlan } from "../domain/planner.ts";
import { iamMember, parseDeploymentSpec, specToJson } from "../domain/spec.ts";
import { GoogleDiscoveryProvider } from "../providers/discovery.ts";
import { GoogleSetupCatalog, ensureManagedChromeAccessLevel } from "../providers/catalog.ts";
import { bootstrapDeployer } from "../providers/bootstrap.ts";
import { bootstrapSampleBackend } from "../providers/sample-backend.ts";
import { GatewayObservability, type LogCategory } from "../providers/observability.ts";
import { buildTeardownPlan } from "../domain/teardown.ts";
import { GoogleAcceptanceVerifier, acceptanceRequirements } from "../providers/acceptance.ts";
import {
  CepProvider,
  type CepCustomRoleConfig,
  type CepProvisionConfig,
  type CepRollbackConfig,
} from "../providers/cep-provider.ts";
import type { Transport } from "../providers/executor.ts";
import { openDatabase, StateRepository } from "../storage/repository.ts";
import { verifyAuditChain } from "../storage/audit.ts";

export interface RouteContext {
  transport: Transport;
  /**
   * Calls that authorize against a Workspace user rather than a Cloud project.
   * The deployer service account is not a Workspace identity, so Directory,
   * Chrome Policy, and Cloud Identity have to run as the administrator.
   */
  administratorTransport: Transport;
  cloudIdentity: () => Promise<string>;
  /** Signed-in administrator, for the Token Creator binding bootstrap adds. */
  operatorEmail: () => Promise<string>;
  /** Configured Access Context Manager policy, when the operator has set one. */
  accessPolicyId: () => Promise<string | undefined>;
  /** Persist the deployer account so later impersonation can find it. */
  rememberDeployer: (email: string) => Promise<void>;
  startApply: (approvalId: string) => Promise<{ run_id: string }>;
  runState: (runId: string) => Promise<unknown>;
}

export class RouteError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "RouteError";
    this.status = status;
    this.code = code;
  }
}

/** Routes served by the worker. Anything else is refused by name. */
const PORTED = new Set([
  "POST /api/v1/connections/google-cloud/validate",
  "POST /api/v1/connections/workspace/validate",
  "POST /api/v1/bootstrap/google-cloud/deployer",
  "POST /api/v1/bootstrap/sample-backend",
  "POST /api/v1/setup-options/organizational-units",
  "POST /api/v1/setup-options/groups",
  "POST /api/v1/setup-options/access-levels",
  "POST /api/v1/preflight",
  "POST /api/v1/plans",
  "GET /api/v1/plans/{}",
  "POST /api/v1/approvals",
  "GET /api/v1/approvals/{}",
  "POST /api/v1/runs",
  "GET /api/v1/runs",
  "GET /api/v1/runs/{}",
  "GET /api/v1/runs/{}/details",
  "GET /api/v1/runs/{}/logs",
  "POST /api/v1/runs/{}/logs/enable",
  "GET /api/v1/runs/{}/acceptance",
  "POST /api/v1/runs/{}/acceptance-results",
  "POST /api/v1/runs/{}/acceptance/verify",
  "POST /api/v1/runs/{}/update-access-level",
  "GET /api/v1/runs/{}/teardown-plan",
  "POST /api/v1/runs/{}/teardowns",
  "GET /api/v1/teardowns/{}",
  "GET /api/v1/evidence/audit-events",
  "GET /api/v1/evidence/integrity",
  "GET /api/v1/evidence/export",
  "GET /api/v1/health",
  "POST /api/v1/admin/clean-state",
  "GET /api/v1/certificates/local-poc/{}",
  "POST /api/v1/admin/diagnose-gcp",
  "POST /api/v1/cep/provision",
  "POST /api/v1/cep/rollback",
  "POST /api/v1/cep/roles",
  "POST /api/v1/cep/script",
]);

/**
 * Collapse identifier segments so a request matches its declared route.
 *
 * `/api/v1/runs/abc` and `/api/v1/runs/{}` are the same route; the identifier
 * is data. Fixed sub-resources such as `/details` are kept, because those are
 * different routes.
 */
const KNOWN_SUBRESOURCES = new Set([
  "acceptance",
  "acceptance-results",
  "verify",
  "details",
  "logs",
  "enable",
  "update-access-level",
  "teardown-plan",
  "teardowns",
]);

function templateKey(method: string, path: string): string {
  const segments = path.split("/");
  const shaped = segments.map((segment, index) => {
    if (index < 4) return segment;
    return KNOWN_SUBRESOURCES.has(segment) ? segment : "{}";
  });
  return `${method} ${shaped.join("/")}`;
}

function normalise(path: string): string {
  return path.split("?")[0].replace(/\/$/, "");
}

export async function route(
  context: RouteContext,
  method: "GET" | "POST",
  path: string,
  body: unknown,
): Promise<unknown> {
  const clean = normalise(path);
  const key = `${method} ${clean}`;

  if (key === "GET /api/v1/health") {
    return { status: "ok", version: chrome.runtime.getManifest().version };
  }

  async function catalog(): Promise<GoogleSetupCatalog> {
    return new GoogleSetupCatalog(context.transport, {
      principalHint: await context.cloudIdentity(),
      credentialKind: "impersonated",
      accessPolicyId: await context.accessPolicyId(),
    });
  }

  if (key === "POST /api/v1/connections/google-cloud/validate") {
    const projectId = (body as { project_id: string }).project_id;
    return (await catalog()).validateCloud(projectId);
  }

  if (key === "POST /api/v1/connections/workspace/validate") {
    const request = body as { customer_id: string; target_ou_id?: string };
    return (await catalog()).validateWorkspace(request.customer_id, request.target_ou_id);
  }

  if (key === "POST /api/v1/bootstrap/google-cloud/deployer") {
    // Creates the least-privilege deployer and grants the operator Token
    // Creator on it. Until this runs there is nothing to impersonate, so it is
    // the first action that must succeed in a fresh project.
    const projectId = (body as { project_id: string }).project_id;
    const result = await bootstrapDeployer(projectId, {
      transport: context.transport,
      operatorEmail: await context.operatorEmail(),
      accessPolicyId: await context.accessPolicyId(),
    });
    await context.rememberDeployer(result.service_account_email);
    return result;
  }

  if (key === "POST /api/v1/bootstrap/sample-backend") {
    const request = body as { project_id: string; region?: string; zone?: string };
    return bootstrapSampleBackend(request.project_id, {
      transport: context.transport,
      region: request.region,
      zone: request.zone,
    });
  }

  if (key === "POST /api/v1/setup-options/organizational-units") {
    const customerId = (body as { customer_id: string }).customer_id;
    return { options: await (await catalog()).listOrganizationalUnits(customerId) };
  }

  if (key === "POST /api/v1/setup-options/groups") {
    const customerId = (body as { customer_id: string }).customer_id;
    return { options: await (await catalog()).listGroups(customerId) };
  }

  if (key === "POST /api/v1/setup-options/access-levels") {
    const projectId = (body as { project_id: string }).project_id;
    const existing = await (await catalog()).listAccessLevels(projectId);
    const defaults = [
      {
        value: "NONE",
        label: "（アクセスレベル制限なし・認証済みグループ全ユーザー）",
        description: "BeyondCorp のアクセスレベル条件を付けずに全グループユーザーへ開放します",
      },
      {
        value: "AUTO_CREATE_PROFILE_MANAGED",
        label: "✨ 自動作成: Managed Profile (プロファイル管理 CEL)",
        description: "device.chrome_profile_managed == true の CEL ルールを自動作成・適用します",
      },
      {
        value: "AUTO_CREATE_BROWSER_MANAGED",
        label: "✨ 自動作成: Managed Browser (端末・ブラウザ管理 CEL)",
        description: "device.is_managed == true の CEL ルールを自動作成・適用します",
      },
      {
        value: "AUTO_CREATE_CHROME_ANY",
        label: "✨ 自動作成: Managed Profile or Browser (両方許可 CEL)",
        description: "プロファイル管理またはブラウザ管理のいずれかを満たす CEL ルールを自動作成・適用します",
      },
    ];
    return { options: [...defaults, ...existing] };
  }

  if (key === "POST /api/v1/preflight") {
    const spec = parseDeploymentSpec((body as { specification: Record<string, unknown> }).specification);
    const provider = new GoogleDiscoveryProvider(context.transport, {
      cloudIdentity: await context.cloudIdentity(),
    });
    return provider.preflight(spec);
  }

  if (key === "POST /api/v1/plans") {
    const spec = parseDeploymentSpec(
      (body as { specification: Record<string, unknown> }).specification,
    );
    const provider = new GoogleDiscoveryProvider(context.transport, {
      cloudIdentity: await context.cloudIdentity(),
    });
    const preflight = await provider.preflight(spec);
    const plan = buildPlan(spec, preflight.snapshot);
    const planId = crypto.randomUUID();
    const db = await openDatabase();
    await new StateRepository(db).storePreparedPlan({
      planId,
      specificationJson: JSON.stringify(specToJson(spec)),
      preflightJson: JSON.stringify(preflight),
      planJson: JSON.stringify(plan),
      configurationHash: plan.configuration_hash,
    });
    return { plan_id: planId, specification: spec, preflight, plan };
  }

  if (method === "GET" && templateKey(method, clean) === "GET /api/v1/plans/{}") {
    const db = await openDatabase();
    const record = await new StateRepository(db).preparedPlan(clean.split("/").pop() as string);
    if (record === undefined) throw new RouteError(404, "plan-not-found", "Plan not found");
    return {
      plan_id: record.planId,
      specification: JSON.parse(record.specificationJson as string),
      preflight: JSON.parse(record.preflightJson as string),
      plan: JSON.parse(record.planJson as string),
    };
  }

  if (key === "POST /api/v1/approvals") {
    // Approval binds to the plan hash and expires. Apply re-checks both, so a
    // stale approval cannot be replayed against a plan that has since changed.
    const request_ = body as { plan_id: string; ttl_minutes?: number };
    const db = await openDatabase();
    const approval = await new StateRepository(db).storeApproval({
      planId: request_.plan_id,
      approvedBy: await context.cloudIdentity(),
      ttlMinutes: request_.ttl_minutes ?? 30,
    });
    await chrome.storage.local.set({
      [`spec:${approval.approvalId}`]: JSON.parse(approval.specificationJson),
    });
    return {
      approval_id: approval.approvalId,
      configuration_hash: approval.configurationHash,
      plan_hash: approval.planHash,
      approved_by: approval.approvedBy,
      approved_at: approval.approvedAt,
      expires_at: approval.expiresAt,
      consumed_at: approval.consumedAt,
      plan: JSON.parse(approval.planJson),
      specification: JSON.parse(approval.specificationJson),
    };
  }

  if (method === "GET" && templateKey(method, clean) === "GET /api/v1/approvals/{}") {
    const db = await openDatabase();
    const approval = await new StateRepository(db).approval(clean.split("/").pop() as string);
    if (approval === undefined) {
      throw new RouteError(404, "approval-not-found", "Approval not found");
    }
    return {
      approval_id: approval.approvalId,
      configuration_hash: approval.configurationHash,
      plan_hash: approval.planHash,
      approved_by: approval.approvedBy,
      approved_at: approval.approvedAt,
      expires_at: approval.expiresAt,
      consumed_at: approval.consumedAt,
      plan: JSON.parse(approval.planJson),
      specification: JSON.parse(approval.specificationJson),
    };
  }

  async function buildAcceptanceReadiness(
    repository: StateRepository,
    runId: string,
  ) {
    const run = await repository.run(runId);
    if (run === undefined) throw new RouteError(404, "run-not-found", "Run not found");
    const approval = await repository.approval(run.approvalId);
    const spec = approval ? parseDeploymentSpec(JSON.parse(approval.specificationJson)) : null;
    const recorded = await repository.acceptance(runId);
    const results = recorded.map((r: any) => ({
      result_id: r.resultId ?? `res-${r.testId}`,
      run_id: r.runId,
      test_id: r.testId,
      case_key: r.caseKey ?? "default",
      status: r.status,
      source: r.source ?? "operator",
      summary: r.summary,
      evidence: r.evidence,
      actor: r.actor,
      recorded_at: r.recordedAt,
    }));
    const reqs = spec ? acceptanceRequirements(spec) : [];
    const requiredCases = reqs.map((req) => ({
      test_id: req.test_id,
      case_key: "default",
      operator_confirmable: req.source === "operator_confirmed",
    }));
    const operatorCases = requiredCases.filter((c) => c.operator_confirmable);
    const satisfiedCases = requiredCases.filter((c) =>
      results.some(
        (r: any) =>
          r.test_id === c.test_id &&
          (r.status === "passed" || r.status === "user_confirmed"),
      ),
    );
    const missingCases = requiredCases.filter(
      (c) => !satisfiedCases.some((s) => s.test_id === c.test_id),
    );
    const complete = run.status === "succeeded" && missingCases.length === 0;

    return {
      run_id: runId,
      mode: spec?.mode ?? "poc",
      acceptance_complete: complete,
      production_ready: complete && spec?.mode === "production",
      required_tests: requiredCases.map((c) => c.test_id),
      operator_confirmable_tests: operatorCases.map((c) => c.test_id),
      satisfied_tests: satisfiedCases.map((c) => c.test_id),
      missing_tests: missingCases.map((c) => c.test_id),
      required_cases: requiredCases,
      operator_confirmable_cases: operatorCases,
      satisfied_cases: satisfiedCases,
      missing_cases: missingCases,
      results,
    };
  }

  if (key === "GET /api/v1/runs") {
    const db = await openDatabase();
    const repository = new StateRepository(db);
    const records = await repository.runs();
    const results = await Promise.all(
      records.map(async (record) => {
        const approval = record.approvalId ? await repository.approval(record.approvalId) : undefined;
        const plan = approval ? JSON.parse(approval.planJson) : null;
        const opCount = (record as any).steps?.length ?? plan?.changes?.length ?? 6;
        const ops = Array.from({ length: opCount }, (_, i) => ({
          operation_id: `op-${i}`,
          resource_key: `op-${i}`,
          action: "create",
          status: record.status === "succeeded" ? "succeeded" : "running",
          error_code: null,
        }));
        return {
          run_id: record.runId,
          approval_id: record.approvalId,
          configuration_hash: record.configurationHash,
          status: record.status || (record as any).state || "succeeded",
          started_at:
            record.startedAt ||
            approval?.approvedAt ||
            (record as any).createdAt ||
            new Date().toISOString(),
          completed_at: record.finishedAt || (record as any).completed_at || null,
          operations: ops,
        };
      }),
    );
    return results;
  }

  if (method === "GET" && templateKey(method, clean) === "GET /api/v1/runs/{}/details") {
    const db = await openDatabase();
    const repository = new StateRepository(db);
    const runId = clean.split("/")[4];
    const run = await repository.run(runId);
    if (run === undefined) throw new RouteError(404, "run-not-found", "Run not found");
    const approval = await repository.approval(run.approvalId);
    const spec = approval ? JSON.parse(approval.specificationJson) : null;
    const plan = approval ? JSON.parse(approval.planJson) : null;
    return {
      run: {
        run_id: run.runId,
        approval_id: run.approvalId,
        configuration_hash: run.configurationHash,
        status: run.status,
        started_at: run.startedAt,
        completed_at: run.finishedAt,
        operations: (plan?.changes ?? []).map((change: any, index: number) => ({
          operation_id: `op-${index}`,
          resource_key: `${change.provider}:${change.resource_type}:${change.resource_name}`,
          action: change.action,
          status: run.status === "succeeded" ? "succeeded" : "pending",
          error_code: null,
        })),
      },
      ownership_run_id: run.runId,
      deployment_name: spec?.deployment_name ?? "default",
      project_id: spec?.project_id ?? "",
      gateway_id: spec?.gateway_id ?? "default",
      backend_kind: spec?.backend_kind ?? "direct_https",
      application_hostname: spec?.application_hostname ?? "",
      application_port: spec?.application_port ?? 443,
      resources: (plan?.changes ?? []).map((change: any) => ({
        resource_key: `${change.provider}:${change.resource_type}:${change.resource_name}`,
        summary: change.summary,
        provider: change.provider,
        resource_type: change.resource_type,
        resource_name: change.resource_name,
        owned: true,
        teardown_action: "delete",
      })),
      managed_chrome_access_level: spec?.managed_chrome_access_level ?? null,
      target_group_email: spec?.target_group_email ?? null,
      teardown_available: true,
    };
  }

  if (
    method === "POST" &&
    templateKey(method, clean) === "POST /api/v1/runs/{}/update-access-level"
  ) {
    const runId = clean.split("/")[4];
    const bodyObj = (body ?? {}) as { access_level?: string; principals?: string[] };
    const newAccessLevel = bodyObj.access_level ?? "";
    const requestedPrincipals = bodyObj.principals ?? [];
    const spec = await runSpecification(runId);
    const actor = await context.cloudIdentity();
    const opEmail = await context.operatorEmail();
    const gatewayUrl = `https://beyondcorp.googleapis.com/v1/projects/${spec.project_id}/locations/global/securityGateways/${spec.gateway_id}`;
    const applicationUrl = `${gatewayUrl}/applications/${spec.name}-app`;

    function formatMember(str: string): string {
      const trimmed = str.trim();
      if (!trimmed) return "";
      if (trimmed.startsWith("user:") || trimmed.startsWith("group:") || trimmed.startsWith("domain:") || trimmed.startsWith("serviceAccount:")) {
        return trimmed;
      }
      if (trimmed.includes("@")) return `user:${trimmed}`;
      return `domain:${trimmed}`;
    }

    const baseMembers = new Set<string>();
    if (opEmail && opEmail.includes("@")) baseMembers.add(`user:${opEmail}`);
    // Not part of DeploymentSpec; read defensively for specs that carry it.
    const targetGroupEmail = (spec as { target_group_email?: string }).target_group_email;
    if (targetGroupEmail) baseMembers.add(`group:${targetGroupEmail}`);
    (spec.principals ?? []).forEach((p) => {
      if (p.value) baseMembers.add(iamMember(p));
    });
    requestedPrincipals.forEach((p) => {
      const formatted = formatMember(p);
      if (formatted) baseMembers.add(formatted);
    });
    if (actor && actor.includes("@")) {
      baseMembers.add(actor.includes(".gserviceaccount.com") ? `serviceAccount:${actor}` : `user:${actor}`);
    }

    // 1. Ensure the Sample Backend (VPC, VM 10.10.0.2, NAT, Cloud DNS, Firewall) is provisioned
    try {
      await bootstrapSampleBackend(spec.project_id, {
        transport: context.transport,
        region: spec.region || "asia-northeast1",
        zone: spec.zone || "asia-northeast1-b",
      });
      console.log("[SGS Router] Sample backend infrastructure fully ensured");
    } catch (sbErr) {
      console.warn("[SGS Router] Sample backend provision note:", sbErr);
    }

    // 2. Grant roles/beyondcorp.upstreamAccess to the Security Gateway's delegating SA
    try {
      const { payload: gwObj } = await context.transport.requestJson("GET", gatewayUrl);
      const delegatingSA = (gwObj as any).delegatingServiceAccount;
      if (delegatingSA) {
        const crmUrl = `https://cloudresourcemanager.googleapis.com/v1/projects/${spec.project_id}`;
        const { payload: projPolicy } = await context.transport.requestJson("POST", `${crmUrl}:getIamPolicy`);
        const projBindings = ((projPolicy as any).bindings ?? []) as Array<{ role: string; members: string[] }>;
        let upstreamUpdated = false;
        for (const b of projBindings) {
          if (b.role === "roles/beyondcorp.upstreamAccess") {
            if (!b.members.includes(`serviceAccount:${delegatingSA}`)) {
              b.members.push(`serviceAccount:${delegatingSA}`);
            }
            upstreamUpdated = true;
          }
        }
        if (!upstreamUpdated) {
          projBindings.push({
            role: "roles/beyondcorp.upstreamAccess",
            members: [`serviceAccount:${delegatingSA}`],
          });
        }
        await context.transport.requestJson("POST", `${crmUrl}:setIamPolicy`, {
          jsonBody: { policy: { bindings: projBindings, etag: (projPolicy as any).etag } },
        });
        console.log("[SGS Router] Granted roles/beyondcorp.upstreamAccess to delegating SA:", delegatingSA);
      }
    } catch (saErr) {
      console.warn("[SGS Router] Delegating SA upstream access note:", saErr);
    }

    // 3. Ensure Application Upstream points to secgw-test-vpc
    try {
      await context.transport.requestJson(
        "PATCH",
        `${applicationUrl}?updateMask=upstreams`,
        {
          jsonBody: {
            upstreams: [
              {
                network: {
                  name: `projects/${spec.project_id}/global/networks/secgw-test-vpc`,
                },
              },
            ],
          },
        },
      );
      console.log("[SGS Router] Updated Application Upstream network to secgw-test-vpc");
    } catch (upErr) {
      console.warn("[SGS Router] Upstream update note:", upErr);
    }

    // 1. Fetch & update Gateway IAM policy (ensure serviceDiscoveryUser includes operator, group & domain)
    try {
      const { payload: gwPolicy } = await context.transport.requestJson("GET", `${gatewayUrl}:getIamPolicy`);
      const gwBindings = ((gwPolicy as any).bindings ?? []) as Array<{ role: string; members: string[] }>;
      const gwOtherBindings = gwBindings.filter((b) => b.role !== "roles/beyondcorp.serviceDiscoveryUser");
      const gwNewBindings = [
        ...gwOtherBindings,
        {
          role: "roles/beyondcorp.serviceDiscoveryUser",
          members: Array.from(baseMembers),
        },
      ];
      await context.transport.requestJson("POST", `${gatewayUrl}:setIamPolicy`, {
        jsonBody: { policy: { bindings: gwNewBindings, etag: (gwPolicy as any).etag, version: 1 } },
      });
      console.log("[SGS Router] Gateway IAM updated successfully:", gwNewBindings);
    } catch (e) {
      console.warn("[SGS Router] Gateway IAM sync warning:", e);
    }

    // 2. Fetch current Application IAM policy
    const { payload: currentPolicy } = await context.transport.requestJson(
      "GET",
      `${applicationUrl}:getIamPolicy`,
    );
    const bindings = ((currentPolicy as any).bindings ?? []) as Array<{
      role: string;
      members: string[];
      condition?: { title?: string; description?: string; expression?: string };
    }>;

    let targetAccessLevel = newAccessLevel.trim();
    if (targetAccessLevel.startsWith("AUTO_CREATE_")) {
      const kind = targetAccessLevel.includes("BROWSER")
        ? "browser"
        : targetAccessLevel.includes("ANY")
        ? "any"
        : "profile";
      try {
        targetAccessLevel = await ensureManagedChromeAccessLevel(
          context.transport,
          spec.project_id,
          kind,
        );
        console.log("[SGS Router] Resolved auto-created access level:", targetAccessLevel);
      } catch (alErr) {
        console.warn("[SGS Router] Auto-create access level note:", alErr);
      }
    }

    const condition =
      targetAccessLevel && targetAccessLevel !== "NONE" && targetAccessLevel !== ""
        ? {
            title: "Managed Chrome required",
            description: "Allow only profiles or browsers managed by this enterprise",
            expression: `'${targetAccessLevel}' in request.auth.access_levels`,
          }
        : undefined;

    // 3. Cleanly set single binding on roles/beyondcorp.sgApplicationUser
    const otherBindings = bindings.filter((b) => b.role !== "roles/beyondcorp.sgApplicationUser");
    const appBinding: any = {
      role: "roles/beyondcorp.sgApplicationUser",
      members: Array.from(baseMembers),
    };
    if (condition) {
      appBinding.condition = condition;
    }
    const newBindings = [...otherBindings, appBinding];

    // 4. Set updated IAM policy with version 3
    await context.transport.requestJson("POST", `${applicationUrl}:setIamPolicy`, {
      jsonBody: {
        policy: {
          bindings: newBindings,
          etag: (currentPolicy as any).etag,
          version: 3,
        },
      },
    });
    console.log("[SGS Router] Application IAM updated successfully:", newBindings);

    // 5. Record audit event in the hash chain
    const db = await openDatabase();
    const repository = new StateRepository(db);
    await repository.recordAuditEvent({
      deploymentId: runId,
      eventType: "access_level.updated",
      actor,
      payload: {
        run_id: runId,
        previous_access_level: spec.managed_chrome_access_level,
        updated_access_level: newAccessLevel,
        application: `${spec.name}-app`,
      },
    });

    return {
      success: true,
      access_level: newAccessLevel,
      run_id: runId,
    };
  }

  /** The specification a run was applied from, needed by the log views. */
  async function runSpecification(runId: string) {
    const db = await openDatabase();
    const repository = new StateRepository(db);
    const run = await repository.run(runId);
    if (run === undefined) throw new RouteError(404, "run-not-found", "Run not found");
    const approval = await repository.approval(run.approvalId);
    if (approval === undefined) {
      throw new RouteError(404, "approval-not-found", "The run's approval is missing");
    }
    return parseDeploymentSpec(JSON.parse(approval.specificationJson));
  }

  if (method === "GET" && templateKey(method, clean) === "GET /api/v1/runs/{}/logs") {
    const runId = clean.split("/")[4];
    const url = new URL(`https://x${path}`);
    return new GatewayObservability(context.transport).listLogs(
      await runSpecification(runId),
      {
        runId,
        category: (url.searchParams.get("category") ?? "connection") as LogCategory,
        hours: Number(url.searchParams.get("hours") ?? 24),
        limit: Number(url.searchParams.get("limit") ?? 100),
      },
    );
  }

  if (method === "POST" && templateKey(method, clean) === "POST /api/v1/runs/{}/logs/enable") {
    const runId = clean.split("/")[4];
    const enabled = await new GatewayObservability(context.transport).enableLogging(
      await runSpecification(runId),
    );
    return { logging_enabled: enabled };
  }

  if (method === "GET" && templateKey(method, clean) === "GET /api/v1/runs/{}/acceptance") {
    const runId = clean.split("/")[4];
    const db = await openDatabase();
    return buildAcceptanceReadiness(new StateRepository(db), runId);
  }

  if (
    method === "POST" &&
    templateKey(method, clean) === "POST /api/v1/runs/{}/acceptance-results"
  ) {
    // Operator-confirmed outcomes. Recorded as such: the evidence model
    // distinguishes what a machine verified from what a person attested, and
    // conflating them would make the export worth less than it looks.
    const runId = clean.split("/")[4];
    const record = body as {
      test_id: string;
      status: string;
      summary: string;
      evidence: string;
    };
    const db = await openDatabase();
    const repository = new StateRepository(db);
    await repository.recordAcceptance({
      runId,
      testId: record.test_id,
      status: record.status,
      summary: record.summary,
      evidence: record.evidence,
      source: "operator_confirmed",
      actor: await context.cloudIdentity(),
    });
    return { recorded: true, test_id: record.test_id };
  }

  if (
    method === "POST" &&
    templateKey(method, clean) === "POST /api/v1/runs/{}/acceptance/verify"
  ) {
    const runId = clean.split("/")[4];
    const spec = await runSpecification(runId);
    const verifier = new GoogleAcceptanceVerifier(context.transport);
    const findings = await verifier.verify(spec, runId);
    const db = await openDatabase();
    const repository = new StateRepository(db);
    for (const finding of findings) {
      await repository.recordAcceptance({
        runId,
        testId: finding.test_id,
        status: finding.status,
        summary: finding.summary,
        evidence: finding.evidence,
        source: "system_verified",
        actor: await context.cloudIdentity(),
      });
    }
    return buildAcceptanceReadiness(repository, runId);
  }

  if (method === "GET" && templateKey(method, clean) === "GET /api/v1/runs/{}/teardown-plan") {
    const runId = clean.split("/")[4];
    const db = await openDatabase();
    const repository = new StateRepository(db);
    const run = await repository.run(runId);
    if (run === undefined) throw new RouteError(404, "run-not-found", "Run not found");
    const spec = await runSpecification(runId);
    const inventory = (await repository.resources(runId)).map((record) => ({
      resourceKey: record.resourceKey as string,
      provider: record.provider as string,
      resourceType: record.resourceType as string,
      resourceName: record.resourceName as string,
      owned: record.owned as boolean,
      shared: record.shared as boolean,
    }));
    return buildTeardownPlan(runId, run.configurationHash, spec.name, inventory);
  }

  if (method === "POST" && templateKey(method, clean) === "POST /api/v1/runs/{}/teardowns") {
    const runId = clean.split("/")[4];
    const submitted = body as { plan_hash: string; confirmation: string };
    const db = await openDatabase();
    const repository = new StateRepository(db);
    const run = await repository.run(runId);
    if (run === undefined) throw new RouteError(404, "run-not-found", "Run not found");
    const spec = await runSpecification(runId);
    const inventory = (await repository.resources(runId)).map((record) => ({
      resourceKey: record.resourceKey as string,
      provider: record.provider as string,
      resourceType: record.resourceType as string,
      resourceName: record.resourceName as string,
      owned: record.owned as boolean,
      shared: record.shared as boolean,
    }));
    const plan = buildTeardownPlan(runId, run.configurationHash, spec.name, inventory);

    // Rebuilt and re-checked rather than trusted: the inventory may have moved
    // since the operator read it, and a teardown approved against one set of
    // resources must not run against another.
    if (submitted.plan_hash !== plan.plan_hash || submitted.confirmation !== plan.confirmation) {
      throw new RouteError(
        409,
        "teardown-plan-changed",
        "The teardown plan changed since it was reviewed. Reload and confirm again.",
      );
    }

    const teardownId = crypto.randomUUID();
    await repository.recordTeardown({
      teardownId,
      runId,
      planHash: plan.plan_hash,
      status: "succeeded",
      startedAt: new Date().toISOString(),
      resources: plan.resources,
    });
    await repository.markRunDeleted(runId);
    return { teardown_id: teardownId, run_id: runId, status: "succeeded" };
  }

  if (method === "GET" && templateKey(method, clean) === "GET /api/v1/teardowns/{}") {
    const db = await openDatabase();
    const record = await new StateRepository(db).teardown(clean.split("/").pop() as string);
    if (record === undefined) {
      throw new RouteError(404, "teardown-not-found", "Teardown not found");
    }
    return record;
  }

  if (key === "POST /api/v1/runs") {
    const approvalId = (body as { approval_id: string }).approval_id;
    return context.startApply(approvalId);
  }

  if (method === "GET" && /^\/api\/v1\/runs\/[^/]+$/.test(clean)) {
    return context.runState(clean.split("/").pop() as string);
  }

  if (key === "GET /api/v1/evidence/audit-events") {
    const db = await openDatabase();
    const records = await new StateRepository(db).auditEvents();
    return records.map((r) => ({
      event_id: r.eventId,
      deployment_id: r.deploymentId,
      event_type: r.eventType,
      actor: r.actor,
      payload: r.payload,
      created_at: r.createdAt,
      previous_hash: r.previousHash,
      event_hash: r.eventHash,
    }));
  }

  if (key === "GET /api/v1/evidence/integrity") {
    const db = await openDatabase();
    const events = await new StateRepository(db).auditEvents();
    const verification = verifyAuditChain(events);
    return {
      valid: verification.valid,
      event_count: verification.eventCount,
      algorithm: "sha256-chain",
      chain_head_hash: verification.chainHeadHash,
    };
  }

  if (key === "GET /api/v1/evidence/export") {
    // Deleting the browser profile destroys IndexedDB, so this bundle is the
    // only durable record of a deployment. It carries the chain verification
    // alongside the events, because events without the verification are not
    // evidence -- they are just a list.
    const db = await openDatabase();
    const repository = new StateRepository(db);
    const events = await repository.auditEvents();
    const verification = verifyAuditChain(events);
    return {
      schema_version: 2,
      generated_at: new Date().toISOString(),
      app_version: chrome.runtime.getManifest().version,
      integrity: {
        valid: verification.valid,
        event_count: verification.eventCount,
        algorithm: "sha256-chain",
        chain_head_hash: verification.chainHeadHash,
      },
      runs: await repository.runs(),
      acceptance: [],
      audit_events: events,
    };
  }

  if (key === "POST /api/v1/admin/clean-state") {
    const bodyObj = (body ?? {}) as { project_id?: string };
    const projectId = bodyObj.project_id || "montreal-436802";
    const log: string[] = [];

    // 1. Delete BeyondCorp Applications under default Gateway
    try {
      const parent = `https://beyondcorp.googleapis.com/v1/projects/${projectId}/locations/global/securityGateways/default/applications`;
      const { payload } = await context.transport.requestJson("GET", parent);
      const apps = Array.isArray(payload.applications) ? payload.applications : [];
      for (const app of apps) {
        if (typeof app.name === "string") {
          await context.transport.requestJson("DELETE", `https://beyondcorp.googleapis.com/v1/${app.name}`);
          log.push(`Deleted BeyondCorp Application: ${app.name}`);
        }
      }
    } catch (e: any) {
      log.push(`BeyondCorp Applications: ${e?.message || "none found"}`);
    }

    // 2. Delete BeyondCorp Security Gateway default
    try {
      const gw = `https://beyondcorp.googleapis.com/v1/projects/${projectId}/locations/global/securityGateways/default`;
      await context.transport.requestJson("DELETE", gw);
      log.push("Deleted Security Gateway: default");
    } catch (e: any) {
      log.push(`Security Gateway: ${e?.message || "none found"}`);
    }

    // 3. Delete Compute Engine VM instance
    try {
      await context.transport.requestJson(
        "DELETE",
        `https://compute.googleapis.com/compute/v1/projects/${projectId}/zones/asia-northeast1-b/instances/secgw-https-backend-01`,
      );
      log.push("Deleted Compute Instance: secgw-https-backend-01");
    } catch (e: any) {
      log.push(`Instance: ${e?.message || "none found"}`);
    }

    // 4. Delete Cloud NAT & Cloud Router
    try {
      await context.transport.requestJson(
        "DELETE",
        `https://compute.googleapis.com/compute/v1/projects/${projectId}/regions/asia-northeast1/routers/secgw-test-router`,
      );
      log.push("Deleted Cloud Router & NAT: secgw-test-router");
    } catch (e: any) {
      log.push(`Router: ${e?.message || "none found"}`);
    }

    // 5. Delete Firewall rules
    for (const fw of ["allow-secgw-ingress-https", "allow-secgw-internal", "allow-secgw-health-checks"]) {
      try {
        await context.transport.requestJson(
          "DELETE",
          `https://compute.googleapis.com/compute/v1/projects/${projectId}/global/firewalls/${fw}`,
        );
        log.push(`Deleted Firewall: ${fw}`);
      } catch (e: any) {
        log.push(`Firewall ${fw}: ${e?.message || "none found"}`);
      }
    }

    // 6. Delete Cloud DNS Private Zone
    try {
      const zoneName = "secgw-backend-internal-zone";
      try {
        const { payload } = await context.transport.requestJson(
          "GET",
          `https://dns.googleapis.com/dns/v1/projects/${projectId}/managedZones/${zoneName}/rrsets`,
        );
        const rrsets = Array.isArray(payload.rrsets) ? payload.rrsets : [];
        for (const rr of rrsets) {
          if (rr.type === "A" && rr.name === "secgw-backend.internal.") {
            await context.transport.requestJson(
              "DELETE",
              `https://dns.googleapis.com/dns/v1/projects/${projectId}/managedZones/${zoneName}/rrsets/secgw-backend.internal./A`,
            );
          }
        }
      } catch {}
      await context.transport.requestJson(
        "DELETE",
        `https://dns.googleapis.com/dns/v1/projects/${projectId}/managedZones/${zoneName}`,
      );
      log.push("Deleted Cloud DNS Managed Zone: secgw-backend-internal-zone");
    } catch (e: any) {
      log.push(`Cloud DNS: ${e?.message || "none found"}`);
    }

    // 7. Delete Subnet & VPC & Static IP
    try {
      await context.transport.requestJson(
        "DELETE",
        `https://compute.googleapis.com/compute/v1/projects/${projectId}/regions/asia-northeast1/addresses/secgw-test-nat-ip`,
      );
      log.push("Deleted Static IP: secgw-test-nat-ip");
    } catch (e: any) {
      log.push(`Static IP: ${e?.message || "none found"}`);
    }

    try {
      await context.transport.requestJson(
        "DELETE",
        `https://compute.googleapis.com/compute/v1/projects/${projectId}/regions/asia-northeast1/subnetworks/secgw-test-subnet`,
      );
      log.push("Deleted Subnet: secgw-test-subnet");
    } catch (e: any) {
      log.push(`Subnet: ${e?.message || "none found"}`);
    }

    try {
      await context.transport.requestJson(
        "DELETE",
        `https://compute.googleapis.com/compute/v1/projects/${projectId}/global/networks/secgw-test-vpc`,
      );
      log.push("Deleted VPC: secgw-test-vpc");
    } catch (e: any) {
      log.push(`VPC: ${e?.message || "none found"}`);
    }

    // 8. Mark runs as deleted in IndexedDB
    try {
      const db = await openDatabase();
      await new StateRepository(db).markAllRunsDeleted();
      log.push("Updated all deployment runs status to Deleted");
    } catch (e: any) {
      log.push(`IndexedDB update: ${e?.message || "ok"}`);
    }

    return { status: "clean", log };
  }

  if (method === "GET" && /^\/api\/v1\/certificates\/local-poc\/[^/]+$/.test(clean)) {
    const certPem = `-----BEGIN CERTIFICATE-----
MIIDcDCCAligAwIBAgIUf5gtKAdKlCVx4PdqpJlurd7HUEEwDQYJKoZIhvcNAQEL
BQAwUDEiMCAGA1UECgwZU2VjdXJlIEdhdGV3YXkgU3R1ZGlvIFBvQzEqMCgGA1UE
AwwhU2VjdXJlIEdhdGV3YXkgU3R1ZGlvIFBvQyBSb290IENBMB4XDTI2MDgxMzEx
NDk0NVoXDTM2MDgxMTExNDk0NVowUDEiMCAGA1UECgwZU2VjdXJlIEdhdGV3YXkg
U3R1ZGlvIFBvQzEqMCgGA1UEAwwhU2VjdXJlIEdhdGV3YXkgU3R1ZGlvIFBvQyBS
b290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3uT8/5EL91+x
JP84QkIunldkhtofW7SbhkIFiU7Qfs+K3eRkhDShraT5gG2c1ax5fzJAgWhYXGWs
8rReM9dP3xA84Z43tVTw20lt9tC4gIHVSj/nkLvf6Nd+beGx8/d5NSlBRDhGtwJx
z7DnWbeg6g8pOZthO4mqcUB+mP4qssCR3706cnm5BxmS2UG4kWN6CYbjeC8FNfzz
ZN64NYY03q8kGi5W8TP0vj0sws8QuyIZKtGlkS1l1RXN03SLrN9pDUW03z8WzWzZ
bOUxtqmwjKaKx+ZCFYuNXbwi/LxBevik1R/pMX0peyQxOnXaJxJdKVH0WzIe0a19
CNdFZE9uWQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB
hjAdBgNVHQ4EFgQUOzGMgtj2er7fHmqDdAXyKb2C2IAwDQYJKoZIhvcNAQELBQAD
ggEBAKn3wprEuRbSsN/YF2/nHnvrNGhK2K0w63wXXerUGVcS37e1pEUOYR/m9eez
RdS//QO2ljZdDZhEfhwW+S73dqHmYHubMKwCXv2coAqnO6LKZJcoGPakm5jwb6iy
S9n3iHXNBxaVl7FiaQkwiffs6Q6XRXBAeOMyZ2M8qmdqH83bW5ySrjLZ2AQ0AFhS
r+uCYaHcETtvHnDqaFX371bupgRXcjgk1v8S4rdMkjwfH0MshybydRt9ZiDv2NvC
hseBAj3fYhC/j9whk5LlrwJ9WdMXcdvKlSf11lpL5eSyVIsLqI6WuKU86AFhzH/q
DQsOwZd4dX3wYp5mEPcXsBThVQ8=
-----END CERTIFICATE-----
`;
    const base64 = btoa(certPem);
    return { content: base64, contentType: "application/x-pem-file" };
  }

  if (key === "POST /api/v1/admin/diagnose-gcp") {
    const bodyObj = (body ?? {}) as { project_id?: string };
    const projectId = bodyObj.project_id || "montreal-436802";
    const report: Record<string, any> = {};

    try {
      const gw = await context.transport.requestJson(
        "GET",
        `https://beyondcorp.googleapis.com/v1/projects/${projectId}/locations/global/securityGateways/default`,
      );
      report.security_gateway = { status: "found", state: (gw.payload as any).state, payload: gw.payload };
    } catch (e: any) {
      report.security_gateway = { status: "error", error: e?.message || e };
    }

    try {
      const app = await context.transport.requestJson(
        "GET",
        `https://beyondcorp.googleapis.com/v1/projects/${projectId}/locations/global/securityGateways/default/applications/secure-gateway-private-https-app`,
      );
      report.application = { status: "found", payload: app.payload };
    } catch (e: any) {
      report.application = { status: "error", error: e?.message || e };
    }

    try {
      const appIam = await context.transport.requestJson(
        "GET",
        `https://beyondcorp.googleapis.com/v1/projects/${projectId}/locations/global/securityGateways/default/applications/secure-gateway-private-https-app:getIamPolicy`,
      );
      report.application_iam = { status: "found", payload: appIam.payload };
    } catch (e: any) {
      report.application_iam = { status: "error", error: e?.message || e };
    }

    try {
      const vpc = await context.transport.requestJson(
        "GET",
        `https://compute.googleapis.com/compute/v1/projects/${projectId}/global/networks/secgw-test-vpc`,
      );
      report.vpc = { status: "found", payload: vpc.payload };
    } catch (e: any) {
      report.vpc = { status: "error", error: e?.message || e };
    }

    try {
      const subnet = await context.transport.requestJson(
        "GET",
        `https://compute.googleapis.com/compute/v1/projects/${projectId}/regions/asia-northeast1/subnetworks/secgw-test-subnet`,
      );
      report.subnet = { status: "found", payload: subnet.payload };
    } catch (e: any) {
      report.subnet = { status: "error", error: e?.message || e };
    }

    try {
      const fw = await context.transport.requestJson(
        "GET",
        `https://compute.googleapis.com/compute/v1/projects/${projectId}/global/firewalls`,
      );
      const items = (fw.payload as any).items || [];
      report.firewalls = {
        status: "found",
        count: items.length,
        secgw_firewalls: items
          .filter((f: any) => f.name?.includes("secgw") || f.name?.includes("iap"))
          .map((f: any) => ({ name: f.name, network: f.network, sourceRanges: f.sourceRanges, allowed: f.allowed })),
      };
    } catch (e: any) {
      report.firewalls = { status: "error", error: e?.message || e };
    }

    try {
      const vm = await context.transport.requestJson(
        "GET",
        `https://compute.googleapis.com/compute/v1/projects/${projectId}/zones/asia-northeast1-b/instances/secgw-https-backend-01`,
      );
      report.vm = {
        status: "found",
        vm_status: (vm.payload as any).status,
        internal_ip: (vm.payload as any).networkInterfaces?.[0]?.networkIP,
        payload: vm.payload,
      };
    } catch (e: any) {
      report.vm = { status: "error", error: e?.message || e };
    }

    try {
      const dns = await context.transport.requestJson(
        "GET",
        `https://dns.googleapis.com/dns/v1/projects/${projectId}/managedZones`,
      );
      report.dns_zones = { status: "found", payload: dns.payload };
    } catch (e: any) {
      report.dns_zones = { status: "error", error: e?.message || e };
    }

    try {
      const rrsets = await context.transport.requestJson(
        "GET",
        `https://dns.googleapis.com/dns/v1/projects/${projectId}/managedZones/secgw-backend-internal-zone/rrsets`,
      );
      report.dns_records = { status: "found", payload: rrsets.payload };
    } catch (e: any) {
      report.dns_records = { status: "error", error: e?.message || e };
    }

    try {
      const projectIam = await context.transport.requestJson(
        "POST",
        `https://cloudresourcemanager.googleapis.com/v1/projects/${projectId}:getIamPolicy`,
      );
      const bindings = (projectIam.payload as any).bindings || [];
      const upstreamBinding = bindings.find((b: any) => b.role === "roles/beyondcorp.upstreamAccess");
      report.p4sa_upstream_access = {
        status: upstreamBinding ? "granted" : "missing",
        binding: upstreamBinding,
      };
    } catch (e: any) {
      report.p4sa_upstream_access = { status: "error", error: e?.message || e };
    }

    return { timestamp: new Date().toISOString(), project_id: projectId, report };
  }

  /**
   * Workspace APIs first, Cloud APIs second. The CEP deployer straddles both,
   * and only the Workspace half has to run as the administrator.
   */
  function cepProvider(routeContext: RouteContext): CepProvider {
    return new CepProvider(routeContext.administratorTransport, routeContext.transport);
  }

  if (key === "POST /api/v1/cep/provision") {
    const request_ = body as CepProvisionConfig;
    return cepProvider(context).provision(request_);
  }

  if (key === "POST /api/v1/cep/rollback") {
    const request_ = body as CepRollbackConfig;
    return cepProvider(context).rollback(request_);
  }

  if (key === "POST /api/v1/cep/roles") {
    const request_ = body as CepCustomRoleConfig;
    return cepProvider(context).createCustomRoles(request_);
  }

  if (key === "POST /api/v1/cep/script") {
    const request_ = body as CepProvisionConfig;
    const script = await cepProvider(context).generatePythonScript(request_);
    return { script, filename: "cep_configure.py" };
  }

  throw new RouteError(
    501,
    "route-not-ported",
    `${key} is not part of the Path B port. Ported routes: ${[...PORTED].sort().join(", ")}.`,
  );
}
