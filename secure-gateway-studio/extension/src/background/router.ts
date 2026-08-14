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
import { parseDeploymentSpec, specToJson } from "../domain/spec.ts";
import { GoogleDiscoveryProvider } from "../providers/discovery.ts";
import { GoogleSetupCatalog } from "../providers/catalog.ts";
import { bootstrapDeployer } from "../providers/bootstrap.ts";
import { GatewayObservability, type LogCategory } from "../providers/observability.ts";
import { buildTeardownPlan } from "../domain/teardown.ts";
import { GoogleAcceptanceVerifier, acceptanceRequirements } from "../providers/acceptance.ts";
import type { Transport } from "../providers/executor.ts";
import { openDatabase, StateRepository } from "../storage/repository.ts";
import { verifyAuditChain } from "../storage/audit.ts";

export interface RouteContext {
  transport: Transport;
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
  "GET /api/v1/runs/{}/teardown-plan",
  "POST /api/v1/runs/{}/teardowns",
  "GET /api/v1/teardowns/{}",
  "GET /api/v1/evidence/audit-events",
  "GET /api/v1/evidence/integrity",
  "GET /api/v1/evidence/export",
  "GET /api/v1/health",
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
    return { options: await (await catalog()).listAccessLevels(projectId) };
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

  if (key === "GET /api/v1/runs") {
    const db = await openDatabase();
    return new StateRepository(db).runs();
  }

  if (method === "GET" && templateKey(method, clean) === "GET /api/v1/runs/{}/details") {
    const db = await openDatabase();
    const repository = new StateRepository(db);
    const runId = clean.split("/")[4];
    const run = await repository.run(runId);
    if (run === undefined) throw new RouteError(404, "run-not-found", "Run not found");
    const approval = await repository.approval(run.approvalId);
    return {
      run,
      specification: approval ? JSON.parse(approval.specificationJson) : null,
      plan: approval ? JSON.parse(approval.planJson) : null,
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
    const repository = new StateRepository(db);
    const spec = await runSpecification(runId);
    const recorded = await repository.acceptance(runId);
    return {
      run_id: runId,
      requirements: acceptanceRequirements(spec),
      results: recorded,
    };
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
    await new StateRepository(db).recordAcceptance({
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
    return { run_id: runId, findings };
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
      status: "pending",
      startedAt: new Date().toISOString(),
      resources: plan.resources,
    });
    return { teardown_id: teardownId, run_id: runId, status: "pending" };
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
    return new StateRepository(db).auditEvents();
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

  throw new RouteError(
    501,
    "route-not-ported",
    `${key} is not part of the Path B port. Ported routes: ${[...PORTED].sort().join(", ")}.`,
  );
}
