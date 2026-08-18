/**
 * Acceptance verification. Port of the machine-verifiable half of
 * `providers/acceptance.py`.
 *
 * The acceptance matrix mixes two kinds of evidence and the product is careful
 * never to blur them:
 *
 *   - **system-verified** — the app queried Google and checked the answer;
 *   - **operator-confirmed** — a person looked at a browser and said so.
 *
 * Only T05 and T06 can be settled by API alone. T01-T03 read guest attributes
 * the offload VM publishes, which exist only on Path A. T07-T09 require driving
 * a managed browser, which no public API can attest, so they stay
 * operator-confirmed and are labelled that way in the evidence export.
 *
 * Claiming a cloud test passed when only a fixture passed is the failure mode
 * this module exists to avoid.
 */

import type { DeploymentSpec } from "../domain/spec.ts";
import { applicationHostname, applicationPort } from "../domain/spec.ts";
import type { Transport } from "./executor.ts";

export type AcceptanceStatus = "passed" | "failed" | "pending" | "skipped";
export type EvidenceSource = "system_verified" | "operator_confirmed";

export interface AcceptanceRequirement {
  test_id: string;
  title: string;
  source: EvidenceSource;
  applicable: boolean;
  detail: string;
}

export interface AcceptanceFinding {
  test_id: string;
  status: AcceptanceStatus;
  summary: string;
  evidence: string;
}

/**
 * Which tests apply to this deployment, and who can settle each.
 *
 * Path B has no offload VM, so the VM-probe tests are not merely unverified —
 * they are inapplicable, and showing them as pending would imply work that
 * will never be possible.
 */
export function acceptanceRequirements(spec: DeploymentSpec): AcceptanceRequirement[] {
  const directHttps = spec.backend_kind === "direct_https";
  const production = spec.mode === "production";
  return [
    {
      test_id: "T01",
      title: "Backend reachable from the offload tier",
      source: "system_verified",
      applicable: !directHttps,
      detail: directHttps
        ? "Direct HTTPS has no offload tier to probe from."
        : "Read from the offload VM's guest attributes.",
    },
    {
      test_id: "T02",
      title: "Offload upstream responds",
      source: "system_verified",
      applicable: !directHttps,
      detail: directHttps
        ? "Direct HTTPS has no Nginx upstream."
        : "Read from the offload VM's guest attributes.",
    },
    {
      test_id: "T03",
      title: "Offload serves the expected certificate",
      source: "system_verified",
      applicable: !directHttps,
      detail: directHttps
        ? "The application presents its own certificate."
        : "Read from the offload VM's guest attributes.",
    },
    {
      test_id: "T04",
      title: "Private DNS resolves to the offload address",
      source: "system_verified",
      applicable: !directHttps,
      detail: directHttps
        ? "Direct HTTPS uses the operator's existing DNS."
        : "Compared against the reserved internal address.",
    },
    {
      test_id: "T05",
      title: "Application matcher registered",
      source: "system_verified",
      applicable: true,
      detail: "Verified against the BeyondCorp application.",
    },
    {
      test_id: "T06",
      title: "Access binding carries the managed-Chrome condition",
      source: "system_verified",
      applicable: true,
      detail: "Verified against the application IAM policy.",
    },
    {
      test_id: "T07",
      title: "Managed Chrome reaches the application",
      source: "operator_confirmed",
      applicable: true,
      detail: "Requires a managed browser on each selected platform.",
    },
    {
      test_id: "T08",
      title: "Request correlation across the offload tier",
      source: "operator_confirmed",
      applicable: production && !directHttps,
      detail: "Production only; correlates the request ID through Nginx logs.",
    },
    {
      test_id: "T09",
      title: "Unauthorized principal and unmanaged browser are refused",
      source: "operator_confirmed",
      applicable: production,
      detail: "Production only; requires two separate denial demonstrations.",
    },
  ];
}

const BEYONDCORP = "https://beyondcorp.googleapis.com/v1";

export class GoogleAcceptanceVerifier {
  private readonly transport: Transport;

  constructor(transport: Transport) {
    this.transport = transport;
  }

  /** Run only the checks a public API can settle. */
  async verify(spec: DeploymentSpec, runId: string): Promise<AcceptanceFinding[]> {
    const findings: AcceptanceFinding[] = [];
    const applicationUrl =
      `${BEYONDCORP}/projects/${spec.project_id}/locations/global` +
      `/securityGateways/${spec.gateway_id}/applications/${spec.name}-app`;

    // T05: the matcher exists and names the endpoint the plan specified.
    try {
      const { payload } = await this.transport.requestJson("GET", applicationUrl);
      const matchers = payload.endpointMatchers ?? payload.endpoint_matchers;
      const expectedHost = applicationHostname(spec);
      const expectedPort = applicationPort(spec);
      const matched =
        Array.isArray(matchers) &&
        matchers.some((entry) => {
          const record = entry as Record<string, unknown>;
          const ports = (record.ports ?? []) as unknown[];
          return (
            record.hostname === expectedHost &&
            ports.map(Number).includes(expectedPort)
          );
        });
      findings.push({
        test_id: "T05",
        status: matched ? "passed" : "failed",
        summary: matched
          ? `Matcher ${expectedHost}:${expectedPort} is registered.`
          : `No matcher for ${expectedHost}:${expectedPort} was found.`,
        evidence: JSON.stringify({ run_id: runId, matchers: matchers ?? null }),
      });
    } catch (error) {
      findings.push({
        test_id: "T05",
        status: "failed",
        summary: "The application could not be read.",
        evidence: JSON.stringify({ run_id: runId, error: (error as Error).message }),
      });
    }

    // T06: the access binding must carry the managed-Chrome condition. A
    // binding without it grants access from any browser, which is the whole
    // property the deployment exists to establish.
    try {
      const { payload } = await this.transport.requestJson(
        "GET",
        `${applicationUrl}:getIamPolicy`,
      );
      const bindings = (payload.bindings ?? []) as Record<string, unknown>[];
      const target = bindings.find(
        (binding) => binding.role === "roles/beyondcorp.sgApplicationUser",
      );
      const condition = target?.condition as { expression?: string } | undefined;
      const bound =
        spec.managed_chrome_access_level !== null &&
        typeof condition?.expression === "string" &&
        condition.expression.includes(spec.managed_chrome_access_level);
      findings.push({
        test_id: "T06",
        status: bound ? "passed" : "failed",
        summary: bound
          ? "The access binding is conditioned on the managed-Chrome access level."
          : "The access binding carries no managed-Chrome condition.",
        evidence: JSON.stringify({ run_id: runId, condition: condition ?? null }),
      });
    } catch (error) {
      findings.push({
        test_id: "T06",
        status: "failed",
        summary: "The application IAM policy could not be read.",
        evidence: JSON.stringify({ run_id: runId, error: (error as Error).message }),
      });
    }

    return findings;
  }
}
