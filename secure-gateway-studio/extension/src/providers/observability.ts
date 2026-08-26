/**
 * Post-deployment log views. Port of `providers/observability.py`.
 *
 * Four sanitized views over Cloud Logging, each a fixed filter rather than a
 * free-text query. The operator cannot compose their own filter, which is the
 * point: a query box over an administrator's project is a data-exfiltration
 * surface, and the four questions worth asking after a deployment are known in
 * advance.
 */

import type { DeploymentSpec } from "../domain/spec.ts";
import type { Transport } from "./executor.ts";

export type LogCategory = "access" | "connection" | "admin" | "nginx";

export interface LogEntry {
  insert_id: string;
  category: LogCategory;
  timestamp: string | null;
  severity: string;
  summary: string;
  principal: string | null;
  method: string | null;
  resource: string | null;
  request_id: string | null;
  caller_ip: string | null;
  payload: Record<string, unknown>;
}

export interface LogsResponse {
  run_id: string;
  category: LogCategory;
  entries: LogEntry[];
  logging_enabled: boolean | null;
  data_access_notice?: boolean;
  setup_notice?: string | null;
}

const LOGGING = "https://logging.googleapis.com/v2";
const COMPUTE = "https://compute.googleapis.com/compute/v1";
const BEYONDCORP = "https://beyondcorp.googleapis.com/v1";
// Request only the fields needed for the operator-facing health/audit view.
// In particular, never receive textPayload, requestMetadata/callerIp, an
// authenticated principal, or Nginx URI/query fields. Chrome Web Store policy
// classifies URL paths obtained from a cloud service as web-browsing activity;
// this feature does not need that data.
const LOG_ENTRY_FIELDS = [
  "insertId",
  "timestamp",
  "severity",
  "protoPayload.methodName",
  "protoPayload.serviceName",
  "protoPayload.resourceName",
  "protoPayload.status",
  "jsonPayload.status",
  "jsonPayload.upstream_status",
  "jsonPayload.request_id",
  "jsonPayload.requestId",
].join(",");
const LOG_FIELDS = encodeURIComponent(`entries(${LOG_ENTRY_FIELDS}),nextPageToken`);
const MAX_LOG_PAGES = 100;

export class GatewayObservability {
  private readonly transport: Transport;

  constructor(transport: Transport) {
    this.transport = transport;
  }

  async listLogs(
    spec: DeploymentSpec,
    options: { runId: string; category: LogCategory; hours?: number; limit?: number },
  ): Promise<LogsResponse> {
    // Clamped rather than validated: an out-of-range value is a UI slip, not an
    // attack, and refusing the whole request would be less useful than serving
    // a sane window.
    const hours = Math.max(1, Math.min(options.hours ?? 24, 168));
    const limit = Math.max(1, Math.min(options.limit ?? 100, 200));
    const since = new Date(Date.now() - hours * 3_600_000).toISOString();
    const filters = [`timestamp>="${since}"`];
    let setupNotice: string | null = null;
    let dataAccessNotice = false;
    let loggingEnabled: boolean | null = null;

    if (options.category === "access") {
      filters.push(
        'resource.type="audited_resource"',
        'resource.labels.method="AuthorizeUser"',
        'resource.labels.service="beyondcorp.googleapis.com"',
      );
      // These are Data Access audit logs; they are off by default and the UI
      // says so rather than showing an empty list as if nothing happened.
      dataAccessNotice = true;
    } else if (options.category === "connection") {
      loggingEnabled = await this.gatewayLoggingEnabled(spec);
      filters.push('resource.type="beyondcorp.googleapis.com/SecurityGateway"');
    } else if (options.category === "admin") {
      filters.push(
        'resource.type="audited_resource"',
        'resource.labels.service="beyondcorp.googleapis.com"',
      );
    } else {
      const instanceId = await this.offloadInstanceId(spec);
      if (instanceId === null) {
        return {
          run_id: options.runId,
          category: options.category,
          entries: [],
          logging_enabled: loggingEnabled,
          setup_notice:
            spec.backend_kind === "direct_https"
              ? "Nginx logs require an HTTP-offload VM and the Google Cloud Ops Agent. " +
                "Direct HTTPS has no Nginx tier."
              : "The offload VM was not found or its instance ID is unavailable.",
        };
      }
      filters.push(
        'resource.type="gce_instance"',
        `resource.labels.instance_id="${instanceId}"`,
        '(log_id("nginx_access") OR log_id("nginx_access.log"))',
      );
      setupNotice =
        "Nginx entries appear after the Google Cloud Ops Agent is configured " +
        "to collect /var/log/nginx/sgstudio-access.log.";
    }

    const raw: Record<string, unknown>[] = [];
    const seenPageTokens = new Set<string>();
    let pageToken: string | undefined;
    for (let page = 0; page < MAX_LOG_PAGES; page += 1) {
      const { payload } = await this.transport.requestJson(
        "POST",
        `${LOGGING}/entries:list?fields=${LOG_FIELDS}`,
        {
          jsonBody: {
            resourceNames: [`projects/${spec.project_id}`],
            filter: filters.join(" AND "),
            orderBy: "timestamp desc",
            pageSize: Math.min(limit - raw.length, 200),
            ...(pageToken === undefined ? {} : { pageToken }),
          },
        },
      );
      const pageEntries = payload.entries === undefined ? [] : payload.entries;
      if (
        !Array.isArray(pageEntries) ||
        pageEntries.some((item) => item === null || typeof item !== "object" || Array.isArray(item))
      ) {
        throw new Error("cloud-logging-entries-invalid");
      }
      raw.push(
        ...(pageEntries as Record<string, unknown>[]).slice(0, limit - raw.length),
      );

      const next = payload.nextPageToken;
      if (next === undefined || next === "") break;
      if (typeof next !== "string" || seenPageTokens.has(next)) {
        throw new Error("cloud-logging-page-token-invalid");
      }
      seenPageTokens.add(next);
      if (raw.length >= limit) break;
      if (page + 1 >= MAX_LOG_PAGES) {
        throw new Error("cloud-logging-pagination-incomplete");
      }
      pageToken = next;
    }

    const entries = raw.map((item, index) => this.entry(item, options.category, index));

    return {
      run_id: options.runId,
      category: options.category,
      entries,
      logging_enabled: loggingEnabled,
      data_access_notice: dataAccessNotice,
      setup_notice: setupNotice,
    };
  }

  private async gatewayLoggingEnabled(spec: DeploymentSpec): Promise<boolean> {
    // `logging: {}` is the current Security Gateway connection-logging enable
    // marker. Request only that field so this state check cannot receive
    // gateway addresses or any unrelated provider output.
    const { payload } = await this.transport.requestJson(
      "GET",
      `${BEYONDCORP}/projects/${spec.project_id}/locations/global/` +
        `securityGateways/${spec.gateway_id}?fields=logging`,
    );
    if (!Object.prototype.hasOwnProperty.call(payload, "logging")) return false;
    const logging = payload.logging;
    if (
      logging === null ||
      typeof logging !== "object" ||
      Array.isArray(logging) ||
      Object.keys(logging as Record<string, unknown>).length !== 0
    ) {
      throw new Error("security-gateway-logging-state-invalid");
    }
    return true;
  }

  private async offloadInstanceId(spec: DeploymentSpec): Promise<string | null> {
    if (spec.backend_kind === "direct_https") return null;
    try {
      const { payload } = await this.transport.requestJson(
        "GET",
        `${COMPUTE}/projects/${spec.project_id}/zones/${spec.zone}/instances/${spec.name}-offload`,
      );
      return typeof payload.id === "string" ? payload.id : null;
    } catch {
      return null;
    }
  }

  /**
   * Reduce an entry to what the UI shows.
   *
   * Only explicitly allowlisted operational metadata leaves this function.
   * Payloads can carry request paths, query data, IP addresses, free text, and
   * principal identifiers; the views exist to answer "did an operation happen"
   * rather than to surface or persist those contents.
   */
  private entry(item: Record<string, unknown>, category: LogCategory, index: number): LogEntry {
    const proto = item.protoPayload as Record<string, unknown> | undefined;
    const json = item.jsonPayload as Record<string, unknown> | undefined;
    const status = json?.status ?? json?.upstream_status ??
      (proto?.status as Record<string, unknown> | undefined)?.code;
    const summary = String(proto?.methodName ?? proto?.serviceName ?? status ?? "audited event");
    return {
      insert_id: String(item.insertId ?? item.insert_id ?? `log-${index}`),
      category,
      timestamp: typeof item.timestamp === "string" ? item.timestamp : null,
      severity: String(item.severity ?? "DEFAULT"),
      summary: summary.slice(0, 500) || "(no summary)",
      principal: null,
      method: typeof proto?.methodName === "string" ? proto.methodName : null,
      resource: typeof proto?.resourceName === "string" ? proto.resourceName : null,
      request_id:
        typeof json?.request_id === "string"
          ? json.request_id
          : typeof json?.requestId === "string"
            ? json.requestId
            : null,
      caller_ip: null,
      payload: {
        method_name: proto?.methodName ?? null,
        service_name: proto?.serviceName ?? null,
        status: (json?.status ?? json?.upstream_status) ?? null,
      },
    };
  }
}
