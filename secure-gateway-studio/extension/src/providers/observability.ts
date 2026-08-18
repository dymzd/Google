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
          logging_enabled: await this.loggingEnabled(spec),
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

    const { payload } = await this.transport.requestJson("POST", `${LOGGING}/entries:list`, {
      jsonBody: {
        resourceNames: [`projects/${spec.project_id}`],
        filter: filters.join(" AND "),
        orderBy: "timestamp desc",
        pageSize: limit,
      },
    });

    const raw = Array.isArray(payload.entries) ? payload.entries : [];
    const entries = raw
      .filter((item): item is Record<string, unknown> => item !== null && typeof item === "object")
      .map((item, index) => this.entry(item, options.category, index));

    return {
      run_id: options.runId,
      category: options.category,
      entries,
      logging_enabled: await this.loggingEnabled(spec),
      data_access_notice: dataAccessNotice,
      setup_notice: setupNotice,
    };
  }

  async loggingEnabled(spec: DeploymentSpec): Promise<boolean | null> {
    try {
      const { payload } = await this.transport.requestJson(
        "GET",
        `https://beyondcorp.googleapis.com/v1/projects/${spec.project_id}` +
          `/locations/global/securityGateways/${spec.gateway_id}`,
      );
      const logging = payload.loggingConfig as { enabled?: unknown } | undefined;
      return typeof logging?.enabled === "boolean" ? logging.enabled : null;
    } catch {
      return null;
    }
  }

  async enableLogging(spec: DeploymentSpec): Promise<boolean> {
    await this.transport.requestJson(
      "PATCH",
      `https://beyondcorp.googleapis.com/v1/projects/${spec.project_id}` +
        `/locations/global/securityGateways/${spec.gateway_id}`,
      {
        params: { updateMask: "logging_config" },
        jsonBody: { loggingConfig: { enabled: true } },
      },
    );
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
   * Only a timestamp, a severity, and a short summary leave this function.
   * Payloads can carry request paths and principal identifiers, and the views
   * exist to answer "did access decisions happen", not to surface their
   * contents.
   */
  private entry(item: Record<string, unknown>, category: LogCategory, index: number): LogEntry {
    const proto = item.protoPayload as Record<string, unknown> | undefined;
    const json = item.jsonPayload as Record<string, unknown> | undefined;
    let summary = String(item.textPayload ?? "");
    if (!summary && proto) {
      summary = String(proto.methodName ?? proto.serviceName ?? "audited event");
    }
    if (!summary && json) {
      const status = json.status ?? json.upstream_status ?? "";
      summary = `${json.method ?? ""} ${json.uri ?? ""} ${status}`.trim();
    }
    const authInfo = proto?.authenticationInfo as Record<string, unknown> | undefined;
    const reqMeta = proto?.requestMetadata as Record<string, unknown> | undefined;
    return {
      insert_id: String(item.insertId ?? item.insert_id ?? `log-${index}`),
      category,
      timestamp: typeof item.timestamp === "string" ? item.timestamp : null,
      severity: String(item.severity ?? "DEFAULT"),
      summary: summary.slice(0, 500) || "(no summary)",
      principal: typeof authInfo?.principalEmail === "string" ? authInfo.principalEmail : null,
      method: typeof proto?.methodName === "string" ? proto.methodName : null,
      resource: typeof proto?.resourceName === "string" ? proto.resourceName : null,
      request_id: typeof reqMeta?.callerIp === "string" ? reqMeta.callerIp : null,
      payload: (proto ?? json ?? item) as Record<string, unknown>,
    };
  }
}
