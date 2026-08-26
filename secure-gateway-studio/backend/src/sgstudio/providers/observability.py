from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from google.auth.exceptions import DefaultCredentialsError, RefreshError

from sgstudio.domain.models import (
    BackendKind,
    DeploymentSpec,
    GatewayLogCategory,
    GatewayLogEntry,
    GatewayLogsResponse,
)
from sgstudio.providers.google_rest import GoogleAuthorizedTransport, JsonTransport

LOG_FIELDS = (
    "entries(insertId,timestamp,severity,protoPayload(methodName,status),"
    "jsonPayload(request_id,requestId,role,method,status,outcome,decision,"
    "request_time,tls_protocol,upstream_status,upstream_time)),nextPageToken"
)
MAX_LOG_PAGES = 100
OPERATIONAL_PAYLOAD_KEYS = (
    "role",
    "method",
    "status",
    "outcome",
    "decision",
    "request_time",
    "tls_protocol",
    "upstream_status",
    "upstream_time",
)


class GoogleGatewayObservability:
    def __init__(self, transport: JsonTransport) -> None:
        self._transport = transport

    def list_logs(
        self,
        spec: DeploymentSpec,
        *,
        run_id: str,
        category: GatewayLogCategory,
        hours: int = 24,
        limit: int = 100,
    ) -> GatewayLogsResponse:
        safe_hours = max(1, min(hours, 168))
        safe_limit = max(1, min(limit, 200))
        since = datetime.now(UTC) - timedelta(hours=safe_hours)
        filters = [f'timestamp>="{since.isoformat()}"']
        setup_notice: str | None = None
        data_access_notice = False
        logging_enabled: bool | None = None

        if category is GatewayLogCategory.ACCESS:
            filters.extend(
                [
                    'resource.type="audited_resource"',
                    'resource.labels.method="AuthorizeUser"',
                    'resource.labels.service="beyondcorp.googleapis.com"',
                ]
            )
            data_access_notice = True
        elif category is GatewayLogCategory.CONNECTION:
            logging_enabled = self._gateway_logging_enabled(spec)
            filters.append('resource.type="beyondcorp.googleapis.com/SecurityGateway"')
        elif category is GatewayLogCategory.ADMIN:
            filters.extend(
                [
                    'resource.type="audited_resource"',
                    'resource.labels.service="beyondcorp.googleapis.com"',
                ]
            )
        else:
            instance_id = self._offload_instance_id(spec)
            if instance_id is None:
                return GatewayLogsResponse(
                    run_id=run_id,
                    category=category,
                    entries=[],
                    logging_enabled=logging_enabled,
                    setup_notice=(
                        "Nginx logs require an HTTP-offload VM and the Google Cloud "
                        "Ops Agent. This architecture has no Nginx tier."
                        if spec.backend_kind
                        in {BackendKind.DIRECT_HTTPS, BackendKind.INTERNAL_HTTPS_LB}
                        else "The offload VM was not found or its instance ID is unavailable."
                    ),
                )
            filters.extend(
                [
                    'resource.type="gce_instance"',
                    f'resource.labels.instance_id="{instance_id}"',
                    '(log_id("nginx_access") OR log_id("nginx_access.log"))',
                ]
            )
            setup_notice = (
                "Nginx entries appear after the Google Cloud Ops Agent is configured "
                "to collect /var/log/nginx/sgstudio-access.log."
            )

        raw_entries: list[dict[str, Any]] = []
        seen_page_tokens: set[str] = set()
        page_token: str | None = None
        for page in range(MAX_LOG_PAGES):
            body: dict[str, Any] = {
                "resourceNames": [f"projects/{spec.project_id}"],
                "filter": " AND ".join(filters),
                "orderBy": "timestamp desc",
                "pageSize": min(safe_limit - len(raw_entries), 200),
            }
            if page_token is not None:
                body["pageToken"] = page_token
            _, payload = self._transport.request_json(
                "POST",
                "https://logging.googleapis.com/v2/entries:list",
                params={"fields": LOG_FIELDS},
                json_body=body,
            )
            page_entries = payload.get("entries", [])
            if not isinstance(page_entries, list) or any(
                not isinstance(item, dict) for item in page_entries
            ):
                raise ValueError("cloud-logging-entries-invalid")
            raw_entries.extend(page_entries[: safe_limit - len(raw_entries)])

            if "nextPageToken" not in payload or payload["nextPageToken"] == "":
                break
            next_page_token = payload["nextPageToken"]
            if (
                not isinstance(next_page_token, str)
                or next_page_token in seen_page_tokens
            ):
                raise ValueError("cloud-logging-page-token-invalid")
            seen_page_tokens.add(next_page_token)
            if len(raw_entries) >= safe_limit:
                break
            if page + 1 >= MAX_LOG_PAGES:
                raise ValueError("cloud-logging-pagination-incomplete")
            page_token = next_page_token

        entries = [
            self._entry(item, category, index)
            for index, item in enumerate(raw_entries)
        ]
        return GatewayLogsResponse(
            run_id=run_id,
            category=category,
            entries=entries,
            logging_enabled=logging_enabled,
            data_access_notice=data_access_notice,
            setup_notice=setup_notice,
        )

    def _gateway_logging_enabled(self, spec: DeploymentSpec) -> bool:
        # The empty LoggingConfig message is the connection-logging enable
        # marker. A field mask keeps this state read from receiving unrelated
        # Security Gateway provider output.
        _, payload = self._transport.request_json(
            "GET",
            (
                "https://beyondcorp.googleapis.com/v1/"
                f"projects/{spec.project_id}/locations/global/"
                f"securityGateways/{spec.gateway_id}"
            ),
            params={"fields": "logging"},
        )
        if "logging" not in payload:
            return False
        logging = payload["logging"]
        if not isinstance(logging, dict) or logging:
            raise ValueError("security-gateway-logging-state-invalid")
        return True

    def _offload_instance_id(self, spec: DeploymentSpec) -> str | None:
        if spec.backend_kind in {
            BackendKind.DIRECT_HTTPS,
            BackendKind.INTERNAL_HTTPS_LB,
        }:
            return None
        if spec.mode.value != "poc":
            return None
        url = (
            f"https://compute.googleapis.com/compute/v1/projects/{spec.project_id}/"
            f"zones/{spec.zone}/instances/{spec.name}-offload"
        )
        status, payload = self._transport.request_json(
            "GET", url, accepted_statuses=(200, 404)
        )
        if status == 404:
            return None
        identifier = payload.get("id")
        return str(identifier) if isinstance(identifier, (str, int)) else None

    @classmethod
    def _entry(
        cls,
        item: dict[str, Any],
        category: GatewayLogCategory,
        index: int,
    ) -> GatewayLogEntry:
        proto = item.get("protoPayload") if isinstance(item.get("protoPayload"), dict) else {}
        json_payload = (
            item.get("jsonPayload") if isinstance(item.get("jsonPayload"), dict) else {}
        )
        method = proto.get("methodName")
        request_id = json_payload.get("request_id") or json_payload.get("requestId")
        summary = cls._summary(proto, json_payload)
        timestamp = item.get("timestamp")
        parsed_timestamp: datetime | None = None
        if isinstance(timestamp, str):
            try:
                parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                parsed_timestamp = None
        safe_payload = cls._operational_payload(proto, json_payload)
        return GatewayLogEntry(
            insert_id=str(item.get("insertId") or f"entry-{index}"),
            timestamp=parsed_timestamp,
            severity=str(item.get("severity") or "DEFAULT")[:32],
            category=category,
            summary=summary,
            principal=None,
            method=str(method)[:300] if isinstance(method, str) else None,
            resource=None,
            request_id=str(request_id)[:200] if isinstance(request_id, str) else None,
            payload=safe_payload,
        )

    @staticmethod
    def _summary(
        proto: dict[str, Any], json_payload: dict[str, Any]
    ) -> str:
        for key in ("status", "outcome", "decision"):
            value = json_payload.get(key)
            if isinstance(value, (str, int, bool)):
                return str(value)[:500]
        status = proto.get("status")
        if isinstance(status, dict) and status:
            return json.dumps(status, ensure_ascii=False, sort_keys=True)[:500]
        method = proto.get("methodName")
        return str(method)[:500] if method else "Secure Gateway log entry"

    @staticmethod
    def _operational_payload(
        proto: dict[str, Any], json_payload: dict[str, Any]
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        status = proto.get("status")
        if isinstance(status, dict) and isinstance(status.get("code"), int):
            payload["api_status_code"] = status["code"]
        for key in OPERATIONAL_PAYLOAD_KEYS:
            value = json_payload.get(key)
            if isinstance(value, str):
                payload[key] = value[:200]
            elif isinstance(value, (int, float, bool)):
                payload[key] = value
        return payload


def create_google_gateway_observability(
    *, require_impersonation: bool = False
) -> GoogleGatewayObservability:
    try:
        transport = GoogleAuthorizedTransport.from_adc(
            require_impersonation=require_impersonation
        )
    except (DefaultCredentialsError, RefreshError) as error:
        raise RuntimeError("Application Default Credentials are unavailable for logs.") from error
    return GoogleGatewayObservability(transport)
