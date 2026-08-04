from __future__ import annotations

import json
import re
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

SENSITIVE_KEY = re.compile(
    r"(?i)(authorization|cookie|credential|password|private.?key|refresh.?token|access.?token)"
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
                    logging_enabled=self.gateway_logging_enabled(spec),
                    setup_notice=(
                        "Nginx logs require an HTTP-offload VM and the Google Cloud "
                        "Ops Agent. Direct HTTPS has no Nginx tier."
                        if spec.backend_kind is BackendKind.DIRECT_HTTPS
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

        _, payload = self._transport.request_json(
            "POST",
            "https://logging.googleapis.com/v2/entries:list",
            json_body={
                "resourceNames": [f"projects/{spec.project_id}"],
                "filter": " AND ".join(filters),
                "orderBy": "timestamp desc",
                "pageSize": safe_limit,
            },
        )
        raw_entries = payload.get("entries", [])
        entries = [
            self._entry(item, category, index)
            for index, item in enumerate(raw_entries)
            if isinstance(item, dict)
        ]
        return GatewayLogsResponse(
            run_id=run_id,
            category=category,
            entries=entries,
            logging_enabled=self.gateway_logging_enabled(spec),
            data_access_notice=data_access_notice,
            setup_notice=setup_notice,
        )

    def gateway_logging_enabled(self, spec: DeploymentSpec) -> bool | None:
        url = (
            f"https://beyondcorp.googleapis.com/v1/projects/{spec.project_id}/"
            f"locations/global/securityGateways/{spec.gateway_id}"
        )
        status, payload = self._transport.request_json(
            "GET", url, accepted_statuses=(200, 404)
        )
        if status == 404:
            return None
        return isinstance(payload.get("logging"), dict)

    def enable_gateway_logging(self, spec: DeploymentSpec) -> bool:
        url = (
            f"https://beyondcorp.googleapis.com/v1/projects/{spec.project_id}/"
            f"locations/global/securityGateways/{spec.gateway_id}"
        )
        self._transport.request_json(
            "PATCH",
            url,
            params={"updateMask": "logging"},
            json_body={"logging": {}},
        )
        return True

    def _offload_instance_id(self, spec: DeploymentSpec) -> str | None:
        if spec.backend_kind is BackendKind.DIRECT_HTTPS:
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
        authentication = (
            proto.get("authenticationInfo")
            if isinstance(proto.get("authenticationInfo"), dict)
            else {}
        )
        principal = authentication.get("principalEmail")
        method = proto.get("methodName")
        resource = proto.get("resourceName")
        request_id = json_payload.get("request_id") or json_payload.get("requestId")
        summary = cls._summary(item, proto, json_payload)
        timestamp = item.get("timestamp") or item.get("receiveTimestamp")
        parsed_timestamp: datetime | None = None
        if isinstance(timestamp, str):
            try:
                parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                parsed_timestamp = None
        safe_payload = cls._redact(item)
        return GatewayLogEntry(
            insert_id=str(item.get("insertId") or f"entry-{index}"),
            timestamp=parsed_timestamp,
            severity=str(item.get("severity") or "DEFAULT")[:32],
            category=category,
            summary=summary,
            principal=str(principal)[:320] if isinstance(principal, str) else None,
            method=str(method)[:300] if isinstance(method, str) else None,
            resource=str(resource)[:1000] if isinstance(resource, str) else None,
            request_id=str(request_id)[:200] if isinstance(request_id, str) else None,
            payload=safe_payload if isinstance(safe_payload, dict) else {},
        )

    @staticmethod
    def _summary(
        item: dict[str, Any], proto: dict[str, Any], json_payload: dict[str, Any]
    ) -> str:
        text = item.get("textPayload")
        if isinstance(text, str) and text.strip():
            return text.strip()[:500]
        for key in ("message", "status", "outcome", "decision"):
            value = json_payload.get(key)
            if isinstance(value, (str, int, bool)):
                return str(value)[:500]
        status = proto.get("status")
        if isinstance(status, dict) and status:
            return json.dumps(status, ensure_ascii=False, sort_keys=True)[:500]
        method = proto.get("methodName")
        return str(method)[:500] if method else "Secure Gateway log entry"

    @classmethod
    def _redact(cls, value: Any, *, depth: int = 0) -> Any:
        if depth > 7:
            return "[truncated]"
        if isinstance(value, dict):
            return {
                str(key)[:100]: (
                    "[redacted]"
                    if SENSITIVE_KEY.search(str(key))
                    else cls._redact(item, depth=depth + 1)
                )
                for key, item in list(value.items())[:80]
            }
        if isinstance(value, list):
            return [cls._redact(item, depth=depth + 1) for item in value[:80]]
        if isinstance(value, str):
            return value[:2000]
        if isinstance(value, (int, float, bool)) or value is None:
            return value
        return str(value)[:500]


def create_google_gateway_observability() -> GoogleGatewayObservability:
    try:
        transport = GoogleAuthorizedTransport.from_adc()
    except (DefaultCredentialsError, RefreshError) as error:
        raise RuntimeError("Application Default Credentials are unavailable for logs.") from error
    return GoogleGatewayObservability(transport)
