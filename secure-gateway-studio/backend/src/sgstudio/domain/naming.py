from __future__ import annotations

import hashlib


def service_account_id(deployment_name: str, role: str) -> str:
    """Return a stable Google service-account ID within the 30-char limit."""
    candidate = f"{deployment_name}-{role}"
    if len(candidate) <= 30:
        return candidate
    digest = hashlib.sha256(deployment_name.encode()).hexdigest()[:6]
    prefix_length = 30 - len(role) - len(digest) - 2
    prefix = deployment_name[:prefix_length].rstrip("-") or "sgs"
    return f"{prefix}-{digest}-{role}"


def service_account_email(deployment_name: str, project_id: str, role: str) -> str:
    return f"{service_account_id(deployment_name, role)}@{project_id}.iam.gserviceaccount.com"

