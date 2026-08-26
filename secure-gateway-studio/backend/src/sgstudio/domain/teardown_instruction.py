from __future__ import annotations

from copy import deepcopy

from sgstudio.domain.models import DeploymentResource


def teardown_instruction(
    *,
    run_id: str,
    configuration_hash: str,
    resources: list[DeploymentResource],
    ownership_metadata: dict[str, dict[str, object]],
) -> dict[str, object]:
    """Return the complete immutable instruction approved for teardown."""
    return {
        "schema_version": 1,
        "run_id": run_id,
        "configuration_hash": configuration_hash,
        "resources": [
            {
                "resource_key": resource.resource_key,
                "provider": resource.provider,
                "resource_type": resource.resource_type,
                "resource_name": resource.resource_name,
                "owned": resource.owned,
                "action": resource.teardown_action,
                "ownership_metadata": deepcopy(
                    ownership_metadata.get(resource.resource_key)
                ),
            }
            for resource in resources
        ],
    }
