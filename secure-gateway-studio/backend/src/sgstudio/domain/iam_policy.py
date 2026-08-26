from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

_POLICY_FIELDS = frozenset({"version", "bindings", "auditConfigs", "etag"})
_BINDING_FIELDS = frozenset({"role", "members", "condition"})
_CONDITION_FIELDS = frozenset({"title", "expression", "description", "location"})
_AUDIT_CONFIG_FIELDS = frozenset({"service", "auditLogConfigs"})
_AUDIT_LOG_CONFIG_FIELDS = frozenset({"logType", "exemptedMembers"})
_AUDIT_LOG_TYPES = frozenset({"ADMIN_READ", "DATA_WRITE", "DATA_READ"})


class IamPolicyValidationError(ValueError):
    """A provider IAM policy cannot be safely round-tripped."""


class IamPolicyEtagMissingError(IamPolicyValidationError):
    """A policy about to be written has no usable concurrency token."""


def _assert_exact_fields(
    value: dict[object, object],
    allowed: frozenset[str],
    *,
    context: str,
) -> None:
    fields = set(value)
    if any(not isinstance(field, str) for field in fields) or not fields <= allowed:
        raise IamPolicyValidationError(f"IAM {context} contains an unknown field")


def _nonempty_string(value: object, *, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise IamPolicyValidationError(f"IAM {context} must be a nonempty string")
    return value


def _unique_nonempty_strings(
    value: object,
    *,
    context: str,
    require_item: bool,
) -> list[str]:
    if not isinstance(value, list) or (require_item and not value):
        raise IamPolicyValidationError(
            f"IAM {context} must be a{' nonempty' if require_item else ''} list"
        )
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise IamPolicyValidationError(f"IAM {context} contains an empty or non-string value")
    if len(set(value)) != len(value):
        raise IamPolicyValidationError(f"IAM {context} contains a duplicate value")
    return list(value)


def _validate_condition(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise IamPolicyValidationError("IAM binding condition must be an object")
    _assert_exact_fields(value, _CONDITION_FIELDS, context="binding condition")
    condition: dict[str, str] = {}
    for required in ("title", "expression"):
        condition[required] = _nonempty_string(
            value.get(required),
            context=f"binding condition {required}",
        )
    for optional in ("description", "location"):
        if optional in value:
            raw = value[optional]
            if not isinstance(raw, str):
                raise IamPolicyValidationError(
                    f"IAM binding condition {optional} must be a string"
                )
            condition[optional] = raw
    return condition


def _validate_audit_configs(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise IamPolicyValidationError("IAM policy auditConfigs must be a list")
    configs: list[dict[str, Any]] = []
    services: set[str] = set()
    for raw_config in value:
        if not isinstance(raw_config, dict):
            raise IamPolicyValidationError("IAM audit config must be an object")
        _assert_exact_fields(raw_config, _AUDIT_CONFIG_FIELDS, context="audit config")
        service = _nonempty_string(raw_config.get("service"), context="audit config service")
        if service in services:
            raise IamPolicyValidationError("IAM policy contains duplicate audit services")
        services.add(service)
        config: dict[str, Any] = {"service": service}
        if "auditLogConfigs" in raw_config:
            raw_log_configs = raw_config["auditLogConfigs"]
            if not isinstance(raw_log_configs, list):
                raise IamPolicyValidationError("IAM auditLogConfigs must be a list")
            log_configs: list[dict[str, Any]] = []
            log_types: set[str] = set()
            for raw_log_config in raw_log_configs:
                if not isinstance(raw_log_config, dict):
                    raise IamPolicyValidationError("IAM audit log config must be an object")
                _assert_exact_fields(
                    raw_log_config,
                    _AUDIT_LOG_CONFIG_FIELDS,
                    context="audit log config",
                )
                log_type = _nonempty_string(
                    raw_log_config.get("logType"),
                    context="audit log type",
                )
                if log_type not in _AUDIT_LOG_TYPES or log_type in log_types:
                    raise IamPolicyValidationError("IAM audit log type is invalid or duplicated")
                log_types.add(log_type)
                log_config: dict[str, Any] = {"logType": log_type}
                if "exemptedMembers" in raw_log_config:
                    log_config["exemptedMembers"] = _unique_nonempty_strings(
                        raw_log_config["exemptedMembers"],
                        context="audit exemptedMembers",
                        require_item=False,
                    )
                log_configs.append(log_config)
            config["auditLogConfigs"] = log_configs
        configs.append(config)
    return configs


def validate_iam_policy_v3(
    policy: object,
    *,
    require_etag: bool = False,
) -> dict[str, Any]:
    """Return a defensive copy of a strict Google IAM v3-compatible policy.

    Google may return version 1 (or omit the version) after a v3 read when the
    policy has no conditions. Conditional policies must already identify
    themselves as version 3. Callers set ``version`` to 3 before mutation.
    """

    if not isinstance(policy, dict):
        raise IamPolicyValidationError("IAM policy must be an object")
    _assert_exact_fields(policy, _POLICY_FIELDS, context="policy")

    version = policy.get("version")
    if version is not None and (
        isinstance(version, bool) or not isinstance(version, int) or version not in {0, 1, 3}
    ):
        raise IamPolicyValidationError("IAM policy version is invalid")

    etag = policy.get("etag")
    if require_etag and (not isinstance(etag, str) or not etag.strip()):
        raise IamPolicyEtagMissingError("IAM policy is missing a nonempty etag")
    if etag is not None and not isinstance(etag, str):
        raise IamPolicyValidationError("IAM policy etag must be a string")

    raw_bindings = policy.get("bindings", [])
    if not isinstance(raw_bindings, list):
        raise IamPolicyValidationError("IAM policy bindings must be a list")
    bindings: list[dict[str, Any]] = []
    has_condition = False
    for raw_binding in raw_bindings:
        if not isinstance(raw_binding, dict):
            raise IamPolicyValidationError("IAM policy binding must be an object")
        _assert_exact_fields(raw_binding, _BINDING_FIELDS, context="binding")
        binding: dict[str, Any] = {
            "role": _nonempty_string(raw_binding.get("role"), context="binding role"),
            "members": _unique_nonempty_strings(
                raw_binding.get("members"),
                context="binding members",
                require_item=True,
            ),
        }
        if "condition" in raw_binding:
            binding["condition"] = _validate_condition(raw_binding["condition"])
            has_condition = True
        bindings.append(binding)
    if has_condition and version != 3:
        raise IamPolicyValidationError("IAM policy with conditions must use version 3")

    validated: dict[str, Any] = {}
    if "version" in policy:
        validated["version"] = version
    if "etag" in policy:
        validated["etag"] = etag
    if "bindings" in policy:
        validated["bindings"] = bindings
    if "auditConfigs" in policy:
        validated["auditConfigs"] = _validate_audit_configs(policy["auditConfigs"])
    return validated


@dataclass
class _ParsedBinding:
    binding: dict[str, Any]
    key: str
    members: list[str]


def _parse_bindings(policy: dict[str, Any]) -> list[_ParsedBinding]:
    bindings = policy.get("bindings", [])
    parsed: list[_ParsedBinding] = []
    for raw in bindings:
        binding = deepcopy(raw)
        role = binding["role"]
        members = binding["members"]
        key = json.dumps(
            [role, binding.get("condition")],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        parsed.append(_ParsedBinding(binding=binding, key=key, members=list(members)))
    return parsed


def _member_groups(bindings: list[_ParsedBinding]) -> dict[str, set[str]]:
    groups: dict[str, set[str]] = {}
    for binding in bindings:
        groups.setdefault(binding.key, set()).update(binding.members)
    return groups


def revert_iam_policy_delta(
    *,
    before_policy: dict[str, Any],
    after_policy: dict[str, Any],
    current_policy: dict[str, Any],
) -> dict[str, Any]:
    """Reverse one run's binding-member delta against a freshly read policy.

    Role/condition/member changes made after Apply by another administrator are
    retained. Only members in ``after - before`` are removed and members in
    ``before - after`` are restored. Policy metadata and the concurrency token
    come from ``current_policy``.
    """

    validated_before = validate_iam_policy_v3(before_policy)
    validated_after = validate_iam_policy_v3(after_policy)
    validated_current = validate_iam_policy_v3(current_policy, require_etag=True)
    before_bindings = _parse_bindings(validated_before)
    after_bindings = _parse_bindings(validated_after)
    reverted = _parse_bindings(validated_current)
    before_groups = _member_groups(before_bindings)
    after_groups = _member_groups(after_bindings)

    for key in sorted(before_groups.keys() | after_groups.keys()):
        before_members = before_groups.get(key, set())
        after_members = after_groups.get(key, set())
        added = after_members - before_members
        removed = before_members - after_members
        if not added and not removed:
            continue

        target = next((entry for entry in reverted if entry.key == key), None)
        for entry in reverted:
            if entry.key == key:
                entry.members = [member for member in entry.members if member not in added]

        if removed:
            if target is None:
                template = next(
                    (entry for entry in (*before_bindings, *after_bindings) if entry.key == key),
                    None,
                )
                if template is None:
                    raise ValueError("IAM delta lacks a binding template")
                target = _ParsedBinding(
                    binding=deepcopy(template.binding),
                    key=key,
                    members=[],
                )
                reverted.append(target)
            target.members = sorted(set(target.members) | removed)

        reverted = [entry for entry in reverted if entry.key != key or entry.members]

    result = deepcopy(validated_current)
    result["bindings"] = [{**entry.binding, "members": entry.members} for entry in reverted]
    result["version"] = 3
    return validate_iam_policy_v3(result, require_etag=True)
