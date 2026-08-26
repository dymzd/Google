import pytest

from sgstudio.domain.iam_policy import (
    IamPolicyEtagMissingError,
    revert_iam_policy_delta,
    validate_iam_policy_v3,
)


@pytest.mark.parametrize(
    "malformed",
    [
        [],
        {"version": 3, "etag": "fresh", "bindings": [], "unexpected": True},
        {
            "version": 3,
            "etag": "fresh",
            "bindings": [
                {
                    "role": "roles/viewer",
                    "members": ["user:owner@example.com"],
                    "unexpected": True,
                }
            ],
        },
        {
            "version": 3,
            "etag": "fresh",
            "bindings": [
                {
                    "role": "roles/viewer",
                    "members": [
                        "user:owner@example.com",
                        "user:owner@example.com",
                    ],
                }
            ],
        },
        {
            "version": 3,
            "etag": "fresh",
            "bindings": [
                {
                    "role": "roles/viewer",
                    "members": [""],
                }
            ],
        },
        {
            "version": 3,
            "etag": "fresh",
            "bindings": [
                {
                    "role": "roles/viewer",
                    "members": ["user:owner@example.com"],
                    "condition": {"expression": "true"},
                }
            ],
        },
        {
            "version": 3,
            "etag": "fresh",
            "bindings": [
                {
                    "role": "roles/viewer",
                    "members": ["user:owner@example.com"],
                    "condition": {
                        "title": "Temporary",
                        "expression": "true",
                        "unexpected": "unsafe",
                    },
                }
            ],
        },
    ],
    ids=[
        "non-object",
        "policy-unknown-field",
        "binding-unknown-field",
        "duplicate-member",
        "empty-member",
        "condition-missing-title",
        "condition-unknown-field",
    ],
)
def test_v3_policy_validator_rejects_malformed_policy(malformed: object) -> None:
    with pytest.raises(ValueError):
        validate_iam_policy_v3(malformed, require_etag=True)


@pytest.mark.parametrize("etag", [None, ""])
def test_v3_policy_validator_requires_nonempty_send_etag(etag: str | None) -> None:
    policy: dict[str, object] = {"version": 1, "bindings": []}
    if etag is not None:
        policy["etag"] = etag

    with pytest.raises(IamPolicyEtagMissingError):
        validate_iam_policy_v3(policy, require_etag=True)


def test_v3_policy_validator_preserves_documented_condition_location() -> None:
    policy = {
        "version": 3,
        "etag": "fresh",
        "bindings": [
            {
                "role": "roles/viewer",
                "members": ["user:owner@example.com"],
                "condition": {
                    "title": "Source guard",
                    "expression": "resource.name.startsWith('projects/example')",
                    "description": "Limit this binding to one source tree.",
                    "location": "bootstrap-policy.json:12",
                },
            }
        ],
    }

    validated = validate_iam_policy_v3(policy, require_etag=True)

    assert validated == policy
    assert validated is not policy


def test_three_way_rollback_preserves_concurrent_bindings_members_and_conditions() -> None:
    old_condition = {
        "title": "Managed",
        "expression": "'old' in request.auth.access_levels",
    }
    new_condition = {
        "title": "Managed",
        "expression": "'new' in request.auth.access_levels",
    }
    before = {
        "version": 3,
        "etag": "before",
        "bindings": [
            {
                "role": "roles/beyondcorp.sgApplicationUser",
                "members": ["group:run@example.com", "group:shared@example.com"],
                "condition": old_condition,
            },
            {"role": "roles/viewer", "members": ["user:owner@example.com"]},
        ],
    }
    after = {
        "version": 3,
        "etag": "after",
        "bindings": [
            {
                "role": "roles/beyondcorp.sgApplicationUser",
                "members": ["group:shared@example.com"],
                "condition": old_condition,
            },
            {
                "role": "roles/beyondcorp.sgApplicationUser",
                "members": ["group:replacement@example.com"],
                "condition": new_condition,
            },
            {"role": "roles/viewer", "members": ["user:owner@example.com"]},
        ],
    }
    current = {
        "version": 3,
        "etag": "fresh",
        "auditConfigs": [{"service": "allServices"}],
        "bindings": [
            {
                "role": "roles/beyondcorp.sgApplicationUser",
                "members": [
                    "group:shared@example.com",
                    "group:concurrent-old@example.com",
                ],
                "condition": old_condition,
            },
            {
                "role": "roles/beyondcorp.sgApplicationUser",
                "members": [
                    "group:replacement@example.com",
                    "group:concurrent-new@example.com",
                ],
                "condition": new_condition,
            },
            {
                "role": "roles/beyondcorp.sgApplicationUser",
                "members": ["group:break-glass@example.com"],
                "condition": {"title": "Break glass", "expression": "false"},
            },
            {
                "role": "roles/viewer",
                "members": ["user:owner@example.com", "user:concurrent@example.com"],
            },
            {"role": "roles/editor", "members": ["user:new-admin@example.com"]},
        ],
    }

    reverted = revert_iam_policy_delta(
        before_policy=before,
        after_policy=after,
        current_policy=current,
    )

    by_condition = {
        binding.get("condition", {}).get("expression"): binding
        for binding in reverted["bindings"]
        if binding["role"] == "roles/beyondcorp.sgApplicationUser"
    }
    assert by_condition[old_condition["expression"]]["members"] == [
        "group:concurrent-old@example.com",
        "group:run@example.com",
        "group:shared@example.com",
    ]
    assert by_condition[new_condition["expression"]]["members"] == [
        "group:concurrent-new@example.com"
    ]
    assert by_condition["false"]["members"] == ["group:break-glass@example.com"]
    assert any(binding["role"] == "roles/editor" for binding in reverted["bindings"])
    assert reverted["etag"] == "fresh"
    assert reverted["auditConfigs"] == [{"service": "allServices"}]


def test_three_way_rollback_rejects_malformed_policy() -> None:
    with pytest.raises(ValueError, match="binding members"):
        revert_iam_policy_delta(
            before_policy={"bindings": [{"role": "roles/test", "members": "bad"}]},
            after_policy={"bindings": []},
            current_policy={"bindings": []},
        )
