from typing import Any

import pytest

from sgstudio.providers.catalog import GoogleSetupCatalogProvider


class FakeCatalogTransport:
    def __init__(
        self,
        *,
        project_parent: str = "organizations/123456789",
        policy_scopes: list[str] | None = None,
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self.project_parent = project_parent
        self.policy_scopes = policy_scopes

    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]:
        del json_body, accepted_statuses
        self.calls.append({"method": method, "url": url, "params": params})
        if url.endswith("/orgunits"):
            return 200, {
                "organizationUnits": [
                    {
                        "orgUnitId": "id:03-test-ou",
                        "orgUnitPath": "/PoC/Secure Gateway",
                        "name": "Secure Gateway",
                    },
                    {
                        "orgUnitId": "id:03-root",
                        "orgUnitPath": "/",
                        "name": "Root",
                    },
                ]
            }
        if url.endswith("/groups"):
            return 200, {
                "groups": [
                    {
                        "email": "secure-access@example.com",
                        "name": "Secure Access",
                    }
                ]
            }
        if url.endswith("/projects/enterprise-secgw-01"):
            return 200, {
                "name": "projects/987654321",
                "parent": self.project_parent,
            }
        if url.endswith("/folders/456"):
            return 200, {"name": "folders/456", "parent": "folders/123"}
        if url.endswith("/folders/123"):
            return 200, {"name": "folders/123", "parent": "organizations/123456789"}
        if url.endswith("/accessPolicies/123"):
            policy = {
                "name": "accessPolicies/123",
                "title": "Organization",
                "parent": "organizations/123456789",
            }
            if self.policy_scopes is not None:
                policy["scopes"] = self.policy_scopes
            return 200, policy
        if url.endswith("/accessPolicies/123/accessLevels"):
            return 200, {
                "accessLevels": [
                    {
                        "name": "accessPolicies/123/accessLevels/managed_chrome",
                        "title": "Managed Chrome",
                        "description": "Managed browser or profile",
                    }
                ]
            }
        raise AssertionError(f"Unexpected catalog request: {method} {url}")


class HierarchyCatalogTransport(FakeCatalogTransport):
    def __init__(self, depth: int, *, cycle: bool = False) -> None:
        super().__init__(policy_scopes=["folders/1"])
        self.depth = depth
        self.cycle = cycle

    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict[str, Any]]:
        if url.endswith("/projects/enterprise-secgw-01"):
            self.calls.append({"method": method, "url": url, "params": params})
            return 200, {
                "name": "projects/987654321",
                "parent": f"folders/{self.depth}",
            }
        marker = "/folders/"
        if marker in url and url.rsplit(marker, 1)[1].isdigit():
            self.calls.append({"method": method, "url": url, "params": params})
            folder_id = int(url.rsplit(marker, 1)[1])
            if self.cycle and folder_id == self.depth - 1:
                parent = f"folders/{self.depth}"
            elif folder_id == 1:
                parent = "organizations/123456789"
            else:
                parent = f"folders/{folder_id - 1}"
            return 200, {"name": f"folders/{folder_id}", "parent": parent}
        return super().request_json(
            method,
            url,
            params=params,
            json_body=json_body,
            accepted_statuses=accepted_statuses,
        )


def test_catalog_lists_ou_ids_without_the_directory_prefix() -> None:
    provider = GoogleSetupCatalogProvider(FakeCatalogTransport(), "123")

    options = provider.list_organizational_units("C012abcde")

    assert [(option.value, option.label) for option in options] == [
        ("03-test-ou", "/PoC/Secure Gateway"),
    ]


def test_catalog_lists_groups_as_email_values() -> None:
    provider = GoogleSetupCatalogProvider(FakeCatalogTransport(), "123")

    options = provider.list_groups("C012abcde")

    assert options[0].value == "secure-access@example.com"
    assert options[0].label == "Secure Access"


def test_catalog_rejects_repeated_group_page_token_without_returning_partial_results() -> None:
    class RepeatingGroupTransport(FakeCatalogTransport):
        def request_json(
            self,
            method: str,
            url: str,
            *,
            params: dict[str, str | int] | None = None,
            json_body: dict[str, Any] | None = None,
            accepted_statuses: tuple[int, ...] = (200,),
        ) -> tuple[int, dict[str, Any]]:
            if url.endswith("/groups"):
                self.calls.append({"method": method, "url": url, "params": params})
                return 200, {
                    "groups": [{"email": "partial@example.com", "name": "Partial"}],
                    "nextPageToken": "repeated",
                }
            return super().request_json(
                method,
                url,
                params=params,
                json_body=json_body,
                accepted_statuses=accepted_statuses,
            )

    provider = GoogleSetupCatalogProvider(RepeatingGroupTransport(), "123")

    try:
        provider.list_groups("C012abcde")
    except ValueError as error:
        assert "page token" in str(error)
    else:
        raise AssertionError("a repeated group page token must fail closed")


def test_catalog_resolves_project_organization_and_lists_access_levels() -> None:
    transport = FakeCatalogTransport()
    provider = GoogleSetupCatalogProvider(transport, "123")

    options = provider.list_access_levels("enterprise-secgw-01")

    assert options[0].value == "accessPolicies/123/accessLevels/managed_chrome"
    assert options[0].label == "Managed Chrome"
    assert any(call["url"].endswith("/accessPolicies/123") for call in transport.calls)


def test_catalog_rejects_repeated_access_level_page_token() -> None:
    class RepeatingAccessLevelTransport(FakeCatalogTransport):
        def request_json(
            self,
            method: str,
            url: str,
            *,
            params: dict[str, str | int] | None = None,
            json_body: dict[str, Any] | None = None,
            accepted_statuses: tuple[int, ...] = (200,),
        ) -> tuple[int, dict[str, Any]]:
            if url.endswith("/accessPolicies/123/accessLevels"):
                self.calls.append({"method": method, "url": url, "params": params})
                return 200, {"accessLevels": [], "nextPageToken": "repeated"}
            return super().request_json(
                method,
                url,
                params=params,
                json_body=json_body,
                accepted_statuses=accepted_statuses,
            )

    provider = GoogleSetupCatalogProvider(RepeatingAccessLevelTransport(), "123")

    try:
        provider.list_access_levels("enterprise-secgw-01")
    except ValueError as error:
        assert "page token" in str(error)
    else:
        raise AssertionError("a repeated access-level page token must fail closed")


def test_catalog_accepts_project_and_ancestor_folder_scoped_policies() -> None:
    for scope in ["projects/987654321", "folders/456", "folders/123"]:
        provider = GoogleSetupCatalogProvider(
            FakeCatalogTransport(project_parent="folders/456", policy_scopes=[scope]),
            "123",
        )

        assert provider.list_access_levels("enterprise-secgw-01")


def test_catalog_accepts_the_resource_manager_ten_folder_boundary() -> None:
    transport = HierarchyCatalogTransport(10)
    provider = GoogleSetupCatalogProvider(transport, "123")

    assert provider.list_access_levels("enterprise-secgw-01")
    assert sum("/folders/" in call["url"] for call in transport.calls) == 10
    assert any("/accessPolicies/123" in call["url"] for call in transport.calls)


@pytest.mark.parametrize(
    ("depth", "cycle"),
    [(11, False), (3, True)],
    ids=["eleven-folders", "cycle"],
)
def test_catalog_rejects_invalid_project_hierarchies_before_policy_read(
    depth: int,
    cycle: bool,
) -> None:
    transport = HierarchyCatalogTransport(depth, cycle=cycle)
    provider = GoogleSetupCatalogProvider(transport, "123")

    with pytest.raises(ValueError, match="not attached to an organization"):
        provider.list_access_levels("enterprise-secgw-01")

    assert all("/accessPolicies/" not in call["url"] for call in transport.calls)


def test_catalog_rejects_sibling_scoped_policy() -> None:
    provider = GoogleSetupCatalogProvider(
        FakeCatalogTransport(project_parent="folders/456", policy_scopes=["folders/999"]),
        "123",
    )

    try:
        provider.list_access_levels("enterprise-secgw-01")
    except ValueError as error:
        assert "not scoped" in str(error)
    else:
        raise AssertionError("sibling-scoped policy must be rejected")
