from typing import Any

from sgstudio.providers.catalog import GoogleSetupCatalogProvider


class FakeCatalogTransport:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

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
            return 200, {"parent": "organizations/123456789"}
        if url.endswith("/accessPolicies/123"):
            return 200, {
                "name": "accessPolicies/123",
                "title": "Organization",
                "parent": "organizations/123456789",
            }
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


def test_catalog_lists_ou_ids_without_the_directory_prefix() -> None:
    provider = GoogleSetupCatalogProvider(FakeCatalogTransport(), "123")

    options = provider.list_organizational_units("C012abcde")

    assert [(option.value, option.label) for option in options] == [
        ("03-root", "/"),
        ("03-test-ou", "/PoC/Secure Gateway"),
    ]


def test_catalog_lists_groups_as_email_values() -> None:
    provider = GoogleSetupCatalogProvider(FakeCatalogTransport(), "123")

    options = provider.list_groups("C012abcde")

    assert options[0].value == "secure-access@example.com"
    assert options[0].label == "Secure Access"


def test_catalog_resolves_project_organization_and_lists_access_levels() -> None:
    transport = FakeCatalogTransport()
    provider = GoogleSetupCatalogProvider(transport, "123")

    options = provider.list_access_levels("enterprise-secgw-01")

    assert options[0].value == "accessPolicies/123/accessLevels/managed_chrome"
    assert options[0].label == "Managed Chrome"
    assert any(call["url"].endswith("/accessPolicies/123") for call in transport.calls)
