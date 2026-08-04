from __future__ import annotations

import os
from typing import Protocol

from google.auth.exceptions import DefaultCredentialsError, RefreshError

from sgstudio.domain.models import SetupOption
from sgstudio.providers.google_rest import GoogleAuthorizedTransport, JsonTransport


class SetupCatalogProvider(Protocol):
    def list_organizational_units(self, customer_id: str) -> list[SetupOption]: ...

    def list_groups(self, customer_id: str) -> list[SetupOption]: ...

    def list_access_levels(self, project_id: str) -> list[SetupOption]: ...


class GoogleSetupCatalogProvider:
    def __init__(self, transport: JsonTransport, access_policy_id: str) -> None:
        self._transport = transport
        self._access_policy_id = access_policy_id

    def list_organizational_units(self, customer_id: str) -> list[SetupOption]:
        _, payload = self._transport.request_json(
            "GET",
            (f"https://admin.googleapis.com/admin/directory/v1/customer/{customer_id}/orgunits"),
            params={"type": "all_including_parent"},
        )
        options: list[SetupOption] = []
        for item in payload.get("organizationUnits", []):
            if not isinstance(item, dict):
                continue
            raw_id = item.get("orgUnitId")
            path = item.get("orgUnitPath")
            if not isinstance(raw_id, str) or not isinstance(path, str):
                continue
            options.append(
                SetupOption(
                    value=raw_id.removeprefix("id:"),
                    label=path,
                    description=str(item.get("name") or ""),
                )
            )
        return sorted(options, key=lambda option: option.label.casefold())

    def list_groups(self, customer_id: str) -> list[SetupOption]:
        options: list[SetupOption] = []
        page_token = ""
        while len(options) < 2000:
            params: dict[str, str | int] = {
                "customer": customer_id,
                "maxResults": 200,
                "orderBy": "email",
            }
            if page_token:
                params["pageToken"] = page_token
            _, payload = self._transport.request_json(
                "GET",
                "https://admin.googleapis.com/admin/directory/v1/groups",
                params=params,
            )
            for item in payload.get("groups", []):
                if not isinstance(item, dict):
                    continue
                email = item.get("email")
                if not isinstance(email, str) or not email:
                    continue
                options.append(
                    SetupOption(
                        value=email.lower(),
                        label=str(item.get("name") or email),
                        description=email.lower(),
                    )
                )
            next_token = payload.get("nextPageToken")
            if not isinstance(next_token, str) or not next_token:
                break
            page_token = next_token
        return options

    def list_access_levels(self, project_id: str) -> list[SetupOption]:
        organization = self._project_organization(project_id)
        policy_name = f"accessPolicies/{self._access_policy_id}"
        _, policy = self._transport.request_json(
            "GET",
            f"https://accesscontextmanager.googleapis.com/v1/{policy_name}",
        )
        if policy.get("parent") != organization:
            raise ValueError("The access policy does not belong to the project organization")

        options: list[SetupOption] = []
        levels = self._list_collection(
            (f"https://accesscontextmanager.googleapis.com/v1/{policy_name}/accessLevels"),
            collection="accessLevels",
            params={"pageSize": 100},
        )
        for level in levels:
            name = level.get("name")
            title = level.get("title")
            if not isinstance(name, str) or not isinstance(title, str):
                continue
            options.append(
                SetupOption(
                    value=name,
                    label=title,
                    description=str(level.get("description") or ""),
                )
            )
        return sorted(options, key=lambda option: option.label.casefold())

    def _project_organization(self, project_id: str) -> str:
        _, resource = self._transport.request_json(
            "GET",
            f"https://cloudresourcemanager.googleapis.com/v3/projects/{project_id}",
        )
        parent = resource.get("parent")
        for _ in range(10):
            if not isinstance(parent, str):
                break
            if parent.startswith("organizations/"):
                return parent
            if not parent.startswith("folders/"):
                break
            _, folder = self._transport.request_json(
                "GET",
                f"https://cloudresourcemanager.googleapis.com/v3/{parent}",
            )
            parent = folder.get("parent")
        raise ValueError("The Google Cloud project is not attached to an organization")

    def _list_collection(
        self,
        url: str,
        *,
        collection: str,
        params: dict[str, str | int],
    ) -> list[dict[str, object]]:
        items: list[dict[str, object]] = []
        page_token = ""
        while len(items) < 2000:
            request_params = dict(params)
            if page_token:
                request_params["pageToken"] = page_token
            _, payload = self._transport.request_json("GET", url, params=request_params)
            items.extend(item for item in payload.get(collection, []) if isinstance(item, dict))
            next_token = payload.get("nextPageToken")
            if not isinstance(next_token, str) or not next_token:
                break
            page_token = next_token
        return items


def create_google_setup_catalog_provider() -> GoogleSetupCatalogProvider:
    access_policy_id = os.getenv("SGSTUDIO_ACCESS_POLICY_ID", "").strip()
    if not access_policy_id.isdigit():
        raise RuntimeError(
            "SGSTUDIO_ACCESS_POLICY_ID must be configured with a numeric policy ID."
        )
    try:
        transport = GoogleAuthorizedTransport.from_adc()
    except (DefaultCredentialsError, RefreshError) as error:
        raise RuntimeError(
            "Application Default Credentials are unavailable for setup option lookup."
        ) from error
    return GoogleSetupCatalogProvider(transport, access_policy_id)
