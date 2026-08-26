from __future__ import annotations

import os
import re
from typing import Protocol

from google.auth.exceptions import DefaultCredentialsError, RefreshError

from sgstudio.domain.models import SetupOption
from sgstudio.providers.google_rest import GoogleAuthorizedTransport, JsonTransport

_MAX_CATALOG_ITEMS = 2000
_MAX_CATALOG_PAGES = 20


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
        raw_units = payload.get("organizationUnits", [])
        if not isinstance(raw_units, list):
            raise ValueError("Google returned an invalid organizational-unit catalogue")
        for item in raw_units:
            if not isinstance(item, dict):
                raise ValueError("Google returned a malformed organizational-unit item")
            raw_id = item.get("orgUnitId")
            path = item.get("orgUnitPath")
            if not isinstance(raw_id, str) or not raw_id or not isinstance(path, str) or not path:
                raise ValueError("Google returned an invalid organizational-unit identity")
            # Root-scoped Chrome policies affect the entire Workspace domain.
            if path == "/":
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
        seen_page_tokens: set[str] = set()
        complete = False
        for _ in range(_MAX_CATALOG_PAGES):
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
            raw_groups = payload.get("groups", [])
            if not isinstance(raw_groups, list):
                raise ValueError("Google returned an invalid Directory group catalogue")
            for item in raw_groups:
                if not isinstance(item, dict):
                    raise ValueError("Google returned a malformed Directory group item")
                email = item.get("email")
                if not isinstance(email, str) or not email:
                    raise ValueError("Google returned an invalid Directory group identity")
                options.append(
                    SetupOption(
                        value=email.lower(),
                        label=str(item.get("name") or email),
                        description=email.lower(),
                    )
                )
            if len(options) > _MAX_CATALOG_ITEMS:
                raise ValueError("Google Directory group catalogue exceeded the safety limit")
            next_token = payload.get("nextPageToken")
            if "nextPageToken" not in payload or next_token == "":
                complete = True
                break
            if not isinstance(next_token, str) or next_token in seen_page_tokens:
                raise ValueError("Google Directory returned an invalid group page token")
            if len(options) >= _MAX_CATALOG_ITEMS:
                raise ValueError("Google Directory group catalogue exceeded the safety limit")
            seen_page_tokens.add(next_token)
            page_token = next_token
        if not complete:
            raise ValueError("Google Directory group catalogue pagination did not complete")
        return options

    def list_access_levels(self, project_id: str) -> list[SetupOption]:
        organization, applicable_scopes = self._project_policy_context(project_id)
        policy_name = f"accessPolicies/{self._access_policy_id}"
        _, policy = self._transport.request_json(
            "GET",
            f"https://accesscontextmanager.googleapis.com/v1/{policy_name}",
        )
        if policy.get("parent") != organization:
            raise ValueError("The access policy does not belong to the project organization")
        scopes = policy.get("scopes", [])
        if (
            not isinstance(scopes, list)
            or any(
                not isinstance(scope, str)
                or re.fullmatch(r"(?:projects|folders)/\d+", scope) is None
                for scope in scopes
            )
        ):
            raise ValueError("Google returned malformed Access Context Manager policy scopes")
        if scopes and not any(scope in applicable_scopes for scope in scopes):
            raise ValueError(
                "The access policy is not scoped to this project or an ancestor folder"
            )

        options: list[SetupOption] = []
        levels = self._list_collection(
            (f"https://accesscontextmanager.googleapis.com/v1/{policy_name}/accessLevels"),
            collection="accessLevels",
            params={"pageSize": 100},
        )
        for level in levels:
            name = level.get("name")
            title = level.get("title")
            if not isinstance(name, str) or not name or not isinstance(title, str) or not title:
                raise ValueError("Google returned an invalid Access Context Manager level")
            options.append(
                SetupOption(
                    value=name,
                    label=title,
                    description=str(level.get("description") or ""),
                )
            )
        return sorted(options, key=lambda option: option.label.casefold())

    def _project_policy_context(self, project_id: str) -> tuple[str, set[str]]:
        _, resource = self._transport.request_json(
            "GET",
            f"https://cloudresourcemanager.googleapis.com/v3/projects/{project_id}",
        )
        project_name = resource.get("name")
        if not isinstance(project_name, str) or re.fullmatch(
            r"projects/\d+", project_name
        ) is None:
            raise ValueError("Google Cloud did not return the project's numeric resource name")
        applicable_scopes = {project_name}
        parent = resource.get("parent")
        seen_folders: set[str] = set()
        folder_count = 0
        while isinstance(parent, str):
            if re.fullmatch(r"organizations/\d+", parent) is not None:
                return parent, applicable_scopes
            if re.fullmatch(r"folders/\d+", parent) is None:
                break
            # Resource Manager permits ten nested folders. Inspect the parent
            # returned by the tenth folder before applying the limit so a
            # legal project -> folder x10 -> organization chain is accepted.
            if folder_count >= 10 or parent in seen_folders:
                break
            seen_folders.add(parent)
            folder_count += 1
            applicable_scopes.add(parent)
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
        seen_page_tokens: set[str] = set()
        complete = False
        for _ in range(_MAX_CATALOG_PAGES):
            request_params = dict(params)
            if page_token:
                request_params["pageToken"] = page_token
            _, payload = self._transport.request_json("GET", url, params=request_params)
            page = payload.get(collection, [])
            if not isinstance(page, list):
                raise ValueError(f"Google returned an invalid {collection} catalogue")
            if any(not isinstance(item, dict) for item in page):
                raise ValueError(f"Google returned a malformed {collection} item")
            items.extend(page)
            if len(items) > _MAX_CATALOG_ITEMS:
                raise ValueError(f"Google {collection} catalogue exceeded the safety limit")
            next_token = payload.get("nextPageToken")
            if "nextPageToken" not in payload or next_token == "":
                complete = True
                break
            if not isinstance(next_token, str) or next_token in seen_page_tokens:
                raise ValueError(f"Google returned an invalid {collection} page token")
            if len(items) >= _MAX_CATALOG_ITEMS:
                raise ValueError(f"Google {collection} catalogue exceeded the safety limit")
            seen_page_tokens.add(next_token)
            page_token = next_token
        if not complete:
            raise ValueError(f"Google {collection} catalogue pagination did not complete")
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
