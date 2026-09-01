import json
import sys
from typing import Any, Dict, List

from google.auth.transport.requests import AuthorizedSession
from google.oauth2 import service_account

# /******* BEGIN: Customer to modify this section *******/
SERVICE_ACCOUNT_FILE = '.json'  # Path to the service account JSON file
CUSTOMER_ID = ''  # Your Google Workspace customer ID (e.g., 'C01234567')
ADMIN_USER_EMAIL = ''  # Google Admin Console Admin email (optional, for domain delegation)
ORG_UNIT_ID = ''  # The unique ID for the target Organizational Unit (OU)
REQUEST_TIMEOUT = 30  # Timeout for API requests in seconds

# List of bookmarks to add. This includes both individual links and folders with nested links
BOOKMARKS: List[Dict[str, Any]] = [
    {
        "link": {
            "name": "Test1",
            "url": "https://example.com/test1",
        }
    },
    {
        "link": {
            "name": "Test2",
            "url": "https://example.com/test2",
        }
    },
    {
        "folder": {
            "name": "TestFolder",
            "entries": [
                {
                    "link": {
                        "name": "Test3",
                        "url": "https://example.com/test3",
                    }
                }
            ],
        }
    },
]
# /******* END: Customer to modify this section *******/

SCOPES = ['https://www.googleapis.com/auth/chrome.management.policy']


def add_managed_bookmarks(
    session: AuthorizedSession,
    customer_id: str,
    org_unit_id: str,
    bookmarks: List[Dict[str, Any]],
) -> None:
    """Add managed bookmarks to a specified organizational unit.

    Args:
        session: AuthorizedSession for making Google API requests.
        customer_id: The customer ID in Google Workspace.
        org_unit_id: The unique ID for the target Organizational Unit.
        bookmarks: List of bookmarks to add, formatted according to Chrome policy specifications.
    """
    url = f"https://chromepolicy.googleapis.com/v1/customers/{customer_id}/policies/orgunits:batchModify"

    managed_bookmarks_payload = {
        "managedBookmarks": {
            "bookmarks": bookmarks
        }
    }

    bookmark_payload = {
        "policyTargetKey": {
            "targetResource": f"orgunits/{org_unit_id}"
        },
        "policyValue": {
            "policySchema": "chrome.users.ManagedBookmarksSetting",
            "value": managed_bookmarks_payload
        },
        "updateMask": "managedBookmarks"
    }
    payload = {"requests": [bookmark_payload]}

    response = session.post(
        url,
        data=json.dumps(payload),
        headers={'Content-Type': 'application/json'},
        timeout=REQUEST_TIMEOUT,
    )
    if response.status_code != 200:
        raise RuntimeError(f"Failed to add managed bookmarks ({response.status_code}): {response.text}")


def main() -> None:
    if not CUSTOMER_ID:
        print("Error: CUSTOMER_ID is not configured. Please set CUSTOMER_ID in the script.", file=sys.stderr)
        sys.exit(1)
    if not ORG_UNIT_ID:
        print("Error: ORG_UNIT_ID is not configured. Please set ORG_UNIT_ID in the script.", file=sys.stderr)
        sys.exit(1)

    # Load service account credentials
    if ADMIN_USER_EMAIL.strip():
        credentials = service_account.Credentials.from_service_account_file(
            SERVICE_ACCOUNT_FILE, scopes=SCOPES, subject=ADMIN_USER_EMAIL.strip()
        )
    else:
        credentials = service_account.Credentials.from_service_account_file(
            SERVICE_ACCOUNT_FILE, scopes=SCOPES
        )

    session = AuthorizedSession(credentials)

    print(f"Applying managed bookmarks policy to OU '{ORG_UNIT_ID}' for customer '{CUSTOMER_ID}'...")
    add_managed_bookmarks(session, CUSTOMER_ID, ORG_UNIT_ID, BOOKMARKS)
    print("Successfully applied managed bookmarks policy.")


if __name__ == '__main__':
    main()
