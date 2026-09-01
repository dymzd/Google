import json
import sys
from typing import Any, Dict, List, Optional, Tuple

import requests
from google.auth.transport.requests import AuthorizedSession
from google.oauth2 import service_account

# /******* BEGIN: Customer to modify this section *******/
SERVICE_ACCOUNT_FILE = '.json'  # Path to the service account JSON file
# Add the customer id here. You can find the customer Id by navigating to:
# Google Admin Console > Account > Account Settings
CUSTOMER_ID = ''  # Your Google Workspace customer ID (e.g., 'C01234567')
ADMIN_USER_EMAIL = ''  # Admin email for domain-wide delegation (leave empty if not using delegation)
TARGET_OU_ID = ''  # The unique ID for the target Organizational Unit (OU)
CRX_RISK_THRESHOLD = 550  # Threshold for Crxcavator risk score (higher = riskier)
SPIN_RISK_THRESHOLD = 70  # Threshold for Spin.ai risk score
REQUEST_TIMEOUT = 30  # Timeout for API requests in seconds
# /******* END: Customer to modify this section *******/

SCOPES = [
    'https://www.googleapis.com/auth/admin.directory.device.chromeos',
    'https://www.googleapis.com/auth/chrome.management.reports.readonly',
    'https://www.googleapis.com/auth/chrome.management.appdetails.readonly',
    'https://www.googleapis.com/auth/chrome.management.policy',
    'https://www.googleapis.com/auth/admin.directory.orgunit.readonly',
]


def list_extensions(session: AuthorizedSession, customer_id: str) -> List[Dict[str, Any]]:
    """List all Chrome extensions for a given customer ID.

    Args:
        session: AuthorizedSession for making Google API requests.
        customer_id: The customer ID in Google Workspace.

    Returns:
        List of dictionaries containing details of each extension.
    """
    extensions: List[Dict[str, Any]] = []
    page_token: Optional[str] = None

    while True:
        params: Dict[str, Any] = {}
        if page_token:
            params['pageToken'] = page_token

        response = session.get(
            f'https://chromemanagement.googleapis.com/v1/customers/{customer_id}/reports:countInstalledApps',
            params=params,
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code != 200:
            raise RuntimeError(f"Failed to list extensions ({response.status_code}): {response.text}")

        data = response.json()

        for app in data.get('installedApps', []):
            if app.get('appType') == 'EXTENSION':
                extension_id = app.get('appId')
                if extension_id:
                    try:
                        extension_details = get_extension_details(session, customer_id, extension_id)
                        extensions.append(extension_details)
                    except Exception as e:
                        print(f"Warning: Could not fetch details for extension {extension_id}: {e}", file=sys.stderr)
                        extensions.append({'id': extension_id, 'version': None})

        page_token = data.get('nextPageToken')
        if not page_token:
            break

    return extensions


def get_extension_details(session: AuthorizedSession, customer_id: str, extension_id: str) -> Dict[str, Any]:
    """Fetch detailed information for a specific Chrome extension.

    Args:
        session: AuthorizedSession for making Google API requests.
        customer_id: The customer ID in Google Workspace.
        extension_id: The 32-character ID of the Chrome extension.

    Returns:
        Dictionary containing the extension ID and its version (revisionId).
    """
    response = session.get(
        f'https://chromemanagement.googleapis.com/v1/customers/{customer_id}/apps/chrome/{extension_id}',
        timeout=REQUEST_TIMEOUT,
    )
    if response.status_code != 200:
        raise RuntimeError(f"Failed to get details for extension {extension_id}: {response.text}")

    extension_data = response.json()
    return {
        'id': extension_id,
        'version': extension_data.get('revisionId'),
    }


def block_extension(session: AuthorizedSession, customer_id: str, org_unit_id: str, extension_id: str) -> None:
    """Block a specific Chrome extension in a given Organizational Unit.

    Args:
        session: AuthorizedSession for making Google API requests.
        customer_id: The customer ID in Google Workspace.
        org_unit_id: The unique ID for the target Organizational Unit.
        extension_id: The ID of the Chrome extension to block.
    """
    url = f"https://chromepolicy.googleapis.com/v1/customers/{customer_id}/policies/orgunits:batchModify"
    payload = {
        "requests": [{
            "policyTargetKey": {
                "targetResource": f"orgunits/{org_unit_id}",
                "additionalTargetKeys": {"app_id": f"chrome:{extension_id}"}
            },
            "policyValue": {
                "policySchema": "chrome.users.apps.InstallType",
                "value": {"appInstallType": "BLOCKED"}
            },
            "updateMask": "appInstallType"
        }]
    }
    response = session.post(
        url,
        data=json.dumps(payload),
        headers={'Content-Type': 'application/json'},
        timeout=REQUEST_TIMEOUT,
    )
    if response.status_code != 200:
        raise RuntimeError(f"Failed to block extension {extension_id} ({response.status_code}): {response.text}")


def get_risk_score(extension_id: str, version: Optional[str]) -> Tuple[Optional[float], Optional[float]]:
    """Fetch the risk scores from Crxcavator and Spin.ai for a specific Chrome extension.

    Args:
        extension_id: The ID of the Chrome extension.
        version: Optional version string of the Chrome extension.

    Returns:
        Tuple of (crxcavator_score, spin_score). Values are None if unavailable.
    """
    crxcavator_score: Optional[float] = None
    spin_score: Optional[float] = None

    # Fetch Crxcavator risk score
    try:
        url = (
            f"https://api.crxcavator.io/v1/report/{extension_id}/{version}?platform=Chrome"
            if version
            else f"https://api.crxcavator.io/v1/report/{extension_id}?platform=Chrome"
        )
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            crx_data = resp.json()
            if isinstance(crx_data, list) and len(crx_data) > 0:
                crxcavator_score = crx_data[0].get('data', {}).get('risk', {}).get('total')
            elif isinstance(crx_data, dict):
                crxcavator_score = crx_data.get('data', {}).get('risk', {}).get('total')
    except Exception as e:
        print(f"Notice: Crxcavator score lookup for {extension_id} returned: {e}", file=sys.stderr)

    # Fetch Spin.ai risk score
    try:
        spin_url = f"https://apg-1.spin.ai/api/v1/assessment/platform/chrome/{extension_id}"
        if version:
            spin_url += f"/version/{version}"
        resp = requests.get(spin_url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            spin_data = resp.json()
            if isinstance(spin_data, dict):
                spin_score = spin_data.get('trustRate')
    except Exception as e:
        print(f"Notice: Spin.ai score lookup for {extension_id} returned: {e}", file=sys.stderr)

    return crxcavator_score, spin_score


def main() -> None:
    if not CUSTOMER_ID:
        print("Error: CUSTOMER_ID is not configured. Please set CUSTOMER_ID in the script.", file=sys.stderr)
        sys.exit(1)
    if not TARGET_OU_ID:
        print("Error: TARGET_OU_ID is not configured. Please set TARGET_OU_ID in the script.", file=sys.stderr)
        sys.exit(1)

    # Load service account credentials with optional domain-wide delegation
    if ADMIN_USER_EMAIL.strip():
        credentials = service_account.Credentials.from_service_account_file(
            SERVICE_ACCOUNT_FILE, scopes=SCOPES, subject=ADMIN_USER_EMAIL.strip()
        )
    else:
        credentials = service_account.Credentials.from_service_account_file(
            SERVICE_ACCOUNT_FILE, scopes=SCOPES
        )

    session = AuthorizedSession(credentials)

    print(f"Retrieving Chrome extensions for Customer ID: {CUSTOMER_ID}...")
    extensions = list_extensions(session, CUSTOMER_ID)
    print(f"Found {len(extensions)} extensions. Evaluating risk scores...")

    for extension in extensions:
        ext_id = extension['id']
        ext_version = extension.get('version')
        crxcavator_score, spin_score = get_risk_score(ext_id, ext_version)

        if crxcavator_score is not None and spin_score is not None:
            if crxcavator_score > CRX_RISK_THRESHOLD and spin_score > SPIN_RISK_THRESHOLD:
                print(f"[BLOCK] Extension {ext_id} (Crx: {crxcavator_score}, Spin: {spin_score}) -> Blocking in OU {TARGET_OU_ID}")
                try:
                    block_extension(session, CUSTOMER_ID, TARGET_OU_ID, ext_id)
                    print(f"        Successfully applied block policy.")
                except Exception as e:
                    print(f"        Failed to block: {e}", file=sys.stderr)
            else:
                print(f"[SAFE]  Extension {ext_id} (Crx: {crxcavator_score}, Spin: {spin_score}) is within allowed thresholds.")
        else:
            print(f"[WARN]  Extension {ext_id} (Crx: {crxcavator_score}, Spin: {spin_score}) requires manual review.")


if __name__ == '__main__':
    main()
