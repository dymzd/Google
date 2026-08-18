import json
import sys
from typing import List, Optional

import pandas as pd
from google.auth.transport.requests import AuthorizedSession
from google.oauth2.service_account import Credentials

# /******* BEGIN: Customer to modify this section *******/
# Path to your Google Cloud service account key JSON file
SERVICE_ACCOUNT_KEY_PATH = ""
# Your Google Workspace customer ID (e.g., 'C01234567' or 'my_customer')
CUSTOMER_ID = ""
# The destination OU path (e.g., 'North America/Austin/AUS Managed User' or '/')
DESTINATION_ORG_UNIT_PATH = ""
# Path to the CSV file containing device IDs exported from Google Admin Console
DEVICE_CSV_PATH = ""
# Admin user email for domain-wide delegation (optional)
ADMIN_USER_EMAIL = ""
# Number of devices to move per API request (max recommended: 100)
BATCH_SIZE = 50
# Request timeout in seconds
REQUEST_TIMEOUT = 30
# /******* END: Customer to modify this section *******/

SCOPES = ['https://www.googleapis.com/auth/admin.directory.device.chromebrowsers']


def create_authorized_session(
    service_account_path: str,
    admin_email: Optional[str] = None,
) -> AuthorizedSession:
    """Load credentials and create an AuthorizedSession."""
    with open(service_account_path, "r", encoding="utf-8") as f:
        service_account_info = json.load(f)

    credentials = Credentials.from_service_account_info(
        service_account_info,
        scopes=SCOPES,
    )
    if admin_email and admin_email.strip():
        credentials = credentials.with_subject(admin_email.strip())

    return AuthorizedSession(credentials)


def move_chrome_browsers(
    session: AuthorizedSession,
    customer_id: str,
    destination_ou_path: str,
    device_ids: List[str],
) -> int:
    """Move Chrome browser devices to the destination OU in batches.

    Args:
        session: AuthorizedSession for making Google API requests.
        customer_id: Google Workspace customer ID.
        destination_ou_path: Target Organizational Unit path.
        device_ids: List of device IDs to move.

    Returns:
        Total number of devices successfully processed.
    """
    url = f"https://www.googleapis.com/admin/directory/v1.1beta1/customer/{customer_id}/devices/chromebrowsers/moveChromeBrowsersToOu"
    headers = {'Content-Type': 'application/json'}
    total_moved = 0

    for i in range(0, len(device_ids), BATCH_SIZE):
        batch = device_ids[i:i + BATCH_SIZE]
        payload = json.dumps({
            "org_unit_path": destination_ou_path,
            "resource_ids": batch,
        })

        response = session.request(
            method="POST",
            url=url,
            headers=headers,
            data=payload,
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code in (200, 204):
            total_moved += len(batch)
            print(f"[{i + 1}-{min(i + len(batch), len(device_ids))}/{len(device_ids)}] Successfully moved {len(batch)} devices.")
        else:
            print(
                f"[{i + 1}-{min(i + len(batch), len(device_ids))}/{len(device_ids)}] Failed with status {response.status_code}: {response.text}",
                file=sys.stderr,
            )

    return total_moved


def main() -> None:
    if not SERVICE_ACCOUNT_KEY_PATH:
        print("Error: SERVICE_ACCOUNT_KEY_PATH is required.", file=sys.stderr)
        sys.exit(1)
    if not CUSTOMER_ID:
        print("Error: CUSTOMER_ID is required.", file=sys.stderr)
        sys.exit(1)
    if not DESTINATION_ORG_UNIT_PATH:
        print("Error: DESTINATION_ORG_UNIT_PATH is required.", file=sys.stderr)
        sys.exit(1)
    if not DEVICE_CSV_PATH:
        print("Error: DEVICE_CSV_PATH is required.", file=sys.stderr)
        sys.exit(1)

    print(f"Reading device list from {DEVICE_CSV_PATH}...")
    df = pd.read_csv(DEVICE_CSV_PATH)

    # Detect device ID column regardless of casing
    device_id_col = None
    for candidate in ['deviceId', 'Device ID', 'Device Id', 'device_id', 'DeviceId', 'ID', 'Id']:
        if candidate in df.columns:
            device_id_col = candidate
            break

    if not device_id_col:
        # Fall back to first column
        device_id_col = df.columns[0]
        print(f"Notice: Device ID column not explicitly found by name. Using first column '{device_id_col}'.")

    device_ids = df[device_id_col].dropna().astype(str).str.strip().tolist()
    # Filter out empty strings
    device_ids = [d for d in device_ids if d]

    print(f"Found {len(device_ids)} devices to move to '{DESTINATION_ORG_UNIT_PATH}'.")
    session = create_authorized_session(SERVICE_ACCOUNT_KEY_PATH, ADMIN_USER_EMAIL)
    moved_count = move_chrome_browsers(session, CUSTOMER_ID, DESTINATION_ORG_UNIT_PATH, device_ids)
    print(f"Done. Successfully moved {moved_count} of {len(device_ids)} devices.")


if __name__ == '__main__':
    main()