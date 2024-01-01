import google.auth
from google.auth.transport.requests import AuthorizedSession
from google.oauth2 import service_account
from googleapiclient.discovery import build

import requests
import json

# Constants
SERVICE_ACCOUNT_FILE = '.json'  # Path to the service account JSON file
SCOPES = [
    'https://www.googleapis.com/auth/admin.directory.device.chromeos',
    'https://www.googleapis.com/auth/chrome.management.reports.readonly',
    'https://www.googleapis.com/auth/chrome.management.appdetails.readonly',
    'https://www.googleapis.com/auth/chrome.management.policy',
    'https://www.googleapis.com/auth/admin.directory.orgunit.readonly'
]  # OAuth scopes required for accessing the necessary APIs
CUSTOMER_ID = ''  # Your Google Workspace customer ID
CRX_RISK_THRESHOLD = 550  # Threshold for Crxcavator risk score
SPIN_RISK_THRESHOLD = 70  # Threshold for Spin risk score
ADMIN_USER_EMAIL = 'admin@yourdomain.com'  # Admin email for user delegation
TARGET_OU_ID = '' # The unique ID for the target Organizational Unit (OU)

def list_extensions(session, customer_id):
    """List all Chrome extensions for a given customer ID.

    Args:
        session (AuthorizedSession): The authorized session for making API requests.
        customer_id (str): The customer ID in Google Workspace.

    Returns:
        list: A list of dictionaries containing details of each extension.
    """
    extensions = []
    page_token = None

    while True:
        # Make a request to list installed Chrome Extensions & Apps
        response = session.get(
            f'https://chromemanagement.googleapis.com/v1/customers/{customer_id}/reports:countInstalledApps',
            params={'pageToken': page_token}
        )
        if response.status_code != 200:
            raise Exception("Failed to list extensions: " + response.text)

        data = response.json()

        # Process each apps, filtering for extensions and fetching their details
        for app in data.get('installedApps', []):
            if app.get('appType') == 'EXTENSION':
                extension_id = app.get('appId')
                # Fetch additional details for each extension
                extension_details = get_extension_details(session, customer_id, extension_id)
                extensions.append(extension_details)

        page_token = data.get('nextPageToken')
        if not page_token:
            break

    return extensions

def get_extension_details(session, customer_id, extension_id):
    """
    Fetch detailed information for a specific Chrome extension.

    Args:
        session (AuthorizedSession): The authorized session for making API requests.
        customer_id (str): The customer ID in Google Workspace.
        extension_id (str): The ID of the Chrome extension.

    Returns:
        dict: A dictionary containing the extension's ID and its version.
    """
    # Make a request to get detailed information about the specified Chrome extension
    response = session.get(
        f'https://chromemanagement.googleapis.com/v1/customers/{customer_id}/apps/chrome/{extension_id}'
    )
    # Raise an exception if the request fails
    if response.status_code != 200:
        raise Exception(f"Failed to get details for extension {extension_id}: {response.text}")

    # Parse the response to extract extension data
    extension_data = response.json()
    # Return a dictionary with the extension's ID and its version
    return {
        'id': extension_id,
        'version': extension_data.get('revisionId')
    }

def block_extension(session, customer_id, org_unit_id, extension_id):
    """
    Block a specific Chrome extension in a given Organizational Unit.

    Args:
        session (AuthorizedSession): The authorized session for making API requests.
        customer_id (str): The customer ID in Google Workspace.
        org_unit_id (str): The unique ID for the target Organizational Unit.
        extension_id (str): The ID of the Chrome extension to be blocked.

    Raises:
        Exception: If the API request to block the extension fails.
    """
    # Endpoint URL for modifying organizational unit policies
    url = f"https://chromepolicy.googleapis.com/v1/customers/{customer_id}/policies/orgunits:batchModify"
    # Construct the payload for the POST request
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
            "updateMask": {"paths": "appInstallType"}
        }]
    }
    # Make the POST request to apply the blocking policy
    response = session.post(url, data=json.dumps(payload))
    # Raise an exception if the request fails
    if response.status_code != 200:
        raise Exception(f"Failed to block extension {extension_id}: {response.text}")

def get_risk_score(extension_id, version):
    """
    Fetch the risk scores from Crxcavator and Spin.ai for a specific Chrome extension.

    Args:
        extension_id (str): The ID of the Chrome extension.
        version (str): The version of the Chrome extension.

    Returns:
        tuple: A tuple containing the Crxcavator and Spin.ai risk scores.
    """
    # Initialize risk scores to None
    crxcavator_score = None
    spin_score = None

    # Attempt to fetch the risk score from Crxcavator
    crxcavator_url = f"https://api.crxcavator.io/v1/report/{extension_id}/{version}?platform=Chrome"
    try:
        crxcavator_response = requests.get(crxcavator_url)
        # If successful, parse and extract the Crxcavator score
        if crxcavator_response.status_code == 200:
            crxcavator_data = crxcavator_response.json()
            # Ensure data is not None
            if crxcavator_data:
                crxcavator_score = crxcavator_data.get('data', {}).get('risk', {}).get('total')
            else:
                # Try fetching Crxcavator score without specifying version
                crxcavator_url = f"https://api.crxcavator.io/v1/report/{extension_id}?platform=Chrome"
                try:
                    crxcavator_response = requests.get(crxcavator_url)
                    if crxcavator_response.status_code == 200:
                        crxcavator_data = crxcavator_response.json()
                        if crxcavator_data:
                            # Handle case where response is a list
                            crxcavator_score = crxcavator_data[0].get('data', {}).get('risk', {}).get('total')
                except Exception as e:
                    print(f"Error fetching Crxcavator score for {extension_id}: {e}")
    except Exception as e:
        print(f"Error fetching Crxcavator score for {extension_id}: {e}")

    # Attempt to fetch the risk score from Spin.ai
    spin_url = f"https://apg-1.spin.ai/api/v1/assessment/platform/chrome/{extension_id}"
    temp_url = spin_url  # Backup URL in case the first Spin.ai request fails
    if version:
        spin_url += f"/version/{version}"
    try:
        spin_response = requests.get(spin_url)
        # If successful, parse and extract the Spin score
        if spin_response.status_code == 200:
            spin_data = spin_response.json()
            spin_score = spin_data.get('trustRate')
        # If no specific version data, try without the version
        elif spin_response.status_code in [204, 202]:
            try:
                spin_response = requests.get(temp_url)
                if spin_response.status_code == 200:
                    spin_data = spin_response.json()
                    spin_score = spin_data.get('trustRate')
            except Exception as e:
                print(f"Error fetching Spin score for {extension_id}: {e}")
    except Exception as e:
        print(f"Error fetching Spin score for {extension_id}: {e}")

    # Return both Crxcavator and Spin scores
    return crxcavator_score, spin_score


def main():
    # Load service account credentials from a specified JSON file.
    # These credentials are used to authenticate API requests.
    credentials = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES)

    # Create an authorized session with the loaded credentials.
    # This session will be used to make authenticated API requests.
    session = AuthorizedSession(credentials)

    # Retrieve a list of all Chrome extensions for the specified customer ID.
    extensions = list_extensions(session, CUSTOMER_ID)
    for extension in extensions:
        # Fetch the risk scores (Crxcavator and Spin) for each extension.
        crxcavator_score, spin_score = get_risk_score(extension['id'], extension.get('version'))

        # Check if both risk scores are above their respective thresholds.
        # If so, block the extension in the specified Organizational Unit.
        if crxcavator_score is not None and spin_score is not None and \
           crxcavator_score > CRX_RISK_THRESHOLD and spin_score > SPIN_RISK_THRESHOLD:
            print(f"BLOCKING Extension ID: {extension['id']}, Crxcavator Score: {crxcavator_score}, Spin Score: {spin_score}")
            block_extension(session, CUSTOMER_ID, TARGET_OU_ID, extension['id'])

        # If either risk score is unknown (None), flag the extension for manual review.
        elif crxcavator_score is None or spin_score is None:
            print(f"Extension ID for manual review (unknown score): {extension['id']} , Crxcavator Score: {crxcavator_score}, Spin Score: {spin_score}")

        # If both scores are known and below the threshold, consider the extension safe.
        else:
            print(f"Safe: Extension ID: {extension['id']}, Crxcavator Score: {crxcavator_score}, Spin Score: {spin_score}")



if __name__ == '__main__':
    main()
