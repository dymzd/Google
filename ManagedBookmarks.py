import google.auth
from google.auth.transport.requests import AuthorizedSession
from google.oauth2 import service_account
import json

#/******* BEGIN: Customer to modify this section *******/
SERVICE_ACCOUNT_FILE = '.json'  # Path to the service account JSON file
CUSTOMER_ID = ''  # Your Google Workspace customer ID
ADMIN_USER_EMAIL = ''  # Google Admin Console Admin email 
ORG_UNIT_ID = ''  # The unique ID for the target Organizational Unit (OU)
# List of bookmarks to add. This includes both individual links and folders with nested links
BOOKMARKS = [
    {
        "link": {
            "name": "Test1",
            "url": "test1.com"
        }
    },
    { 
        "link": {
            "name": "Test2",
            "url": "Test2.com"
        }
    },
    {
        "folder": {
            "name": "TestFolder",
            "entries": [
                {
                    "link": {
                        "name": "Test3",
                        "url": "Test3.com"
                    }
                }
            ]
        }
    }
]
#/******* END: Customer to modify this section *******/

SCOPES = ['https://www.googleapis.com/auth/chrome.management.policy']  # OAuth scopes for Chrome Management Policy

def add_managed_bookmarks(session, customer_id, org_unit_id, bookmarks):
    """
    Function to add managed bookmarks to a specified organizational unit.

    Args:
        session (AuthorizedSession): The authorized session for making API requests.
        customer_id (str): The customer ID in Google Workspace.
        org_unit_id (str): The unique ID for the target Organizational Unit.
        bookmarks (list): List of bookmarks to add, formatted according to Chrome policy specifications.
    """
    # Endpoint URL for modifying organizational unit policies
    url = f"https://chromepolicy.googleapis.com/v1/customers/{customer_id}/policies/orgunits:batchModify"

    # Construct the managed bookmarks payload
    managed_bookmarks_payload = {
        "managedBookmarks": {
            "bookmarks": bookmarks
        }
    }

    # Construct the payload for the POST request
    bookmark_payload = {
        "policyTargetKey": {
            "targetResource": f"orgunits/{org_unit_id}"
        },
        "policyValue": {
            "policySchema": "chrome.users.ManagedBookmarksSetting",
            "value": managed_bookmarks_payload
        },
        "updateMask": "managedBookmarks"  # Specify the field being updated
    }
    payload = {"requests": [bookmark_payload]}

    # Make the POST request to apply the managed bookmarks policy
    response = session.post(url, data=json.dumps(payload))
    if response.status_code != 200:
        raise Exception(f"Failed to add managed bookmarks: {response.text}")


def main():
    """
    Main function to set up credentials and add managed bookmarks.
    """
    # Load service account credentials
    credentials = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES, subject=ADMIN_USER_EMAIL)

    # Create an authorized session with the loaded credentials
    session = AuthorizedSession(credentials)

    # Add managed bookmarks to the specified organizational unit
    add_managed_bookmarks(session, CUSTOMER_ID, ORG_UNIT_ID, BOOKMARKS)

if __name__ == '__main__':
    main()
