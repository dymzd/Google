import json
import pandas as pd
from google.auth.transport.requests import AuthorizedSession
from google.oauth2.service_account import Credentials

#/******* BEGIN: Customer to modify this section *******/
# Add service account key JSON file path
service_account_key_path = ""
# Add the customer id here. You can find the customer Id by navigating to the Google Admin Console > Account > Account Settings
customerId = ""
# Add the destination OU path. An example of the destination OU path 'North America/Austin/AUS Managed User'
destinationOrgUnitPath = ""
# Add the path to the CSV file containing device IDs. 
# You can download this CSV from the Admin Console under Chrome Browser -> Managed Browser tab. 
# In that section of Admin Console, you can select a specific OU and export it as a CSV file.
device_csv_path = ""
#/******* END: Customer to modify this section *******/


# Function to move a single device to a specific OU
def move_device_to_ou(device_id):
    service_account_info = json.load(open(service_account_key_path))
    credentials = Credentials.from_service_account_info(
        service_account_info,
        scopes=['https://www.googleapis.com/auth/admin.directory.device.chromebrowsers']
        
    )

    payload = json.dumps({
        "org_unit_path": destinationOrgUnitPath,
        "resource_ids": [device_id]
    })

    headers = {'Content-Type': 'application/json'}
    moveChromeBrowsersToOuServiceUrl = f"https://www.googleapis.com/admin/directory/v1.1beta1/customer/{customerId}/devices/chromebrowsers/moveChromeBrowsersToOu"

    response = AuthorizedSession(credentials).request(
        method="POST", 
        headers=headers, 
        url=moveChromeBrowsersToOuServiceUrl,
        data=payload,
    )

    print("Move device to OU: ", response.status_code)
    print(response.content.decode("utf-8"))

# Read device IDs from the CSV file and move each device
df = pd.read_csv(device_csv_path)
for device_id in df['deviceId']:
    move_device_to_ou(device_id)