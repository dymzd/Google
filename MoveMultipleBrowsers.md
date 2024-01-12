
# MoveMultipleBrowsers Script

## Overview
This Python script, `MoveMultipleBrowsers.py`, is designed to facilitate the movement of multiple Chrome browser devices across different Organizational Units (OUs) in Google Workspace. It is particularly useful for administrators managing a large number of devices.

## Requirements
- Python 3.x
- Google OAuth2 credentials
- Access to Google Admin SDK

## Setup Instructions
1. **Service Account Key**: Ensure you have a service account key JSON file from Google Cloud Console with necessary permissions.
2. **Customer ID**: Obtain your Google Workspace customer ID from the Admin Console.
3. **Destination OU Path**: Determine the OU path where the devices need to be moved.
4. **Device CSV File**: Prepare a CSV file with device IDs. You can download this CSV from the Admin Console under Chrome Browser -> Managed Browser tab. In that section of Admin Console, you can select a specific OU and export it as a CSV file.

## Configuration
Fill in the following fields in the script:
- `service_account_key_path`: Path to your service account key JSON file.
- `customerId`: Your Google Workspace customer ID.
- `destinationOrgUnitPath`: The OU path where devices will be moved.
- `device_csv_path`: Path to the CSV file containing device IDs.

## Usage
Run the script in a Python environment. It will process each device ID in the CSV file and move the corresponding devices to the specified OU.

## Support
This script is provided 'as-is' without official support. However, you may report issues or seek help through GitHub issues.

## License
This project is licensed under the MIT License - see the LICENSE file for details.
