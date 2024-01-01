
# Google Sheets WiFi Management Script

## Description
This script enables automated management of WiFi settings for Google Workspace Organizational Units (OUs) using Google Sheets and Google Apps Script. It integrates with the Google Admin SDK and uses OAuth2 for authentication to apply WiFi settings.

## Setup
1. Enter your Google service account credentials (Client ID, Client Secret, Customer ID) in the script.
2. Create a Google Sheets document and add a sheet named 'Wifi Settings'.
3. Populate the sheet with WiFi settings data for each OU.

## Usage
- Open the Google Sheets document.
- A custom menu 'Custom Script' will appear in the Sheets UI. Click on it and select 'Add Wifi Settings'.
- The script will process each row in the 'Wifi Settings' sheet and apply the settings to the corresponding OUs.

## Authorization
- The first run will require authorization to interact with Google Workspace.
- Follow the instructions in the script logs to authorize.

## Disclaimer
- The operation of this code is not guaranteed. Use it at your own risk.
- I do not take any responsibility for problems that occur due to the use of this script.

## Support
This script is provided 'as-is', without official support. However, you may report issues or seek help through GitHub issues.

## License
This project is licensed under the MIT License - see the LICENSE file for details.
