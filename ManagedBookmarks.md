# Chrome Managed Bookmarks Script

## Overview
This Python script is designed to automate the process of setting up managed bookmarks in Google Chrome for users within a specified Organizational Unit (OU) in Google Admin Console. It utilizes the Chrome Management Policy API to centrally manage and distribute bookmarks across the organization.

## Requirements
- Python 3.x
- Access to a Google Admin Console Admin account
- A Google Cloud Platform project with the Chrome Management API enabled
- A service account with domain-wide delegation set up in Google Workspace

## Configuration
- `SERVICE_ACCOUNT_FILE`: The file path to your service account JSON key.
- `CUSTOMER_ID`: Your Google Workspace customer ID. You can find the customer Id by navigating to the [Google Admin Console](https://admin.google.com/) > Account > Account Settings.
- `ADMIN_USER_EMAIL`: The email address of a Google Admin Console admin user.
- `ORG_UNIT_ID`: The unique ID of the Organizational Unit where the bookmarks will be applied.

## Bookmark Format
The bookmarks are defined in the `BOOKMARKS` list within the script. Each bookmark can be a direct link or a folder containing additional bookmarks.

## Usage
1. Update the `SERVICE_ACCOUNT_FILE`, `CUSTOMER_ID`, `ADMIN_USER_EMAIL`, and `ORG_UNIT_ID` in the script with your specific details.
2. Modify the `BOOKMARKS` list to include the bookmarks you want to manage.
3. Run the script to set the managed bookmarks for the specified OU.

## Caution
This script modifies Chrome policy settings for the specified OU. Ensure you have the necessary permissions and understand the potential impacts before running the script.

## Support
This script is provided as-is without official support. For assistance, consider using community forums or Google Workspace support channels.

## License
This project is licensed under the MIT License - see the LICENSE file for details.
