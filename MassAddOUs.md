# Google Sheets OU Management Script

## Description
This script is designed to automate the process of adding Organizational Units (OUs) to a Google Workspace domain using Google Sheets and Google Apps Script. It interacts with the Google Admin SDK to create new OUs based on the data provided in a Google Sheets document.

## Setup
1. Insert your Google service account credentials in the script.
2. Open your Google Sheets and add a sheet named 'OU Settings'.
3. Populate this sheet with OU names and their respective parent OUs.

## Usage
- Open the Google Sheets document.
- A custom menu 'Custom Script' will appear. Click on it and select 'Add OUs'.
- The script will attempt to create OUs based on the spreadsheet's data.

## Disclaimer
- The operation of this code is not guaranteed. Please use it at your own risk.
- I do not take any responsibility for problems that occur due to the use of this script.

## Support
This script is provided as-is, and support is not officially offered. However, for any queries or issues, you may reach out through GitHub issues.

## License
This project is licensed under the MIT License - see the LICENSE file for details.
