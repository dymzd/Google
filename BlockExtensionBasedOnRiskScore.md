# BlockExtensionBasedOnRiskScore Script

## Overview
This Python script, `BlockExtensionBasedOnRiskScore.py`, is designed to automate the process of identifying and blocking potentially risky Chrome extensions in a Chrome Browser Cloud Management environment. It evaluates extensions based on risk scores obtained from Crxcavator and Spin.ai.

## Requirements
- Python 3.x
- Google OAuth2 credentials with appropriate permissions
- Access to Google Admin SDK and Chrome Management APIs

## Setup Instructions
1. **Service Account Key**: Ensure you have a service account key JSON file from Google Cloud Console with the necessary permissions.
2. **Customer ID**: Obtain your Google Workspace customer ID.
3. **Organizational Unit ID**: Specify the Organizational Unit ID where the policy will be applied.
4. **Risk Thresholds**: Define the risk thresholds for Crxcavator and Spin.ai scores.

## Configuration
Update the following fields in the script:
- `SERVICE_ACCOUNT_FILE`: Path to your service account key JSON file.
- `CUSTOMER_ID`: Your Google Workspace customer ID. Your Google Workspace customer ID. You can find the customer Id by navigating to the [Google Admin Console](https://admin.google.com/) > Account > Account Settings.
- `CRX_RISK_THRESHOLD` and `SPIN_RISK_THRESHOLD`: The risk thresholds for Crxcavator and Spin.ai scores.
- `ADMIN_USER_EMAIL`: The email address of an admin user in your Google Workspace.
- `TARGET_OU_ID`: The OU ID where extensions will be blocked.

## Usage
Run the script in a Python environment. It will evaluate each Chrome extension's risk score and block those exceeding the defined thresholds in the specified OU.

## Support
This script is provided 'as-is' without official support. However, users are encouraged to report issues or seek assistance through GitHub issues or community forums.

## License
This project is licensed under the MIT License - see the LICENSE file for details.
