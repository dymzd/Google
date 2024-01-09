
# Google Workspace and Google Admin Console Scripts

## Introduction
This repository contains a collection of scripts written in Google Apps Script and Python. These scripts are designed to enhance the functionalities and management of Google Workspace Services (GWS) and Google Admin Console, providing valuable tools for companies utilizing these services.

## Scripts in this Repository

### 1. WiFi Settings Management
Automates the management of WiFi settings for Google Workspace Organizational Units using Google Sheets.
- For detailed information and setup instructions, refer to [WiFi Settings Management Documentation](WiFi_Settings_Management_README.md).

### 2. Organizational Unit (OU) Settings Management
Facilitates the management of Organizational Units in Google Workspace, streamlining the process of adding and modifying OUs.
- See the [OU Settings Management Documentation](OU_Settings_Management_README.md) for more details.

### 3. Move Multiple Browsers
This script, `MoveMultipleBrowsers.py`, enables administrators to move multiple Chrome browser devices across different Organizational Units (OUs) in Google Workspace efficiently. Ideal for managing large numbers of devices.
- For more information, see the [Move Multiple Browsers Documentation](MoveMultipleBrowsers.md).

### 4. Block Extensions Based On Risk Score
Automates the assessment and blocking of Chrome extensions in Google Workspace based on risk scores from Crxcavator and Spin.ai. This script evaluates each extension's risk score and blocks those exceeding defined thresholds within a specified Organizational Unit, enhancing security and compliance in the digital workspace.
- For more information, see the [Block Extensions Based On Risk Score Documentation](BlockExtensionBasedOnRiskScore.md).

## 5. Configure Managed Bookmarks For Organizational Unit (OU)
Automates the process of setting up managed bookmarks in Google Chrome for users within a specified Organizational Unit (OU) in Google Admin Console. It utilizes the Chrome Management Policy API to centrally manage and distribute bookmarks across the organization.
- For more information, see the [Managed Bookmarks Documentation](ManagedBookmarks.md)



## Usage
These scripts are intended for use by administrators and IT professionals who manage Google Workspace or Google Admin Console environments. They are designed to be user-friendly and easily integrated into existing Google Workspace setups.

## Disclaimer
- The operation of these scripts is not guaranteed. Use them at your own risk.
- The author does not take any responsibility for problems that may occur due to the use of these scripts.

## Support
While these scripts are provided 'as-is', users are welcome to report issues or seek assistance through GitHub issues. 
If you are encountering issues running or configuring the script, take a look at [Config Guide](ConfigGuide.md) for detailed guidance on configuration settings.

## License
All scripts in this repository are licensed under the MIT License - see the LICENSE file for details.
