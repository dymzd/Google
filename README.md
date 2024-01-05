
# Chrome Browser Cloud Management & Google Admin Console Scripts

## Introduction
This repository contains a collection of scripts written in Google Apps Script and Python. These scripts are designed to enhance the functionalities and management of Google Workspace Services (GWS) and Google Admin Console, providing valuable tools for companies utilizing these services.

## Scripts in this Repository

### 1. WiFi Settings Management
Automates the management of WiFi settings for Google Admin Console Organizational Units using Google Sheets.
- For detailed information and setup instructions, refer to [WiFi Settings Management Documentation](MassAddWifiSettings.md).

### 2. Organizational Unit (OU) Settings Management
Facilitates the management of Organizational Units in Google Admin Console, streamlining the process of adding and modifying OUs.
- See the [OU Settings Management Documentation](MassAddOUs.md) for more details.

### 3. Move Multiple Browsers
This script, `MoveMultipleBrowsers.py`, enables administrators to move multiple Chrome browser devices across different Organizational Units (OUs) in Google Admin Console efficiently. Ideal for managing large numbers of devices.
- For more information, see the [Move Multiple Browsers Documentation](MoveMultipleBrowsers.md).

### 4. Block Extensions Based On Risk Score
Automates the assessment and blocking of Chrome extensions in Google Admin Console based on risk scores from Crxcavator and Spin.ai. This script evaluates each extension's risk score and blocks those exceeding defined thresholds within a specified Organizational Unit, enhancing security and compliance in the digital workspace.
- For more information, see the [Block Extensions Based On Risk Score Documentation](BlockExtensionBasedOnRiskScore.md).

### 5. Managed Bookmarks
This script, `ManagedBookmarks.py`, simplifies the administration of Google Chrome by enabling the creation and distribution of managed bookmarks within specified Organizational Units (OUs) in Google Admin Console. It leverages the Chrome Management Policy API to centrally manage bookmarks, ensuring consistent access to essential web resources across the organization.
- Detailed setup and usage instructions can be found in the [Chrome Managed Bookmarks Documentation](ManagedBookmarks.md).


## Usage
These scripts are intended for use by administrators and IT professionals who manage Google Workspace or Google Admin Console environments. They are designed to be user-friendly and easily integrated into existing Google Admin Console setups.

## Disclaimer
- The operation of these scripts is not guaranteed. Use them at your own risk.
- The author does not take any responsibility for problems that may occur due to the use of these scripts.

## Support
While these scripts are provided 'as-is', users are welcome to report issues or seek assistance through GitHub issues.

## License
All scripts in this repository are licensed under the MIT License - see the LICENSE file for details.
