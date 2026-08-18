
# Google Workspace and Google Admin Console Scripts

## Introduction
This repository contains a collection of enterprise-ready scripts written in Google Apps Script and Python, as well as the **Secure Gateway Studio** suite. These tools are designed to enhance the functionalities and management of Google Workspace Services (GWS), Google Admin Console, Chrome Enterprise, and BeyondCorp Security Gateway.

## Scripts & Tools in this Repository

### 1. WiFi Settings Management
Automates the management of WiFi settings for Google Workspace Organizational Units using Google Sheets.
- For detailed information and setup instructions, refer to [WiFi Settings Management Documentation](MassAddWifiSettings.md).

### 2. Organizational Unit (OU) Settings Management
Facilitates the management of Organizational Units in Google Workspace, streamlining the process of adding and modifying OUs via Google Sheets.
- See the [OU Settings Management Documentation](MassAddOUs.md) for more details.

### 3. Move Multiple Browsers
This script, `MoveMultipleBrowsers.py`, enables administrators to move multiple Chrome browser devices across different Organizational Units (OUs) in Google Workspace efficiently. Ideal for managing large numbers of devices.
- For more information, see the [Move Multiple Browsers Documentation](MoveMultipleBrowsers.md).

### 4. Block Extensions Based On Risk Score
Automates the assessment and blocking of Chrome extensions in Google Workspace based on risk scores from Crxcavator and Spin.ai. This script evaluates each extension's risk score and blocks those exceeding defined thresholds within a specified Organizational Unit, enhancing security and compliance in the digital workspace.
- For more information, see the [Block Extensions Based On Risk Score Documentation](BlockExtensionBasedOnRiskScore.md).

### 5. Configure Managed Bookmarks For Organizational Unit (OU)
Automates the process of setting up managed bookmarks in Google Chrome for users within a specified Organizational Unit (OU) in Google Admin Console. It utilizes the Chrome Management Policy API to centrally manage and distribute bookmarks across the organization.
- For more information, see the [Managed Bookmarks Documentation](ManagedBookmarks.md).

### 6. Chrome Enterprise Release Scraper
`ReleaseScraper.py` monitors official Google Chrome Enterprise release notes and automatically publishes structured updates to a Slack channel via Webhook.

### 7. Secure Gateway Studio
A comprehensive tool and Chrome Extension suite (`secure-gateway-studio/`) for designing, evaluating, and applying Google Cloud BeyondCorp Private Security Gateway architectures, enabling zero-trust private HTTPS access for managed Chrome devices.
- For more information, see [Secure Gateway Studio Documentation](secure-gateway-studio/README.md).

## Configuration & Setup
If you are configuring or running any of the scripts, take a look at the [Config Guide](ConfigGuide.md) for detailed guidance on configuration settings and permissions.

## Usage
These scripts are intended for use by administrators, security engineers, and IT professionals who manage Google Workspace, Google Cloud, or Google Admin Console environments.

## Disclaimer
These scripts and tools are an independent open-source project. They are **not
built, endorsed, or supported by Google**, and are not affiliated with Google
LLC. "Google", "Google Workspace", "Google Cloud", "Chrome", and "Chrome
Enterprise Premium" are trademarks of Google LLC.

Everything here is provided as is, with no warranty and no support commitment.
Several of these tools change configuration in a live Google Workspace tenant or
Google Cloud project. Test in a non-production organizational unit first. The
author accepts no responsibility for problems arising from their use.

## Support
For questions about Google Workspace, Chrome Enterprise Premium, Secure Gateway,
or licensing, contact your Google account team — your Field Sales Representative
or Customer Success Manager. Google supports its own products; these tools are
not among them.

For problems with the tools in this repository, open a GitHub issue. Best effort
only, with no response time commitment.

## License
All scripts in this repository are licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
