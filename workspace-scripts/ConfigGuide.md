# Configuration Guide

This guide provides instructions on how to find the necessary configuration details for using the scripts. 

## Configuration Details

### SERVICE_ACCOUNT_FILE
- **Description**: Path to your service account key JSON file.
- **Steps**:
  1. Navigate to [Google Cloud Console](https://console.cloud.google.com/).
  2. Access `IAM & Admin` > `Service Accounts`.
  3. Create a new service account and assign the necessary roles.
  4. Generate a new JSON key for this account.
  5. The downloaded JSON file is your `SERVICE_ACCOUNT_FILE`.

### CUSTOMER_ID
- **Description**: Your Google Workspace customer ID.
- **Steps**:
  1. Go to the [Google Admin Console](https://admin.google.com/).
  2. Navigate to `Account` > `Account Settings`.
  3. Your Customer ID is listed under the `Profile` section.

### ADMIN_USER_EMAIL
- **Description**: The email address of an admin user in your Google Workspace.
- **Steps**:
  1. Choose a user with admin privileges in your Google Workspace domain.
  2. This email is found in the Google Admin Console under `Users`.


### TARGET_OU_ID
- **Description**: The OU (Organizational Unit) ID. 
- **Steps**:
  1. Open the Google Admin Console.
  2. Navigate to `Directory` > `Organizational units`.
  3. Right-click on the page and select `Inspect` (or press `Ctrl+Shift+I`/`Cmd+Option+I` for direct access to developer tools).
  4. In the `Elements` tab of the developer tools, look for elements matching the XPath `//tr[@data-row-id]`.
  5. Locate the `data-row-id` attribute corresponding to your desired OU.
  6. The value of this attribute is the `TARGET_OU_ID`.

## Notes
- Accessing the OU ID via inspect element is an advanced method and requires basic knowledge of HTML and browser developer tools.
- Ensure you have administrative privileges in your Google Workspace account to access these details.
- Always follow your organization's security and privacy policies when handling sensitive information.
- For the `SERVICE_ACCOUNT_FILE`, ensure Domain Wide Delegation is set up:
  1. Copy the Unique ID from the [service account](https://console.cloud.google.com/iam-admin/serviceaccounts/) you created in the Google Cloud Console.
  2. Go to [Domain-wide Delegation](https://admin.google.com/ac/owl/domainwidedelegation) in the Admin Console.
  3. Paste the Unique ID and add the required OAuth scopes as per each script's requirements.
- Make sure required APIs are enabled on [Google Cloud Console](https://console.cloud.google.com/).
- Setting up Domain Wide Delegation is crucial for the service account to interact with Google Workspace on behalf of your domain.

---