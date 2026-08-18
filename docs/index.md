---
title: Chrome Enterprise Premium PoC Deployer
description: >-
  Chrome Enterprise Premium PoC Deployer is a Chrome extension for Google Workspace
  and Google Cloud administrators. It provides turnkey planning, deployment, verification,
  and rollback for Chrome Enterprise Premium (CEP) and BeyondCorp Security Gateway (SGW).
---

# Chrome Enterprise Premium PoC Deployer

**Chrome Enterprise Premium PoC Deployer** is an administrator tool (packaged as a Chrome extension) designed to streamline the evaluation, configuration, and verification of **Chrome Enterprise Premium (CEP)** and **BeyondCorp Security Gateway (SGW)** across Google Workspace tenants and Google Cloud projects.

It is the application registered on the Google Cloud OAuth consent screen and distributed in the Chrome Web Store as **Chrome Enterprise Premium PoC Deployer**.

---

## Two Core Deployment Modules

The tool is organized into two distinct functional engines:

```
┌─────────────────────────────────────────────────────────────┐
│           Chrome Enterprise Premium PoC Deployer            │
├──────────────────────────────┬──────────────────────────────┤
│    1. CEP PoC Deployer       │      2. SGW Deployer         │
│ (Chrome Enterprise Premium)  │ (BeyondCorp Security Gateway)│
├──────────────────────────────┼──────────────────────────────┤
│ • Automated OU Structure     │ • Zero-Trust Private App GW  │
│ • Threat & Malware Policies  │ • 3 Gateway Architectures    │
│ • Context-Aware Access (CAA) │ • Custom IAM Roles & SA      │
│ • Data Boundary Policies     │ • Private DNS & TLS Certs    │
│ • Starter DLP Rule Sets      │ • Upstream Health Checks     │
└──────────────────────────────┴──────────────────────────────┘
```

### 1. CEP PoC Deployer (Chrome Enterprise Premium Module)
Accelerates the evaluation of Chrome's advanced security features without manual, error-prone configuration across multiple admin consoles:
* **Organizational Unit (OU) Lifecycle**: Automatically provisions dedicated test OUs (e.g., `CEP Users`, `CEP Browsers`) to isolate pilot testing from production users.
* **Threat & Data Protection**: Sets Chrome policies for real-time URL scanning, malware deep scanning, password reuse detection, and security telemetry.
* **Context-Aware Access (CAA)**: Configures device posture signals and Endpoint Verification requirements.
* **Data Boundary & Starter DLP**: Deploys data-loss-prevention policies and content-inspection rules tailored to your tenant's primary domain.

### 2. SGW Deployer (BeyondCorp Security Gateway Module / Secure Gateway Studio)
Automates the zero-trust application access architecture for managed Chrome browsers:
* **Gateway Architecture Options**:
  * **Path A (Full Enterprise Offload)**: Internal Regional Application Load Balancer, Nginx TLS-to-HTTP offload tier, VPC subnets, firewall rules, and Private DNS.
  * **Path B (Direct Private HTTPS)**: Direct BeyondCorp routing to internal HTTPS endpoints.
  * **Path C (Cloud Run / Modern Workloads)**: Serverless container integration.
* **Least-Privilege Security**: Provisions a scoped deployer service account and tailored project IAM custom roles, ensuring operations never run with excessive administrator privileges.
* **Certificate Management**: Manages private CA issuance and Secret Manager TLS bundles for internal applications.

---

## How It Works: The 5-Stage Orchestration Cycle

All deployments follow a strict, auditable 5-stage lifecycle:

1. **Plan**: Inspects the current state of your Workspace tenant and Google Cloud project. Generates a line-by-line diff of proposed changes with zero writes.
2. **Approve**: Displays the exact plan for explicit administrator review. Nothing is modified until approved.
3. **Apply**: Executes approved mutations using Google's public REST APIs with the signed-in administrator's credentials or impersonated scoped service accounts.
4. **Verify**: Runs end-to-end acceptance tests to confirm policies are live and generates a tamper-evident SHA-256 cryptographic audit chain.
5. **Rollback & Teardown**: Reverts policies to their parent OU settings and cleanly removes only the resources created during the PoC.

---

## Detailed API Calls & Host Permissions

The extension calls Google APIs directly from the browser runtime (`https://*.googleapis.com`). No third-party servers or external services are involved.

| API Host Endpoint | Used By | Purpose & Action Performed |
|---|---|---|
| `admin.googleapis.com` | CEP & SGW | Reads organizational units and domain details (`admin.directory.customer.readonly`), creates PoC sub-OUs (`admin.directory.orgunit`), and lists pilot groups. |
| `cloudidentity.googleapis.com` | CEP | Manages DLP policies and rule detectors (`cloud-identity.policies`) for Chrome content inspection. |
| `chromepolicy.googleapis.com` | CEP & SGW | Sets and resolves target OU policies (Threat Protection, Endpoint Verification, Extension Settings). |
| `chromemanagement.googleapis.com` | CEP | Verifies managed browser enrollment status and telemetry reporting. |
| `accesscontextmanager.googleapis.com` | CEP & SGW | Reads and binds Context-Aware Access levels and device policy conditions. |
| `iamcredentials.googleapis.com` | SGW | Generates short-lived credentials (`generateAccessToken`) for the scoped deployer service account. |
| `iam.googleapis.com` | SGW | Creates the deployer service account and configures custom IAM project roles. |
| `cloudresourcemanager.googleapis.com` | SGW | Resolves GCP project/organization IDs and binds IAM policies. |
| `serviceusage.googleapis.com` | SGW | Enables required Google Cloud service APIs (BeyondCorp, Compute, DNS, etc.) in the project. |
| `beyondcorp.googleapis.com` | SGW | Configures Security Gateways, App Connections, and Client Gateways. |
| `compute.googleapis.com` | SGW (Path A) | Provisions VPC subnets, firewall rules, instance templates, and internal load balancers. |
| `dns.googleapis.com` | SGW (Path A) | Manages private DNS zones and records for internal application resolution. |
| `secretmanager.googleapis.com` | SGW | Stores and rotates TLS certificates and private keys. |
| `privateca.googleapis.com` | SGW | Issues PoC certificates from Google Cloud Certificate Authority Service. |
| `cloudbilling.googleapis.com` | SGW | Checks that the Google Cloud project has an active billing account prior to deployment. |
| `licensing.googleapis.com` | CEP | Confirms active Chrome Enterprise Premium subscription licenses. |
| `logging.googleapis.com` | SGW | Fetches diagnostic and audit logs for verification and evidence export. |

---

## OAuth Scopes Justification

In compliance with the Google API Services User Data Policy, only scopes strictly necessary for operation are requested:

| OAuth Scope | Primary Component | Justification & Principle of Least Privilege |
|---|---|---|
| `.../auth/admin.directory.orgunit` | CEP Deployer | Required to automatically create, configure, and clean up isolated test OUs (`CEP Users`, `CEP Browsers`) so production users are unaffected. |
| `.../auth/admin.directory.customer.readonly` | CEP Deployer | Required to read the tenant's primary domain name, which is necessary to formulate domain-specific data boundary policies. |
| `.../auth/cloud-identity.policies` | CEP Deployer | Required to create, configure, and delete Chrome Data Loss Prevention (DLP) rules and detectors. |
| `.../auth/admin.directory.group.readonly` | CEP / SGW | Enables the administrator to select specific pilot user groups in the configuration wizard. |
| `.../auth/admin.directory.user.readonly` | CEP / SGW | Resolves administrator profile attributes to ensure proper tenant context. |
| `.../auth/chrome.management.policy` | CEP / SGW | Applies Chrome policies to target organizational units. |
| `.../auth/chrome.management.profiles.readonly`| CEP | Verifies profile-level Chrome policy application. |
| `.../auth/apps.licensing` | CEP | Verifies the tenant possesses Chrome Enterprise Premium licenses. |
| `.../auth/cloud-platform` | SGW Deployer | Used to orchestrate multi-service GCP infrastructure (BeyondCorp, Compute, IAM, DNS). Mutations run through impersonated least-privilege service accounts. |
| `.../auth/userinfo.email` | Core | Displays the signed-in administrator email in the local audit log and evidence bundle. |

---

## Architecture & Privacy Guarantee

* **100% Client-Side / Zero-Backend**: The extension runs entirely in your local browser runtime. It has no backend server and transmits no telemetry or user data to the developer or any third party.
* **In-Memory Credential Handling**: OAuth access tokens remain strictly in volatile memory. They are never written to disk or logged.
* **Local Audit Store**: All drafts, plans, and SHA-256 audit evidence are kept in your browser's local `IndexedDB` storage and are exportable as JSON at any time.

For full privacy commitments, see the [Privacy Policy](privacy.html).

---

## Independent Open Source Notice

Chrome Enterprise Premium PoC Deployer is an **independent open-source project** published under the Apache 2.0 License at [github.com/dymzd/Google](https://github.com/dymzd/Google).

It is **not built, endorsed, or supported by Google LLC**, and is not an official Google product. "Google", "Google Workspace", "Google Cloud", "Chrome", and "Chrome Enterprise Premium" are trademarks of Google LLC.

---

## Support & Issue Reporting

* **For Tool Issues & Feature Requests**: Open an issue on our [GitHub Issues page](https://github.com/dymzd/Google/issues).
* **For Google Product Licensing & Official Support**: Contact your Google account representative (FSR / CE / CSM) or visit the [Google Cloud Support Center](https://cloud.google.com/support).
