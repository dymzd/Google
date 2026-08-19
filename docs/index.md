---
layout: default
title: Chrome Enterprise Premium PoC Deployer
description: >-
  Chrome Enterprise Premium PoC Deployer is an administrator tool for Google Workspace
  and Google Cloud administrators. It provides turnkey planning, deployment, verification,
  and rollback for Chrome Enterprise Premium (CEP) and BeyondCorp Security Gateway (SGW).
---

<div class="mb-12 text-center sm:text-left">
  <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sky-50 border border-sky-200 text-sky-700 text-xs font-semibold uppercase tracking-wider mb-4 shadow-sm">
    <span class="w-2 h-2 rounded-full bg-sky-500 animate-pulse"></span>
    Enterprise Administrator Tool &bull; Apache 2.0 Open Source
  </div>
  <h1 class="text-3xl sm:text-4xl lg:text-5xl font-extrabold text-slate-900 tracking-tight leading-tight">
    Chrome Enterprise Premium<br class="hidden sm:block">
    <span class="bg-gradient-to-r from-sky-600 to-indigo-600 bg-clip-text text-transparent">PoC Deployer</span>
  </h1>
  <p class="text-lg text-slate-600 max-w-3xl mt-4 leading-relaxed">
    Fast-track the evaluation, configuration, and verification of <strong>Chrome Enterprise Premium (CEP)</strong> and <strong>BeyondCorp Security Gateway (SGW)</strong> across Google Workspace tenants and Google Cloud projects.
  </p>
  <div class="flex flex-wrap items-center gap-3 mt-6">
    <a href="#two-core-deployment-modules" class="px-5 py-2.5 rounded-xl bg-sky-600 hover:bg-sky-700 text-white font-semibold text-sm shadow-md shadow-sky-500/20 transition-all">Explore Modules</a>
    <a href="{{ '/privacy.html' | relative_url }}" class="px-5 py-2.5 rounded-xl bg-white hover:bg-slate-50 text-slate-700 font-semibold text-sm border border-slate-200 shadow-sm transition-all">Privacy Policy</a>
    <a href="https://github.com/dymzd/Google" target="_blank" class="px-5 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-white font-semibold text-sm shadow-sm transition-all flex items-center gap-2">
      <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/></svg>
      Source Code
    </a>
  </div>
</div>

<h2 id="two-core-deployment-modules">Two Core Deployment Modules</h2>

<p class="text-slate-600 mb-6">
  The extension integrates two specialized automation engines to cover both endpoint policy configuration and cloud zero-trust networking:
</p>

<div class="grid grid-cols-1 md:grid-cols-2 gap-6 my-8 not-prose">
  <!-- Module 1: CEP -->
  <div class="p-6 rounded-2xl bg-white border border-slate-200/80 shadow-md shadow-slate-100 hover:shadow-lg transition-all flex flex-col justify-between">
    <div>
      <div class="w-12 h-12 rounded-xl bg-sky-100 text-sky-600 flex items-center justify-center font-bold text-lg mb-4">
        CEP
      </div>
      <h3 class="text-xl font-bold text-slate-900 mb-2">1. CEP PoC Deployer</h3>
      <p class="text-xs font-semibold uppercase tracking-wider text-sky-600 mb-4">Chrome Enterprise Premium Module</p>
      <p class="text-sm text-slate-600 leading-relaxed mb-4">
        Accelerates the evaluation of Chrome's advanced security policies without manual configuration in the Admin Console:
      </p>
      <ul class="space-y-2 text-sm text-slate-600">
        <li class="flex items-start gap-2">
          <span class="text-sky-500 font-bold">&check;</span>
          <span><strong>Automated OU Setup:</strong> Dedicated test OUs (<code>CEP Users</code>, <code>CEP Browsers</code>) to isolate pilot evaluations.</span>
        </li>
        <li class="flex items-start gap-2">
          <span class="text-sky-500 font-bold">&check;</span>
          <span><strong>Threat Protection:</strong> Real-time URL checks, malware deep inspection, and password protections.</span>
        </li>
        <li class="flex items-start gap-2">
          <span class="text-sky-500 font-bold">&check;</span>
          <span><strong>Context-Aware Access (CAA):</strong> Device posture verification and Endpoint Verification requirements.</span>
        </li>
        <li class="flex items-start gap-2">
          <span class="text-sky-500 font-bold">&check;</span>
          <span><strong>Starter DLP Rules:</strong> Tailored data protection policies matching tenant primary domains.</span>
        </li>
      </ul>
    </div>
  </div>

  <!-- Module 2: SGW -->
  <div class="p-6 rounded-2xl bg-white border border-slate-200/80 shadow-md shadow-slate-100 hover:shadow-lg transition-all flex flex-col justify-between">
    <div>
      <div class="w-12 h-12 rounded-xl bg-indigo-100 text-indigo-600 flex items-center justify-center font-bold text-lg mb-4">
        SGW
      </div>
      <h3 class="text-xl font-bold text-slate-900 mb-2">2. SGW Deployer</h3>
      <p class="text-xs font-semibold uppercase tracking-wider text-indigo-600 mb-4">BeyondCorp Security Gateway Module</p>
      <p class="text-sm text-slate-600 leading-relaxed mb-4">
        Automates private zero-trust application access for managed Chrome browsers in Google Cloud:
      </p>
      <ul class="space-y-2 text-sm text-slate-600">
        <li class="flex items-start gap-2">
          <span class="text-indigo-500 font-bold">&check;</span>
          <span><strong>3 Gateway Architectures:</strong> Path A (Load Balancer & Nginx offload), Path B (Direct HTTPS), Path C (Cloud Run).</span>
        </li>
        <li class="flex items-start gap-2">
          <span class="text-indigo-500 font-bold">&check;</span>
          <span><strong>Least-Privilege Security:</strong> Provisions scoped service accounts and custom project IAM roles.</span>
        </li>
        <li class="flex items-start gap-2">
          <span class="text-indigo-500 font-bold">&check;</span>
          <span><strong>Infrastructure Automation:</strong> VPC subnets, firewall rules, private DNS zones, and Private CA certificate issuance.</span>
        </li>
        <li class="flex items-start gap-2">
          <span class="text-indigo-500 font-bold">&check;</span>
          <span><strong>Audit & Verification:</strong> Pre-flight checks, live health probes, and SHA-256 evidence generation.</span>
        </li>
      </ul>
    </div>
  </div>
</div>

---

## 5-Stage Orchestration Cycle

All deployments follow a strict, auditable lifecycle designed to guarantee zero unintended changes:

<div class="grid grid-cols-1 sm:grid-cols-5 gap-3 my-6 not-prose">
  <div class="p-4 rounded-xl bg-white border border-slate-200 text-center">
    <div class="w-8 h-8 rounded-full bg-slate-100 text-slate-700 font-bold text-sm mx-auto mb-2 flex items-center justify-center">1</div>
    <div class="font-bold text-sm text-slate-900">Plan</div>
    <div class="text-xs text-slate-500 mt-1">Read-only diff of proposed changes</div>
  </div>
  <div class="p-4 rounded-xl bg-white border border-slate-200 text-center">
    <div class="w-8 h-8 rounded-full bg-slate-100 text-slate-700 font-bold text-sm mx-auto mb-2 flex items-center justify-center">2</div>
    <div class="font-bold text-sm text-slate-900">Approve</div>
    <div class="text-xs text-slate-500 mt-1">Explicit admin confirmation required</div>
  </div>
  <div class="p-4 rounded-xl bg-white border border-slate-200 text-center">
    <div class="w-8 h-8 rounded-full bg-slate-100 text-slate-700 font-bold text-sm mx-auto mb-2 flex items-center justify-center">3</div>
    <div class="font-bold text-sm text-slate-900">Apply</div>
    <div class="text-xs text-slate-500 mt-1">API writes via admin credentials</div>
  </div>
  <div class="p-4 rounded-xl bg-white border border-slate-200 text-center">
    <div class="w-8 h-8 rounded-full bg-slate-100 text-slate-700 font-bold text-sm mx-auto mb-2 flex items-center justify-center">4</div>
    <div class="font-bold text-sm text-slate-900">Verify</div>
    <div class="text-xs text-slate-500 mt-1">SHA-256 audit chain confirmation</div>
  </div>
  <div class="p-4 rounded-xl bg-white border border-slate-200 text-center">
    <div class="w-8 h-8 rounded-full bg-slate-100 text-slate-700 font-bold text-sm mx-auto mb-2 flex items-center justify-center">5</div>
    <div class="font-bold text-sm text-slate-900">Rollback</div>
    <div class="text-xs text-slate-500 mt-1">Complete teardown of created resources</div>
  </div>
</div>

---

## Detailed API Calls & Host Permissions

The extension calls Google APIs directly from the local browser runtime (`https://*.googleapis.com`). No intermediate proxy or external server is contacted.

| Google API Host Endpoint | Component | Purpose & Operation Performed |
|---|---|---|
| `admin.googleapis.com` | CEP & SGW | Reads organizational units and tenant domain (`admin.directory.customer.readonly`), creates test sub-OUs (`admin.directory.orgunit`), and lists user groups. |
| `cloudidentity.googleapis.com` | CEP | Manages DLP policies and rule detectors (`cloud-identity.policies`) for Chrome content inspection. |
| `chromepolicy.googleapis.com` | CEP & SGW | Applies Chrome policies (Threat Protection, Extension Settings, Endpoint Verification) to target test OUs. |
| `chromemanagement.googleapis.com` | CEP | Verifies managed browser enrollment and security telemetry reporting. |
| `accesscontextmanager.googleapis.com` | CEP & SGW | Reads and binds Context-Aware Access levels and device posture criteria. |
| `iamcredentials.googleapis.com` | SGW | Generates short-lived credentials (`generateAccessToken`) for the scoped deployer service account. |
| `iam.googleapis.com` | SGW | Creates the deployer service account and configures custom IAM project roles. |
| `cloudresourcemanager.googleapis.com` | SGW | Resolves GCP project/organization IDs and binds project IAM policies. |
| `serviceusage.googleapis.com` | SGW | Enables required Google Cloud service APIs (BeyondCorp, Compute, DNS, etc.) in the project. |
| `beyondcorp.googleapis.com` | SGW | Configures Security Gateways, App Connections, and Client Gateways. |
| `compute.googleapis.com` | SGW (Path A) | Provisions VPC subnets, firewall rules, instance templates, and internal load balancers. |
| `dns.googleapis.com` | SGW (Path A) | Manages private DNS zones and records for internal application resolution. |
| `secretmanager.googleapis.com` | SGW | Stores and rotates TLS certificates and private keys. |
| `privateca.googleapis.com` | SGW | Issues PoC certificates from Google Cloud Certificate Authority Service. |
| `cloudbilling.googleapis.com` | SGW | Verifies that the Google Cloud project has an active billing account prior to deployment. |
| `licensing.googleapis.com` | CEP | Confirms active Chrome Enterprise Premium subscription licenses. |
| `logging.googleapis.com` | SGW | Fetches diagnostic and audit logs for verification and evidence export. |

---

## OAuth Scopes Justification

In compliance with the Google API Services User Data Policy, only scopes strictly necessary for operation are requested:

| OAuth Scope | Primary Engine | Justification & Principle of Least Privilege |
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

<div class="grid grid-cols-1 md:grid-cols-3 gap-4 my-6 not-prose">
  <div class="p-5 rounded-xl bg-white border border-slate-200 shadow-sm">
    <div class="text-sky-600 font-bold text-base mb-1">100% Client-Side</div>
    <div class="text-xs text-slate-500 leading-relaxed">Runs entirely in your local browser runtime. Zero backend, zero telemetry, and zero third-party servers.</div>
  </div>
  <div class="p-5 rounded-xl bg-white border border-slate-200 shadow-sm">
    <div class="text-sky-600 font-bold text-base mb-1">In-Memory Tokens</div>
    <div class="text-xs text-slate-500 leading-relaxed">OAuth access tokens remain strictly in volatile memory. Never written to disk or storage.</div>
  </div>
  <div class="p-5 rounded-xl bg-white border border-slate-200 shadow-sm">
    <div class="text-sky-600 font-bold text-base mb-1">Local Audit Store</div>
    <div class="text-xs text-slate-500 leading-relaxed">All evidence and SHA-256 logs stay in your browser IndexedDB and are exportable as JSON anytime.</div>
  </div>
</div>

For full privacy commitments, see the [Privacy Policy](privacy.html).

---

## Independent Open Source Notice

Chrome Enterprise Premium PoC Deployer is an **independent open-source project** published under the Apache 2.0 License at [github.com/dymzd/Google](https://github.com/dymzd/Google).

It is **not built, endorsed, or supported by Google LLC**, and is not an official Google product. "Google", "Google Workspace", "Google Cloud", "Chrome", and "Chrome Enterprise Premium" are trademarks of Google LLC.

---

## Support & Issue Reporting

* **Tool Issues & Feature Requests**: Open an issue on our [GitHub Issues page](https://github.com/dymzd/Google/issues).
* **Google Product Licensing & Support**: Contact your Google account representative (FSR / CE / CSM) or visit the [Google Cloud Support Center](https://cloud.google.com/support).
