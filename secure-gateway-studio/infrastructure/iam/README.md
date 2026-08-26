# Deployer identity

Secure Gateway Studio uses a dedicated service account through short-lived
impersonated credentials. Do not create or download a service-account key. The
ID step can create or reconcile the account and its GCP bindings automatically
with the active administrator session (browser OAuth in the extension, or
gcloud ADC in the loopback app).

The operator needs `roles/iam.serviceAccountTokenCreator` only on the deployer
service account. The deployer needs:

1. `roles/serviceusage.serviceUsageConsumer` on the deployment project, so
   impersonated requests can consume project quota;
2. the PoC project custom role in
   `secure-gateway-poc-deployer-role.yaml` (created automatically by the app),
   or the standalone role in `secure-gateway-deployer-role.yaml`, which adds the
   seven read/base permissions otherwise supplied by the standard roles; and
3. for the loopback runtime, direct Google Admin Console roles containing the
   required Chrome Policy, Directory OU/group/user, and License Management
   privileges, scoped to the dedicated test OU where the Admin console permits.

The extension calls Directory, Chrome Policy, licensing, and Cloud Identity
with the signed-in administrator's browser OAuth token; project IAM cannot
grant those Workspace privileges. Cloud Identity DLP mutations require the
dedicated Super Administrator described in the main README.

The custom role is intentionally high impact and is not a per-run role: it is
the project-permission union for all three supported implementations
(extension paths A/C and local path B), so it can create and roll back network,
compute, DNS, IAM, certificate, and secret resources. The approved plan and
preflight constrain each run to its selected path's subset. Its creation and
binding require a separate privileged approval; a future capability-specific
role split would reduce standing permissions further:

```bash
gcloud iam roles create secureGatewayStudioDeployer \
  --project=PROJECT_ID \
  --file=infrastructure/iam/secure-gateway-deployer-role.yaml

gcloud projects add-iam-policy-binding PROJECT_ID \
  --member=serviceAccount:secure-gateway-deployer@PROJECT_ID.iam.gserviceaccount.com \
  --role=projects/PROJECT_ID/roles/secureGatewayStudioDeployer \
  --condition=None
```

## Shared VPC or other cross-project upstream

Bootstrap creates and grants the deployer role only in the deployment project.
It intentionally does not mutate an upstream VPC project. A project custom role
can be granted only in the project that owns it, so the deployment project's
`secureGatewayStudioDeployer` role is not grantable in a Shared VPC host
project.

After bootstrap has created the deployment-project service account, but before
cross-project validation or preflight, an upstream-project administrator must
manually create and grant the exact role in
`secure-gateway-upstream-role.yaml`. Its complete permission set is:

1. `compute.networks.get`
2. `compute.networks.use`
3. `resourcemanager.projects.get`
4. `resourcemanager.projects.getIamPolicy`
5. `resourcemanager.projects.setIamPolicy`

From `secure-gateway-studio/`, replace both IDs and run:

```bash
gcloud iam roles create secureGatewayStudioUpstream \
  --project=UPSTREAM_PROJECT_ID \
  --file=infrastructure/iam/secure-gateway-upstream-role.yaml

gcloud projects add-iam-policy-binding UPSTREAM_PROJECT_ID \
  --member=serviceAccount:secure-gateway-deployer@DEPLOYMENT_PROJECT_ID.iam.gserviceaccount.com \
  --role=projects/UPSTREAM_PROJECT_ID/roles/secureGatewayStudioUpstream \
  --condition=None
```

The upstream administrator needs project custom-role creation and allow-policy
management authority there (for example, `roles/iam.roleAdmin` and
`roles/resourcemanager.projectIamAdmin`, or equivalent custom roles). If the
role already exists, review and reconcile it instead of granting an unknown or
broader definition. This manually managed prerequisite is not owned or removed
by Secure Gateway Studio teardown.

Configure local keyless ADC:

```bash
gcloud auth application-default login \
  --impersonate-service-account=secure-gateway-deployer@PROJECT_ID.iam.gserviceaccount.com
gcloud auth application-default set-quota-project PROJECT_ID
```

The loopback app rejects ADC loaded directly from a service-account JSON key.
Both runtimes use Admin Directory, but neither uses domain-wide delegation:
authority comes from direct Admin Console role assignment or the signed-in
administrator, as described above.
