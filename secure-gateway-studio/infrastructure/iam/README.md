# Deployer identity

Secure Gateway Studio uses a dedicated service account through short-lived
impersonated credentials. Do not create or download a service-account key. The
ID step can create or reconcile the account and its GCP bindings automatically
with the active gcloud administrator.

The operator needs `roles/iam.serviceAccountTokenCreator` only on the deployer
service account. The deployer needs:

1. `roles/serviceusage.serviceUsageConsumer` on the deployment project, so
   impersonated requests can consume project quota;
2. the PoC project custom role in
   `secure-gateway-poc-deployer-role.yaml` (created automatically by the app),
   or the broader Production-capable role in `secure-gateway-deployer-role.yaml`;
   and
3. a direct Google Admin Console role containing the required Chrome Policy
   privileges, scoped to the dedicated test OU.

The custom role is intentionally high impact: it can create and roll back
network, compute, DNS, IAM, certificate, and secret resources. Its creation and
binding require a separate privileged approval:

```bash
gcloud iam roles create secureGatewayStudioDeployer \
  --project=PROJECT_ID \
  --file=infrastructure/iam/secure-gateway-deployer-role.yaml

gcloud projects add-iam-policy-binding PROJECT_ID \
  --member=serviceAccount:secure-gateway-deployer@PROJECT_ID.iam.gserviceaccount.com \
  --role=projects/PROJECT_ID/roles/secureGatewayStudioDeployer \
  --condition=None
```

Configure local keyless ADC:

```bash
gcloud auth application-default login \
  --impersonate-service-account=secure-gateway-deployer@PROJECT_ID.iam.gserviceaccount.com
gcloud auth application-default set-quota-project PROJECT_ID
```

The app rejects ADC loaded directly from a service-account JSON key. It does
not use Admin Directory or domain-wide delegation.
