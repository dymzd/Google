/**
 * Startup-script rendering.
 *
 * The scripts themselves are generated from the Python implementation into
 * `startup-scripts.generated.ts` rather than retyped, because two subtly
 * different Nginx offload configurations would behave differently with no test
 * able to see it. This module only substitutes the five values that vary per
 * deployment.
 */

import { configurationHash } from "../domain/planner.ts";
import type { DeploymentSpec } from "../domain/spec.ts";
import {
  OFFLOAD_EXISTING_BACKEND,
  OFFLOAD_HARDENED,
  OFFLOAD_MANAGED_SAMPLE,
  SAMPLE_BACKEND,
  SAMPLE_BACKEND_HARDENED,
} from "./startup-scripts.generated.ts";

export interface StartupContext {
  /** Reserved internal address of the sample backend, when one is deployed. */
  backendAddress?: string;
  /** Plan-bound immutable public SecretVersion; aliases are forbidden. */
  publicCertificateVersionName?: string;
}

function tlsSecretName(spec: DeploymentSpec): string {
  return spec.certificate_strategy === "public_trusted" && spec.public_certificate_secret
    ? (spec.public_certificate_secret.split("/").pop() as string)
    : `${spec.name}-tls`;
}

function render(
  template: string,
  spec: DeploymentSpec,
  backendUrl: string,
  publicCertificateVersionName?: string,
): string {
  let secret: string;
  if (spec.certificate_strategy === "public_trusted") {
    const expectedPrefix =
      `projects/${spec.project_id}/secrets/${tlsSecretName(spec)}/versions/`;
    if (
      template.includes("@@SECRET_VERSION@@") &&
      (typeof publicCertificateVersionName !== "string" ||
        !publicCertificateVersionName.startsWith(expectedPrefix) ||
        !/^[1-9][0-9]*$/.test(publicCertificateVersionName.slice(expectedPrefix.length)))
    ) {
      throw new Error("A numeric Plan-bound public certificate version is required");
    }
    secret = publicCertificateVersionName ?? `${expectedPrefix}invalid`;
  } else {
    secret =
      `projects/${spec.project_id}/secrets/${tlsSecretName(spec)}/versions/active`;
  }

  return template
    .replaceAll("@@BACKEND_URL@@", backendUrl)
    .replaceAll("@@PRIVATE_HOSTNAME@@", spec.private_hostname)
    .replaceAll("@@SECRET_VERSION@@", secret)
    .replaceAll(
      "@@PIN_PRESENTED_CHAIN@@",
      spec.certificate_strategy === "public_trusted" ? "False" : "True",
    )
    .replaceAll("@@CONFIGURATION_HASH@@", configurationHash(spec));
}

export function offloadStartupScript(
  spec: DeploymentSpec,
  context: StartupContext = {},
): string {
  if (spec.backend_kind === "managed_sample") {
    if (context.backendAddress === undefined) {
      throw new Error("The sample backend address must be resolved before the offload VM");
    }
    // Production runs on an immutable hardened image that already ships Nginx
    // and Python, and must never install packages from a mutable repository at
    // boot. The choice follows mode, not whether an image happens to be set.
    const template = spec.mode === "production" ? OFFLOAD_HARDENED : OFFLOAD_MANAGED_SAMPLE;
    return render(
      template,
      spec,
      `http://${context.backendAddress}`,
      context.publicCertificateVersionName,
    );
  }
  return render(
    OFFLOAD_EXISTING_BACKEND,
    spec,
    String(spec.existing_backend_url),
    context.publicCertificateVersionName,
  );
}

export function sampleBackendStartupScript(spec: DeploymentSpec): string {
  // The sample backend is used both by Option C managed-sample deployments and
  // by the local Option B ILB path. Production must consume only the packages
  // baked into the approval-bound immutable image; boot-time apt repositories
  // would make the approved artifact non-reproducible.
  return render(spec.mode === "production" ? SAMPLE_BACKEND_HARDENED : SAMPLE_BACKEND, spec, "");
}
