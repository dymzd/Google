/**
 * Startup-script rendering.
 *
 * The scripts themselves are generated from the Python implementation into
 * `startup-scripts.generated.ts` rather than retyped, because two subtly
 * different Nginx offload configurations would behave differently with no test
 * able to see it. This module only substitutes the four values that vary per
 * deployment.
 */

import { configurationHash } from "../domain/planner.ts";
import type { DeploymentSpec } from "../domain/spec.ts";
import {
  OFFLOAD_EXISTING_BACKEND,
  OFFLOAD_HARDENED,
  OFFLOAD_MANAGED_SAMPLE,
  SAMPLE_BACKEND,
} from "./startup-scripts.generated.ts";

export interface StartupContext {
  /** Reserved internal address of the sample backend, when one is deployed. */
  backendAddress?: string;
}

function tlsSecretName(spec: DeploymentSpec): string {
  return spec.certificate_strategy === "public_trusted" && spec.public_certificate_secret
    ? (spec.public_certificate_secret.split("/").pop() as string)
    : `${spec.name}-tls`;
}

function render(template: string, spec: DeploymentSpec, backendUrl: string): string {
  // A publicly trusted secret is managed outside the deployment and read at
  // `latest`; anything this deployment issues is promoted through the `active`
  // alias so a rotation is atomic.
  const version = spec.certificate_strategy === "public_trusted" ? "latest" : "active";
  const secret =
    `projects/${spec.project_id}/secrets/${tlsSecretName(spec)}/versions/${version}`;

  return template
    .replaceAll("@@BACKEND_URL@@", backendUrl)
    .replaceAll("@@PRIVATE_HOSTNAME@@", spec.private_hostname)
    .replaceAll("@@SECRET_VERSION@@", secret)
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
    return render(template, spec, `http://${context.backendAddress}`);
  }
  return render(OFFLOAD_EXISTING_BACKEND, spec, String(spec.existing_backend_url));
}

export function sampleBackendStartupScript(spec: DeploymentSpec): string {
  return render(SAMPLE_BACKEND, spec, "");
}
