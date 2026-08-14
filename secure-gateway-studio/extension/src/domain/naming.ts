/**
 * Resource naming. Port of `domain/naming.py`.
 *
 * Service-account IDs are capped at 30 characters by Google. When the natural
 * name would overflow, a digest of the deployment name is folded in so the
 * result stays stable for a given deployment rather than being truncated into
 * a collision with a differently-named one.
 */

import { sha256HexOfString } from "./sha256.ts";

/** A stable Google service-account ID within the 30-character limit. */
export function serviceAccountId(deploymentName: string, role: string): string {
  const candidate = `${deploymentName}-${role}`;
  if (candidate.length <= 30) return candidate;
  const digest = sha256HexOfString(deploymentName).slice(0, 6);
  const prefixLength = 30 - role.length - digest.length - 2;
  const prefix = deploymentName.slice(0, prefixLength).replace(/-+$/, "") || "sgs";
  return `${prefix}-${digest}-${role}`;
}

export function serviceAccountEmail(
  deploymentName: string,
  projectId: string,
  role: string,
): string {
  return `${serviceAccountId(deploymentName, role)}@${projectId}.iam.gserviceaccount.com`;
}
