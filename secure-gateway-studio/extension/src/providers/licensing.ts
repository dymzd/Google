export interface LicenseAssignmentIdentity {
  productId: string;
  skuId: string;
  userId: string;
  selfLink: string;
}

/** Strictly parse the immutable identity returned by License Manager. */
export function validateLicenseAssignment(
  payload: Record<string, unknown>,
  expected: { productId: string; skuId: string; userId?: string },
): LicenseAssignmentIdentity {
  if (
    payload.kind !== "licensing#licenseAssignment" ||
    payload.productId !== expected.productId ||
    payload.skuId !== expected.skuId ||
    typeof payload.userId !== "string" || payload.userId.trim() === "" ||
    typeof payload.selfLink !== "string"
  ) {
    throw new Error("license-assignment-identity-invalid");
  }
  let url: URL;
  try {
    url = new URL(payload.selfLink);
  } catch {
    throw new Error("license-assignment-self-link-invalid");
  }
  if (
    ![
      "https://licensing.googleapis.com",
      "https://www.googleapis.com",
    ].includes(url.origin) ||
    url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== ""
  ) {
    throw new Error("license-assignment-self-link-invalid");
  }
  const match = /^\/apps\/licensing\/v1\/product\/([^/]+)\/sku\/([^/]+)\/user\/([^/]+)$/.exec(
    url.pathname,
  );
  let linkProduct: string;
  let linkSku: string;
  let linkUser: string;
  try {
    if (match === null) throw new Error("shape");
    linkProduct = decodeURIComponent(match[1]!);
    linkSku = decodeURIComponent(match[2]!);
    linkUser = decodeURIComponent(match[3]!);
  } catch {
    throw new Error("license-assignment-self-link-invalid");
  }
  if (
    linkProduct !== expected.productId || linkSku !== expected.skuId ||
    linkUser.toLowerCase() !== payload.userId.trim().toLowerCase() ||
    (expected.userId !== undefined &&
      expected.userId.trim().toLowerCase() !== payload.userId.trim().toLowerCase())
  ) {
    throw new Error("license-assignment-self-link-mismatch");
  }
  return {
    productId: expected.productId,
    skuId: expected.skuId,
    userId: payload.userId.trim(),
    selfLink: payload.selfLink,
  };
}
