import { describe, expect, it, vi } from "vitest";

import {
  acceptAndMigrateExtensionState,
  loadPreviouslyAcceptedExtensionState,
} from "./extension-state";
import { clearLegacyExtensionState } from "./setup-state";

function dependencies() {
  const order: string[] = [];
  return {
    order,
    values: {
      consentStatus: vi.fn(async () => {
        order.push("status");
        return { accepted: false, migrationPrepared: false, version: null };
      }),
      loadEncryptedState: vi.fn(async () => {
        order.push("load-encrypted");
        return { setup: { projectId: "encrypted-project" }, workflow: { runId: "run-1" } };
      }),
      prepare: vi.fn(async () => {
        order.push("prepare");
        return { prepared: true as const };
      }),
      finalize: vi.fn(async () => {
        order.push("finalize");
        return { accepted: true, migrationPrepared: false, version: "0.2.1" };
      }),
      readLegacySetup: vi.fn(() => {
        order.push("read-setup");
        return { projectId: "legacy-project" } as never;
      }),
      readLegacyWorkflow: vi.fn(() => {
        order.push("read-workflow");
        return { planId: "plan-1", approvalId: "", runId: "" };
      }),
      clearLegacySetup: vi.fn(() => order.push("clear-setup")),
      clearLegacyWorkflow: vi.fn(() => order.push("clear-workflow")),
    },
  };
}

describe("extension consent ordering", () => {
  it("clears every old SGS localStorage value except the non-sensitive locale", () => {
    window.localStorage.setItem("sgs.setup.v8", "operator@enterprise.example.com");
    window.localStorage.setItem("sgs.principals.run-1", "group:users@enterprise.example.com");
    window.localStorage.setItem("sgs.locale.v1", "ja");
    clearLegacyExtensionState();
    expect(window.localStorage.getItem("sgs.setup.v8")).toBeNull();
    expect(window.localStorage.getItem("sgs.principals.run-1")).toBeNull();
    expect(window.localStorage.getItem("sgs.locale.v1")).toBe("ja");
    window.localStorage.removeItem("sgs.locale.v1");
  });

  it("does not read legacy state when durable consent is absent", async () => {
    const { order, values } = dependencies();
    expect(await loadPreviouslyAcceptedExtensionState(values)).toBeNull();
    expect(order).toEqual(["status"]);
    expect(values.readLegacySetup).not.toHaveBeenCalled();
    expect(values.loadEncryptedState).not.toHaveBeenCalled();
  });

  it("encrypts, clears both cleartext surfaces, then finalizes and decrypts", async () => {
    const { order, values } = dependencies();
    const restored = await acceptAndMigrateExtensionState(values);
    expect(restored.setup).toEqual({ projectId: "encrypted-project" });
    expect(order).toEqual([
      "read-setup",
      "read-workflow",
      "prepare",
      "clear-setup",
      "clear-workflow",
      "finalize",
      "load-encrypted",
    ]);
  });
});
