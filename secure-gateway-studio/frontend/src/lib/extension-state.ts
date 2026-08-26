import {
  finalizeUserDataConsent,
  getExtensionClientState,
  getUserDataConsentStatus,
  prepareUserDataConsent,
  type ExtensionClientState,
} from "./api";
import {
  clearLegacyExtensionState,
  loadSetupState,
} from "./setup-state";
import {
  clearWorkflowRefs,
  loadWorkflowRefs,
} from "./workflow-refs";

interface ConsentDependencies {
  consentStatus: typeof getUserDataConsentStatus;
  loadEncryptedState: typeof getExtensionClientState;
  prepare: typeof prepareUserDataConsent;
  finalize: typeof finalizeUserDataConsent;
  readLegacySetup: typeof loadSetupState;
  readLegacyWorkflow: typeof loadWorkflowRefs;
  clearLegacySetup: typeof clearLegacyExtensionState;
  clearLegacyWorkflow: typeof clearWorkflowRefs;
}

const defaults: ConsentDependencies = {
  consentStatus: getUserDataConsentStatus,
  loadEncryptedState: getExtensionClientState,
  prepare: prepareUserDataConsent,
  finalize: finalizeUserDataConsent,
  readLegacySetup: loadSetupState,
  readLegacyWorkflow: loadWorkflowRefs,
  clearLegacySetup: clearLegacyExtensionState,
  clearLegacyWorkflow: clearWorkflowRefs,
};

/** Check only durable consent metadata before the worker may decrypt state. */
export async function loadPreviouslyAcceptedExtensionState(
  dependencies: ConsentDependencies = defaults,
): Promise<ExtensionClientState | null> {
  const status = await dependencies.consentStatus();
  return status.accepted ? dependencies.loadEncryptedState() : null;
}

/**
 * Called only from the affirmative disclosure button.
 *
 * Legacy reads occur after that click, prepare encrypts both Chrome storage
 * surfaces, the page removes its cleartext keys, and only then does finalize
 * make background reconciliation reachable.
 */
export async function acceptAndMigrateExtensionState(
  dependencies: ConsentDependencies = defaults,
): Promise<ExtensionClientState> {
  const legacySetup = dependencies.readLegacySetup();
  const legacyWorkflow = dependencies.readLegacyWorkflow();
  await dependencies.prepare({ legacySetup, legacyWorkflow });
  dependencies.clearLegacySetup();
  dependencies.clearLegacyWorkflow();
  const status = await dependencies.finalize();
  if (!status.accepted) throw new Error("consent-finalization-failed");
  return dependencies.loadEncryptedState();
}
