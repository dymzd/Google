/**
 * Register every browser lifecycle wake that must reconcile durable work.
 *
 * Chrome can install an update while no extension page is open. `onStartup`
 * does not fire in that case, so both events must enter the same cold-start
 * path. Keeping this wiring outside the service-worker module also gives the
 * release checks an executable seam instead of relying on source matching.
 */
export interface ColdStartEvent<TArgs extends readonly unknown[]> {
  addListener(listener: (...args: TArgs) => void): void;
}

export interface ColdStartWakeups {
  onInstalled: ColdStartEvent<readonly [details: unknown]>;
  onStartup: ColdStartEvent<readonly []>;
}

export function registerColdStartWakeups(
  wakeups: ColdStartWakeups,
  reconcile: () => Promise<void>,
): void {
  const wake = (): void => {
    void reconcile().catch(() => {
      // A later alarm/message/startup wake retries the durable reconciliation.
      // The service worker must never turn an install/update event into an
      // unhandled rejection.
    });
  };
  wakeups.onInstalled.addListener(wake);
  wakeups.onStartup.addListener(wake);
}

/**
 * Preserve the first-screen privacy boundary around cold-start inspection.
 * `inspectDurableState` is not invoked until the current disclosure metadata
 * says consent is complete.
 */
export async function reconcileAfterConsent(options: {
  consentAccepted: () => Promise<boolean>;
  inspectDurableState: () => Promise<void>;
}): Promise<boolean> {
  if (!(await options.consentAccepted())) return false;
  await options.inspectDurableState();
  return true;
}
