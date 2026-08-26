export interface WorkflowRefs {
  planId: string;
  approvalId: string;
  runId: string;
}

const WORKFLOW_KEY = "sgs.workflow.v1";

export const emptyWorkflowRefs: WorkflowRefs = { planId: "", approvalId: "", runId: "" };

export function restoreWorkflowRefs(value: unknown): WorkflowRefs {
  if (!value || typeof value !== "object") return emptyWorkflowRefs;
  const candidate = value as Partial<WorkflowRefs>;
  return {
    planId: typeof candidate.planId === "string" ? candidate.planId : "",
    approvalId: typeof candidate.approvalId === "string" ? candidate.approvalId : "",
    runId: typeof candidate.runId === "string" ? candidate.runId : "",
  };
}

export function loadWorkflowRefs(): WorkflowRefs {
  try {
    const value: unknown = JSON.parse(
      window.localStorage.getItem(WORKFLOW_KEY) ?? "{}",
    );
    return restoreWorkflowRefs(value);
  } catch {
    return emptyWorkflowRefs;
  }
}

export function saveWorkflowRefs(refs: WorkflowRefs): void {
  window.localStorage.setItem(WORKFLOW_KEY, JSON.stringify(refs));
}

export function clearWorkflowRefs(): void {
  window.localStorage.removeItem(WORKFLOW_KEY);
}
