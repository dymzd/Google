import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { getMessages } from "../../i18n/messages";
import { defaultSetupState } from "../../lib/setup-state";
import { EnvironmentStep } from "./ConfigurationSteps";

const exactUpstreamPermissions = [
  "compute.networks.get",
  "compute.networks.use",
  "resourcemanager.projects.get",
  "resourcemanager.projects.getIamPolicy",
  "resourcemanager.projects.setIamPolicy",
].sort();

function permissionsIn(text: string): string[] {
  return [...text.matchAll(/\b(?:compute|resourcemanager)\.[A-Za-z.]+\b/g)]
    .map(([permission]) => permission)
    .sort();
}

describe("Shared VPC prerequisite disclosure", () => {
  it("shows the exact manual upstream-project grant in the English environment UI", () => {
    render(
      <EnvironmentStep
        messages={getMessages("en")}
        onPatch={vi.fn()}
        state={{
          ...defaultSetupState,
          backendKind: "direct_https",
          networkStrategy: "existing",
          upstreamVpcProjectId: "shared-vpc-host-123",
        }}
      />,
    );

    const notice = screen.getByText(/Cross-project prerequisite:/);
    expect(permissionsIn(notice.textContent ?? "")).toEqual(exactUpstreamPermissions);
    expect(notice).toHaveTextContent("before validation or preflight");
    expect(notice).toHaveTextContent("Bootstrap configures only the deployment project");
    expect(notice).toHaveTextContent(
      "A project custom role created in the deployment project cannot be granted in the upstream project",
    );
  });

  it("shows the same exact boundary in Japanese and in both guide translations", () => {
    render(
      <EnvironmentStep
        messages={getMessages("ja")}
        onPatch={vi.fn()}
        state={{
          ...defaultSetupState,
          backendKind: "direct_https",
          networkStrategy: "existing",
          upstreamVpcProjectId: "shared-vpc-host-123",
        }}
      />,
    );

    const notice = screen.getByText(/クロスプロジェクトの前提条件:/);
    expect(permissionsIn(notice.textContent ?? "")).toEqual(exactUpstreamPermissions);
    expect(notice).toHaveTextContent("初回準備が構成するのはデプロイ先プロジェクトだけ");

    for (const locale of ["en", "ja"] as const) {
      const guideText = getMessages(locale).guide.steps
        .flatMap((step) => step.actions)
        .find((action) => action.includes("compute.networks.get"));
      expect(guideText).toBeDefined();
      expect(permissionsIn(guideText ?? "")).toEqual(exactUpstreamPermissions);
    }
  });
});
