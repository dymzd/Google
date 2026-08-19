import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { CepDeployerPage } from "./CepDeployerPage";
import { getMessages } from "../../i18n/messages";
import * as api from "../../lib/api";

const messages = getMessages("ja");
const m = messages.cepDeployer;

const OU_OPTIONS = [
  { value: "03pilot", label: "/Pilot", description: "Pilot" },
  { value: "03root", label: "/", description: "Root" },
];

const ACCESS_LEVELS = [
  {
    value: "accessPolicies/123/accessLevels/corp_managed",
    label: "Corporate managed devices",
    description: "",
  },
];

function renderPage() {
  const rendered = render(
    <CepDeployerPage customerId="C012345" messages={messages} projectId="my-test-proj" />,
  );
  // Simulate clicking the verify button to load OUs in tests
  const verifyBtn = screen.queryByText(/Verify Google Account & Load OUs/i);
  if (verifyBtn) {
    fireEvent.click(verifyBtn);
  }
  return rendered;
}

function emptyResult(overrides: Partial<api.CepProvisionResult> = {}): api.CepProvisionResult {
  return {
    success: true,
    message: "ok",
    created_items: [],
    skipped_items: [],
    debug_trace: [],
    ...overrides,
  };
}

describe("CepDeployerPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(api, "listOrganizationalUnitOptions").mockResolvedValue(OU_OPTIONS);
    vi.spyOn(api, "listAccessLevelOptions").mockResolvedValue(ACCESS_LEVELS);
  });

  it("renders the modules and presets it can actually apply", async () => {
    renderPage();

    expect(screen.getByText(m.title)).toBeInTheDocument();
    expect(screen.getByText(m.presetFullPoc)).toBeInTheDocument();
    expect(screen.getByText(m.moduleCorePolicies)).toBeInTheDocument();
    expect(screen.getByText(m.moduleConnectors)).toBeInTheDocument();
    // Context-Aware Access is a dropdown now, not a toggle: an existing level
    // can be selected instead of only ever creating one.
    expect(screen.getByLabelText(m.accessLevelTitle)).toBeInTheDocument();
    expect(screen.getByText(m.accessLevelAutoAny)).toBeInTheDocument();

    // DLP rules and watermarking have no API, so they are listed as manual
    // Admin Console steps rather than as toggles that would do nothing.
    const manualTitles = m.manualChecklistItems.map((item) => item.title);
    for (const title of manualTitles) {
      expect(screen.getByText(title)).toBeInTheDocument();
    }
  });

  it("sends the selected OU, its path, and the module choices", async () => {
    const provision = vi.spyOn(api, "provisionCepPolicies").mockResolvedValue(
      emptyResult({ message: "Applied 5 CEP settings to the target OU.", created_items: ["Enhanced Safe Browsing"] }),
    );

    renderPage();
    await waitFor(() => expect(screen.getByLabelText(m.selectTargetOu)).toHaveValue("03pilot"));

    fireEvent.click(screen.getByText(m.btnDeploy));

    await waitFor(() => {
      expect(provision).toHaveBeenCalledWith(
        expect.objectContaining({
          target_ou_id: "03pilot",
          target_ou_path: "/Pilot",
          create_sub_ous: true,
          core_policies: true,
          connectors: true,
          dlp_detectors: true,
          dlp_rules: true,
        }),
      );
    });
    expect(screen.getByText("Applied 5 CEP settings to the target OU.")).toBeInTheDocument();
  });

  it("shows what was applied and what was skipped, not just the trace", async () => {
    vi.spyOn(api, "provisionCepPolicies").mockResolvedValue(
      emptyResult({
        created_items: ["Enhanced Safe Browsing"],
        skipped_items: ["Security event reporting: policy schema is not available"],
        debug_trace: [
          {
            label: "Apply core policies (4)",
            method: "POST",
            url: "https://chromepolicy.googleapis.com",
            status: 200,
            ok: true,
          },
        ],
      }),
    );

    renderPage();
    await waitFor(() => expect(screen.getByLabelText(m.selectTargetOu)).toHaveValue("03pilot"));
    fireEvent.click(screen.getByText(m.btnDeploy));

    await waitFor(() => {
      expect(screen.getByText("Enhanced Safe Browsing")).toBeInTheDocument();
      expect(
        screen.getByText("Security event reporting: policy schema is not available"),
      ).toBeInTheDocument();
      expect(screen.getByText(/Apply core policies/)).toBeInTheDocument();
    });
  });

  it("refuses to deploy when the OU list could not be loaded", async () => {
    vi.spyOn(api, "listOrganizationalUnitOptions").mockRejectedValue(new Error("no access"));
    const provision = vi.spyOn(api, "provisionCepPolicies");

    renderPage();

    await waitFor(() => expect(screen.getByText(m.ouLoadFailed)).toBeInTheDocument());
    expect(screen.getByText(m.btnDeploy)).toBeDisabled();
    expect(provision).not.toHaveBeenCalled();
  });

  it("refuses to deploy when no module is selected", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByLabelText(m.selectTargetOu)).toHaveValue("03pilot"));

    // The accessible name of each toggle is its title plus its description, so
    // these match on the title alone.
    for (const label of [
      m.moduleCorePolicies,
      m.moduleForceExtensions,
      m.moduleConnectors,
      m.moduleDlpDetectors,
      m.moduleDlpRules,
    ]) {
      fireEvent.click(screen.getByLabelText(label, { exact: false }));
    }
    fireEvent.click(screen.getByLabelText(m.dataBoundaryModeNoneDesc, { exact: false }));
    fireEvent.change(screen.getByLabelText(m.accessLevelTitle), {
      target: { value: "NONE" },
    });

    expect(screen.getByText(m.btnDeploy)).toBeDisabled();
    expect(screen.getByText(m.noModulesSelected)).toBeInTheDocument();
  });

  it("copies the sample value alone, without its explanatory hint", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });

    renderPage();
    fireEvent.click(screen.getAllByText(m.copyDummyData)[0]);

    expect(writeText).toHaveBeenCalledWith(m.dummyPiiValue);
    expect(m.dummyPiiValue).not.toContain(m.dummyPiiHint);
  });

  it("reports a failed role provisioning as a failure", async () => {
    vi.spyOn(api, "createCepCustomRoles").mockResolvedValue({
      success: false,
      message: "CEP Policy Administrator: permission denied",
      roles: [],
      debug_trace: [],
    });

    renderPage();
    fireEvent.click(screen.getByText(m.provisionRolesButton));

    await waitFor(() => {
      expect(screen.getByText("CEP Policy Administrator: permission denied")).toBeInTheDocument();
    });
  });

  it("asks for confirmation before rolling back", async () => {
    const rollback = vi.spyOn(api, "rollbackCepPolicies").mockResolvedValue(emptyResult());
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);

    renderPage();
    await waitFor(() => expect(screen.getByLabelText(m.selectTargetOu)).toHaveValue("03pilot"));
    fireEvent.click(screen.getByText(m.btnRollback));

    expect(confirm).toHaveBeenCalledWith(m.confirmRollback);
    expect(rollback).not.toHaveBeenCalled();
  });

  it("assigns licenses to users in the selected OU when clicking the license button", async () => {
    const assign = vi.spyOn(api, "assignCepLicenses").mockResolvedValue({
      success: true,
      message: "組織部門「/Pilot」内のユーザー 3 名を処理しました（新規割り当て: 2 名、割り当て済み: 1 名）。",
      total_users: 3,
      assigned_count: 2,
      already_assigned_count: 1,
      failed_count: 0,
      assigned_users: ["user1@example.com", "user2@example.com"],
      errors: [],
      debug_trace: [],
    });

    renderPage();
    await waitFor(() => expect(screen.getByLabelText(m.selectTargetOu)).toHaveValue("03pilot"));

    expect(screen.getByText(m.licenseCardTitle)).toBeInTheDocument();
    expect(
      screen.getByText(m.licenseAutoAssignWarningLink, { exact: false }),
    ).toHaveAttribute("href", "https://admin.google.com/ac/billing/licensesettings");

    fireEvent.click(screen.getByText(m.btnAssignLicensesToOu));

    await waitFor(() => {
      expect(assign).toHaveBeenCalledWith({
        customer_id: "C012345",
        target_ou_id: "03pilot",
        target_ou_path: "/Pilot",
      });
      expect(
        screen.getByText(
          "組織部門「/Pilot」内のユーザー 3 名を処理しました（新規割り当て: 2 名、割り当て済み: 1 名）。",
        ),
      ).toBeInTheDocument();
    });
  });

  it("renders the DLP matrix table with presets and threat rows", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByLabelText(m.selectTargetOu)).toHaveValue("03pilot"));

    expect(screen.getByText(m.dlpMatrixTitle)).toBeInTheDocument();
    expect(screen.getByText(m.dlpRowUniversalUpload, { exact: false })).toBeInTheDocument();
    expect(screen.getByText(m.dlpRowUniversalDownload, { exact: false })).toBeInTheDocument();
    expect(screen.getByText(m.dlpRowPaymentCard, { exact: false })).toBeInTheDocument();
    expect(screen.getByText(m.dlpRowNationalId, { exact: false })).toBeInTheDocument();
    expect(screen.getByText(m.dlpRowAccessLevel, { exact: false })).toBeInTheDocument();
    expect(screen.getByText(m.dlpRowWatermark, { exact: false })).toBeInTheDocument();
    expect(screen.getByText(m.dlpRowGenAiBlock, { exact: false })).toBeInTheDocument();

    // Presets
    expect(screen.getByText(m.dlpPresetRecommended)).toBeInTheDocument();
    expect(screen.getByText(m.dlpPresetStrictZeroTrust)).toBeInTheDocument();
    expect(screen.getByText(m.dlpPresetGenAiSecure)).toBeInTheDocument();
    expect(screen.getByText(m.dlpPresetAuditOnly)).toBeInTheDocument();
  });
});
