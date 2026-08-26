import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { UserDataDisclosure } from "./UserDataDisclosure";

describe("UserDataDisclosure", () => {
  it("prominently discloses handled data and requires an affirmative action", () => {
    const onAccept = vi.fn();
    render(<UserDataDisclosure locale="en" onAccept={onAccept} />);

    expect(
      screen.getByText(/administrator email, immutable Google account identifier/),
    ).toBeVisible();
    expect(screen.getByText(/binds approvals and privileged actions/)).toBeVisible();
    expect(screen.getByText(/Diagnostic reads exclude URL paths/)).toBeVisible();
    expect(
      screen.getByText(/approve Security Gateway creation.*enables full Secure Gateway connection records in Cloud Logging/i),
    ).toBeVisible();
    expect(screen.getByText(/records’ contents, retention, and access follow your Google Cloud configuration/i)).toBeVisible();
    expect(screen.getByText(/developer receives none of them/i)).toBeVisible();
    expect(screen.getByText(/developer receives no tenant data/i)).toBeVisible();
    expect(screen.getByText(/encrypted at rest.*non-extractable key/i)).toBeVisible();
    expect(screen.getByText(/TLS private key.*cleared when the run terminates/i)).toBeVisible();
    expect(
      screen.getByText(/existing public-certificate secret.*private key.*never persists it, saves it as a file, passes it to chrome\.downloads, or retransmits it/i),
    ).toBeVisible();
    expect(screen.getByRole("link", { name: "Read the complete Privacy Policy" })).toHaveAttribute(
      "href",
      "https://test-domain.dev/privacy.html",
    );

    fireEvent.click(screen.getByRole("button", { name: "I understand and continue" }));
    expect(onAccept).toHaveBeenCalledOnce();
  });

  it("provides the same connection-logging disclosure in Japanese", () => {
    render(<UserDataDisclosure locale="ja" onAccept={() => undefined} />);
    expect(
      screen.getByText(/Security Gateway の作成を承認すると.*Cloud Logging.*完全な接続レコード/),
    ).toBeVisible();
    expect(screen.getByText(/内容、保持期間、アクセス管理はお客様の Google Cloud 設定に従い/)).toBeVisible();
    expect(screen.getByText(/開発者はこれらのレコードを一切受け取りません/)).toBeVisible();
  });
});
