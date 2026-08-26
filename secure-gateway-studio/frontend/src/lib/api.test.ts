import { describe, expect, it, vi } from "vitest";
import {
  bootstrapGoogleCloudDeployer,
  getRecommendedPocSourceImage,
  resumeDeploymentRun,
  signOutSession,
} from "./api";

describe("local HTTP API contract", () => {
  it("omits the extension-only access_policy_id from FastAPI bootstrap", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ session_nonce: "test-session" }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ project_id: "project-1" }),
      });
    vi.stubGlobal("fetch", fetchMock);

    await bootstrapGoogleCloudDeployer("project-1", "999");

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const request = fetchMock.mock.calls[1]?.[1] as RequestInit;
    expect(JSON.parse(request.body as string)).toEqual({
      project_id: "project-1",
      confirmation: "BOOTSTRAP",
    });
  });

  it("does not call the extension-only sign-out route", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await signOutSession();

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("reads the immutable PoC source image returned by the extension contract", async () => {
    const option = {
      value: "projects/debian-cloud/global/images/debian-12-bookworm-v20260801",
      label: "Google Debian 12",
      description: "Immutable public PoC image · numeric ID 1234567890123456789",
    };
    const fetchMock = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) =>
      String(input).endsWith("/api/v1/health")
        ? {
            ok: true,
            status: 200,
            json: async () => ({ session_nonce: "test-session" }),
          }
        : {
        ok: true,
        status: 200,
        json: async () => ({ option }),
          });
    vi.stubGlobal("fetch", fetchMock);

    await expect(getRecommendedPocSourceImage("project-1")).resolves.toEqual(option);
    const request = fetchMock.mock.calls.at(-1)?.[1] as RequestInit;
    expect(JSON.parse(request.body as string)).toEqual({ project_id: "project-1" });
  });

  it("refreshes a rotated backend session nonce before resuming", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            detail: {
              code: "session-invalid",
              message: "The local API session is missing or invalid",
            },
          }),
          { status: 403, headers: { "Content-Type": "application/json" } },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ session_nonce: "refreshed-session" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ run_id: "run-interrupted", status: "running" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      );
    vi.stubGlobal("fetch", fetchMock);

    await resumeDeploymentRun("run-interrupted");

    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(String(fetchMock.mock.calls[1]?.[0])).toBe("/api/v1/health");
    const retriedRequest = fetchMock.mock.calls[2]?.[1] as RequestInit;
    expect(retriedRequest.headers).toMatchObject({
      "X-SGS-Session": "refreshed-session",
    });
    expect(retriedRequest.body).toBe(JSON.stringify({ confirmation: "RESUME" }));
  });
});
