import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Reports, severityTone } from "./Reports";
import { ToastProvider } from "../../components/Toast";

/**
 * The reports are read for three things: where the fleet stands on its
 * patches, what the campaigns of the period did, and where the hosts sit
 * against the policies.
 *
 * What is held here is what a report must never get wrong: a host that
 * reported nothing is a dash and not a nought, the narrowing goes to the
 * server rather than happening in the browser, a section the reader may
 * not see is left out rather than drawn empty, and a refusal is said in
 * words instead of leaving a blank card.
 */

const asked: string[] = [];
const answers: Record<string, unknown> = {};

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  // The longest key that is a prefix of the path answers it: a short key
  // left to answer a longer path hands the screen the wrong document.
  const answer = (path: string) => {
    asked.push(path);
    const key = Object.keys(answers)
      .filter((one) => path.startsWith(one))
      .sort((a, b) => b.length - a.length)[0];
    if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no such thing"));
    const found = answers[key];
    // An answer that is an error is a refusal: the screen has to say so.
    if (found instanceof Error) return Promise.reject(found);
    return Promise.resolve(found);
  };
  return {
    ...actual,
    api: { ...actual.api, get: answer, post: answer, put: answer, del: answer },
  };
});

const envelope = {
  report: "patch-status", from: "2026-09-01T00:00:00Z", to: "2026-10-01T00:00:00Z",
  generated_at: "2026-10-01T06:00:00Z", generated_by: "ulther",
};

const counts = {
  hosts: 10, fully_patched: 6, security_unknown: 1, patched_in_period: 3,
  reboot_backlog: 2, reboot_unknown: 1, pending_updates: 120, pending_security_updates: 14,
};

const patchHost = (over: Record<string, unknown> = {}) => ({
  host_id: "h1", hostname: "agent-arch", site: "lab", environment: "test",
  lifecycle_state: "active", connection_state: "online", agent_version: "0.63.2",
  last_seen_at: "2026-10-01T05:00:00Z", pending_updates: 18, pending_security_updates: 2,
  reboot_required: false, last_upgrade_at: "2026-09-20T10:00:00Z", campaigns: 1,
  ...over,
});

const patchStatus = (over: Record<string, unknown> = {}) => ({
  ...envelope,
  totals: counts,
  by_site: [{ key: "lab", ...counts }],
  by_environment: [{ key: "test", ...counts }],
  hosts: [patchHost()],
  hosts_listed: 1,
  hosts_truncated: false,
  campaigns_read: true,
  ...over,
});

const outcome = { targets: 4, succeeded: 3, no_change: 1, failed: 1, unknown: 0, skipped: 0, canceled: 0 };

const campaignRow = (over: Record<string, unknown> = {}) => ({
  ...outcome,
  id: "c1", name: "September patches", operation: "packages.upgrade", state: "completed",
  requester: "ulther", approver: "second", created_at: "2026-09-02T00:00:00Z",
  finished_at: "2026-09-02T02:00:00Z", duration_seconds: 7200, success_rate: 0.75,
  by_site: [],
  ...over,
});

const campaignsReport = (rows = [campaignRow()]) => ({
  ...envelope,
  campaigns: rows,
  totals: { ...outcome, campaigns: rows.length, by_state: { completed: 1, failed: 0 }, success_rate: 0.75 },
  by_site: [{ key: "lab", ...outcome }],
});

const complianceReport = (over: Record<string, unknown> = {}) => ({
  ...envelope,
  policies: {
    policies: [{
      id: "p1", name: "ssh hardening", version: 3, enabled: true, remediation_mode: "report",
      hosts: 10, compliant: 7, drift: 2, error: 0, not_applicable: 1, unknown: 0,
      rules: {}, drift_hosts: [{ host_id: "h1", hostname: "agent-arch", site: "lab" }],
    }],
    drift_hosts: [{ host_id: "h1", hostname: "agent-arch", site: "lab", environment: "test", policies: 1, rules: 2 }],
    drift_hosts_truncated: false,
    totals: { policies: 1, compliant: 7, drift: 2, error: 0, not_applicable: 1, unknown: 0, hosts_in_drift: 1 },
  },
  security: {
    total_hosts: 10, evaluated_hosts: 8, unknown_hosts: 2, partial: true, partial_reason: "time_budget",
    hosts: 10, hosts_with_findings: 3,
    by_severity: [{ severity: "high", checks: 2, failed: 1, passed: 1, unknown: 0, not_applicable: 0 }],
    checks: [{ check_id: "ssh-root-login", title: "Root may not log in over ssh", severity: "high", failed: 1, passed: 7, unknown: 2, not_applicable: 0 }],
    evaluated_at: "2026-10-01T05:30:00Z",
  },
  ...over,
});

const reader = { subject: "u", kind: "user", roles: [], bindings: [], permissions: ["host.read", "campaign.read"] };
const noCampaigns = { subject: "u", kind: "user", roles: [], bindings: [], permissions: ["host.read"] };

function draw(address = "/next/reports") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[address]}><ToastProvider>{children}</ToastProvider></MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Reports />, { wrapper });
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the reports", () => {
  it("reads the three documents over one period and says what that period is", async () => {
    Object.assign(answers, {
      "/api/v1/whoami": reader,
      "/api/v1/reports/patch-status": patchStatus(),
      "/api/v1/reports/campaigns": campaignsReport(),
      "/api/v1/reports/compliance": complianceReport(),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("patch-hosts")).toBeInTheDocument());
    // The three reports are asked with the same bounds, so the page is one
    // answer about one window rather than three about "now".
    const bounds = asked.filter((one) => one.startsWith("/api/v1/reports/"))
      .map((one) => new URLSearchParams(one.split("?")[1]).get("from"));
    expect(new Set(bounds).size).toBe(1);
    await waitFor(() => expect(screen.getByTestId("report-campaigns")).toBeInTheDocument());
    expect(screen.getByTestId("report-policies")).toBeInTheDocument();
    expect(screen.getByTestId("report-security")).toBeInTheDocument();
  });

  it("says a figure the host never reported is unknown, and never nought", async () => {
    Object.assign(answers, {
      "/api/v1/whoami": reader,
      "/api/v1/reports/patch-status": patchStatus({
        hosts: [patchHost({
          hostname: "silent", pending_updates: null, pending_security_updates: null,
          reboot_required: null, agent_version: "", last_seen_at: undefined,
        })],
      }),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("patch-silent")).toBeInTheDocument());
    const row = screen.getByTestId("patch-silent");
    expect(within(row).queryByText("0")).toBeNull();
    expect(within(row).getAllByTitle("unknown").length).toBeGreaterThanOrEqual(4);
  });

  it("narrows on the server: the site goes into the question, not into a filter here", async () => {
    Object.assign(answers, {
      "/api/v1/whoami": reader,
      "/api/v1/reports/patch-status": patchStatus(),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("patch-hosts")).toBeInTheDocument());
    asked.length = 0;
    fireEvent.change(screen.getByTestId("report-site"), { target: { value: "lab" } });
    await waitFor(() => expect(
      asked.some((one) => one.startsWith("/api/v1/reports/patch-status") && one.includes("site=lab")),
    ).toBe(true));
  });

  it("asks for nothing until both ends of a custom period are set", async () => {
    Object.assign(answers, { "/api/v1/whoami": reader, "/api/v1/reports/patch-status": patchStatus() });
    draw("/next/reports?preset=custom");
    await waitFor(() => expect(screen.getAllByText("Waiting for the period.").length).toBeGreaterThan(0));
    // Nothing is read with half a period: the server refuses it anyway.
    expect(asked.some((one) => one.startsWith("/api/v1/reports/"))).toBe(false);
  });

  it("says a refusal in words rather than leaving the card blank", async () => {
    const { ApiError } = await import("../../lib/api");
    Object.assign(answers, {
      "/api/v1/whoami": reader,
      "/api/v1/reports/patch-status": patchStatus(),
      "/api/v1/reports/compliance": new ApiError(403, "forbidden", "you may not read the policies"),
    });
    draw();
    await waitFor(() => expect(screen.getByText(/you may not read the policies/)).toBeInTheDocument());
  });

  it("leaves the campaign report off the board for a reader who may not read campaigns", async () => {
    Object.assign(answers, {
      "/api/v1/whoami": noCampaigns,
      "/api/v1/reports/patch-status": patchStatus(),
      "/api/v1/reports/compliance": complianceReport(),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("patch-hosts")).toBeInTheDocument());
    expect(screen.queryByTestId("report-campaigns")).toBeNull();
    // And nothing was asked of an endpoint the reader has no right to.
    expect(asked.some((one) => one.startsWith("/api/v1/reports/campaigns"))).toBe(false);
  });

  /**
   * What is not in the document is not on the paper either.
   *
   * This page is printed, and a report whose table stops at row
   * twenty-five without saying so is a report somebody signs off on
   * half a month. Every campaign of the period is on the page; the
   * reader may fold it back to the first rows for a quick read, and the
   * sentence under it then says what a printed copy would carry.
   */
  it("keeps every campaign of the period on the page, and folds back to the first rows on request", async () => {
    const many = Array.from({ length: 30 }, (_, index) => campaignRow({ id: `c${index}`, name: `campaign ${index}` }));
    Object.assign(answers, {
      "/api/v1/whoami": reader,
      "/api/v1/reports/patch-status": patchStatus(),
      "/api/v1/reports/campaigns": campaignsReport(many),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("report-campaigns")).toBeInTheDocument());
    // The last of the thirty is in the document without anybody asking:
    // that is what a printed copy and a search of the page both need.
    expect(screen.getByTestId("campaign-c29")).toBeInTheDocument();
    expect(screen.getByText("All 30 campaigns are shown, so a printed copy carries them all.")).toBeInTheDocument();
    fireEvent.click(screen.getByTestId("campaigns-fold"));
    expect(screen.queryByTestId("campaign-c29")).toBeNull();
    expect(screen.getByTestId("campaign-c24")).toBeInTheDocument();
    // And the sentence says plainly what a copy of the page would lose.
    expect(screen.getByText(
      "The first 25 of 30 campaigns are shown; the file carries them all, a printed copy only these.",
    )).toBeInTheDocument();
    fireEvent.click(screen.getByTestId("campaigns-fold"));
    expect(screen.getByTestId("campaign-c29")).toBeInTheDocument();
  });

  /**
   * What the printed document's own head used to say.
   *
   * A screen may not write a `@media print` block, so the head that only
   * ever appeared on paper is a card anybody can read: what fleet this
   * is a report of, what part of it, over what period, made when and by
   * whom. A copy of the page that cannot say that is a page nobody can
   * file.
   */
  it("says on the page what a copy of it is a report of, and offers to print it", async () => {
    Object.assign(answers, {
      "/api/v1/whoami": { ...reader, display_name: "Tomasz" },
      "/api/v1/reports/patch-status": patchStatus(),
    });
    draw("/next/reports?preset=30d&site=lab");
    await waitFor(() => expect(screen.getByTestId("patch-hosts")).toBeInTheDocument());
    const head = screen.getByText("This document").closest(".fl-card") as HTMLElement;
    expect(within(head).getByText("site lab")).toBeInTheDocument();
    expect(within(head).getByText("Tomasz")).toBeInTheDocument();
    // The moment it was made is on it, whatever zone the reader is in.
    for (const label of ["Fleet", "Scope", "Period", "Generated", "Generated by"]) {
      expect(within(head).getByText(label)).toBeInTheDocument();
    }
    expect(within(head).queryByTitle("unknown")).toBeNull();
    expect(screen.getByRole("button", { name: "Print" })).toBeEnabled();
  });

  it("says how much of the fleet the security sweep actually read", async () => {
    Object.assign(answers, {
      "/api/v1/whoami": reader,
      "/api/v1/reports/patch-status": patchStatus(),
      "/api/v1/reports/compliance": complianceReport(),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("fleet-coverage")).toBeInTheDocument());
    const coverage = screen.getByTestId("fleet-coverage");
    expect(coverage).toHaveTextContent("8 of 10 hosts evaluated");
    // A sweep that stopped early answered about part of the fleet, and the
    // hosts it never reached are unknown rather than clean.
    expect(coverage).toHaveTextContent("partial answer");
  });

  it("says the policy section is not for this reader rather than drawing an empty one", async () => {
    Object.assign(answers, {
      "/api/v1/whoami": reader,
      "/api/v1/reports/patch-status": patchStatus(),
      "/api/v1/reports/compliance": complianceReport({ policies: null }),
    });
    draw();
    await waitFor(() => expect(
      screen.getByText("The policy section needs the right to read policies."),
    ).toBeInTheDocument());
    expect(screen.getByTestId("report-security")).toBeInTheDocument();
  });

  it("leads from a report row to the thing it is about", async () => {
    Object.assign(answers, {
      "/api/v1/whoami": reader,
      "/api/v1/reports/patch-status": patchStatus(),
      "/api/v1/reports/campaigns": campaignsReport(),
      "/api/v1/reports/compliance": complianceReport(),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("patch-agent-arch")).toBeInTheDocument());
    expect(within(screen.getByTestId("patch-agent-arch")).getByRole("link", { name: "agent-arch" }))
      .toHaveAttribute("href", "/next/hosts/h1");
    await waitFor(() => expect(screen.getByTestId("campaign-c1")).toBeInTheDocument());
    expect(within(screen.getByTestId("campaign-c1")).getByRole("link", { name: "September patches" }))
      .toHaveAttribute("href", "/next/campaigns/c1");
    expect(within(screen.getByTestId("drift-agent-arch")).getByRole("link", { name: "agent-arch" }))
      .toHaveAttribute("href", "/next/hosts/h1/policies");
  });
});

describe("the words a report puts on a severity", () => {
  it("colours a high finding as an error and an unknown one as information", () => {
    expect(severityTone("high")).toBe("error");
    expect(severityTone("medium")).toBe("warn");
    expect(severityTone("low")).toBe("neutral");
    expect(severityTone("whatever the module called it")).toBe("info");
  });
});
