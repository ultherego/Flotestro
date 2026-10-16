import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { SEVERITIES, Vulnerabilities, openFindings, severityTone } from "./Vulnerabilities";
import { ToastProvider } from "../../components/Toast";

/**
 * What this screen must not do is say "nought" where it means "nobody
 * looked". A fleet no assessment has reached, and a host whose packages
 * could not be read, both have to read as unknown - on the tiles and in
 * the row - or the screen reports a clean fleet it has never seen.
 *
 * The rest is the severities keeping their colour and their order, and the
 * list narrowing where the whole fleet is: on the server.
 */

const asked: string[] = [];
const answers: Record<string, unknown> = {};

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      // The longest key that is a prefix of the path answers it: the host
      // list and the CVE list share a path, and a short key would hand the
      // CVE table the host document.
      get: (path: string) => {
        asked.push(path);
        const key = Object.keys(answers)
          .filter((one) => path.startsWith(one))
          .sort((a, b) => b.length - a.length)[0];
        if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
        return Promise.resolve(answers[key]);
      },
      post: () => Promise.resolve({}),
      put: () => Promise.resolve({}),
      del: () => Promise.resolve(undefined),
    },
  };
});

const host = (over: Record<string, unknown> = {}) => ({
  host_id: "h1", hostname: "web-01", distribution: "debian", release: "12", provider: "debian",
  packages_total: 500, packages_covered: 495, affected: 11, affected_with_vendor_fix: 7,
  affected_no_fix: 3, unknown: 1, affected_packages: 9, unique_advisories: 6, unique_cves: 11,
  coverage_percent: 99.4, fully_assessed: false, evaluated_at: "2026-10-16T08:00:00Z",
  by_severity: { critical: 3, high: 2, medium: 5, unrated: 1 },
  generation_id: "g1", generation_at: "2026-10-16T07:00:00Z",
  ...over,
});

const fleet = (over: Record<string, unknown> = {}) => ({
  items: [host()], count: 1, total: 1, offset: 0,
  total_hosts: 4, evaluated_hosts: 3, unknown_hosts: 1,
  affected: 11, affected_with_vendor_fix: 7, affected_no_fix: 3, unknown: 1,
  unique_cves: 11, unique_advisories: 6, affected_package_instances: 9,
  hosts_affected: 1, hosts_total: 4, hosts_assessed: 2, hosts_without_assessment: 1,
  coverage_reasons: {}, sources: [], max_snapshot_age_hours: 48, candidates: [],
  ...over,
});

const cve = (over: Record<string, unknown> = {}) => ({
  cve: "CVE-2026-1001", severity: "critical", vendor_severity: "grave", cvss_score: 9.8,
  cvss_severity: "critical", hosts: 4, hosts_with_vendor_fix: 3,
  packages: ["openssl", "libssl3", "openssl-dev", "libssl-doc", "openssl-misc"],
  first_seen: "2026-10-10T08:00:00Z",
  ...over,
});

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter></QueryClientProvider>
  );
  return render(<Vulnerabilities />, { wrapper });
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the host list", () => {
  it("draws a host as what it is carrying, how much of it was read, and the way in", async () => {
    Object.assign(answers, {
      "/api/v1/vulnerabilities": fleet(),
      "/api/v1/settings/layout": { widgets: [], present: false, revision: 0 },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("host-web-01")).toBeInTheDocument());
    const row = screen.getByTestId("host-web-01");
    // The way into a fix is the host's own vulnerability module.
    expect(within(row).getByRole("link", { name: "web-01" }))
      .toHaveAttribute("href", "/next/hosts/h1/vulnerabilities");
    expect(row).toHaveTextContent("debian 12");
    expect(row).toHaveTextContent("11");
    // Rounding the coverage to a whole number turned 99.4 into 99 and read
    // as a host that had been read completely.
    expect(row).toHaveTextContent("99.4% of 500");
  });

  it("lists the severities worst first, each in its own colour", async () => {
    Object.assign(answers, { "/api/v1/vulnerabilities": fleet() });
    draw();
    await waitFor(() => expect(screen.getByTestId("host-web-01")).toBeInTheDocument());
    const pills = [...screen.getByTestId("host-web-01").querySelectorAll(".fl-pill")];
    const rungs = pills.map((one) => one.textContent ?? "").filter((text) => /critical|high|medium|unrated/.test(text));
    expect(rungs).toEqual(["3 critical", "2 high", "5 medium", "1 unrated"]);
    // The colour rides on the pill, and the top two rungs are not the same
    // colour as the rung nobody has weighed.
    expect(pills[0]).toHaveClass("fl-error");
    expect(pills.find((one) => one.textContent === "1 unrated")).toHaveClass("fl-unknown");
  });

  it("says unknown, not nought, for a host whose packages could not be read", async () => {
    Object.assign(answers, {
      "/api/v1/vulnerabilities": fleet({
        items: [host({
          host_id: "h2", hostname: "sap-02", affected: 0, affected_with_vendor_fix: 0,
          affected_no_fix: 0, unknown: 0, by_severity: {}, coverage_reason: "package_list_missing",
        })],
      }),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("host-sap-02")).toBeInTheDocument());
    const cells = [...screen.getByTestId("host-sap-02").querySelectorAll("td")];
    // Open, vendor fix, no fix, not established: four counts the server
    // sent as nought because it could decide nothing, and not one of them
    // is drawn as a nought.
    expect(cells.slice(1, 6).map((one) => one.textContent)).toEqual(["—", "—", "—", "—", "—"]);
    // And it says why, rather than leaving the dashes to be guessed at.
    expect(cells[6]).toHaveTextContent("no package list yet");
  });
});

describe("a fleet nobody has judged", () => {
  it("reads as unknown rather than as a clean fleet", async () => {
    Object.assign(answers, {
      "/api/v1/vulnerabilities": fleet({
        items: [], count: 0, total: 0,
        total_hosts: 6, evaluated_hosts: 0, unknown_hosts: 6,
        affected: 0, affected_with_vendor_fix: 0, affected_no_fix: 0, unknown: 0,
        unique_cves: 0, unique_advisories: 0, affected_package_instances: 0,
        hosts_affected: 0, hosts_total: 6, hosts_assessed: 0, hosts_without_assessment: 6,
      }),
    });
    draw();
    // The tiles are drawn before the answer arrives and are unknown then
    // too, so the wait is for something only the answer can put on screen.
    await waitFor(() => expect(screen.getByTestId("unassessed")).toHaveTextContent("0 of 6 hosts judged"));
    const findings = screen.getByTestId("findings");
    expect(findings).toHaveAttribute("data-state", "unknown");
    expect(findings).toHaveTextContent("—");
    expect(findings).toHaveTextContent("Open findings: unknown");
    expect(findings).not.toHaveTextContent("0");
    // The six machines nobody has read are a count, and it is the figure
    // that stops the screen looking quiet.
    expect(screen.getByTestId("unassessed")).toHaveTextContent("6");
    // What is split by vendor answer is not counted either, and says so.
    expect(screen.getByTestId("findings-split")).toHaveTextContent("not counted");
  });

  it("names the hosts nothing could be decided for above the numbers", async () => {
    Object.assign(answers, {
      "/api/v1/vulnerabilities": fleet({ coverage_reasons: { feed_missing: 2, distribution_eol: 1 } }),
    });
    draw();
    await waitFor(() => expect(screen.getByRole("status")).toBeInTheDocument());
    expect(screen.getByRole("status")).toHaveTextContent("2 × no feed for the distribution");
    expect(screen.getByRole("status")).toHaveTextContent("1 × release past end of life");
  });
});

describe("the CVE list", () => {
  it("is a different document from the host list at the same path", async () => {
    Object.assign(answers, {
      "/api/v1/vulnerabilities": fleet(),
      "/api/v1/vulnerabilities/cves": {
        items: [cve(), cve({ cve: "CVE-2026-1002", severity: "low", cvss_score: undefined, hosts_with_vendor_fix: 0 })],
        count: 2, total: 2, limit: 50, offset: 0,
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("host-web-01")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "By CVE" }));
    await waitFor(() => expect(screen.getByTestId("cve-CVE-2026-1001")).toBeInTheDocument());

    const row = screen.getByTestId("cve-CVE-2026-1001");
    expect(within(row).getByRole("link", { name: "CVE-2026-1001" }))
      .toHaveAttribute("href", "/next/vulnerabilities/CVE-2026-1001");
    expect(within(row).getByText("critical")).toHaveClass("fl-error");
    expect(row).toHaveTextContent("9.8");
    // Four machines to move and a fix for three of them: the row says both.
    expect(row).toHaveTextContent("3 of 4");
    // Five binary packages, four named and the rest counted.
    expect(row).toHaveTextContent("+1 more");

    // A score nobody published is a dash, and a CVE with no fix anywhere
    // says none rather than nought.
    const second = screen.getByTestId("cve-CVE-2026-1002");
    expect(second).toHaveTextContent("—");
    expect(second).toHaveTextContent("none");
  });
});

describe("narrowing", () => {
  it("asks the server, and asks the CVE endpoint for the CVE view", async () => {
    Object.assign(answers, {
      "/api/v1/vulnerabilities": fleet({ items: [], count: 0, total: 0 }),
      "/api/v1/vulnerabilities/cves": { items: [], count: 0, total: 0, limit: 50, offset: 0 },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("severity")).toBeInTheDocument());
    asked.length = 0;

    fireEvent.change(screen.getByTestId("severity"), { target: { value: "critical" } });
    await waitFor(() => expect(asked.some((one) =>
      one.startsWith("/api/v1/vulnerabilities?") && one.includes("severity=critical"))).toBe(true));

    fireEvent.change(screen.getByTestId("sort"), { target: { value: "hostname" } });
    await waitFor(() => expect(asked.some((one) => one.includes("sort=hostname"))).toBe(true));

    asked.length = 0;
    fireEvent.click(screen.getByRole("button", { name: "By CVE" }));
    await waitFor(() => expect(asked.some((one) =>
      one.startsWith("/api/v1/vulnerabilities/cves?"))).toBe(true));
  });

  it("says an empty answer is empty rather than drawing a head over nothing", async () => {
    Object.assign(answers, { "/api/v1/vulnerabilities": fleet({ items: [], count: 0, total: 0 }) });
    draw();
    await waitFor(() => expect(screen.getByText("No host has been judged yet.")).toBeInTheDocument());
  });
});

describe("the feed fetches the gate held back", () => {
  it("stands on the screen with what it would have lost", async () => {
    Object.assign(answers, {
      "/api/v1/vulnerabilities": fleet({
        candidates: [{
          id: "s1", provider: "debian", digest: "abcdef0123456789", reason: "feed_release_missing",
          advisories: 120, releases: ["12"], fetched_at: "2026-10-16T06:00:00Z",
          held_at: "2026-10-16T06:01:00Z", active_advisories: 4100, active_releases: ["11", "12"],
        }],
      }),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("held-fetch-debian")).toBeInTheDocument());
    const row = screen.getByTestId("held-fetch-debian");
    expect(row).toHaveTextContent("the fetch stopped covering a release that is in force");
    expect(row).toHaveTextContent("no longer covers 11");
    expect(row).toHaveTextContent("120");
    expect(row).toHaveTextContent("4100");
  });

  it("will not accept one without a reason for the trail", async () => {
    Object.assign(answers, {
      "/api/v1/vulnerabilities": fleet({
        candidates: [{
          id: "s1", provider: "debian", digest: "abcdef0123456789", reason: "feed_shrank",
          advisories: 3, fetched_at: "2026-10-16T06:00:00Z", active_advisories: 4100,
        }],
      }),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("accept-debian")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("accept-debian"));
    expect(screen.getByTestId("accept-confirm")).toBeDisabled();
    fireEvent.change(screen.getByTestId("accept-reason"), { target: { value: "short" } });
    expect(screen.getByTestId("accept-confirm")).toBeDisabled();
    fireEvent.change(screen.getByTestId("accept-reason"), { target: { value: "vendor retired the findings" } });
    expect(screen.getByTestId("accept-confirm")).toBeEnabled();
  });
});

describe("a severity", () => {
  it("keeps its order, gravest first", () => {
    expect([...SEVERITIES]).toEqual(["critical", "high", "medium", "low", "negligible", "unrated"]);
  });

  it("keeps its colour, and unrated is not harmless", () => {
    expect(severityTone("critical")).toBe("error");
    expect(severityTone("high")).toBe("error");
    expect(severityTone("medium")).toBe("warn");
    expect(severityTone("low")).toBe("neutral");
    expect(severityTone("negligible")).toBe("neutral");
    // A finding the vendor has not weighed is unknown, never quiet.
    expect(severityTone("unrated")).toBe("unknown");
    expect(severityTone(undefined)).toBe("unknown");
    expect(severityTone("whatever-the-vendor-called-it")).toBe("unknown");
  });
});

describe("the open findings of a host", () => {
  it("are unknown when nothing could be decided, and a count otherwise", () => {
    expect(openFindings(host())).toBe(11);
    expect(openFindings(host({ affected: 0 }))).toBe(0);
    expect(openFindings(host({ affected: 0, coverage_reason: "feed_missing" }))).toBeUndefined();
    // Part of the answer is still an answer: findings were decided here
    // even though the coverage is not complete.
    expect(openFindings(host({ affected: 4, coverage_reason: "package_origin_unknown" }))).toBe(4);
  });
});
