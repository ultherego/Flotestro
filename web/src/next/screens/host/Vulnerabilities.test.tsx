import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Vulnerabilities, findingMatches, patchAddress, severityRung } from "./Vulnerabilities";
import type { Host } from "../../../lib/types";

/**
 * The one thing this module must never do is read as "clean" where it means
 * "nobody looked". So what is tested is the difference: a host no feed
 * covers has dashes and a sentence, a host with findings has counts, and
 * the coverage keeps its tenth - 99.7% rounded to 100 reads as "everything
 * checked" over dozens of packages that were not.
 */

const answers: Record<string, unknown> = {};
const posted: { path: string; body: unknown }[] = [];

vi.mock("../../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        // The longest match wins: `/api/v1/hosts/h1` is a prefix of
        // `/api/v1/hosts/h1/vulnerabilities`, and answering the second with
        // the first hands the screen the wrong document.
        const key = Object.keys(answers)
          .filter((one) => path.startsWith(one))
          .sort((a, b) => b.length - a.length)[0];
        if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
        const answer = answers[key];
        return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
      },
      post: (path: string, body: unknown) => {
        posted.push({ path, body });
        return Promise.resolve({ id: "job-01234567", requires_approval: false });
      },
      put: () => Promise.resolve({}),
      del: () => Promise.resolve(undefined),
    },
  };
});

const host = (over: Record<string, unknown> = {}): Host => ({
  id: "h1", hostname: "agent-deb", machine_id: "m", site: "lab", environment: "test",
  tags: [], release_channel: "stable", lifecycle_state: "active",
  connection_state: "online", management_address: "192.168.56.40",
  os_distribution: "debian", agent_version: "0.63.2",
  reboot_required: false, failed_units: 0, pending_updates: 0, pending_security_updates: 0,
  package_database_broken: false, enrolled_at: "2026-10-01T00:00:00Z",
  capabilities: [], identity: { enrolled: false, sssd_online: null },
  ...over,
} as unknown as Host);

const finding = (over: Record<string, unknown> = {}) => ({
  provider: "debian", advisory_id: "DSA-5600-1", cve_ids: ["CVE-2026-1000"],
  source_package: "openssl", binary_package: "libssl3", architecture: "amd64",
  installed_version: "3.0.11-1", comparison_version: "3.0.11-1", fixed_version: "3.0.11-2",
  state: "affected", vendor_fix: "known", repository_candidate: "visible", transaction: "unknown",
  vendor_severity: "high", evaluated_at: "2026-10-16T08:00:00Z",
  ...over,
});

const report = (over: Record<string, unknown> = {}) => ({
  host_id: "h1",
  state: {
    distribution: "debian", release: "12", provider: "debian",
    packages_total: 400, packages_covered: 399, affected: 1,
    affected_with_vendor_fix: 1, affected_no_fix: 0, unknown: 0,
    affected_packages: 1, unique_advisories: 1, unique_cves: 1,
    evaluated_at: "2026-10-16T08:00:00Z",
  },
  findings: [finding({})],
  package_state: { package_count: 400, collected_at: "2026-10-16T07:00:00Z" },
  advisory_state: { advisory_count: 900, collected_at: "2026-10-16T07:30:00Z" },
  snapshot: { provider: "debian", digest: "0123456789abcdef0123", advisory_count: 900, fetched_at: "2026-10-16T06:00:00Z" },
  snapshot_stale: false,
  coverage_percent: 99.7,
  fully_assessed: false,
  cve_details: { "CVE-2026-1000": { cve: "CVE-2026-1000", source: "nvd", cvss_score: 9.8, cvss_vector: "AV:N" } },
  ...over,
});

const allowed = {
  version: 1,
  items: [{ action: "packages.list", permission: "packages.read", mutating: false, risk: "low", allowed: true }],
};

function draw(one: Host = host()) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter>{children}</MemoryRouter></QueryClientProvider>
  );
  return render(<Vulnerabilities host={one} />, { wrapper });
}

afterEach(() => {
  cleanup();
  posted.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("what the vendor says about this host", () => {
  it("draws a finding with what was compared and what closes it", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/vulnerabilities": report(),
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    const table = await screen.findByTestId("findings");
    const row = within(table).getAllByRole("row")[1];
    expect(row).toHaveTextContent("DSA-5600-1");
    expect(row).toHaveTextContent("libssl3");
    expect(row).toHaveTextContent("3.0.11-2");
    expect(row).toHaveTextContent("published");
    // The upstream score stands beside the vendor's rating, not instead of it.
    expect(row).toHaveTextContent("9.8");
    expect(row).toHaveTextContent("high");
    expect(within(row).getByRole("link", { name: "CVE-2026-1000" }))
      .toHaveAttribute("href", "/next/vulnerabilities/CVE-2026-1000");
  });

  it("keeps the tenth of the coverage: 99.7 is not a hundred", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/vulnerabilities": report(),
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    expect(await screen.findByText("99.7% of packages covered")).toBeInTheDocument();
  });

  it("says nothing was assessed rather than showing a clean host", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/vulnerabilities": report({
        state: {
          distribution: "arch", release: "", packages_total: 500, packages_covered: 0, affected: 0,
          affected_with_vendor_fix: 0, affected_no_fix: 0, unknown: 0, affected_packages: 0,
          unique_advisories: 0, unique_cves: 0, coverage_reason: "feed_missing",
        },
        findings: [],
        coverage_percent: 0,
      }),
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    expect(await screen.findByText(/Zero findings here does not mean the host is clean/)).toBeInTheDocument();
    // Every count drawn from an assessment nobody made is a dash.
    const band = screen.getByTestId("by-severity");
    expect(band).toHaveTextContent("—");
    expect(band).toHaveTextContent("critical: not counted");
    expect(screen.getByText(/The list is empty because nothing was checked/)).toBeInTheDocument();
    expect(screen.getByText(/no package on this host was checked against a feed/)).toBeInTheDocument();
  });

  it("leads to the workspace that patches, inside the new panel", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/vulnerabilities": report(),
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    const table = await screen.findByTestId("findings");
    const patch = within(table).getByRole("link", { name: "Patch" });
    const address = patch.getAttribute("href") ?? "";
    expect(address.startsWith("/next/bulk?")).toBe(true);
    expect(decodeURIComponent(address)).toContain("libssl3");
    expect(decodeURIComponent(address)).toContain("packages.upgrade");
    // Nothing is installed from this module: the order is planned and
    // approved in the workspace.
    expect(posted).toHaveLength(0);
  });

  it("offers nothing to patch where nothing has a vendor fix", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/vulnerabilities": report({
        findings: [finding({ vendor_fix: "unavailable", fixed_version: "" })],
      }),
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    const all = await screen.findByTestId("patch-all");
    expect(all).toBeDisabled();
    // Once the report has landed the reason changes: nothing here has a
    // vendor fix, which is not the same as nothing having been assessed.
    await waitFor(() =>
      expect(all).toHaveAttribute("title", "No finding on this host has a vendor fix to install."));
  });

  it("re-reads the package list through an ordinary job", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/vulnerabilities": report(),
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    fireEvent.click(await screen.findByTestId("reread"));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/hosts/h1/operations");
    expect(posted[0].body).toMatchObject({ action: "packages.list" });
    expect(await screen.findByText(/reads the package list/)).toBeInTheDocument();
  });

  it("will not re-read a host that is not answering", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/vulnerabilities": report(),
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw(host({ connection_state: "offline" }));
    expect(await screen.findByTestId("reread")).toBeDisabled();
  });

  it("narrows the list by what is typed, and by what the vendor rated it", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/vulnerabilities": report({
        findings: [
          finding({}),
          finding({ advisory_id: "DSA-5601-1", binary_package: "curl", cve_ids: ["CVE-2026-2000"], vendor_severity: "low" }),
        ],
        state: { ...report().state, affected: 2, affected_packages: 2, unique_advisories: 2, unique_cves: 2 },
      }),
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    const table = await screen.findByTestId("findings");
    expect(within(table).getAllByRole("row")).toHaveLength(3);
    fireEvent.change(screen.getByTestId("search"), { target: { value: "curl" } });
    await waitFor(() => expect(within(screen.getByTestId("findings")).getAllByRole("row")).toHaveLength(2));
    fireEvent.change(screen.getByTestId("search"), { target: { value: "" } });
    fireEvent.change(screen.getByTestId("severity"), { target: { value: "low" } });
    await waitFor(() => expect(within(screen.getByTestId("findings")).getAllByRole("row")).toHaveLength(2));
    expect(screen.getByTestId("findings")).toHaveTextContent("curl");
  });

  it("names the reason a finding could not be decided, in words", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/vulnerabilities": report({
        findings: [finding({ state: "unknown", reason_code: "source_package_unknown", fixed_version: "" })],
      }),
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    // The "not established" list is the one that holds it, and the reason
    // is a sentence rather than a code.
    fireEvent.click(await screen.findByRole("button", { name: "Not established" }));
    expect(await screen.findByText("the source package is unknown")).toBeInTheDocument();
  });

  it("says nothing rather than guessing when the report cannot be read", async () => {
    Object.assign(answers, {
      "/api/v1/hosts/h1/vulnerabilities": new Error("the assessment service is down"),
      "/api/v1/hosts/h1/actions": allowed,
    });
    draw();
    expect(await screen.findByRole("alert")).toHaveTextContent("the assessment service is down");
  });
});

describe("the rules this module judges by", () => {
  it("folds every vendor's words onto one ladder", () => {
    expect(severityRung("important")).toBe("high");
    expect(severityRung("moderate")).toBe("medium");
    expect(severityRung(undefined)).toBe("unrated");
  });

  it("matches a finding on its advisory, its package or any of its CVEs", () => {
    const one = finding({});
    expect(findingMatches(one, "dsa-56")).toBe(true);
    expect(findingMatches(one, "libssl")).toBe(true);
    expect(findingMatches(one, "CVE-2026-1000")).toBe(true);
    expect(findingMatches(one, "nothing")).toBe(false);
  });

  it("names no package to patch where the vendor published no fix", () => {
    expect(patchAddress({ id: "h1" }, [finding({ vendor_fix: "unavailable" })])).toBeNull();
    const address = patchAddress({ id: "h1", hostname: "agent-deb" }, [finding({})]);
    expect(address?.startsWith("/next/bulk?")).toBe(true);
  });
});
