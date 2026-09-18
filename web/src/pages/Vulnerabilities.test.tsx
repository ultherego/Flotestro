import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { FleetVulnerabilities, fleetListAddress, generationState, packagesPreview, severityTone } from "./Vulnerabilities";
import { patchAddress } from "./Vulnerability";
import { findingMatches, patchAddress as hostPatchAddress, severityRung } from "./host/Vulnerabilities";

/* The fleet screen reads the same findings two ways. The host table is
   sorted and cut in the database over the whole visible fleet and pages
   by the key of its last row; the CVE table is a grouped query and still
   pages by offset. The address it asks for is a pure function of the
   filters, so every branch is checked here without a screen. */

const params = (address: string) => new URLSearchParams(address.slice(address.indexOf("?") + 1));

describe("fleetListAddress", () => {
  it("asks the host list with the hostname search, the severity, the sort and the cursor", () => {
    const address = fleetListAddress(
      { view: "hosts", q: " web ", severity: "critical", fixable: true, sort: "fixable" }, "the-next-page");
    expect(address.startsWith("/api/v1/vulnerabilities?")).toBe(true);
    const query = params(address);
    expect(query.get("q")).toBe("web");
    expect(query.get("severity")).toBe("critical");
    expect(query.get("sort")).toBe("fixable");
    expect(query.get("cursor")).toBe("the-next-page");
    expect(query.get("limit")).toBe("100");
    // A key-set list never offsets: an offset loses rows when the fleet
    // moves under the reader.
    expect(query.has("offset")).toBe(false);
    // The fix toggle belongs to the CVE table alone.
    expect(query.has("fixable")).toBe(false);
  });

  it("asks the first page of the host list without a cursor", () => {
    const query = params(fleetListAddress({ view: "hosts", q: "", severity: "", fixable: false, sort: "" }, ""));
    expect(query.has("cursor")).toBe(false);
    expect(query.has("offset")).toBe(false);
  });

  it("asks the CVE list with the fix toggle and without a sort", () => {
    const address = fleetListAddress({ view: "cves", q: "CVE-2024", severity: "", fixable: true, sort: "hostname" }, 0, 50);
    expect(address.startsWith("/api/v1/vulnerabilities/cves?")).toBe(true);
    const query = params(address);
    expect(query.get("q")).toBe("CVE-2024");
    expect(query.get("fixable")).toBe("true");
    expect(query.get("limit")).toBe("50");
    expect(query.has("sort")).toBe(false);
    expect(query.has("severity")).toBe(false);
    // The first page carries no offset, so its address is the plain list.
    expect(query.has("offset")).toBe(false);
  });
});

/* A generation says which fetch of the feed judged a host. The answer has
   three states rather than two: a verdict that names no generation is not
   a verdict against the current one. */

describe("generationState", () => {
  const sources = [
    { provider: "debian", digest: "d", advisories: 1, fetched_at: "", stale: false, generation_id: "g2" },
    { provider: "ubuntu", digest: "u", advisories: 1, fetched_at: "", stale: false },
  ];
  const host = (over: Record<string, unknown>) => ({
    host_id: "h", packages_total: 1, packages_covered: 1, affected: 0,
    affected_with_vendor_fix: 0, affected_no_fix: 0, unknown: 0, affected_packages: 0,
    unique_advisories: 0, unique_cves: 0, coverage_percent: 100, fully_assessed: true,
    ...over,
  }) as Parameters<typeof generationState>[0];

  it("calls a host judged against the fetch in force current", () => {
    expect(generationState(host({ provider: "debian", generation_id: "g2" }), sources)).toBe("current");
  });

  it("calls a host judged against an earlier fetch older", () => {
    expect(generationState(host({ provider: "debian", generation_id: "g1" }), sources)).toBe("older");
  });

  it("never turns a missing generation into a current one", () => {
    // A verdict from before generations were recorded.
    expect(generationState(host({ provider: "debian" }), sources)).toBe("unknown");
    // A source that has no central generation at all: the findings came
    // from the host's own repository metadata.
    expect(generationState(host({ provider: "ubuntu", generation_id: "g9" }), sources)).toBe("unknown");
    // A provider the fleet answer does not name.
    expect(generationState(host({ provider: "fedora", generation_id: "g9" }), sources)).toBe("unknown");
  });
});

describe("packagesPreview", () => {
  it("shows a handful of packages and counts the rest", () => {
    expect(packagesPreview(["a", "b", "c", "d", "e", "f"])).toEqual({ shown: ["a", "b", "c", "d"], more: 2 });
    expect(packagesPreview(["a"])).toEqual({ shown: ["a"], more: 0 });
    expect(packagesPreview([])).toEqual({ shown: [], more: 0 });
  });
});

describe("severity", () => {
  it("colours the top rungs red, the middle amber and leaves the unrated as unknown", () => {
    expect(severityTone("critical")).toBe("error");
    expect(severityTone("high")).toBe("error");
    expect(severityTone("medium")).toBe("warn");
    expect(severityTone("low")).toBe("neutral");
    // An unrated finding is not harmless: the vendor has not weighed it.
    expect(severityTone("unrated")).toBe("unknown");
    expect(severityTone(undefined)).toBe("unknown");
  });

  it("puts every vendor's words on one ladder", () => {
    expect(severityRung("important")).toBe("high");
    expect(severityRung("Moderate")).toBe("medium");
    expect(severityRung("unimportant")).toBe("negligible");
    expect(severityRung("")).toBe("unrated");
    expect(severityRung("end-of-life")).toBe("unrated");
  });
});

describe("findingMatches", () => {
  const finding = { advisory_id: "DSA-5678-1", cve_ids: ["CVE-2024-1111", "CVE-2024-2222"], binary_package: "libssl3", source_package: "openssl" };

  it("matches a CVE, an advisory or a package by prefix, whatever the case", () => {
    expect(findingMatches(finding, "cve-2024-2")).toBe(true);
    expect(findingMatches(finding, "dsa-5678")).toBe(true);
    expect(findingMatches(finding, "libssl")).toBe(true);
    expect(findingMatches(finding, "OPENSSL")).toBe(true);
    expect(findingMatches(finding, "ssl")).toBe(false);
    expect(findingMatches(finding, "  ")).toBe(true);
  });
});

/* A patch order is an address of the Bulk workspace: the hosts by
   identifier, the packages in the payload. A finding without a vendor fix
   yields no order - it is a risk to weigh, not something to install. */

describe("patchAddress on the CVE page", () => {
  const rows = [
    { host_id: "h1", package: "libssl3", state: "affected", vendor_fix: "known" },
    { host_id: "h1", package: "openssl", state: "affected", vendor_fix: "known" },
    { host_id: "h2", package: "libssl3", state: "affected", vendor_fix: "unavailable" },
    { host_id: "h3", package: "libssl3", state: "unknown", vendor_fix: "unknown" },
    { host_id: "h4", package: "libssl3", state: "affected", vendor_fix: "known" },
  ];

  it("names the hosts with a vendor fix once each and the packages in the payload", () => {
    const address = patchAddress("CVE-2024-1111", rows);
    expect(address).not.toBeNull();
    const query = params(address ?? "");
    expect(query.get("action")).toBe("packages.upgrade");
    expect(query.get("name")).toBe("Patch CVE-2024-1111");
    expect(query.getAll("host_id")).toEqual(["h1", "h4"]);
    expect(JSON.parse(query.get("payload") ?? "")).toEqual({ package_upgrade: { packages: ["libssl3", "openssl"] } });
  });

  it("offers no order when no host has a vendor fix", () => {
    expect(patchAddress("CVE-2024-1111", rows.slice(2, 4))).toBeNull();
    expect(patchAddress("CVE-2024-1111", [])).toBeNull();
  });
});

describe("patchAddress on the host tab", () => {
  const host = { id: "0123456789abcdef", hostname: "web-01" };

  it("orders one package from a row and names the host", () => {
    const address = hostPatchAddress(host, [{ state: "affected", vendor_fix: "known", binary_package: "libssl3", source_package: "openssl" }]);
    const query = params(address ?? "");
    expect(query.get("name")).toBe("Patch libssl3 on web-01");
    expect(query.getAll("host_id")).toEqual([host.id]);
    expect(JSON.parse(query.get("payload") ?? "")).toEqual({ package_upgrade: { packages: ["libssl3"] } });
  });

  it("orders every fixable package at once and skips the rest", () => {
    const address = hostPatchAddress(host, [
      { state: "affected", vendor_fix: "known", binary_package: "libssl3" },
      { state: "affected", vendor_fix: "known", binary_package: "libssl3" },
      { state: "affected", vendor_fix: "known", binary_package: "", source_package: "linux" },
      { state: "affected", vendor_fix: "unavailable", binary_package: "curl" },
      { state: "unknown", vendor_fix: "unknown", binary_package: "vim" },
    ]);
    const query = params(address ?? "");
    expect(query.get("name")).toBe("Patch 2 packages on web-01");
    expect(JSON.parse(query.get("payload") ?? "")).toEqual({ package_upgrade: { packages: ["libssl3", "linux"] } });
  });

  it("offers nothing when no finding has a fix to install", () => {
    expect(hostPatchAddress(host, [{ state: "affected", vendor_fix: "unavailable", binary_package: "curl" }])).toBeNull();
  });
});

/* The screen itself has two numbers, not one: how many vulnerabilities
   and what part of the fleet could be assessed at all. Without the second
   the first is a promise - a host the feed does not cover carries the
   same zero as a clean one - so the coverage line is checked on a fleet
   larger than the five hundred hosts the old screen read. */

const fleetAnswer = {
  total_hosts: 1001, evaluated_hosts: 300, unknown_hosts: 701, partial: false,
  unknown_reasons: { no_assessment: 701 },
  items: [
    {
      host_id: "h1", hostname: "web-01", distribution: "debian", release: "12",
      packages_total: 120, packages_covered: 120, affected: 9, affected_with_vendor_fix: 5,
      affected_no_fix: 4, unknown: 0, affected_packages: 7, unique_advisories: 3, unique_cves: 9,
      coverage_reason: "", advisories_reason: "", evaluated_at: "2026-09-18T08:00:00Z",
      coverage_percent: 100, fully_assessed: true, by_severity: { critical: 2 },
      provider: "debian", generation_id: "g-now", generation_at: "2026-09-18T07:00:00Z",
    },
  ],
  count: 1, total: 300, next_cursor: "the-next-page", limit: 100, offset: 0,
  affected: 900, affected_with_vendor_fix: 500, affected_no_fix: 400, unknown: 0,
  unique_cves: 120, unique_advisories: 60, affected_package_instances: 700, hosts_affected: 210,
  hosts_total: 1001, hosts_assessed: 300, hosts_without_assessment: 701,
  coverage_reasons: { package_list_missing: 701 },
  sources: [{ provider: "debian", digest: "d1", advisories: 12000, fetched_at: "2026-09-18T07:00:00Z", stale: false, generation_id: "g-now", generation_at: "2026-09-18T07:00:00Z" }],
  max_snapshot_age_hours: 48,
  candidates: [],
};

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        if (path.startsWith("/api/v1/vulnerabilities/cves")) {
          return Promise.resolve({ items: [], count: 0, total: 0, limit: 50, offset: 0 });
        }
        if (path.startsWith("/api/v1/vulnerabilities")) return Promise.resolve(fleetAnswer);
        return Promise.reject(new Error(`no answer for ${path}`));
      },
    },
  };
});

function draw(node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(cleanup);

describe("the fleet vulnerability screen", () => {
  it("says how much of the fleet it assessed and never shows the rest as a zero", async () => {
    draw(<FleetVulnerabilities />);
    const coverage = await screen.findByTestId("fleet-coverage");
    expect(coverage).toHaveTextContent("300 of 1001 hosts evaluated · 701 unknown");
    // A host nobody has assessed is not a host without vulnerabilities.
    expect(coverage).toHaveTextContent("701 never assessed");
    expect(screen.queryByTestId("fleet-partial")).toBeNull();
  });

  it("counts the whole fleet above a table that grows on the cursor", async () => {
    draw(<FleetVulnerabilities />);
    await waitFor(() => expect(screen.getByText("300 of 1001 hosts fully assessed")).toBeInTheDocument());
    expect(screen.getByRole("button", { name: "Load more (299 left)" })).toBeInTheDocument();
  });
});
