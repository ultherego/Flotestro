import { describe, expect, it } from "vitest";
import { fleetListAddress, packagesPreview, severityTone } from "./Vulnerabilities";
import { patchAddress } from "./Vulnerability";
import { findingMatches, patchAddress as hostPatchAddress, severityRung } from "./host/Vulnerabilities";

/* The fleet screen reads the same findings two ways and pages both by
   offset; the address it asks for is a pure function of the filters, so
   every branch is checked here without a screen. */

const params = (address: string) => new URLSearchParams(address.slice(address.indexOf("?") + 1));

describe("fleetListAddress", () => {
  it("asks the host list with the hostname search, the severity, the sort and the page", () => {
    const address = fleetListAddress({ view: "hosts", q: " web ", severity: "critical", fixable: true, sort: "fixable" }, 200);
    expect(address.startsWith("/api/v1/vulnerabilities?")).toBe(true);
    const query = params(address);
    expect(query.get("q")).toBe("web");
    expect(query.get("severity")).toBe("critical");
    expect(query.get("sort")).toBe("fixable");
    expect(query.get("offset")).toBe("200");
    expect(query.get("limit")).toBe("100");
    // The fix toggle belongs to the CVE table alone.
    expect(query.has("fixable")).toBe(false);
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
