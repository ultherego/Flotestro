import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Certificates, expiryTone } from "./Certificates";
import { ToastProvider } from "../../components/Toast";

/**
 * What this screen has to get right is the difference between three
 * answers that look alike from a distance: a certificate that is fine, a
 * certificate that is about to stop working, and a certificate nobody
 * could read. The third is the one a panel gets wrong, because silence
 * costs nothing to draw as a nought.
 */

const asked: string[] = [];
const answers: Record<string, unknown> = {};

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        asked.push(path);
        // The longest registered key wins. Without this "/api/v1/certificates"
        // would answer "/api/v1/certificates/trust" as well, and the screen
        // would be handed the wrong document while the test went green.
        const key = Object.keys(answers)
          .filter((one) => path.startsWith(one))
          .sort((a, b) => b.length - a.length)[0];
        if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
        return Promise.resolve(answers[key]);
      },
      put: () => Promise.resolve({}),
      del: () => Promise.resolve(undefined),
    },
  };
});

const certificate = (over: Record<string, unknown> = {}) => ({
  host_id: "h1", hostname: "panel", path: "/etc/pki/tls/certs/panel.crt",
  subject: "CN=panel.lab", issuer: "CN=Fleet CA 2026",
  not_after: "2026-10-23T00:00:00Z", days_to_expiry: 7, status: "critical",
  renewal: "tracked", owner_service: "flotestro-panel.service",
  ...over,
});

const page = (over: Record<string, unknown> = {}) => ({
  items: [certificate()],
  count: 1, total: 1,
  counts: { expired: 0, critical: 1, warning: 0, unknown: 0, valid: 0 },
  total_hosts: 7, evaluated_hosts: 6, unknown_hosts: 1,
  hosts_total: 7, hosts_without_certificates: 2,
  timeline: [{ reason: "7 days", count: 1 }, { reason: "later", count: 0 }],
  thresholds: { critical_days: 7, warning_days: 30 },
  ...over,
});

const trust = (over: Record<string, unknown> = {}) => ({
  items: [], hosts_total: 7, hosts_unknown: 1,
  total_hosts: 7, evaluated_hosts: 6, unknown_hosts: 1,
  ...over,
});

/** The arrangement the board reads before it draws anything. */
const layout = { widgets: [], present: false, revision: 0 };

/**
 * The screen opens on the certificates; the authorities are the second
 * sub-tab, asked for by address the way a link to them would arrive.
 */
function draw(tab = "") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const where = tab ? `/certificates?tab=${tab}` : "/certificates";
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter initialEntries={[where]}><ToastProvider>{children}</ToastProvider></MemoryRouter></QueryClientProvider>
  );
  return render(<Certificates />, { wrapper });
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the fleet's certificates", () => {
  it("draws a certificate as its deadline, its host, its path and what renews it", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/certificates": page(),
      "/api/v1/certificates/trust": trust(),
    });
    draw();
    const id = "certificate-panel-/etc/pki/tls/certs/panel.crt";
    await waitFor(() => expect(screen.getByTestId(id)).toBeInTheDocument());
    const row = screen.getByTestId(id);
    expect(within(row).getByText("7 d")).toBeInTheDocument();
    expect(within(row).getByRole("link", { name: "panel" }))
      .toHaveAttribute("href", "/hosts/h1/certificates");
    expect(row).toHaveTextContent("/etc/pki/tls/certs/panel.crt");
    expect(row).toHaveTextContent("CN=Fleet CA 2026");
    // certmonger renews it: a finding, and not the same thing as nobody
    // knowing how it is renewed.
    expect(within(row).getByText("certmonger")).toBeInTheDocument();
  });

  it("keeps the server's order, nearest deadline first, and colours each by how close it is", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/certificates": page({
        items: [
          certificate({ path: "/a", status: "expired", days_to_expiry: -3, not_after: "2026-10-13T00:00:00Z" }),
          certificate({ path: "/b", status: "critical", days_to_expiry: 2 }),
          certificate({ path: "/c", status: "warning", days_to_expiry: 21 }),
          certificate({ path: "/d", status: "valid", days_to_expiry: 300 }),
        ],
        count: 4, total: 4,
        counts: { expired: 1, critical: 1, warning: 1, unknown: 0, valid: 1 },
      }),
      "/api/v1/certificates/trust": trust(),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("certificate-panel-/d")).toBeInTheDocument());
    const paths = [...screen.getByTestId("certificates").querySelectorAll("tbody tr code")]
      .map((cell) => cell.textContent);
    expect(paths).toEqual(["/a", "/b", "/c", "/d"]);
    const tone = (path: string) =>
      screen.getByTestId(`certificate-panel-${path}`).querySelector(".fl-pill")?.className;
    // Expired and urgent are both "today"; expiring is still a plan.
    expect(tone("/a")).toContain("fl-error");
    expect(tone("/b")).toContain("fl-error");
    expect(tone("/c")).toContain("fl-warn");
    expect(tone("/d")).toContain("fl-ok");
    expect(screen.getByTestId("certificate-panel-/a")).toHaveTextContent("expired 3 d ago");
  });

  it("does not let a certificate nobody could read pass for a valid one", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/certificates": page({
        items: [certificate({
          path: "/unreadable", status: "unknown", days_to_expiry: undefined, not_after: undefined,
          subject: undefined, issuer: undefined, renewal: "unknown",
          unavailable_reason: "permission_denied",
        })],
        counts: { expired: 0, critical: 0, warning: 0, unknown: 1, valid: 0 },
      }),
      "/api/v1/certificates/trust": trust(),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("certificate-panel-/unreadable")).toBeInTheDocument());
    const row = screen.getByTestId("certificate-panel-/unreadable");
    expect(row.querySelector(".fl-pill")?.className).toContain("fl-unknown");
    // No date was read, and the cell says that rather than leaving a blank
    // that reads as "no deadline".
    expect(row).toHaveTextContent("no date read");
    expect(row).toHaveTextContent("permission_denied");
    // The band gives the unreadable one a share of its own; "Valid" sits
    // under the band at nought, which is a count and not a colour.
    const band = screen.getByTestId("certificate-states");
    expect(band.querySelector(".fl-band")).toHaveTextContent("Unreadable");
    expect(band.querySelector(".fl-band")).not.toHaveTextContent("Valid");
    expect(band.querySelector(".fl-quiet-row")).toHaveTextContent("Valid");
  });

  it("counts the fleet above the list and the hosts that report nothing beside it", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/certificates": page({
        count: 1, total: 412,
        counts: { expired: 3, critical: 4, warning: 11, unknown: 2, valid: 392 },
      }),
      "/api/v1/certificates/trust": trust(),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("kpi-Past due")).toHaveTextContent("3"));
    expect(screen.getByTestId("kpi-Due soon")).toHaveTextContent("15");
    expect(screen.getByTestId("kpi-Unreadable")).toHaveTextContent("2");
    // Two hosts report no certificate and one has said nothing at all;
    // those are two different answers and the card keeps them apart.
    const hosts = screen.getByText("Reporting none").closest(".fl-bars") as HTMLElement;
    expect(hosts).toHaveTextContent("Reporting certificates");
    expect(hosts).toHaveTextContent("Nothing known");
  });

  it("shows a dash while the fleet has not answered, never a nought", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      // The answer never arrives: this is the state a panel must not draw
      // as a fleet with nothing wrong.
      "/api/v1/certificates": new Promise(() => {}),
      "/api/v1/certificates/trust": trust(),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("kpi-Past due")).toBeInTheDocument());
    const tile = screen.getByTestId("kpi-Past due");
    expect(tile).toHaveAttribute("data-state", "unknown");
    expect(tile).toHaveTextContent("—");
    expect(tile).not.toHaveTextContent("0");
    expect(tile).toHaveTextContent("Past due: unknown");
  });

  it("says the answer did not come instead of drawing an empty fleet", async () => {
    Object.assign(answers, { "/api/v1/settings/layout": layout });
    draw();
    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
    expect(screen.queryByTestId("certificates")).not.toBeInTheDocument();
  });

  it("asks the server again when the page size changes", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/certificates": page(),
      "/api/v1/certificates/trust": trust(),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("certificates")).toBeInTheDocument());
    asked.length = 0;
    fireEvent.click(screen.getByRole("button", { name: "50" }));
    await waitFor(() => expect(asked.some((one) => one.includes("/api/v1/certificates?limit=50"))).toBe(true));
  });

  it("names the stage of an authority and what can be ordered about it", async () => {
    Object.assign(answers, {
      "/api/v1/settings/layout": layout,
      "/api/v1/certificates": page(),
      "/api/v1/certificates/trust": trust({
        items: [
          { anchor_id: "fleet-ca-2026", subject: "CN=Fleet CA 2026", hosts: 7, fingerprint_sha256: "a".repeat(64) },
          { anchor_id: "fleet-ca-2024", subject: "CN=Fleet CA 2024", hosts: 3 },
        ],
        hosts_unknown: 0,
      }),
    });
    draw("authorities");
    await waitFor(() => expect(screen.getByTestId("authority-fleet-ca-2026")).toBeInTheDocument());
    // The loaded certificate is signed by the 2026 authority, so nothing
    // may be withdrawn and the row says so rather than offering it.
    const inUse = screen.getByTestId("authority-fleet-ca-2026");
    expect(within(inUse).getByText("in use")).toBeInTheDocument();
    expect(within(inUse).queryByRole("link", { name: "withdraw" })).not.toBeInTheDocument();
    // The 2024 authority signs nothing and reached only three of seven
    // hosts, so the one thing to do with it is finish distributing it.
    const old = screen.getByTestId("authority-fleet-ca-2024");
    const link = within(old).getByRole("link", { name: "distribute to the rest" });
    expect(link.getAttribute("href")).toContain("action=certificate.trust.ensure");
    expect(old).toHaveTextContent("3 of 7");
  });
});

describe("the colour of a deadline", () => {
  it("keeps a certificate nobody could read apart from a valid one", () => {
    expect(expiryTone("valid")).toBe("ok");
    expect(expiryTone("warning")).toBe("warn");
    expect(expiryTone("critical")).toBe("error");
    expect(expiryTone("expired")).toBe("error");
    // The one that matters: unreadable is not fine.
    expect(expiryTone("unknown")).toBe("unknown");
    expect(expiryTone("")).toBe("unknown");
  });
});
