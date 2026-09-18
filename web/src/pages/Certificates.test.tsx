import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { FleetCertificates } from "./Certificates";

/* A certificate expires quietly, so this screen's worst failure is a
   plausible number: a count of the first five hundred hosts read as the
   count of the fleet. The counts now come from the database over every
   host in scope and the list comes a page at a time, and the test holds
   the screen to saying which hosts those counts leave out. */

const firstPage = {
  total_hosts: 1001, evaluated_hosts: 300, unknown_hosts: 701, partial: false,
  unknown_reasons: { no_observation: 680, unavailable: 21 },
  items: [
    {
      host_id: "h1", hostname: "web-01", path: "/etc/ssl/web.pem", subject: "CN=web",
      issuer: "CN=fleet-ca", not_after: "2026-09-25T00:00:00Z", days_to_expiry: 7,
      status: "critical", renewal: "manual",
    },
    {
      host_id: "h2", hostname: "api-01", path: "/etc/ssl/api.pem", subject: "CN=api",
      issuer: "CN=fleet-ca", not_after: "2026-12-01T00:00:00Z", days_to_expiry: 74,
      status: "valid", renewal: "tracked",
    },
  ],
  count: 2, total: 300, next_cursor: "the-next-page",
  counts: { expired: 1, critical: 12, warning: 30, unknown: 3, valid: 254 },
  hosts_total: 1001, hosts_without_certificates: 40,
  timeline: [{ reason: "expired", count: 1 }, { reason: "7 days", count: 12 }],
  thresholds: { critical_days: 7, warning_days: 30 },
};

const trust = {
  total_hosts: 1001, evaluated_hosts: 300, unknown_hosts: 701, partial: false,
  items: [], hosts_total: 1001, hosts_unknown: 701, hosts_without_trust_store: [],
};

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        if (path.startsWith("/api/v1/certificates/trust")) return Promise.resolve(trust);
        if (path.startsWith("/api/v1/certificates")) return Promise.resolve(firstPage);
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

describe("the fleet certificate screen", () => {
  it("says how much of the fleet it judged and names the hosts nothing is known about", async () => {
    draw(<FleetCertificates />);
    const coverage = (await screen.findAllByTestId("fleet-coverage"))[0];
    expect(coverage).toHaveTextContent("300 of 1001 hosts evaluated · 701 unknown");
    expect(coverage).toHaveTextContent("680 never reported this");
    expect(coverage).toHaveTextContent("21 could not be read");
    expect(screen.queryByTestId("fleet-partial")).toBeNull();
  });

  it("tells a host that reports no certificate from one nobody has heard from", async () => {
    draw(<FleetCertificates />);
    await waitFor(() => expect(screen.getByText("40 of 1001 hosts report none")).toBeInTheDocument());
    // Reporting an empty list and never reporting are two different
    // states, and the second is the larger one here.
    expect(screen.getByText("Nothing known")).toBeInTheDocument();
    expect(screen.getByText("Reporting none")).toBeInTheDocument();
  });

  it("counts every certificate of the fleet and pages the list with the cursor", async () => {
    draw(<FleetCertificates />);
    await waitFor(() => expect(screen.getByText("/etc/ssl/web.pem")).toBeInTheDocument());
    expect(screen.getByRole("button", { name: "Load more (298 left)" })).toBeInTheDocument();
  });
});
