import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { FleetBackups } from "./Backups";

/* The fleet backup screen used to read the first five hundred hosts and
   add them up in the browser. It now reads counts taken over the whole
   fleet and a list paged by a cursor, so the test holds it to the two
   things that go wrong when those are confused: the counters must be the
   fleet's, not the loaded page's, and a host with nothing defined must
   stand on the screen as unknown rather than disappear into a zero. */

const firstPage = {
  total_hosts: 1001, evaluated_hosts: 300, unknown_hosts: 701, partial: false,
  unknown_reasons: { no_definition: 701 },
  items: [
    {
      host_id: "h1", hostname: "db-01", definition: "daily", tool: "restic",
      repository: "sftp:backup:/srv", status: "critical", last_success_at: "2026-08-01T00:00:00Z",
      age_hours: 900, unverified: true,
    },
    {
      host_id: "h2", hostname: "web-01", definition: "etc", tool: "borg",
      repository: "sftp:backup:/srv", status: "ok", last_success_at: "2026-09-17T00:00:00Z",
      age_hours: 6, unverified: false, last_restore_at: "2026-09-01T00:00:00Z",
    },
  ],
  count: 2, total: 300, next_cursor: "the-next-page",
  counts: { never: 4, critical: 10, warning: 20, ok: 266 },
  unverified: 31, never_restored: 44, hosts_total: 1001,
  thresholds: { warning_hours: 48, critical_hours: 168, verification_days: 30 },
  repositories: [],
};

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        if (path.startsWith("/api/v1/backups")) return Promise.resolve(firstPage);
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

describe("the fleet backup screen", () => {
  it("says how much of the fleet it judged and never shows the rest as a zero", async () => {
    draw(<FleetBackups />);
    const coverage = await screen.findByTestId("fleet-coverage");
    expect(coverage).toHaveTextContent("300 of 1001 hosts evaluated · 701 unknown");
    // The hosts with nothing defined are not hosts with fresh copies.
    expect(coverage).toHaveTextContent("701 nothing is defined to run here");
    expect(screen.queryByTestId("fleet-partial")).toBeNull();
  });

  it("counts the fleet, not the page, and offers the rest of the list on the cursor", async () => {
    draw(<FleetBackups />);
    // Two rows are loaded; the screen says three hundred definitions on
    // three hundred of a thousand hosts.
    await waitFor(() => expect(screen.getByText("300 definitions on 300 of 1001 hosts")).toBeInTheDocument());
    expect(screen.getByRole("button", { name: "Load more (298 left)" })).toBeInTheDocument();
    expect(screen.getByText("db-01")).toBeInTheDocument();
  });
});
