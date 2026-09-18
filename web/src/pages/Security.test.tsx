import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { FleetSecurity } from "./Security";

/* The compliance of the fleet is judged in the panel from the inventory,
   host by host, so this is the one fleet screen whose answer can cover
   only a part of the fleet. Two things must then be true and are checked
   here: the hosts nothing could be read about are counted as unknown
   rather than as compliant, and an answer that stopped early says so on
   the screen instead of letting its numbers pass for the whole fleet. */

const partialAnswer = {
  total_hosts: 1001, evaluated_hosts: 420, unknown_hosts: 581,
  partial: true, partial_reason: "time_budget",
  unknown_reasons: { no_observation: 180, not_reached: 401 },
  hosts: 600,
  checks: [
    {
      check_id: "ssh.root-login", title: "Root login over SSH", severity: "high",
      expected: "PermitRootLogin no", failed: 120, passed: 280, unknown: 20, not_applicable: 0, fixable: 120,
      hosts: [{ host_id: "h1", hostname: "web-01", observed: "yes", action: "ssh.config.apply" }],
    },
  ],
  generated_at: "2026-09-18T09:00:00Z",
};

const checkHosts = {
  check_id: "ssh.root-login",
  items: [
    { host_id: "h1", hostname: "web-01", observed: "yes", action: "ssh.config.apply" },
    { host_id: "h2", hostname: "web-02", observed: "prohibit-password", action: "ssh.config.apply" },
  ],
  count: 2, next_cursor: "the-next-page", partial: false,
};

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        if (path.startsWith("/api/v1/whoami")) return Promise.resolve({ permissions: ["security.read"] });
        if (path.startsWith("/api/v1/security?check=")) return Promise.resolve(checkHosts);
        if (path.startsWith("/api/v1/security")) return Promise.resolve(partialAnswer);
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

describe("the fleet security screen", () => {
  it("says how much of the fleet it judged and never shows the rest as a zero", async () => {
    draw(<FleetSecurity />);
    const coverage = await screen.findByTestId("fleet-coverage");
    expect(coverage).toHaveTextContent("420 of 1001 hosts evaluated · 581 unknown");
    // The hosts the sweep never opened stand apart from the ones it read
    // and found nothing on.
    expect(coverage).toHaveTextContent("401 not reached by this sweep");
    expect(coverage).toHaveTextContent("180 never reported this");
  });

  it("shows a badge saying why the answer is not the whole fleet", async () => {
    draw(<FleetSecurity />);
    const badge = await screen.findByTestId("fleet-partial");
    expect(badge).toHaveTextContent("partial answer");
    expect(screen.getByTestId("fleet-coverage")).toHaveTextContent("ran out of its time budget");
  });

  it("reads the whole list of hosts failing a check with the cursor", async () => {
    draw(<FleetSecurity />);
    const expander = await screen.findByRole("button", { name: "Show the hosts failing ssh.root-login" });
    fireEvent.click(expander);
    // The sample the fleet answer carried is replaced by the paged list,
    // and the rest of the hosts are one click away.
    await waitFor(() => expect(screen.getByText("web-02")).toBeInTheDocument());
    expect(screen.getByRole("button", { name: "Load more (118 left)" })).toBeInTheDocument();
  });
});
