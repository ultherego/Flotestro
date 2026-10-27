import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, useLocation } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Technologies, campaignFor, hostsWhere, withEveryTechnology } from "./Technologies";
import { prefilledOrder } from "../../lib/orders";
import { buildExpression } from "../../lib/selectors";

/**
 * Who has a technology, who cannot, who never said - and the way from that list into a campaign.
 *
 * What is held hardest: the three answers stay three, a technology no host reported is unknown
 * on every host and not absent from all of them, and the campaign receives a selector.
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
        const key = Object.keys(answers).filter((one) => path.startsWith(one)).sort((a, b) => b.length - a.length)[0];
        return key ? Promise.resolve(answers[key]) : Promise.reject(new actual.ApiError(404, "not_found", "no"));
      },
    },
  };
});

const host = (id: string, hostname: string) => ({
  id, hostname, site: "lab", environment: "sim", connection_state: "online",
});

function Where() {
  const location = useLocation();
  return <div data-testid="where">{location.pathname + location.search}</div>;
}

function draw(entry = "/technologies") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter initialEntries={[entry]}>{children}</MemoryRouter></QueryClientProvider>
  );
  return render(<><Technologies /><Where /></>, { wrapper });
}

function fleet() {
  asked.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
  answers["/api/v1/fleet/capabilities"] = {
    total: 10,
    items: [
      { name: "docker", available: 3, missing: 5, unknown: 2, reasons: [{ key: "this host has no Docker socket", count: 5 }] },
    ],
  };
  answers["/api/v1/hosts?limit=100&capability=docker&capability_state=available"] = {
    items: [host("a", "web-1"), host("b", "web-2"), host("c", "web-3")],
  };
  answers["/api/v1/hosts?limit=100&capability=docker&capability_state=missing"] = { items: [host("d", "db-1")] };
  answers["/api/v1/hosts?limit=100&capability=docker&capability_state=unknown"] = { items: [host("e", "old-1")] };
}

afterEach(cleanup);

describe("the technologies of the fleet", () => {
  it("keeps the hosts that have it, the hosts that cannot and the hosts that never said apart", async () => {
    fleet();
    draw();
    expect(await screen.findByText("web-1")).toBeInTheDocument();
    expect(screen.getByText("db-1")).toBeInTheDocument();
    expect(screen.getByText("old-1")).toBeInTheDocument();
    // Three lists, each asked of the server for its own answer.
    for (const state of ["available", "missing", "unknown"]) {
      expect(asked).toContain(`/api/v1/hosts?limit=100&capability=docker&capability_state=${state}`);
    }
    // The reason the hosts give is drawn, and "never said" is not worded as "without".
    // The reason is a row of a table that wraps it, not a bar label that outgrows its column.
    expect(screen.getByTestId("reason-this host has no Docker socket")).toHaveTextContent("this host has no Docker socket");
    expect(screen.getByText(/not the same as hosts without it/)).toBeInTheDocument();
  });

  it("hands the campaign the technology as a selector, not as a list", async () => {
    fleet();
    draw();
    const button = await screen.findByTestId("technology-campaign");
    fireEvent.click(button);
    await waitFor(() => expect(screen.getByTestId("where").textContent).toBe("/bulk?capability=docker"));
  });

  it("does not offer a campaign to nobody", async () => {
    fleet();
    (answers["/api/v1/fleet/capabilities"] as { items: { available: number }[] }).items[0].available = 0;
    draw();
    expect(await screen.findByTestId("technology-campaign")).toBeDisabled();
  });

  it("shows a technology no host reported as unknown on every host, not as absent from all", () => {
    const rows = withEveryTechnology({ total: 7, items: [] });
    const firewall = rows.find((one) => one.name === "firewall");
    expect(firewall).toMatchObject({ available: 0, missing: 0, unknown: 7 });
    expect(withEveryTechnology(undefined).every((one) => one.unknown === 0)).toBe(true);
  });

  it("gives the addresses the campaign wizard and the host list read", () => {
    expect(campaignFor("docker.compose")).toBe("/bulk?capability=docker.compose");
    expect(hostsWhere("docker", "unknown")).toBe("/hosts?capability=docker&capability_state=unknown");
  });

  it("opens the order wizard on the capability selector", () => {
    const draft = prefilledOrder(new URLSearchParams("capability=docker"));
    expect(draft?.order.targetMode).toBe("expression");
    expect(buildExpression(draft!.order.rules, draft!.order.combine)).toEqual({ capability: "docker" });
    // Without the parameter nothing about the order changes.
    expect(prefilledOrder(new URLSearchParams(""))).toBeNull();
  });
});
