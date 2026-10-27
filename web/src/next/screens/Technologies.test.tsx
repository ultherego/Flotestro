import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, useLocation } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Technologies, campaignFor, pageAddress, withEveryTechnology } from "./Technologies";
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
  answers[pageAddress("docker", "available", 10, 1, "")] = {
    items: [host("a", "web-1"), host("b", "web-2"), host("c", "web-3")], total: 3,
  };
  answers[pageAddress("docker", "missing", 10, 1, "")] = { items: [host("d", "db-1")], total: 1 };
  answers[pageAddress("docker", "unknown", 10, 1, "")] = { items: [host("e", "old-1")], total: 1 };
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
      expect(asked).toContain(pageAddress("docker", state, 10, 1, ""));
    }
    // The reason the hosts give is drawn, and "never said" is not worded as "without".
    // The reason is a row of a table that wraps it, not a bar label that outgrows its column.
    expect(screen.getByTestId("reason-this host has no Docker socket")).toHaveTextContent("this host has no Docker socket");
    expect(screen.getByText(/not the same as hosts without it/)).toBeInTheDocument();
  });

  it("draws a long reason in a table row that can wrap it, never as a bar label", async () => {
    fleet();
    const long = "this host has no Docker socket at /var/run/docker.sock and the rootless one is not running either";
    (answers["/api/v1/fleet/capabilities"] as { items: { reasons: unknown[] }[] }).items[0].reasons = [{ key: long, count: 5 }];
    const { container } = draw();
    const row = await screen.findByTestId(`reason-${long}`);
    expect(row).toHaveTextContent(long);
    expect(container.querySelector(".fl-bars")).toBeNull();
  });

  it("walks a long list ten hosts at a time, by numbered page", async () => {
    fleet();
    const many = Array.from({ length: 10 }, (_, i) => host(`h${i}`, `web-${i}`));
    answers[pageAddress("docker", "available", 10, 1, "")] = { items: many, total: 25 };
    answers[pageAddress("docker", "available", 10, 3, "")] = { items: [host("z", "web-24")], total: 25 };
    draw();
    expect(await screen.findByText("web-0")).toBeInTheDocument();
    // Pages 1, 2 and 3 are numbered; ten rows are drawn from the first.
    expect(screen.getAllByTestId("page-3").length).toBeGreaterThan(0);
    fireEvent.click(screen.getAllByTestId("page-3")[0]);
    expect(await screen.findByText("web-24")).toBeInTheDocument();
    expect(asked).toContain(pageAddress("docker", "available", 10, 3, ""));
  });

  it("never draws more than ten hosts of one answer and offers no other page size", async () => {
    fleet();
    answers[pageAddress("docker", "available", 10, 1, "")] = {
      items: Array.from({ length: 10 }, (_, i) => host(`h${i}`, `web-${i}`)), total: 95,
    };
    draw();
    await screen.findByText("web-0");
    expect(screen.getAllByTestId(/^host-available-/)).toHaveLength(10);
    expect(screen.queryAllByTestId("page-size")).toHaveLength(0);
    expect(pageAddress("docker", "available", 10, 1, "")).toContain("limit=10");
  });

  it("searches each list on the server and goes back to its first page", async () => {
    fleet();
    answers[pageAddress("docker", "available", 10, 1, "web-2")] = { items: [host("b", "web-2")], total: 1 };
    draw();
    await screen.findByText("web-1");
    vi.useFakeTimers({ shouldAdvanceTime: true });
    fireEvent.change(screen.getByTestId("find-available"), { target: { value: "web-2" } });
    await act(async () => { vi.advanceTimersByTime(400); });
    vi.useRealTimers();
    await waitFor(() => expect(asked).toContain(pageAddress("docker", "available", 10, 1, "web-2")));
    // The three lists have a search each.
    expect(screen.getByTestId("find-missing")).toBeInTheDocument();
    expect(screen.getByTestId("find-unknown")).toBeInTheDocument();
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
    expect(pageAddress("docker", "unknown", 10, 3, "web")).toBe(
      "/api/v1/hosts?limit=10&offset=20&capability=docker&capability_state=unknown&q=web");
  });

  it("opens the order wizard on the capability selector", () => {
    const draft = prefilledOrder(new URLSearchParams("capability=docker"));
    expect(draft?.order.targetMode).toBe("expression");
    expect(buildExpression(draft!.order.rules, draft!.order.combine)).toEqual({ capability: "docker" });
    // Without the parameter nothing about the order changes.
    expect(prefilledOrder(new URLSearchParams(""))).toBeNull();
  });
});
