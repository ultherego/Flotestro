import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Hosts } from "./Hosts";

/**
 * The list is read for two things: which machines answer, and which of
 * them is carrying something somebody has to deal with. Both are held
 * here, and so is the rule the panel is built on - a figure the host
 * never reported is a dash, never a nought.
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
        const key = Object.keys(answers).find((one) => path.startsWith(one));
        if (!key) return Promise.reject(new actual.ApiError(403, "forbidden", "not for you"));
        return Promise.resolve(answers[key]);
      },
    },
  };
});

const host = (over: Record<string, unknown>) => ({
  id: "h1", hostname: "agent-arch", machine_id: "m", site: "lab", environment: "test",
  tags: [], release_channel: "stable", lifecycle_state: "active",
  connection_state: "online", management_address: "192.168.56.70",
  os_distribution: "arch", agent_version: "0.63.2",
  reboot_required: false, failed_units: 0, pending_updates: 18, pending_security_updates: 0,
  package_database_broken: false, enrolled_at: "2026-10-01T00:00:00Z",
  capabilities: {}, identity: {},
  ...over,
});

const activity = {
  hours: [], succeeded: [], failed: [], other: [],
  by_connection_state: [{ key: "online", count: 3 }, { key: "offline", count: 1 }],
  by_os_family: [{ key: "arch", count: 1 }],
  by_agent_version: [{ key: "0.63.2", count: 1 }],
  by_site: [{ key: "lab", count: 1 }],
  by_environment: [{ key: "test", count: 1 }],
};

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter>{children}</MemoryRouter></QueryClientProvider>
  );
  return render(<Hosts />, { wrapper });
}

afterEach(() => { cleanup(); asked.length = 0; });

describe("the host list", () => {
  it("draws a host as its name, its address and what it is", async () => {
    Object.assign(answers, {
      "/api/v1/hosts": { items: [host({})] },
      "/api/v1/fleet/activity": activity,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("host-agent-arch")).toBeInTheDocument());
    const row = screen.getByTestId("host-agent-arch");
    expect(within(row).getByRole("link", { name: "agent-arch" })).toHaveAttribute("href", "/next/hosts/h1");
    expect(row).toHaveTextContent("192.168.56.70");
    expect(row).toHaveTextContent("arch");
    expect(within(row).getByText("online")).toBeInTheDocument();
  });

  it("says a figure the host never reported is unknown, and never nought", async () => {
    Object.assign(answers, {
      "/api/v1/hosts": { items: [host({ hostname: "silent", pending_updates: null, failed_units: null })] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("host-silent")).toBeInTheDocument());
    const row = screen.getByTestId("host-silent");
    expect(row).toHaveTextContent("—");
    expect(within(row).queryByText("0")).toBeNull();
  });

  it("names what a host is carrying, and says nothing where it carries nothing", async () => {
    Object.assign(answers, {
      "/api/v1/hosts": { items: [
        host({ hostname: "busy", reboot_required: true, failed_units: 2, pending_security_updates: 3 }),
        host({ id: "h2", hostname: "clean" }),
      ] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("host-busy")).toBeInTheDocument());
    const busy = screen.getByTestId("host-busy");
    expect(busy).toHaveTextContent("reboot");
    expect(busy).toHaveTextContent("2 failed units");
    expect(busy).toHaveTextContent("3 security");
    // A host with nothing to report says so with a dash, not with an empty
    // cell that reads as a column that failed to draw.
    expect(screen.getByTestId("host-clean").querySelectorAll(".fl-pill")).toHaveLength(1);
  });

  it("narrows on the server, not in the browser", async () => {
    Object.assign(answers, { "/api/v1/hosts": { items: [host({})] } });
    draw();
    await waitFor(() => expect(screen.getByTestId("host-agent-arch")).toBeInTheDocument());
    asked.length = 0;
    fireEvent.change(screen.getByTestId("search"), { target: { value: "agent-fed" } });
    // The question goes to the server with the text in it: a list filtered
    // in the browser would answer over the page that happens to be loaded.
    await waitFor(() => expect(asked.some((one) => one.includes("q=agent-fed"))).toBe(true));
  });

  it("counts the states over the whole fleet, not over the page", async () => {
    Object.assign(answers, {
      "/api/v1/hosts": { items: [host({})] },
      "/api/v1/fleet/activity": activity,
    });
    draw();
    // One host is drawn; the filter still says three are online and one is
    // offline, because that is counted in the database over what may be seen.
    await waitFor(() => expect(screen.getByRole("button", { name: /Online 3/ })).toBeInTheDocument());
    expect(screen.getByRole("button", { name: /Offline 1/ })).toBeInTheDocument();
  });
});
