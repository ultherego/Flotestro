import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, useLocation } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Hosts } from "./Hosts";

/**
 * The list is read for two things: which machines answer, and which of
 * them is carrying something somebody has to deal with. Both are held
 * here, and so is the rule the panel is built on - a figure the host
 * never reported is a dash, never a nought.
 */

const asked: string[] = [];
const posted: { path: string; body: unknown }[] = [];
const answers: Record<string, unknown> = {};
/** What the server refuses, by the address it is asked at. */
const refusals: Record<string, Error> = {};

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        asked.push(path);
        // The longest match wins: /api/v1/hosts is a prefix of
        // /api/v1/hosts/bulk-metadata, and the first key found is not
        // necessarily the one the screen asked for.
        const key = Object.keys(answers)
          .filter((one) => path.startsWith(one))
          .sort((a, b) => b.length - a.length)[0];
        if (!key) return Promise.reject(new actual.ApiError(403, "forbidden", "not for you"));
        return Promise.resolve(answers[key]);
      },
      post: (path: string, body: unknown) => {
        posted.push({ path, body });
        const refusal = refusals[path];
        if (refusal) return Promise.reject(refusal);
        return Promise.resolve({ applied: 1, failed: 0, results: [{ host_id: "h1", ok: true, code: "" }] });
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

/** Where the screen has taken the reader; a navigation is an outcome too. */
function Where() {
  const location = useLocation();
  return <span data-testid="where">{`${location.pathname}${location.search}`}</span>;
}

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter>{children}<Where /></MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Hosts />, { wrapper });
}

/** What the signed-in reader may do; absent, they may only read. */
const whoami = (...permissions: string[]) => ({
  subject: "operator", kind: "user", roles: [], bindings: [], permissions,
});

afterEach(() => {
  cleanup();
  asked.length = 0;
  posted.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
  for (const key of Object.keys(refusals)) delete refusals[key];
});

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

describe("what the list can do to the hosts on it", () => {
  const two = () => ({
    "/api/v1/hosts": { items: [host({}), host({ id: "h2", hostname: "agent-debian" })] },
    "/api/v1/fleet/activity": activity,
  });

  it("offers a reader who may only read nothing to do", async () => {
    Object.assign(answers, { ...two(), "/api/v1/whoami": whoami() });
    draw();
    await waitFor(() => expect(screen.getByTestId("host-agent-arch")).toBeInTheDocument());
    // No way into enrolment, no boxes to tick, and so nothing the rows
    // could be acted on with.
    expect(screen.queryByRole("link", { name: "Add host" })).toBeNull();
    expect(screen.queryByLabelText("select agent-arch")).toBeNull();
    expect(screen.queryByTestId("set-metadata")).toBeNull();
    expect(screen.queryByTestId("filter-relay")).toBeNull();
  });

  it("ticks rows and takes them to the Bulk workspace", async () => {
    Object.assign(answers, { ...two(), "/api/v1/whoami": whoami("campaign.read") });
    draw();
    await waitFor(() => expect(screen.getByLabelText("select agent-arch")).toBeInTheDocument());
    fireEvent.click(screen.getByLabelText("select agent-arch"));
    expect(screen.getByText("1 selected")).toBeInTheDocument();
    // Whoever may not write tags is not offered the editor, only the
    // workspace the selection is for.
    expect(screen.queryByTestId("set-metadata")).toBeNull();
    fireEvent.click(screen.getByTestId("open-bulk"));
    expect(screen.getByTestId("where")).toHaveTextContent("/next/bulk?host_id=h1");
  });

  it("ticks every loaded host, and only the loaded ones", async () => {
    Object.assign(answers, { ...two(), "/api/v1/whoami": whoami("campaign.read") });
    draw();
    await waitFor(() => expect(screen.getByLabelText("select every loaded host")).toBeInTheDocument());
    fireEvent.click(screen.getByLabelText("select every loaded host"));
    expect(screen.getByText("2 selected")).toBeInTheDocument();
    fireEvent.click(screen.getByTestId("clear-selection"));
    expect(screen.queryByText("2 selected")).toBeNull();
  });

  it("sets the tags of the chosen rows with the body the server expects", async () => {
    Object.assign(answers, {
      ...two(),
      "/api/v1/whoami": whoami("campaign.read", "host.tag.write"),
    });
    draw();
    await waitFor(() => expect(screen.getByLabelText("select agent-arch")).toBeInTheDocument());
    fireEvent.click(screen.getByLabelText("select agent-arch"));
    fireEvent.click(screen.getByTestId("set-metadata"));
    // Nothing is set yet, so there is nothing to apply.
    expect(screen.getByTestId("bulk-apply")).toBeDisabled();
    fireEvent.change(screen.getByTestId("bulk-tags-add"), { target: { value: "role=web, patched" } });
    fireEvent.click(screen.getByTestId("bulk-apply"));

    const apply = screen.getByTestId("bulk-confirm");
    // The reason goes into the trail with every host, so a short one is
    // refused here rather than by the server.
    fireEvent.change(screen.getByTestId("bulk-reason"), { target: { value: "ticket" } });
    expect(apply).toBeDisabled();
    fireEvent.change(screen.getByTestId("bulk-reason"), { target: { value: "handover of the web tier" } });
    fireEvent.click(apply);

    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].path).toBe("/api/v1/hosts/bulk-metadata");
    expect(posted[0].body).toEqual({
      host_ids: ["h1"],
      reason: "handover of the web tier",
      set: { tags_add: ["role=web", "patched"] },
    });
    await waitFor(() => expect(screen.getByTestId("bulk-summary")).toHaveTextContent("1 applied, 0 refused."));
  });

  it("opens and closes a maintenance window on the chosen rows", async () => {
    Object.assign(answers, {
      ...two(),
      "/api/v1/whoami": whoami("campaign.read", "host.maintenance.write"),
    });
    draw();
    await waitFor(() => expect(screen.getByLabelText("select agent-arch")).toBeInTheDocument());
    fireEvent.click(screen.getByLabelText("select agent-arch"));
    fireEvent.click(screen.getByTestId("set-metadata"));
    // The tags belong to another permission, so they are not on the form.
    expect(screen.queryByTestId("bulk-tags-add")).toBeNull();

    // A window without an end is not applied: the form asks for both.
    fireEvent.change(screen.getByTestId("bulk-maintenance"), { target: { value: "open" } });
    expect(screen.getByTestId("bulk-apply")).toBeDisabled();
    fireEvent.change(screen.getByTestId("bulk-until"), { target: { value: "2026-10-17T10:00" } });
    fireEvent.change(screen.getByTestId("bulk-window-reason"), { target: { value: "disk swap" } });
    expect(screen.getByTestId("bulk-apply")).toBeEnabled();

    // Closing one is a window set to nothing, which travels as null.
    fireEvent.change(screen.getByTestId("bulk-maintenance"), { target: { value: "close" } });
    fireEvent.click(screen.getByTestId("bulk-apply"));
    fireEvent.change(screen.getByTestId("bulk-reason"), { target: { value: "the work is finished" } });
    fireEvent.click(screen.getByTestId("bulk-confirm"));

    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].body).toEqual({
      host_ids: ["h1"],
      reason: "the work is finished",
      set: { maintenance: null },
    });
  });

  it("says a refusal of the whole edit in the operator's words", async () => {
    Object.assign(answers, {
      ...two(),
      "/api/v1/whoami": whoami("campaign.read", "host.tag.write"),
    });
    refusals["/api/v1/hosts/bulk-metadata"] = new Error("the reason is kept with every host");
    draw();
    await waitFor(() => expect(screen.getByLabelText("select agent-arch")).toBeInTheDocument());
    fireEvent.click(screen.getByLabelText("select agent-arch"));
    fireEvent.click(screen.getByTestId("set-metadata"));
    fireEvent.change(screen.getByTestId("bulk-tags-add"), { target: { value: "role=web" } });
    fireEvent.click(screen.getByTestId("bulk-apply"));
    fireEvent.change(screen.getByTestId("bulk-reason"), { target: { value: "handover of the web tier" } });
    fireEvent.click(screen.getByTestId("bulk-confirm"));
    await waitFor(() => expect(screen.getByText("the reason is kept with every host")).toBeInTheDocument());
    // The dialog is gone and the editor is still there with what was typed.
    expect(screen.queryByTestId("bulk-confirm")).toBeNull();
    expect(screen.getByTestId("bulk-tags-add")).toHaveValue("role=web");
  });

  it("leads from a tag to every host that carries it, and narrows on the server", async () => {
    Object.assign(answers, {
      "/api/v1/hosts": { items: [host({ tags: ["role=db"] })] },
      "/api/v1/whoami": whoami(),
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("host-agent-arch")).toBeInTheDocument());
    const tag = within(screen.getByTestId("host-agent-arch")).getByRole("link", { name: "role=db" });
    expect(tag).toHaveAttribute("href", "/next/hosts?tag=role%3Ddb");
    asked.length = 0;
    fireEvent.click(tag);
    // Every listed tag has to be on the host, and the database decides
    // which ones do - not the page that happens to be loaded.
    await waitFor(() => expect(asked.some((one) => one.includes("tag=role%3Ddb"))).toBe(true));
    expect(screen.getByTestId("clear-tags")).toHaveTextContent("role=db");
  });

  it("offers the route filter only to whoever may list the relays", async () => {
    Object.assign(answers, {
      ...two(),
      "/api/v1/whoami": whoami("host.enroll.read", "host.enroll.create"),
      "/api/v1/relays": { items: [{ id: "r1", name: "relay-lab" }] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("filter-relay")).toBeInTheDocument());
    expect(screen.getByRole("link", { name: "Add host" })).toHaveAttribute("href", "/next/hosts/new");
    // The relays themselves arrive after the list: a route cannot be
    // chosen before the option that names it is there.
    await waitFor(() => expect(screen.getByRole("option", { name: "relay-lab" })).toBeInTheDocument());
    asked.length = 0;
    fireEvent.change(screen.getByTestId("filter-relay"), { target: { value: "r1" } });
    // The route narrows on the server like every other filter here.
    await waitFor(() => expect(asked.some((one) => one.includes("relay=r1"))).toBe(true));
  });
});
