import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Hosts } from "./Hosts";

/**
 * The list is read for two things: which machines answer, and which of
 * them is carrying something somebody has to deal with. Both are held
 * here, and so is the rule the panel is built on - a figure the host
 * never reported is a dash, never a nought.
 */

const asked: string[] = [];
/** The addresses the export asked the server for, through the panel's fetch. */
const fetched: string[] = [];
const posted: { path: string; body: unknown }[] = [];
const answers: Record<string, unknown> = {};
/** What the server refuses, by the address it is asked at. */
const refusals: Record<string, Error> = {};

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  return {
    ...actual,
    // The export goes through the panel's own fetch, which carries the
    // session a bare <a download> would drop.
    fetchWithCredentials: (url: string) => {
      fetched.push(url);
      return Promise.resolve({
        ok: true,
        headers: { get: () => null },
        blob: () => Promise.resolve(new Blob(["hostname\n"])),
      } as unknown as Response);
    },
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

/* The screen sits on its own address, as it does in the panel: a list that
   takes the reader somewhere else is gone by the time they arrive, and one
   left mounted would go on writing its filters into the new address. */
function draw(at = "/hosts") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[at]}>
        <Routes>
          <Route path="/hosts" element={children} />
          <Route path="*" element={null} />
        </Routes>
        <Where />
      </MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Hosts />, { wrapper });
}

/** The filters the old list folded away; they open on one press. */
function openMoreFilters() {
  fireEvent.click(screen.getByTestId("more-filters"));
}

/** What the signed-in reader may do; absent, they may only read. */
const whoami = (...permissions: string[]) => ({
  subject: "operator", kind: "user", roles: [], bindings: [], permissions,
});

/** A relay as the server names one: the filter sends nothing else. */
const RELAY = "9f1c2d3e-4a5b-6c7d-8e9f-0a1b2c3d4e5f";

afterEach(() => {
  cleanup();
  // The folded columns and the page size are this browser's, and this
  // browser is the same one in the next test.
  window.localStorage.clear();
  asked.length = 0;
  fetched.length = 0;
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
    expect(within(row).getByRole("link", { name: "agent-arch" })).toHaveAttribute("href", "/hosts/h1");
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
    const clean = screen.getByTestId("host-clean");
    expect(clean).toHaveTextContent("—");
    expect(clean).not.toHaveTextContent("reboot");
    expect(clean).not.toHaveTextContent("failed units");
    expect(clean).not.toHaveTextContent("security");
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
    // The route is still reachable - by identifier, typed - but the names
    // of the relays belong to whoever may list them.
    openMoreFilters();
    expect(screen.queryByTestId("filter-relay")).toBeNull();
    expect(screen.getByTestId("filter-relay-id")).toBeInTheDocument();
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
    expect(screen.getByTestId("where")).toHaveTextContent("/bulk?host_id=h1");
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
    expect(tag).toHaveAttribute("href", "/hosts?tag=role%3Ddb");
    asked.length = 0;
    fireEvent.click(tag);
    // Every listed tag has to be on the host, and the database decides
    // which ones do - not the page that happens to be loaded.
    await waitFor(() => expect(asked.some((one) => one.includes("tag=role%3Ddb"))).toBe(true));
    // What the list is narrowed by stands over it as a chip, with its own
    // way off.
    expect(screen.getByTestId("active-filters")).toHaveTextContent("role=db");
    expect(screen.getByTestId("clear-tags")).toBeInTheDocument();
  });

  it("offers the route filter only to whoever may list the relays", async () => {
    Object.assign(answers, {
      ...two(),
      "/api/v1/whoami": whoami("host.enroll.read", "host.enroll.create"),
      "/api/v1/relays": { items: [{ id: RELAY, name: "relay-lab" }] },
    });
    draw();
    await waitFor(() => expect(screen.getByRole("link", { name: "Add host" })).toBeInTheDocument());
    expect(screen.getByRole("link", { name: "Add host" })).toHaveAttribute("href", "/hosts/new");
    openMoreFilters();
    expect(screen.getByTestId("filter-relay")).toBeInTheDocument();
    // The relays themselves arrive after the list: a route cannot be
    // chosen before the option that names it is there.
    await waitFor(() => expect(screen.getByRole("option", { name: "relay-lab" })).toBeInTheDocument());
    asked.length = 0;
    fireEvent.change(screen.getByTestId("filter-relay"), { target: { value: RELAY } });
    // The route narrows on the server like every other filter here.
    await waitFor(() => expect(asked.some((one) => one.includes(`relay=${RELAY}`))).toBe(true));
  });
});

/**
 * The chrome the list was read with in the panel being replaced: its
 * twenty-odd filters, its order, its columns, its page and its export.
 *
 * Every one of them is the server's. A filter that sifted the page that
 * happens to be loaded would answer over a hundred hosts out of ten
 * thousand and look like an answer about the fleet.
 */
describe("the chrome of the list", () => {
  const fleet = () => ({
    "/api/v1/hosts": { items: [host({})], total: 1 },
    "/api/v1/fleet/activity": activity,
    "/api/v1/whoami": whoami(),
    "/api/v1/teams": { items: [{ id: "t1", name: "platform" }] },
  });

  /** A filter chosen from a list or ticked: the server hears it at once. */
  const CHOSEN: { name: string; testId: string; value: string; sent: string }[] = [
    { name: "the system", testId: "filter-os-family", value: "arch", sent: "os_family=arch" },
    { name: "the lifecycle", testId: "filter-lifecycle", value: "retired", sent: "lifecycle_state=retired" },
    { name: "the maintenance window", testId: "filter-maintenance", value: "true", sent: "maintenance=true" },
    { name: "the capability", testId: "filter-capability", value: "docker", sent: "capability=docker" },
    { name: "the helper mode", testId: "filter-helper-mode", value: "enforce", sent: "helper_mode=enforce" },
    { name: "the channel", testId: "filter-channel", value: "beta", sent: "channel=beta" },
    { name: "the reboot", testId: "filter-reboot", value: "true", sent: "reboot_required=true" },
    { name: "the security updates", testId: "filter-security", value: "true", sent: "security_updates=true" },
    { name: "the team", testId: "filter-team", value: "none", sent: "team=none" },
  ];

  /** A filter typed into a box: the server hears it once the typing stops. */
  const TYPED: { name: string; testId: string; value: string; sent: string }[] = [
    { name: "the search", testId: "search", value: "agent-fed", sent: "q=agent-fed" },
    { name: "the site", testId: "filter-site", value: "krk", sent: "site=krk" },
    { name: "the environment", testId: "filter-environment", value: "prod", sent: "environment=prod" },
    { name: "the owner", testId: "filter-owner", value: "platform", sent: "owner=platform" },
    { name: "the tags", testId: "filter-tags", value: "role=db", sent: "tag=role%3Ddb" },
    { name: "the directory domain", testId: "filter-identity-domain", value: "corp.example", sent: "identity_domain=corp.example" },
    { name: "the failure domain", testId: "filter-failure-domain", value: "rack-a", sent: "failure_domain=rack-a" },
  ];

  /** A box ticked under "needs attention": one filter, by the label on it. */
  const TICKED: { label: string; sent: string }[] = [
    { label: "failed units", sent: "failed_units=true" },
    { label: "package database broken", sent: "package_db_broken=true" },
    { label: "SSSD offline", sent: "sssd_offline=true" },
    { label: "agent behind", sent: "agent_behind=true" },
  ];

  it.each(CHOSEN)("narrows by $name on the server, and keeps it in the address", async ({ testId, value, sent }) => {
    Object.assign(answers, fleet());
    draw();
    await waitFor(() => expect(screen.getByTestId("host-agent-arch")).toBeInTheDocument());
    openMoreFilters();
    // The systems are the fleet's own, so the option has to have arrived.
    await waitFor(() => expect(screen.getByTestId(testId)).toBeInTheDocument());
    asked.length = 0;
    fireEvent.change(screen.getByTestId(testId), { target: { value } });
    await waitFor(() => expect(asked.some((one) => one.includes(sent))).toBe(true));
    // A narrowed list is a link: what narrows it is in the address.
    expect(screen.getByTestId("where")).toHaveTextContent(sent);
  });

  it.each(TYPED)("narrows by $name on the server, and keeps it in the address", async ({ testId, value, sent }) => {
    Object.assign(answers, fleet());
    draw();
    await waitFor(() => expect(screen.getByTestId("host-agent-arch")).toBeInTheDocument());
    if (testId !== "search") openMoreFilters();
    asked.length = 0;
    fireEvent.change(screen.getByTestId(testId), { target: { value } });
    await waitFor(() => expect(asked.some((one) => one.includes(sent))).toBe(true));
    expect(screen.getByTestId("where")).toHaveTextContent(sent);
  });

  it.each(TICKED)("narrows to the hosts with $label, on the server", async ({ label, sent }) => {
    Object.assign(answers, fleet());
    draw();
    await waitFor(() => expect(screen.getByTestId("host-agent-arch")).toBeInTheDocument());
    openMoreFilters();
    asked.length = 0;
    fireEvent.click(screen.getByLabelText(label));
    await waitFor(() => expect(asked.some((one) => one.includes(sent))).toBe(true));
    expect(screen.getByTestId("where")).toHaveTextContent(sent);
  });

  it("narrows by the connection state, and says how many are in each", async () => {
    Object.assign(answers, fleet());
    draw();
    await waitFor(() => expect(screen.getByRole("button", { name: /Online 3/ })).toBeInTheDocument());
    // Every state the old select offered, including the hosts nobody has
    // heard a word from.
    expect(screen.getByRole("button", { name: /Unknown 0/ })).toBeInTheDocument();
    asked.length = 0;
    fireEvent.click(screen.getByRole("button", { name: /Stale 0/ }));
    await waitFor(() => expect(asked.some((one) => one.includes("connection_state=stale"))).toBe(true));
    expect(screen.getByTestId("where")).toHaveTextContent("connection_state=stale");
  });

  it("carries a refusal handed to it in the address through to the server", async () => {
    Object.assign(answers, fleet());
    draw("/hosts?connection_refusal=certificate_expired");
    await waitFor(() => expect(asked.some((one) => one.includes("connection_refusal=certificate_expired"))).toBe(true));
    // And says in words what the list is narrowed by.
    await waitFor(() => expect(screen.getByTestId("active-filters")).toHaveTextContent("certificate expired"));
  });

  it("will not send a relay identifier that is only half typed", async () => {
    Object.assign(answers, { ...fleet(), "/api/v1/whoami": whoami() });
    draw();
    await waitFor(() => expect(screen.getByTestId("host-agent-arch")).toBeInTheDocument());
    openMoreFilters();
    asked.length = 0;
    fireEvent.change(screen.getByTestId("filter-relay-id"), { target: { value: "9f1c2d3e-4a5b" } });
    // It stays in the address, because the reader typed it; it does not go
    // to the server, which would refuse it and take the whole list with it.
    await waitFor(() => expect(screen.getByTestId("where")).toHaveTextContent("relay=9f1c2d3e-4a5b"));
    expect(asked.some((one) => one.includes("relay="))).toBe(false);
    fireEvent.change(screen.getByTestId("filter-relay-id"), { target: { value: RELAY } });
    await waitFor(() => expect(asked.some((one) => one.includes(`relay=${RELAY}`))).toBe(true));
  });

  it("orders the list on the server, and in the order it is told", async () => {
    Object.assign(answers, fleet());
    draw();
    await waitFor(() => expect(screen.getByTestId("host-agent-arch")).toBeInTheDocument());
    // Nothing asked for is nothing sent: the list's own order is the name.
    expect(asked.some((one) => one.includes("sort="))).toBe(false);
    asked.length = 0;
    // The heading is the control, as it was in the panel being replaced,
    // and the same heading a second time turns the order round.
    fireEvent.click(screen.getByTestId("hosts-sort-seen"));
    await waitFor(() => expect(asked.some((one) => one.includes("sort=last_seen_at"))).toBe(true));
    await waitFor(() => expect(
      screen.getByTestId("hosts-sort-seen").closest("th"),
    ).toHaveAttribute("aria-sort", "ascending"));
    asked.length = 0;
    fireEvent.click(screen.getByTestId("hosts-sort-seen"));
    await waitFor(() => expect(
      asked.some((one) => decodeURIComponent(one).includes("sort=last_seen_at:desc")),
    ).toBe(true));
    await waitFor(() => expect(
      screen.getByTestId("hosts-sort-seen").closest("th"),
    ).toHaveAttribute("aria-sort", "descending"));
    expect(screen.getByTestId("where")).toHaveTextContent("sort=last_seen_at%3Adesc");
    // A column folded away takes its order with it, as it did before:
    // owner starts folded, so it has no heading until it is unfolded.
    expect(screen.queryByTestId("hosts-sort-owner")).toBeNull();
    fireEvent.click(screen.getByTestId("hosts-columns"));
    fireEvent.click(screen.getByLabelText("Owner"));
    expect(screen.getByTestId("hosts-sort-owner")).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText("Owner"));
    expect(screen.queryByTestId("hosts-sort-owner")).toBeNull();
  });

  it("leaves out an order naming a column the server has not got", async () => {
    Object.assign(answers, fleet());
    draw("/hosts?sort=whatever");
    await waitFor(() => expect(screen.getByTestId("host-agent-arch")).toBeInTheDocument());
    expect(asked.some((one) => one.includes("sort="))).toBe(false);
  });

  it("folds a column away, and the browser remembers which", async () => {
    Object.assign(answers, fleet());
    draw();
    await waitFor(() => expect(screen.getByTestId("host-agent-arch")).toBeInTheDocument());
    // The owner is empty on most fleets until somebody records it, so the
    // column starts folded - as it did in the panel being replaced.
    expect(screen.queryByTestId("host-owner")).toBeNull();
    fireEvent.click(screen.getByTestId("hosts-columns"));
    fireEvent.click(screen.getByLabelText("Owner"));
    await waitFor(() => expect(screen.getByTestId("host-owner")).toBeInTheDocument());
    expect(JSON.parse(window.localStorage.getItem("fl.columns.next-hosts") ?? "[]")).not.toContain("owner");

    // And it is still unfolded the next time the screen is opened.
    cleanup();
    draw();
    await waitFor(() => expect(screen.getByTestId("host-owner")).toBeInTheDocument());
  });

  it("asks the server for as many rows as the reader chose, and remembers it", async () => {
    Object.assign(answers, fleet());
    draw();
    await waitFor(() => expect(screen.getByTestId("host-agent-arch")).toBeInTheDocument());
    asked.length = 0;
    fireEvent.change(screen.getByTestId("page-size"), { target: { value: "25" } });
    await waitFor(() => expect(asked.some((one) => one.includes("limit=25"))).toBe(true));
    expect(window.localStorage.getItem("flotestro.page-size.hosts")).toBe("25");
  });

  it("exports the list that is on the screen, with the filter on it", async () => {
    Object.assign(answers, fleet());
    draw();
    await waitFor(() => expect(screen.getByTestId("host-agent-arch")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("search"), { target: { value: "agent-fed" } });
    await waitFor(() => expect(asked.some((one) => one.includes("q=agent-fed"))).toBe(true));
    fireEvent.click(screen.getByTestId("export-csv"));
    await waitFor(() => expect(fetched).toHaveLength(1));
    // The screen's filter, as a file; the page the screen happens to be on
    // is not part of the question.
    expect(fetched[0]).toContain("/api/v1/hosts?");
    expect(fetched[0]).toContain("q=agent-fed");
    expect(fetched[0]).toContain("format=csv");
    expect(fetched[0]).not.toContain("limit=");
    expect(fetched[0]).not.toContain("cursor=");
  });

  it("says when it last read the list, and reads it again on request", async () => {
    Object.assign(answers, fleet());
    draw();
    await waitFor(() => expect(screen.getByTestId("host-agent-arch")).toBeInTheDocument());
    await waitFor(() => expect(screen.getByTestId("refreshed")).toHaveTextContent("refreshed"));
    asked.length = 0;
    fireEvent.click(screen.getByTestId("refresh-now"));
    await waitFor(() => expect(asked.some((one) => one.startsWith("/api/v1/hosts?"))).toBe(true));
  });

  it("clears every filter at once, and leaves the order alone", async () => {
    Object.assign(answers, fleet());
    draw("/hosts?site=krk&sort=last_seen_at");
    await waitFor(() => expect(screen.getByTestId("active-filters")).toHaveTextContent("krk"));
    fireEvent.click(screen.getByTestId("clear-filters"));
    await waitFor(() => expect(screen.queryByTestId("active-filters")).toBeNull());
    expect(screen.getByTestId("where")).toHaveTextContent("sort=last_seen_at");
    expect(screen.getByTestId("where")).not.toHaveTextContent("site=krk");
  });

  it("takes a count in the composition to the hosts it counted", async () => {
    Object.assign(answers, fleet());
    draw();
    await waitFor(() => expect(screen.getByTestId("host-agent-arch")).toBeInTheDocument());
    // The composition carries every dimension the old one did; "lab" is a
    // site, and pressing it asks the server for that site alone.
    asked.length = 0;
    fireEvent.click(screen.getByRole("button", { name: "lab" }));
    await waitFor(() => expect(asked.some((one) => one.includes("site=lab"))).toBe(true));
  });

  it("offers the enrolment to a reader with nothing to look at", async () => {
    Object.assign(answers, { ...fleet(), "/api/v1/hosts": { items: [] }, "/api/v1/whoami": whoami("host.enroll.create") });
    draw();
    await waitFor(() => expect(screen.getByText("No host matches the filters.")).toBeInTheDocument());
    expect(screen.getAllByRole("link", { name: "Add host" })[0]).toHaveAttribute("href", "/hosts/new");
  });
});
