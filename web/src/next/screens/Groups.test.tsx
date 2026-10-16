import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ApiError } from "../../lib/api";
import {
  Groups, campaignAddress, connectionTone, describeSelector, matchingGroups, namedBy, orderGroups,
  readAddress, selectorOf, type GroupUsage,
} from "./Groups";
import { ToastProvider } from "../../components/Toast";

/**
 * What a group's row has to say, and what the two writes the screen owns
 * have to send.
 *
 * The size of a group is the thing worth holding hardest: a selector that
 * has stopped resolving names nobody only because nobody could ask it,
 * and a row that printed 0 there would read as a group somebody emptied.
 */

const asked: string[] = [];
const sent: { method: string; path: string; body?: unknown }[] = [];
const answers: Record<string, unknown> = {};

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  // The longest key that is a prefix of the path answers it. A short key
  // left to answer a longer path hands the screen the wrong document:
  // "/api/v1/host-groups" would otherwise answer the preview and the
  // single record as if they were the collection.
  const answer = (path: string) => {
    asked.push(path);
    const key = Object.keys(answers)
      .filter((one) => path.startsWith(one))
      .sort((a, b) => b.length - a.length)[0];
    if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
    // An Error standing in the table is a refusal, so a test can ask for
    // the 404 an identifier naming nothing comes back with.
    const value = answers[key];
    if (value instanceof Error) return Promise.reject(value);
    return Promise.resolve(value);
  };
  return {
    ...actual,
    api: {
      ...actual.api,
      get: answer,
      post: (path: string, body?: unknown) => { sent.push({ method: "POST", path, body }); return Promise.resolve({ id: "new", name: "databases-gold" }); },
      put: (path: string, body?: unknown) => { sent.push({ method: "PUT", path, body }); return Promise.resolve({}); },
      del: (path: string, body?: unknown) => { sent.push({ method: "DELETE", path, body }); return Promise.resolve(undefined); },
    },
  };
});

const group = (over: Record<string, unknown>) => ({
  id: "g1", name: "databases", description: "every database host", kind: "dynamic",
  selector: { tag: "role=db" }, created_by: "tszymanski", created_at: "2026-10-01T08:00:00Z",
  updated_at: "2026-10-15T08:00:00Z", member_count: 7,
  ...over,
});

/** Where the panel stands now, so a click can be read as an address. */
function Where() {
  const where = useLocation();
  return <span data-testid="where">{where.pathname}</span>;
}

/**
 * The screen under the two addresses it answers on: the catalogue, and
 * one group. They are one component, so both routes lead to it and the
 * parameter is what decides which the reader gets.
 */
function draw(at = "/next/groups") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[at]}>
        <ToastProvider>
          <Routes>
            <Route path="/next/groups" element={<Groups />} />
            <Route path="/next/groups/:id" element={<Groups />} />
          </Routes>
          <Where />
        </ToastProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  sent.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the list of groups", () => {
  it("draws a group as its name, what kind of answer it is and how many hosts it names", async () => {
    Object.assign(answers, {
      "/api/v1/host-groups": { items: [group({})], count: 1 },
      "/api/v1/whoami": { subject: "t", kind: "user", roles: [], bindings: [], permissions: [] },
      "/api/v1/settings/layout": { widgets: [], present: false, revision: 0 },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("group-databases")).toBeInTheDocument());
    const row = screen.getByTestId("group-databases");
    expect(within(row).getByRole("link", { name: "databases" })).toHaveAttribute("href", "/next/groups/g1");
    expect(row).toHaveTextContent("every database host");
    expect(within(row).getByText("selector")).toBeInTheDocument();
    expect(row).toHaveTextContent("tag=role=db");
    expect(row).toHaveTextContent("7");
  });

  it("says a size the server could not give is unknown, never nought", async () => {
    Object.assign(answers, {
      "/api/v1/host-groups": {
        items: [
          group({ id: "g2", name: "uncounted", member_count: undefined }),
          group({ id: "g3", name: "broken", member_count: undefined, unresolvable: "the group it names is gone" }),
        ],
        count: 2,
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("group-uncounted")).toBeInTheDocument());
    expect(within(screen.getByTestId("group-uncounted")).getByText("unknown")).toBeInTheDocument();
    expect(screen.getByTestId("group-uncounted")).not.toHaveTextContent("0");
    // A selector that does not resolve says why, rather than counting to none.
    const broken = screen.getByTestId("group-broken");
    expect(within(broken).getByText("unresolvable")).toHaveAttribute("title", "the group it names is gone");
    expect(screen.getByText("the group it names is gone")).toBeInTheDocument();
  });

  it("says how many of how many it is drawing when the search narrows the catalogue", async () => {
    Object.assign(answers, {
      "/api/v1/host-groups": {
        items: [group({}), group({ id: "g4", name: "web", description: "the front end", member_count: 3 })],
        count: 2,
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("group-web")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("group-search"), { target: { value: "front" } });
    await waitFor(() => expect(screen.queryByTestId("group-databases")).not.toBeInTheDocument());
    const card = screen.getByTestId("group-web").closest(".fl-card") as HTMLElement;
    expect(card.querySelector(".fl-card-note")).toHaveTextContent("1 of 2 groups");
  });

  it("says an empty catalogue is empty rather than drawing a head over nothing", async () => {
    Object.assign(answers, { "/api/v1/host-groups": { items: [], count: 0 } });
    draw();
    await waitFor(() => expect(screen.getByText(/No group yet/)).toBeInTheDocument());
  });
});

describe("one group from the address", () => {
  const member = (over: Record<string, unknown> = {}) => ({
    id: "h1", hostname: "db-1", machine_id: "m1", site: "waw", environment: "prod",
    tags: ["role=db"], release_channel: "stable", lifecycle_state: "active",
    os_distribution: "debian", os_version: "12", connection_state: "online",
    last_seen_at: "2026-10-16T07:00:00Z", enrolled_at: "2026-09-01T08:00:00Z",
    reboot_required: null, failed_units: null, pending_updates: null, pending_security_updates: null,
    package_database_broken: false, capabilities: {}, identity: {},
    ...over,
  });

  it("opens the group the address names: its selector, what names it, and what it resolves to", async () => {
    Object.assign(answers, {
      "/api/v1/host-groups": { items: [group({})], count: 1 },
      "/api/v1/host-groups/g1": group({
        used_by: {
          campaigns: [{ id: "c1", name: "patch the lab", state: "running" }],
          policies: [{ id: "p1", name: "baseline", state: "enabled" }],
        },
      }),
      "/api/v1/host-groups/g1/hosts": { items: [member()], count: 1, total: 1 },
      "/api/v1/whoami": { subject: "t", kind: "user", roles: [], bindings: [], permissions: [] },
    });
    draw("/next/groups/g1");
    await waitFor(() => expect(screen.getByTestId("member-db-1")).toBeInTheDocument());
    // What it answers with, said the way the server logs it.
    expect(screen.getByTestId("group-selector")).toHaveTextContent("tag=role=db");
    // What names it elsewhere, with the campaign as a way in.
    expect(within(screen.getByTestId("uses-patch the lab")).getByRole("link", { name: "patch the lab" }))
      .toHaveAttribute("href", "/next/campaigns/c1");
    expect(screen.getByTestId("uses-baseline")).toHaveTextContent("policy");
    // And what it resolves to now, each host a way into its own screen.
    expect(within(screen.getByTestId("member-db-1")).getByRole("link", { name: "db-1" }))
      .toHaveAttribute("href", "/next/hosts/h1");
    expect(screen.getByTestId("kpi-group-hosts")).toHaveTextContent("7");
    // The catalogue is not drawn underneath it.
    expect(screen.queryByTestId("group-search")).not.toBeInTheDocument();
  });

  it("keeps a size nobody could give unknown on the group's own screen too", async () => {
    Object.assign(answers, {
      "/api/v1/host-groups": { items: [], count: 0 },
      "/api/v1/host-groups/g1": group({ member_count: undefined, unresolvable: "the group it names is gone" }),
      "/api/v1/host-groups/g1/hosts": { items: [], count: 0, total: 0 },
    });
    draw("/next/groups/g1");
    await waitFor(() => expect(screen.getByTestId("kpi-group-hosts")).toBeInTheDocument());
    const hosts = screen.getByTestId("kpi-group-hosts");
    expect(hosts).toHaveAttribute("data-state", "unknown");
    expect(within(hosts).getByText("—")).toBeInTheDocument();
    expect(hosts).not.toHaveTextContent("0");
    expect(screen.getByText(/The selector does not resolve/)).toHaveTextContent("the group it names is gone");
  });

  it("says an identifier naming nothing names nothing, and offers the catalogue", async () => {
    Object.assign(answers, {
      "/api/v1/host-groups": { items: [group({})], count: 1 },
      "/api/v1/host-groups/ghost": new ApiError(404, "not_found", "no such group"),
    });
    draw("/next/groups/ghost");
    await waitFor(() => expect(screen.getByText(/No group with the identifier ghost/)).toBeInTheDocument());
    // No detail card over nothing, and a way to the list.
    expect(screen.queryByTestId("group-selector")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "All groups" })).toHaveAttribute("href", "/next/groups");
  });

  it("puts the group picked from a row in the address", async () => {
    Object.assign(answers, {
      "/api/v1/host-groups": { items: [group({})], count: 1 },
      "/api/v1/host-groups/g1": group({}),
      "/api/v1/host-groups/g1/hosts": { items: [], count: 0, total: 0 },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("group-databases")).toBeInTheDocument());
    expect(screen.getByTestId("where")).toHaveTextContent("/next/groups");
    fireEvent.click(within(screen.getByTestId("group-databases")).getByRole("link", { name: "databases" }));
    await waitFor(() => expect(screen.getByTestId("where")).toHaveTextContent("/next/groups/g1"));
    // And the group itself opens where the catalogue was: one navigation,
    // not a reload of the panel.
    await waitFor(() => expect(screen.getByTestId("group-selector")).toBeInTheDocument());
  });

  it("hands the group's name to the workspaces that take one", () => {
    expect(campaignAddress("databases")).toBe("/next/bulk?name=databases&group=databases");
    expect(readAddress("databases")).toBe("/next/reads?action=journal.read&group=databases");
  });

  it("calls a connection nobody could read unknown, not offline", () => {
    expect(connectionTone("online")).toBe("ok");
    expect(connectionTone("offline")).toBe("error");
    expect(connectionTone("stale")).toBe("warn");
    expect(connectionTone(undefined)).toBe("unknown");
  });
});

describe("creating a group", () => {
  it("sends the name and the selector that was built, not an empty one", async () => {
    Object.assign(answers, {
      "/api/v1/host-groups": { items: [], count: 0 },
      "/api/v1/host-groups/preview": { count: 2, sample: ["db-1", "db-2"], selector: "" },
      "/api/v1/hosts": { items: [], count: 0 },
      "/api/v1/whoami": { subject: "t", kind: "user", roles: [], bindings: [], permissions: ["host.group.write"] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("new-group")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("new-group"));
    fireEvent.change(screen.getByTestId("group-kind"), { target: { value: "dynamic" } });
    fireEvent.change(screen.getByTestId("group-name"), { target: { value: "databases-gold" } });
    fireEvent.change(screen.getByTestId("group-description"), { target: { value: "the gold tier" } });
    fireEvent.change(screen.getByTestId("rule-value-tag"), { target: { value: "role=db" } });
    fireEvent.click(screen.getByTestId("create-group"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].method).toBe("POST");
    expect(sent[0].path).toBe("/api/v1/host-groups");
    expect(sent[0].body).toMatchObject({
      name: "databases-gold", description: "the gold tier", kind: "dynamic", selector: { tag: "role=db" },
    });
  });

  it("keeps the button shut while no rule has a value, so nothing is saved that names everybody", async () => {
    Object.assign(answers, {
      "/api/v1/host-groups": { items: [], count: 0 },
      "/api/v1/hosts": { items: [], count: 0 },
      "/api/v1/whoami": { subject: "t", kind: "user", roles: [], bindings: [], permissions: ["host.group.write"] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("new-group")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("new-group"));
    fireEvent.change(screen.getByTestId("group-kind"), { target: { value: "dynamic" } });
    fireEvent.change(screen.getByTestId("group-name"), { target: { value: "databases-gold" } });
    expect(screen.getByTestId("create-group")).toBeDisabled();
  });
});

describe("deleting a group", () => {
  it("asks first, names what stops resolving, and only then removes it", async () => {
    Object.assign(answers, {
      "/api/v1/host-groups": { items: [group({})], count: 1 },
      "/api/v1/host-groups/g1": group({
        used_by: { campaigns: [{ id: "c1", name: "patch the lab", state: "running" }], policies: [] },
      }),
      "/api/v1/whoami": { subject: "t", kind: "user", roles: [], bindings: [], permissions: ["host.group.write"] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("delete-a-group")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("delete-a-group"));
    // The dialog is open and nothing has been deleted: the button waits
    // for a group to be named.
    expect(screen.getByTestId("group-delete")).toBeDisabled();
    expect(sent).toHaveLength(0);

    fireEvent.change(screen.getByTestId("group-to-delete"), { target: { value: "g1" } });
    await waitFor(() => expect(screen.getByText(/campaign patch the lab/)).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("group-delete"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0]).toMatchObject({ method: "DELETE", path: "/api/v1/host-groups/g1" });
  });

  it("is not offered at all to whoever may not write groups", async () => {
    Object.assign(answers, {
      "/api/v1/host-groups": { items: [group({})], count: 1 },
      "/api/v1/whoami": { subject: "t", kind: "user", roles: [], bindings: [], permissions: ["host.read"] },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("group-databases")).toBeInTheDocument());
    expect(screen.queryByTestId("delete-a-group")).not.toBeInTheDocument();
    expect(screen.queryByTestId("new-group")).not.toBeInTheDocument();
  });
});

describe("the order of the list", () => {
  it("puts a group nobody counted last, rather than treating it as the smallest", () => {
    const items = [
      { name: "a", member_count: undefined },
      { name: "b", member_count: 2 },
      { name: "c", member_count: 9 },
    ];
    expect(orderGroups(items, "size").map((one) => one.name)).toEqual(["c", "b", "a"]);
    expect(orderGroups(items, "name").map((one) => one.name)).toEqual(["a", "b", "c"]);
  });

  it("leaves the list it was given alone", () => {
    const items = [{ name: "b", member_count: 1 }, { name: "a", member_count: 2 }];
    orderGroups(items, "name");
    expect(items.map((one) => one.name)).toEqual(["b", "a"]);
  });
});

describe("the search", () => {
  it("keeps everything for an empty search and finds a group by its description, case aside", () => {
    const items = [{ name: "databases", description: "Every Database Host" }, { name: "web", description: "" }];
    expect(matchingGroups(items, "")).toHaveLength(2);
    expect(matchingGroups(items, "database host").map((one) => one.name)).toEqual(["databases"]);
  });
});

describe("the selector", () => {
  it("builds one leaf per row and joins them the way the operator asked", () => {
    expect(selectorOf([{ field: "tag", value: "role=db", negated: false }], "all")).toEqual({ tag: "role=db" });
    expect(selectorOf([
      { field: "tag", value: "role=db", negated: false },
      { field: "site", value: "waw", negated: true },
    ], "any")).toEqual({ any: [{ tag: "role=db" }, { not: { site: "waw" } }] });
    // A row with no value is not a rule yet; a selector of nothing is null,
    // not a selector that names the whole fleet.
    expect(selectorOf([{ field: "tag", value: "  ", negated: false }], "all")).toBeNull();
  });

  it("says a saved expression in the one line the server logs", () => {
    expect(describeSelector({ all: [{ tag: "role=db" }, { not: { site: "waw" } }] }))
      .toBe("(tag=role=db and not site=waw)");
    expect(describeSelector(null)).toBe("");
  });
});

describe("what names a group", () => {
  const say = (key: string, vars?: Record<string, string | number>) =>
    key.replace(/\{(\w+)\}/g, (_, name: string) => String(vars?.[name] ?? ""));

  it("says nothing when nothing names it", () => {
    expect(namedBy({ campaigns: [], policies: [] }, say)).toBe("");
    expect(namedBy(undefined, say)).toBe("");
  });

  it("names every campaign and every policy in one sentence", () => {
    const usage: GroupUsage = {
      campaigns: [{ id: "c1", name: "patch", state: "running" }],
      policies: [{ id: "p1", name: "baseline", state: "enabled" }],
    };
    expect(namedBy(usage, say)).toContain("campaign patch");
    expect(namedBy(usage, say)).toContain("policy baseline");
  });
});
