import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import type { Translate } from "../../i18n";
import {
  Access, grantRequest, narrowRows, permissionsLost, previewScope, readScope, statusOf,
  expired, expiresSoon,
  type BindingScope, type Filter, type GrantFields,
} from "./Access";
import { ToastProvider } from "../../components/Toast";

/**
 * The shape this screen was rewritten for, held in place.
 *
 * A row says what a subject is and carries nothing to press; the name is
 * the way in; what acts on many appears when many are chosen and says how
 * many; and one count says how much of how much is on screen. Each of
 * those was a verdict of the owner's, so each of them is a test rather
 * than a convention somebody may tidy away.
 */

const asked: string[] = [];
const sent: { method: string; path: string; body?: unknown }[] = [];
const answers: Record<string, unknown> = {};
/** What the next write comes back with, where the server refuses it. */
let refuse: unknown = null;

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  // The longest key that is a prefix of the path answers it. With the
  // shortest, "/api/v1/principals" would answer the sessions of one of
  // them and hand the screen the wrong document.
  const answer = (path: string) => {
    const key = Object.keys(answers)
      .filter((one) => path.startsWith(one))
      .sort((a, b) => b.length - a.length)[0];
    if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
    return Promise.resolve(answers[key]);
  };
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => { asked.push(path); return answer(path); },
      post: (path: string, body?: unknown) => {
        sent.push({ method: "POST", path, body });
        return refuse ? Promise.reject(refuse) : Promise.resolve({});
      },
      put: (path: string, body?: unknown) => {
        sent.push({ method: "PUT", path, body });
        return refuse ? Promise.reject(refuse) : Promise.resolve({});
      },
      del: (path: string, body?: unknown) => {
        sent.push({ method: "DELETE", path, body });
        return refuse ? Promise.reject(refuse) : Promise.resolve(undefined);
      },
    },
  };
});

/** The translation a pure helper is measured with: the key, with its holes filled. */
const tr: Translate = (text, params) =>
  text.replace(/\{(\w+)\}/g, (whole, name: string) => (params && name in params ? String(params[name]) : whole));

const fleetScope: BindingScope = {
  site: "*", environment: "*", team_scope: { mode: "any" }, owners: ["*"], tags: ["*"],
};
const labScope: BindingScope = {
  site: "lab", environment: "test", team_scope: { mode: "any" }, owners: ["*"], tags: ["db"],
};

const holder = (over: Record<string, unknown> = {}) => ({
  subject: "tszymanski",
  display_name: "Tomasz Szymanski",
  kind: "user",
  principal_id: "p1",
  signed_in: true,
  groups: ["flotestro-operators"],
  roles: [{ role: "operator", scope: "site=lab environment=*", from: "group", group: "flotestro-operators" }],
  ...over,
});

const principal = (over: Record<string, unknown> = {}) => ({
  id: "p1",
  subject: "tszymanski",
  display_name: "Tomasz Szymanski",
  kind: "user",
  bindings: [{ role: "operator", scope: labScope }],
  tokens: [{ id: "t1ab2cd3e4", description: "backup runner", created_at: "2026-09-01T08:00:00Z" }],
  ...over,
});

/** The role catalogue: the product's own, and one this installation wrote. */
const roles = {
  items: [
    { role: "viewer", built_in: true, permissions: ["host.read"] },
    { role: "operator", built_in: true, permissions: ["host.read", "unit.restart"] },
    {
      role: "shift_lead",
      description: "restarts services on the night shift",
      permissions: ["unit.restart", "job.create"],
      bindings: 2, mappings: 0, created_by: "admin",
    },
  ],
  count: 3,
};

/** The vocabulary a role is written in, with one permission nobody holds. */
const vocabulary = {
  items: [
    { permission: "host.read", group: "host" },
    { permission: "job.create", group: "job" },
    { permission: "unit.restart", group: "unit" },
    { permission: "secret.write", group: "secret" },
  ],
  count: 4,
};

const review = {
  items: [
    {
      id: "p1", subject: "tszymanski", display_name: "Tomasz Szymanski", kind: "user",
      created_at: "2026-01-01T08:00:00Z", last_seen_at: "2026-07-01T08:00:00Z",
      bindings: [{ role: "operator", scope: labScope, expired: false, created_by: "admin", created_at: "2026-01-01T08:00:00Z" }],
      tokens: [{ id: "t1ab2cd3e4", description: "backup runner", created_at: "2026-01-01T08:00:00Z" }],
      flags: ["unused_90_days"],
    },
    {
      id: "p2", subject: "backup-runner", kind: "service", created_at: "2026-02-01T08:00:00Z",
      bindings: [], tokens: [], flags: [],
    },
  ],
  count: 2, flagged: 1, reviewed_at: "2026-10-16T08:00:00Z",
  thresholds: { unused_days: 90, expires_soon_days: 7, token_max_days: 365 },
};

/** The answers every drawing of this screen needs before it can say anything. */
function given(over: Record<string, unknown> = {}) {
  Object.assign(answers, {
    "/api/v1/roles": roles,
    "/api/v1/permissions": vocabulary,
    "/api/v1/teams": { items: [{ id: "team-1", name: "Night rota" }], count: 1 },
    "/api/v1/group-mappings": { items: [], count: 0 },
    "/api/v1/whoami": { permissions: ["principal.manage"] },
    "/api/v1/access/review": review,
    "/api/v1/access/holders": {
      items: [holder()], count: 1,
      directory: { configured: true, read: true },
    },
    "/api/v1/principals": { items: [principal()], count: 1, total: 1, limit: 50, offset: 0 },
    ...over,
  });
}

/**
 * The screen, opened at an address.
 *
 * It was thirteen containers on one board until 17.10 and is six
 * sub-tabs now, with the open one in `?tab=`, so a test that reads the
 * roles, the mappings, the review or the permissions says which one it
 * is on. A bare address opens on the people.
 */
function draw(at = "/") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter initialEntries={[at]}><ToastProvider>{children}</ToastProvider></MemoryRouter></QueryClientProvider>
  );
  return render(<Access />, { wrapper });
}

/** The list as the identities, which is the scope the server pages. */
async function onIdentities() {
  draw();
  await waitFor(() => expect(screen.getByRole("button", { name: "Identities on record" })).toBeInTheDocument());
  fireEvent.click(screen.getByRole("button", { name: "Identities on record" }));
  await waitFor(() => expect(screen.getByTestId("row-tszymanski")).toBeInTheDocument());
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  sent.length = 0;
  refuse = null;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("a row of the list", () => {
  it("carries the subject as a link and not one button", async () => {
    given();
    draw();
    await waitFor(() => expect(screen.getByTestId("row-tszymanski")).toBeInTheDocument());
    const row = screen.getByTestId("row-tszymanski");
    // The whole point of the rewrite: seven buttons a row became none.
    expect(within(row).queryAllByRole("button")).toHaveLength(0);
    expect(within(row).getByRole("link", { name: "tszymanski" })).toHaveAttribute("href", "/?who=tszymanski");
  });

  it("keeps Remove out of the roles column, because a role is edited in the record", async () => {
    given();
    draw();
    await waitFor(() => expect(screen.getByTestId("row-tszymanski")).toBeInTheDocument());
    const row = screen.getByTestId("row-tszymanski");
    expect(within(row).queryByText("Remove")).not.toBeInTheDocument();
    expect(within(row).getByText(/operator/)).toBeInTheDocument();
  });

  it("says unknown with a dash where the scope was not asked, never with a nought", async () => {
    given();
    draw();
    await waitFor(() => expect(screen.getByTestId("row-tszymanski")).toBeInTheDocument());
    // The holders listing says nothing about tokens, and a nought there
    // would say this person holds none.
    const row = screen.getByTestId("row-tszymanski");
    const unknown = within(row).getAllByTitle("unknown in this scope");
    expect(unknown).toHaveLength(2);
    for (const cell of unknown) expect(cell).toHaveTextContent("—");
    expect(within(row).queryByText("0")).not.toBeInTheDocument();
  });
});

describe("the scope of the one table", () => {
  it("makes who may sign in a scope rather than a second table", async () => {
    given({
      "/api/v1/access/holders": {
        items: [holder({ subject: "jkowalska", principal_id: undefined, signed_in: false })],
        count: 1, directory: { configured: true, read: true },
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("row-jkowalska")).toBeInTheDocument());
    expect(screen.getAllByTestId("access-rows")).toHaveLength(1);
    // The person of the directory the panel has never seen is in the one
    // scope and not in the other; there is still one table.
    fireEvent.click(screen.getByRole("button", { name: "Identities on record" }));
    await waitFor(() => expect(screen.getByTestId("row-tszymanski")).toBeInTheDocument());
    expect(screen.getAllByTestId("access-rows")).toHaveLength(1);
    expect(screen.queryByTestId("row-jkowalska")).not.toBeInTheDocument();
  });
});

describe("the bulk bar", () => {
  it("is not there until something is chosen, and then says how many it acts on", async () => {
    given();
    draw();
    await waitFor(() => expect(screen.getByTestId("row-tszymanski")).toBeInTheDocument());
    expect(screen.queryByTestId("bulk-count")).not.toBeInTheDocument();
    expect(screen.queryByTestId("bulk-disable")).not.toBeInTheDocument();

    fireEvent.click(screen.getByTestId("pick-tszymanski"));
    await waitFor(() => expect(screen.getByTestId("bulk-count")).toBeInTheDocument());
    expect(screen.getByTestId("bulk-count")).toHaveTextContent("1 chosen");
    expect(screen.getByTestId("bulk-disable")).toBeInTheDocument();
  });

  it("disables what it names, and only once a reason has been given", async () => {
    given();
    draw();
    await waitFor(() => expect(screen.getByTestId("row-tszymanski")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("pick-tszymanski"));
    fireEvent.click(await screen.findByTestId("bulk-disable"));

    const confirm = await screen.findByTestId("ask-confirm");
    // Nothing destructive without a confirmation, and the server keeps the
    // reason, so the button stays shut until there is one.
    expect(confirm).toBeDisabled();
    expect(sent).toHaveLength(0);
    fireEvent.change(screen.getByTestId("ask-reason"), { target: { value: "left the company" } });
    expect(confirm).toBeEnabled();
    fireEvent.click(confirm);
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].method).toBe("DELETE");
    expect(sent[0].path).toContain("/api/v1/principals/p1?reason=left");
  });
});

describe("the counter", () => {
  it("says the range it drew and the whole of what was found", async () => {
    given({
      "/api/v1/principals": { items: [principal()], count: 1, total: 1805, limit: 50, offset: 0 },
    });
    await onIdentities();
    // One counter, and it quotes the fleet rather than the page: "among
    // the 50 listed" over 1805 was the fault the owner named.
    expect(screen.getByTestId("page-of")).toHaveTextContent("1-50 of 1805");
  });

  it("counts the kinds over everything that matched, and says so", async () => {
    given({
      "/api/v1/principals": {
        items: [principal()], count: 1, total: 1805, limit: 50, offset: 0,
        by_kind: { user: 1600, service: 205 }, without_bindings: 12,
      },
    });
    await onIdentities();
    // The counts stand above the table, in the card that holds it.
    const card = (await screen.findByText("By kind")).closest(".fl-card") as HTMLElement;
    expect(card).toHaveTextContent("over all 1805 that match");
    expect(card.querySelector("table")).not.toBeNull();
  });
});

describe("the filter", () => {
  it("has named fields and narrows on the server, on Apply", async () => {
    given();
    draw();
    await waitFor(() => expect(screen.getByTestId("filter-subject")).toBeInTheDocument());
    for (const field of ["filter-subject", "filter-name", "filter-role", "filter-kind", "filter-status"]) {
      expect(screen.getByTestId(field)).toBeInTheDocument();
    }
    asked.length = 0;
    fireEvent.change(screen.getByTestId("filter-subject"), { target: { value: "kowalska" } });
    // Typing asks nothing: a list that re-reads the server on every
    // keystroke cannot be filled in by somebody who types slowly.
    expect(asked.some((one) => one.includes("q=kowalska"))).toBe(false);
    fireEvent.click(screen.getByTestId("filter-apply"));
    await waitFor(() => expect(asked.some((one) => one.includes("q=kowalska"))).toBe(true));
  });

  it("puts the list back on Reset", async () => {
    given();
    draw();
    await waitFor(() => expect(screen.getByTestId("filter-subject")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("filter-subject"), { target: { value: "kowalska" } });
    fireEvent.click(screen.getByTestId("filter-apply"));
    await waitFor(() => expect(asked.some((one) => one.includes("q=kowalska"))).toBe(true));
    asked.length = 0;
    fireEvent.click(screen.getByTestId("filter-reset"));
    await waitFor(() => expect(asked.some((one) => one.startsWith("/api/v1/principals?limit="))).toBe(true));
    expect((screen.getByTestId("filter-subject") as HTMLInputElement).value).toBe("");
  });

  it("asks the server for the disabled ones by their own question", async () => {
    given();
    draw();
    await waitFor(() => expect(screen.getByTestId("filter-status")).toBeInTheDocument());
    asked.length = 0;
    fireEvent.change(screen.getByTestId("filter-status"), { target: { value: "disabled" } });
    fireEvent.click(screen.getByTestId("filter-apply"));
    await waitFor(() => expect(asked.some((one) => one.includes("disabled=true"))).toBe(true));
  });
});

describe("the record behind the name", () => {
  it("opens on the subject and sorts the rare acts into four tabs", async () => {
    given();
    draw();
    await waitFor(() => expect(screen.getByTestId("open-tszymanski")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("open-tszymanski"));
    await waitFor(() => expect(screen.getByRole("tab", { name: "Identity" })).toBeInTheDocument());
    for (const tab of ["Identity", "Roles and scopes", "Tokens and sessions", "Password"]) {
      expect(screen.getByRole("tab", { name: new RegExp(`^${tab}`) })).toBeInTheDocument();
    }
  });

  it("grants a role from the record, and says what the grant will reach", async () => {
    given();
    draw();
    await waitFor(() => expect(screen.getByTestId("open-tszymanski")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("open-tszymanski"));
    fireEvent.click(await screen.findByRole("tab", { name: /^Roles and scopes/ }));

    // An empty site and an empty environment are the asterisks the server
    // fills in, so the form says "the whole fleet" before anything is sent.
    expect(await screen.findByTestId("grant-preview")).toHaveTextContent("the whole fleet");
    fireEvent.change(screen.getByTestId("grant-owners"), { target: { value: "alice" } });
    expect(screen.getByTestId("grant-preview")).toHaveTextContent("owner alice");

    fireEvent.change(screen.getByTestId("grant-reason"), { target: { value: "took the night rota" } });
    fireEvent.click(screen.getByTestId("grant-submit"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].path).toBe("/api/v1/principals/p1/roles");
    expect(sent[0].body).toMatchObject({ role: "viewer", owners: ["alice"], team_scope: { mode: "any" } });
  });

  it("revokes a token only after a reason, from the tab and not from a row of the list", async () => {
    given({ "/api/v1/principals/p1/sessions": { items: [], count: 0 } });
    draw();
    await waitFor(() => expect(screen.getByTestId("open-tszymanski")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("open-tszymanski"));
    fireEvent.click(await screen.findByRole("tab", { name: /^Tokens and sessions/ }));

    fireEvent.click(await screen.findByTestId("revoke-token-t1ab2cd3e4"));
    const confirm = await screen.findByTestId("ask-confirm");
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByTestId("ask-reason"), { target: { value: "the runner is gone" } });
    fireEvent.click(confirm);
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].path).toContain("/api/v1/principals/p1/tokens/t1ab2cd3e4?reason=");
  });

  it("sets a password with a reason and never shows one", async () => {
    given();
    draw();
    await waitFor(() => expect(screen.getByTestId("open-tszymanski")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("open-tszymanski"));
    fireEvent.click(await screen.findByRole("tab", { name: "Password" }));

    const save = await screen.findByTestId("save-password");
    expect(save).toBeDisabled();
    fireEvent.change(screen.getByTestId("set-password"), { target: { value: "a-long-enough-one" } });
    fireEvent.change(screen.getByTestId("password-reason"), { target: { value: "new operator on the rota" } });
    fireEvent.click(save);
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].method).toBe("PUT");
    expect(sent[0].path).toBe("/api/v1/principals/p1/password");
    expect(sent[0].body).toMatchObject({ must_change: true });
  });
});

describe("a scope read in words", () => {
  it("says the whole fleet rather than four asterisks", () => {
    expect(readScope(tr, fleetScope)).toEqual({ words: "the whole fleet", reach: "fleet" });
  });

  it("names every category that narrows, so none is read as all", () => {
    const read = readScope(tr, labScope);
    expect(read.reach).toBe("narrowed");
    expect(read.words).toContain("site lab");
    expect(read.words).toContain("environment test");
    expect(read.words).toContain("tag db");
  });

  it("says a rule that reaches nothing, which is not a rule that reaches the fleet", () => {
    expect(readScope(tr, { ...fleetScope, tags: [] })).toEqual({ words: "reaches nothing", reach: "nothing" });
  });

  it("reads a team binding as that team and not as the whole fleet", () => {
    const read = readScope(tr, {
      site: "*", environment: "*", team_scope: { mode: "exact", team_id: "team-1" }, owners: ["*"], tags: ["*"],
    }, "Night rota");
    expect(read.reach).toBe("narrowed");
    expect(read.words).toBe("team Night rota");
  });
});

describe("what a grant sends", () => {
  const fields: GrantFields = {
    role: "operator", site: "lab", environment: "test", team: "", owners: " alice , ", tags: "",
    validUntil: "", reason: "on-call until the quarter ends",
  };

  it("sends a site binding to the role route, saying in words that it covers any team", () => {
    const request = grantRequest("p1", "site", fields);
    expect(request.path).toBe("/api/v1/principals/p1/roles");
    expect(request.body).toMatchObject({
      role: "operator", site: "lab", environment: "test", team_scope: { mode: "any" }, owners: ["alice"], tags: [],
    });
  });

  it("sends a team binding to its own route, with no site or environment in the body", () => {
    const request = grantRequest("p1", "team", { ...fields, team: "team-1" });
    expect(request.path).toBe("/api/v1/principals/p1/team-roles");
    expect(request.body).toMatchObject({ role: "operator", team: "team-1" });
    expect(request.body).not.toHaveProperty("site");
    expect(request.body).not.toHaveProperty("environment");
  });

  it("shows the asterisks the server would fill in, so an empty field is not read as nothing", () => {
    const preview = previewScope("site", { ...fields, site: "", environment: "", owners: "", tags: "" });
    expect(preview).toMatchObject({ site: "*", environment: "*", owners: ["*"], tags: ["*"] });
  });
});

describe("the named fields over the rows", () => {
  const rows = [
    { subject: "tszymanski", name: "Tomasz", kind: "user", roles: [{ role: "operator", from: "binding" as const }], known: true },
    { subject: "backup-runner", name: "", kind: "service", roles: [{ role: "viewer", from: "binding" as const }], known: true },
  ];
  const filter = (over: Partial<Filter>): Filter =>
    ({ subject: "", name: "", role: "", kind: "", status: "enabled", ...over });

  it("means the field it is typed in, where the server matched either", () => {
    expect(narrowRows(rows, filter({ subject: "runner" })).map((one) => one.subject)).toEqual(["backup-runner"]);
    expect(narrowRows(rows, filter({ name: "Tomasz" })).map((one) => one.subject)).toEqual(["tszymanski"]);
  });

  it("narrows by kind and by role", () => {
    expect(narrowRows(rows, filter({ kind: "service" })).map((one) => one.subject)).toEqual(["backup-runner"]);
    expect(narrowRows(rows, filter({ role: "operator" })).map((one) => one.subject)).toEqual(["tszymanski"]);
  });
});

describe("the state of a subject", () => {
  it("keeps disabled, locked and never-seen apart from one another", () => {
    const base = { subject: "a", name: "", kind: "user", roles: [], known: true };
    expect(statusOf(tr, base).label).toBe("Enabled");
    expect(statusOf(tr, { ...base, disabled_at: "2026-10-01T00:00:00Z" }).tone).toBe("unknown");
    expect(statusOf(tr, { ...base, directory_disabled: true }).tone).toBe("error");
    expect(statusOf(tr, { ...base, known: false }).label).toBe("Not signed in yet");
  });

  it("knows a binding whose day has passed from one without a day at all", () => {
    expect(expired(undefined)).toBe(false);
    expect(expired("2020-01-01T00:00:00Z")).toBe(true);
    expect(expired("2099-01-01T00:00:00Z")).toBe(false);
  });

  it("flags a token ending within the week and not one ending later", () => {
    const now = Date.parse("2026-10-16T00:00:00Z");
    expect(expiresSoon({ expires_at: "2026-10-20T00:00:00Z" }, now)).toBe(true);
    expect(expiresSoon({ expires_at: "2026-12-20T00:00:00Z" }, now)).toBe(false);
    expect(expiresSoon({}, now)).toBe(false);
  });
});

describe("editing a role of this installation", () => {
  it("names what everybody holding it loses before anything is sent", async () => {
    given();
    draw("/access?tab=roles");
    fireEvent.click(await screen.findByTestId("edit-role-shift_lead"));
    await waitFor(() => expect(screen.getByTestId("role-save")).toBeInTheDocument());
    expect(screen.queryByTestId("role-losing")).not.toBeInTheDocument();
    // The checkbox of a permission the role holds; unticking it takes the
    // permission away from everybody bound to the role.
    fireEvent.click(screen.getByRole("checkbox", { name: "job.create" }));
    expect(screen.getByTestId("role-losing")).toHaveTextContent("Everybody holding this role loses: job.create");
    expect(sent).toHaveLength(0);
  });

  it("writes the role whole, after a dialog and a reason of its own", async () => {
    given();
    draw("/access?tab=roles");
    fireEvent.click(await screen.findByTestId("edit-role-shift_lead"));
    fireEvent.click(await screen.findByRole("checkbox", { name: "host.read" }));
    fireEvent.change(screen.getByTestId("role-description"), { target: { value: "the night rota" } });
    fireEvent.click(screen.getByTestId("role-save"));

    const confirm = await screen.findByTestId("role-confirm");
    expect(confirm).toBeDisabled();
    expect(sent).toHaveLength(0);
    fireEvent.change(screen.getByTestId("role-reason"), { target: { value: "short" } });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByTestId("role-reason"), { target: { value: "the night rota reads the hosts too" } });
    expect(confirm).toBeEnabled();
    fireEvent.click(confirm);

    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].method).toBe("PUT");
    expect(sent[0].path).toBe("/api/v1/roles/shift_lead");
    expect(sent[0].body).toEqual({
      description: "the night rota",
      // Whole, and sorted: the server reads the list as the role, not as
      // what to add to it.
      permissions: ["host.read", "job.create", "unit.restart"],
      reason: "the night rota reads the hosts too",
    });
  });

  it("refuses to save a role carrying nothing, which the server would refuse too", async () => {
    given();
    draw("/access?tab=roles");
    fireEvent.click(await screen.findByTestId("edit-role-shift_lead"));
    fireEvent.click(await screen.findByRole("checkbox", { name: "job.create" }));
    fireEvent.click(screen.getByRole("checkbox", { name: "unit.restart" }));
    expect(screen.getByTestId("role-save")).toBeDisabled();
    expect(screen.getByText("A role carries at least one permission.")).toBeInTheDocument();
  });

  it("puts a refusal of the save in front of the reader", async () => {
    given();
    const { ApiError } = await import("../../lib/api");
    refuse = new ApiError(403, "escalation", "the role would carry secret.write, which you do not hold everywhere");
    draw("/access?tab=roles");
    fireEvent.click(await screen.findByTestId("edit-role-shift_lead"));
    fireEvent.click(await screen.findByRole("checkbox", { name: "secret.write" }));
    fireEvent.click(screen.getByTestId("role-save"));
    fireEvent.change(await screen.findByTestId("role-reason"), { target: { value: "the night rota needs the secrets" } });
    fireEvent.click(screen.getByTestId("role-confirm"));
    await waitFor(() =>
      expect(screen.getByText(/which you do not hold everywhere/)).toBeInTheDocument());
  });
});

describe("what a save takes away", () => {
  it("names only the permissions the role had and the save does not", () => {
    expect(permissionsLost(["a", "b", "c"], ["a", "c"])).toEqual(["b"]);
    expect(permissionsLost(["a"], ["a", "b"])).toEqual([]);
  });
});

/**
 * A directory that did not answer is not a directory with nobody in it.
 * The panel being replaced said which of the two it was looking at; this
 * one declared the field and never read it, so an unanswering directory
 * read as an empty one - the exact fault the product's first rule is on.
 */
describe("what the directory side of the answer is worth", () => {
  it("says the directory did not answer, and why", async () => {
    given({
      "/api/v1/access/holders": {
        items: [holder()], count: 1,
        directory: { configured: true, read: false, reason: "the bind account is locked" },
      },
    });
    draw();
    const said = await screen.findByTestId("directory-unread");
    expect(said).toHaveTextContent("the bind account is locked");
  });

  it("says when there is no directory at all, which is not the same thing", async () => {
    given({
      "/api/v1/access/holders": {
        items: [holder()], count: 1, directory: { configured: false, read: false },
      },
    });
    draw();
    expect(await screen.findByTestId("directory-absent")).toBeInTheDocument();
    expect(screen.queryByTestId("directory-unread")).toBeNull();
  });

  it("says neither where the directory answered", async () => {
    given();
    draw();
    await screen.findByText("tszymanski");
    expect(screen.queryByTestId("directory-unread")).toBeNull();
    expect(screen.queryByTestId("directory-absent")).toBeNull();
  });
});
