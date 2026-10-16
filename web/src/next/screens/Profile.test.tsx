import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Profile, groupPermissions, reasonGiven } from "./Profile";
import { ToastProvider } from "../../components/Toast";

/**
 * The screen of the person at it, and the two writes nobody can do for
 * them: their own password, and the tokens that act for them.
 *
 * The rule the whole file is about is the one a screen cannot be allowed
 * to break twice: a secret the server shows once is shown once. It is
 * never on the screen after it has been sent, it never goes in a path -
 * a path is written to every access log and to the browser's history -
 * and it is never handed to the console.
 */

const asked: string[] = [];
const sent: { method: string; path: string; body?: unknown }[] = [];
const answers: Record<string, unknown> = {};
/** What the next write answers with; a mint hands back a value once. */
let minted: unknown = {};

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  // The longest key that is a prefix of the path answers it, so
  // "/api/v1/me/tokens" is not answered by "/api/v1/me".
  const answer = (path: string) => {
    asked.push(path);
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
      get: answer,
      post: (path: string, body?: unknown) => { sent.push({ method: "POST", path, body }); return Promise.resolve(minted); },
      put: (path: string, body?: unknown) => { sent.push({ method: "PUT", path, body }); return Promise.resolve({}); },
      del: (path: string, body?: unknown) => { sent.push({ method: "DELETE", path, body }); return Promise.resolve({}); },
    },
  };
});

const me = (over: Record<string, unknown> = {}) => ({
  id: "p1",
  subject: "tszymanski",
  display_name: "Tomasz Szymański",
  kind: "user",
  roles: ["operator"],
  bindings: [],
  permissions: ["host.read"],
  ...over,
});

const token = (over: Record<string, unknown> = {}) => ({
  id: "4b0c2f18-3a11-4a2e-9d55-2f0c9a1b7e33",
  description: "the nightly inventory",
  created_at: "2026-09-01T08:00:00Z",
  last_used_at: "2026-10-15T08:00:00Z",
  expires_at: "2026-11-01T08:00:00Z",
  ...over,
});

/** Every path this render asked for or wrote to, reads and writes alike. */
const everyPath = () => [...asked, ...sent.map((one) => one.path)];

function draw(at = "/next/profile") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[at]}><ToastProvider>{children}</ToastProvider></MemoryRouter>
    </QueryClientProvider>
  );
  return render(<Profile />, { wrapper });
}

/** What the console was handed, so a secret can be shown never to reach it. */
let logged: string[] = [];
const spies: { mockRestore: () => void }[] = [];

beforeEach(() => {
  logged = [];
  for (const name of ["log", "info", "warn", "error", "debug"] as const) {
    spies.push(vi.spyOn(console, name).mockImplementation((...parts: unknown[]) => {
      logged.push(parts.map((one) => String(one)).join(" "));
    }));
  }
});

afterEach(() => {
  cleanup();
  for (const spy of spies.splice(0)) spy.mockRestore();
  asked.length = 0;
  sent.length = 0;
  minted = {};
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("who the panel takes you for", () => {
  it("says the kind, the identifier and the roles, and leads to the access screen for whoever manages it", async () => {
    Object.assign(answers, {
      "/api/v1/whoami": me({ kind: "service", permissions: ["principal.manage"] }),
      "/api/v1/me/sessions": { items: [], count: 0 },
      "/api/v1/me/tokens": { items: [], count: 0 },
    });
    draw();
    await waitFor(() => expect(screen.getByText("tszymanski")).toBeInTheDocument());
    expect(screen.getByText("service")).toBeInTheDocument();
    expect(screen.getByText("p1")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Manage every identity/ }))
      .toHaveAttribute("href", "/next/access");
  });

  it("says a binding that narrows nothing is any, and one that narrows to nothing is nothing", async () => {
    Object.assign(answers, {
      "/api/v1/whoami": me({
        bindings: [
          { role: "operator", scope: { site: "*", environment: "prod", team_scope: { mode: "any" }, owners: ["*"], tags: [] } },
        ],
      }),
      "/api/v1/me/sessions": { items: [], count: 0 },
      "/api/v1/me/tokens": { items: [], count: 0 },
    });
    draw();
    await waitFor(() => expect(screen.getByText("any site")).toBeInTheDocument());
    expect(screen.getByText("prod")).toBeInTheDocument();
    expect(screen.getByText("any owner")).toBeInTheDocument();
    expect(screen.getByText("nothing")).toBeInTheDocument();
    expect(screen.getByText("until revoked")).toBeInTheDocument();
  });

  it("folds the permissions by the part of the panel they concern", async () => {
    Object.assign(answers, {
      "/api/v1/whoami": me({ permissions: ["job.read", "job.create", "audit.read"] }),
      "/api/v1/me/sessions": { items: [], count: 0 },
      "/api/v1/me/tokens": { items: [], count: 0 },
    });
    draw();
    await waitFor(() => expect(screen.getByText("Jobs")).toBeInTheDocument());
    expect(screen.getByText("Audit trail")).toBeInTheDocument();
    expect(screen.getByTitle("job.create")).toBeInTheDocument();
  });
});

describe("your own password", () => {
  const ready = () => {
    Object.assign(answers, {
      "/api/v1/whoami": me(),
      "/api/v1/me/sessions": { items: [], count: 0 },
      "/api/v1/me/tokens": { items: [], count: 0 },
    });
  };

  it("holds the button shut until the one in force and a new one that is typed twice are there", async () => {
    ready();
    draw();
    await waitFor(() => expect(screen.getByTestId("change-password")).toBeInTheDocument());
    expect(screen.getByTestId("change-password")).toBeDisabled();

    fireEvent.change(screen.getByTestId("current-password"), { target: { value: "the-old-one-9" } });
    expect(screen.getByTestId("change-password")).toBeDisabled();
    fireEvent.change(screen.getByTestId("new-password"), { target: { value: "a-longer-new-one-7" } });
    expect(screen.getByTestId("change-password")).toBeEnabled();

    // A repeat that does not match shuts it again and says so.
    fireEvent.change(screen.getByTestId("new-password-again"), { target: { value: "a-longer-new-two-7" } });
    expect(screen.getByText("The two new passwords are not the same.")).toBeInTheDocument();
    expect(screen.getByTestId("change-password")).toBeDisabled();
    expect(sent).toHaveLength(0);
  });

  it("posts both passwords in the body of the one request that changes them", async () => {
    ready();
    draw();
    await waitFor(() => expect(screen.getByTestId("change-password")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("current-password"), { target: { value: "the-old-one-9" } });
    fireEvent.change(screen.getByTestId("new-password"), { target: { value: "a-longer-new-one-7" } });
    fireEvent.change(screen.getByTestId("new-password-again"), { target: { value: "a-longer-new-one-7" } });
    fireEvent.click(screen.getByTestId("change-password"));

    await waitFor(() => expect(sent).toHaveLength(1));
    // The server reads `current` and `new`; a body with other names is a
    // change that silently does nothing.
    expect(sent[0]).toEqual({
      method: "POST",
      path: "/api/v1/profile/password",
      body: { current: "the-old-one-9", new: "a-longer-new-one-7" },
    });
  });

  it("leaves neither password on the screen, in a path or in the console once it is sent", async () => {
    ready();
    draw();
    await waitFor(() => expect(screen.getByTestId("change-password")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("current-password"), { target: { value: "the-old-one-9" } });
    fireEvent.change(screen.getByTestId("new-password"), { target: { value: "a-longer-new-one-7" } });
    fireEvent.change(screen.getByTestId("new-password-again"), { target: { value: "a-longer-new-one-7" } });
    fireEvent.click(screen.getByTestId("change-password"));
    await waitFor(() => expect(sent).toHaveLength(1));

    await waitFor(() => expect(screen.getByTestId("current-password")).toHaveValue(""));
    expect(screen.getByTestId("new-password")).toHaveValue("");
    expect(screen.getByTestId("new-password-again")).toHaveValue("");
    for (const secret of ["the-old-one-9", "a-longer-new-one-7"]) {
      expect(document.body.textContent).not.toContain(secret);
      expect(everyPath().filter((path) => path.includes(secret))).toEqual([]);
      expect(logged.filter((line) => line.includes(secret))).toEqual([]);
    }
  });

  it("says what the server refused and does not pretend the password changed", async () => {
    ready();
    const api = await import("../../lib/api");
    const post = vi.spyOn(api.api, "post").mockRejectedValueOnce(
      new api.ApiError(400, "weak_password", "the password is on every list there is"));
    draw();
    await waitFor(() => expect(screen.getByTestId("change-password")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("current-password"), { target: { value: "the-old-one-9" } });
    fireEvent.change(screen.getByTestId("new-password"), { target: { value: "password1234" } });
    fireEvent.click(screen.getByTestId("change-password"));

    await waitFor(() => expect(screen.getByTestId("password-refusal")).toBeInTheDocument());
    expect(screen.getByTestId("password-refusal")).toHaveTextContent("on every list there is");
    post.mockRestore();
  });

  it("says so when the sign-in sent the person here because somebody else chose the password", async () => {
    ready();
    draw("/next/profile?change_password=1");
    await waitFor(() => expect(screen.getByTestId("must-change-password")).toBeInTheDocument());
    // The card itself says it too, so the person who scrolls past the
    // banner still reads why they are being asked.
    expect(screen.getByText(/Somebody else chose the password you signed in with, so two people know it. Replace it here./))
      .toBeInTheDocument();
  });

  it("does not say the password must be replaced on an ordinary visit", async () => {
    ready();
    draw();
    await waitFor(() => expect(screen.getByTestId("change-password")).toBeInTheDocument());
    expect(screen.queryByTestId("must-change-password")).not.toBeInTheDocument();
  });
});

describe("the tokens that act for you", () => {
  const holder = (over: Record<string, unknown> = {}) => {
    Object.assign(answers, {
      "/api/v1/whoami": me({ permissions: ["principal.manage"] }),
      "/api/v1/me/sessions": { items: [], count: 0 },
      "/api/v1/me/tokens": { items: [token()], count: 1 },
      ...over,
    });
  };

  it("lists a token by its identifier and what it is for, and never by a value", async () => {
    holder();
    draw();
    await waitFor(() => expect(screen.getByTestId(`token-${token().id}`)).toBeInTheDocument());
    const row = screen.getByTestId(`token-${token().id}`);
    expect(within(row).getByTitle(token().id)).toHaveTextContent("4b0c2f18-3a1");
    expect(row).toHaveTextContent("the nightly inventory");
  });

  it("says a token nobody has used yet has never been used, rather than drawing a nought", async () => {
    holder({ "/api/v1/me/tokens": { items: [token({ last_used_at: undefined, expires_at: undefined })], count: 1 } });
    draw();
    await waitFor(() => expect(screen.getByTestId(`token-${token().id}`)).toBeInTheDocument());
    const row = screen.getByTestId(`token-${token().id}`);
    expect(within(row).getByText("never used")).toBeInTheDocument();
    expect(within(row).getByText("never")).toBeInTheDocument();
  });

  it("asks for a reason before it mints one, and sends the description and the lifetime with it", async () => {
    holder();
    minted = { subject: "tszymanski", token: "flt_9XQ2vmS1aZ", token_expires_at: "2026-11-15T08:00:00Z" };
    draw();
    await waitFor(() => expect(screen.getByTestId("issue-token")).toBeEnabled());
    fireEvent.click(screen.getByTestId("issue-token"));
    expect(sent).toHaveLength(0);

    fireEvent.change(screen.getByTestId("token-description"), { target: { value: "the nightly inventory" } });
    fireEvent.change(screen.getByTestId("token-ttl"), { target: { value: "48" } });
    expect(screen.getByTestId("token-confirm")).toBeDisabled();
    fireEvent.change(screen.getByTestId("token-reason"), { target: { value: "short" } });
    expect(screen.getByTestId("token-confirm")).toBeDisabled();

    fireEvent.change(screen.getByTestId("token-reason"), { target: { value: "the inventory job needs its own identity" } });
    expect(screen.getByTestId("token-confirm")).toBeEnabled();
    fireEvent.click(screen.getByTestId("token-confirm"));

    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0]).toEqual({
      method: "POST",
      path: "/api/v1/principals/p1/tokens",
      body: {
        reason: "the inventory job needs its own identity",
        description: "the nightly inventory",
        token_ttl_hours: 48,
      },
    });
  });

  it("refuses a lifetime longer than the year the server gives", async () => {
    holder();
    draw();
    await waitFor(() => expect(screen.getByTestId("issue-token")).toBeEnabled());
    fireEvent.click(screen.getByTestId("issue-token"));
    fireEvent.change(screen.getByTestId("token-reason"), { target: { value: "the inventory job needs one" } });
    fireEvent.change(screen.getByTestId("token-ttl"), { target: { value: "9000" } });
    expect(screen.getByTestId("token-confirm")).toBeDisabled();
    fireEvent.change(screen.getByTestId("token-ttl"), { target: { value: "8760" } });
    expect(screen.getByTestId("token-confirm")).toBeEnabled();
  });

  it("shows the value once, warns that it is the only showing, and lets it go", async () => {
    holder();
    minted = { subject: "tszymanski", token: "flt_9XQ2vmS1aZ", token_expires_at: "2026-11-15T08:00:00Z" };
    draw();
    await waitFor(() => expect(screen.getByTestId("issue-token")).toBeEnabled());
    fireEvent.click(screen.getByTestId("issue-token"));
    fireEvent.change(screen.getByTestId("token-reason"), { target: { value: "the inventory job needs one" } });
    fireEvent.click(screen.getByTestId("token-confirm"));

    await waitFor(() => expect(screen.getByTestId("issued-token")).toBeInTheDocument());
    const shown = screen.getAllByText("flt_9XQ2vmS1aZ");
    // Once, and in the one place that warns it will not come again.
    expect(shown).toHaveLength(1);
    expect(screen.getByTestId("issued-token")).toHaveTextContent(/shown once/);
    expect(screen.getByText(/A value is shown once, when the token is issued, and nowhere again/)).toBeInTheDocument();

    fireEvent.click(screen.getByTestId("close-token"));
    await waitFor(() => expect(screen.queryByTestId("issued-token")).not.toBeInTheDocument());
    expect(document.body.textContent).not.toContain("flt_9XQ2vmS1aZ");
  });

  it("never puts the value of a token in a path or in the console", async () => {
    holder();
    minted = { subject: "tszymanski", token: "flt_9XQ2vmS1aZ" };
    draw();
    await waitFor(() => expect(screen.getByTestId("issue-token")).toBeEnabled());
    fireEvent.click(screen.getByTestId("issue-token"));
    fireEvent.change(screen.getByTestId("token-reason"), { target: { value: "the inventory job needs one" } });
    fireEvent.click(screen.getByTestId("token-confirm"));
    await waitFor(() => expect(screen.getByTestId("issued-token")).toBeInTheDocument());

    expect(everyPath().filter((path) => path.includes("flt_9XQ2vmS1aZ"))).toEqual([]);
    expect(logged.filter((line) => line.includes("flt_9XQ2vmS1aZ"))).toEqual([]);
    // Nor in the body of anything: nothing is sent back after it is read.
    expect(sent.filter((one) => JSON.stringify(one.body ?? "").includes("flt_9XQ2vmS1aZ"))).toEqual([]);
  });

  it("asks before it ends one, and ends it by its identifier with the reason in the trail", async () => {
    holder();
    draw();
    await waitFor(() => expect(screen.getByTestId(`revoke-token-${token().id}`)).toBeEnabled());
    fireEvent.click(screen.getByTestId(`revoke-token-${token().id}`));
    expect(sent).toHaveLength(0);
    expect(screen.getByTestId("token-confirm")).toBeDisabled();

    fireEvent.change(screen.getByTestId("token-reason"), { target: { value: "the pipeline it ran was retired" } });
    fireEvent.click(screen.getByTestId("token-confirm"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].method).toBe("DELETE");
    expect(sent[0].path).toBe(
      `/api/v1/principals/p1/tokens/${token().id}?reason=${encodeURIComponent("the pipeline it ran was retired")}`);
  });

  it("says what the server refused rather than leaving the listing as it was", async () => {
    holder();
    const api = await import("../../lib/api");
    const del = vi.spyOn(api.api, "del").mockRejectedValueOnce(
      new api.ApiError(404, "token_not_found", "no such live token of this identity"));
    draw();
    await waitFor(() => expect(screen.getByTestId(`revoke-token-${token().id}`)).toBeEnabled());
    fireEvent.click(screen.getByTestId(`revoke-token-${token().id}`));
    fireEvent.change(screen.getByTestId("token-reason"), { target: { value: "the pipeline it ran was retired" } });
    fireEvent.click(screen.getByTestId("token-confirm"));
    await waitFor(() => expect(screen.getByTestId("token-refusal")).toBeInTheDocument());
    expect(screen.getByTestId("token-refusal")).toHaveTextContent("no such live token");
    del.mockRestore();
  });

  it("keeps the controls on the screen and shut for whoever does not hold the permission, and says what it takes", async () => {
    Object.assign(answers, {
      "/api/v1/whoami": me({ permissions: ["host.read"] }),
      "/api/v1/me/sessions": { items: [], count: 0 },
      "/api/v1/me/tokens": { items: [token()], count: 1 },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId(`token-${token().id}`)).toBeInTheDocument());
    expect(screen.getByTestId("issue-token")).toBeDisabled();
    expect(screen.getByTestId(`revoke-token-${token().id}`)).toBeDisabled();
    expect(screen.getByText(/This needs the permission principal.manage/)).toBeInTheDocument();
    expect(sent).toHaveLength(0);
  });

  it("says a listing with nothing in it is a fleet with no token, with what one is for", async () => {
    Object.assign(answers, {
      "/api/v1/whoami": me({ permissions: ["principal.manage"] }),
      "/api/v1/me/sessions": { items: [], count: 0 },
      "/api/v1/me/tokens": { items: [], count: 0 },
    });
    draw();
    await waitFor(() => expect(screen.getByText(/No live token/)).toBeInTheDocument());
  });
});

describe("the sessions this identity holds", () => {
  it("says where from, when it ends and how the holder proved who they are", async () => {
    Object.assign(answers, {
      "/api/v1/whoami": me(),
      "/api/v1/me/tokens": { items: [], count: 0 },
      "/api/v1/me/sessions": {
        items: [{
          id: "s1",
          created_at: "2026-10-16T08:00:00Z",
          last_seen_at: "2026-10-16T09:00:00Z",
          expires_at: "2026-10-17T08:00:00Z",
          idle_expires_at: "2026-10-16T10:00:00Z",
          remote_addr: "10.10.10.1",
          acr: "mfa",
          current: true,
        }],
        count: 1,
      },
    });
    draw();
    await waitFor(() => expect(screen.getByText("10.10.10.1")).toBeInTheDocument());
    expect(screen.getByText("mfa")).toBeInTheDocument();
    expect(screen.getByText("this one")).toBeInTheDocument();
  });
});

describe("the helpers the screen is written from", () => {
  it("folds area.action names into one row per area, sorted, with the actions in order", () => {
    expect(groupPermissions(["job.read", "audit.read", "job.create", "job.approve"])).toEqual([
      { area: "audit", actions: ["read"] },
      { area: "job", actions: ["approve", "create", "read"] },
    ]);
  });

  it("keeps the part after the first dot whole and a name without a dot as its own area", () => {
    expect(groupPermissions(["certificate.trust.plan", "everything"])).toEqual([
      { area: "certificate", actions: ["trust.plan"] },
      { area: "everything", actions: ["*"] },
    ]);
  });

  it("returns nothing for no permission", () => {
    expect(groupPermissions([])).toEqual([]);
  });

  it("takes a reason the trail will keep and no shorter one", () => {
    expect(reasonGiven("short")).toBe(false);
    expect(reasonGiven("  eight ch  ")).toBe(true);
  });
});
