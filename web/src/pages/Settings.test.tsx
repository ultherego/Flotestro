import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ApiError } from "../lib/api";
import { hubState, Settings } from "./Settings";

/**
 * A configuration screen is read with one name in mind. It used to answer
 * that by putting every value of every area on the screen at once; now the
 * areas are closed, they say how many values they hold, and the search opens
 * the ones that match.
 */

const settings = {
  source: "the environment of the control plane process",
  note: "",
  areas: [
    {
      key: "server",
      title: "Server",
      facts: [
        { key: "gateway_addr", value: "0.0.0.0:8443" },
        { key: "pool_max_conn_lifetime", value: "12h0m0s" },
      ],
    },
    {
      key: "database",
      title: "Database",
      facts: [
        { key: "dsn", value: "postgres://flotestro@db.flotestro.test:5432/flotestro?sslmode=verify-full" },
        { key: "pool_min_conns", value: null, secret: true, configured: true },
      ],
    },
  ],
};

/** What the sign-in of a test holds, and what each counted collection answers. */
const answers: { permissions: string[]; collections: Record<string, unknown> } = {
  permissions: [],
  collections: {},
};

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        // The panel of this test has no monitoring, so that card draws nothing.
        if (path.startsWith("/api/v1/settings/monitoring")) return Promise.reject(new Error("no monitoring"));
        if (path === "/api/v1/whoami") {
          return Promise.resolve({ subject: "tester", permissions: answers.permissions });
        }
        if (path in answers.collections) {
          const answer = answers.collections[path];
          return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
        }
        // The address the agents dial has its own shape; answering it with the
        // settings document is how this mock once crashed the screen.
        if (path === "/api/v1/settings/advertised") {
          return Promise.resolve({
            in_force: ["192.168.56.10"], source: "confirmed", loopback_only: false,
            environment_in_force: false, detected: [], confirmed: [],
          });
        }
        if (path.startsWith("/api/v1/settings")) return Promise.resolve(settings);
        return Promise.reject(new actual.ApiError(403, "forbidden", "not for you"));
      },
    },
  };
});

/** Everything the hub can count, so a test names only what it changes. */
function grantEverything() {
  answers.permissions = [
    "notification.read", "host.enroll.read", "principal.manage", "budget.read", "policy.read",
  ];
  answers.collections = {
    "/api/v1/notifications/channels": { items: [{}, {}, {}], count: 3 },
    "/api/v1/relays": { items: [{}] },
    "/api/v1/roles": { items: [{}, {}], count: 2 },
    "/api/v1/group-mappings": { items: [], count: 0 },
    "/api/v1/budgets": { items: [{}, {}, {}, {}] },
    "/api/v1/policies": { items: [{}], count: 1 },
  };
}

function draw(node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/settings"]}>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  answers.permissions = [];
  answers.collections = {};
});

/** The tiles of the read-only facts, now that writable tiles stand above them. */
function areaTiles() {
  return document.querySelectorAll('[data-testid="settings-areas"] .part');
}

describe("the settings screen", () => {
  it("puts every area on the screen as a tile, with how many values it holds", async () => {
    draw(<Settings />);
    await waitFor(() => expect(areaTiles().length).toBe(2));
    for (const tile of Array.from(areaTiles())) {
      expect(tile.querySelector(".part-summary")?.textContent).toContain("2 values");
    }
    // The values themselves are there, not behind anything.
    expect(screen.getByText("Agent gateway")).toBeInTheDocument();
  });

  it("finds a setting by name and leaves only what carries it", async () => {
    draw(<Settings />);
    await waitFor(() => expect(screen.getByTestId("settings-search")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("settings-search"), { target: { value: "lifetime" } });
    await waitFor(() => expect(areaTiles().length).toBe(1));
    const tile = areaTiles()[0] as HTMLElement;
    expect(tile.textContent).toContain("Server");
    expect(tile.querySelector(".part-summary")?.textContent).toContain("1 value");
    expect(screen.queryByText("Agent gateway")).toBeNull();
  });

  it("says so when nothing carries that name", async () => {
    draw(<Settings />);
    await waitFor(() => expect(screen.getByTestId("settings-search")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("settings-search"), { target: { value: "kerberos" } });
    await waitFor(() => expect(screen.getByText("No setting of that name.")).toBeInTheDocument());
  });

  it("keeps a secret as the answer whether it is set, never as a value", async () => {
    draw(<Settings />);
    await waitFor(() => expect(screen.getByText("set")).toBeInTheDocument());
    expect(screen.queryByText(/postgres:\/\/flotestro@/)).not.toBeNull();
  });
});

/*
 * The hub: the configuration the installation holds, told apart from what the
 * process was started with.
 *
 * The rule under every one of these is the product's own: a number nobody
 * could take is not a count of nothing. A viewer who may not read the roles
 * has to see that, because "0 roles" reads as an installation with nobody in
 * it - and somebody would go and grant themselves one.
 */
describe("hubState", () => {
  it("counts what the collection says it holds", () => {
    expect(hubState({ items: [{}, {}], count: 2 }, null, false)).toEqual({ kind: "count", n: 2 });
    // A collection that answers with the items alone is still counted.
    expect(hubState({ items: [{}] }, null, false)).toEqual({ kind: "count", n: 1 });
    // An empty collection is a count, and the only honest zero here.
    expect(hubState({ items: [], count: 0 }, null, false)).toEqual({ kind: "count", n: 0 });
  });

  it("tells a refusal apart from an empty collection", () => {
    expect(hubState(undefined, new ApiError(403, "forbidden", "no"), false)).toEqual({ kind: "forbidden" });
  });

  it("says it does not know rather than naming a number it has not got", () => {
    // Still asking.
    expect(hubState(undefined, null, true)).toEqual({ kind: "unknown" });
    // Asked and failed: a timeout, a replica that is down, a proxy in the way.
    expect(hubState(undefined, new Error("network"), false)).toEqual({ kind: "unknown" });
    expect(hubState(undefined, new ApiError(500, "internal", "boom"), false)).toEqual({ kind: "unknown" });
    // An answer of a shape nothing can be counted from is not zero either.
    expect(hubState({ nothing: true }, null, false)).toEqual({ kind: "unknown" });
    expect(hubState(null, null, false)).toEqual({ kind: "unknown" });
  });
});

/*
 * The resources kept on screens of their own, listed at the end of the
 * settings screen.
 *
 * They were six tiles across the top of the screen for half a day, until the
 * owner read what they were: "setting przypomina przejdz do zakladki X-Y a
 * nie ustawienia". A box whose whole content is a sentence and a button to go
 * somewhere else is a menu. What survived the change is the part worth
 * having - the state each resource is in, and the rule that a number nobody
 * could take is never drawn as a zero.
 */
describe("the resources kept elsewhere", () => {
  it("lists every one with what is set now and the way in", async () => {
    grantEverything();
    draw(<Settings />);
    await waitFor(() => expect(screen.getByTestId("elsewhere-channels")).toBeInTheDocument());
    await waitFor(() =>
      expect(screen.getByTestId("elsewhere-channels-state").textContent).toContain("set: 3"));
    expect(screen.getByTestId("elsewhere-budgets-state").textContent).toContain("set: 4");
    // A collection that holds nothing says so in words, not as a count tile.
    await waitFor(() =>
      expect(screen.getByTestId("elsewhere-mappings-state").textContent).toContain("none set"));
    // Every tile offers the screen that owns the resource.
    const channels = screen.getByTestId("elsewhere-channels");
    expect(channels.querySelector("a")).toHaveAttribute("href", "/notifications");
    // One table at the end of the screen, not a board of cards at the top.
    expect(document.querySelectorAll('[data-testid="settings-elsewhere"] tr')).toHaveLength(6);
    expect(screen.getByTestId("elsewhere-roles").querySelector("a"))
      .toHaveAttribute("href", "/access?tab=roles");
    // And the facts of the process are still their own section, named as such.
    expect(screen.getByText("What the process was started with")).toBeInTheDocument();
  });

  it("says a resource is not the viewer's to read rather than drawing it as none", async () => {
    grantEverything();
    answers.permissions = answers.permissions.filter((one) => one !== "principal.manage");
    draw(<Settings />);
    await waitFor(() =>
      expect(screen.getByTestId("elsewhere-roles-state").textContent).toContain("not yours to read"));
    expect(screen.getByTestId("elsewhere-roles-state").textContent).not.toContain("0");
    // No way in is offered to a screen that would refuse on arrival.
    expect(screen.getByTestId("elsewhere-roles").querySelector("a")).toBeNull();
    // The resource is still named: the installation has roles, they are not
    // this viewer's to see.
    expect(screen.getByTestId("elsewhere-roles").textContent).toContain("Roles");
    // And the tile beside it, which this sign-in may read, still counts.
    await waitFor(() =>
      expect(screen.getByTestId("elsewhere-channels-state").textContent).toContain("set: 3"));
  });

  it("says a collection that refused is unread, with the resource still open", async () => {
    grantEverything();
    // The permission is held, and the collection refuses anyway: a role scoped
    // to an owner or a tag, which the server decides and the panel cannot know.
    answers.collections["/api/v1/budgets"] = new ApiError(403, "forbidden", "not yours");
    draw(<Settings />);
    await waitFor(() =>
      expect(screen.getByTestId("elsewhere-budgets-state").textContent).toContain("not yours to read"));
    expect(screen.getByTestId("elsewhere-budgets-state").textContent).not.toContain("set: 0");
  });

  it("does not claim a refusal while the sign-in is still unknown", async () => {
    // Nothing answers: the permissions have not arrived. A tile that read the
    // empty set as "nothing granted" would accuse every viewer of that.
    answers.permissions = [];
    answers.collections = {};
    draw(<Settings />);
    await waitFor(() => expect(screen.getByTestId("elsewhere-roles-state")).toBeInTheDocument());
    expect(screen.getByTestId("elsewhere-roles-state").textContent).toContain("not known");
  });
});
