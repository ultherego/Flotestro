import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { settingsTab, Settings } from "./Settings";

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
    // host.read is what the server asks for the role catalogue, so it is
    // what the tab holding it is gated on.
    "host.read", "notification.read", "host.enroll.read", "principal.manage",
    "budget.read", "policy.read",
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
/*
 * The settings area, which is where an installation is configured.
 *
 * It was a screen of values to read with a list of places to go, twice over,
 * and the owner said so twice: *"setting przypomina przejdz do zakladki X-Y a
 * nie ustawienia"*. The six screens that configure an installation are tabs
 * of this one now, each holding the screen that does the work.
 */
describe("settingsTab", () => {
  const everything = new Set([
    "notification.read", "host.read", "principal.manage", "budget.read", "policy.read",
  ]);

  it("opens the tab the address names", () => {
    expect(settingsTab("policies", everything)).toBe("policies");
    expect(settingsTab("channels", everything)).toBe("channels");
    expect(settingsTab(null, everything)).toBe("general");
    expect(settingsTab("nonsense", everything)).toBe("general");
  });

  // A tab nobody may open is not a tab. An address kept in a bookmark from a
  // wider role has to land on something that exists.
  it("sends an address this sign-in may not open to the first tab it may", () => {
    const reader = new Set(["host.read"]);
    expect(settingsTab("budgets", reader)).toBe("general");
    expect(settingsTab("roles", reader)).toBe("roles");
    expect(settingsTab("mappings", reader)).toBe("general");
  });
});

describe("the settings area", () => {
  it("offers a tab for each part of the configuration this sign-in may read", async () => {
    grantEverything();
    draw(<Settings />);
    // The tabs appear as the sign-in's permissions arrive, so the wait is on
    // the last of them rather than on the bar that holds them.
    await waitFor(() => expect(screen.getByTestId("settings-tab-policies")).toBeInTheDocument());
    for (const key of ["general", "channels", "roles", "mappings", "budgets"]) {
      expect(screen.getByTestId(`settings-tab-${key}`)).toBeInTheDocument();
    }
  });

  it("leaves out the tabs whose contents this sign-in may not read", async () => {
    answers.permissions = ["host.read"];
    answers.collections = {};
    draw(<Settings />);
    await waitFor(() => expect(screen.getByTestId("settings-tab-roles")).toBeInTheDocument());
    expect(screen.queryByTestId("settings-tab-budgets")).toBeNull();
    expect(screen.queryByTestId("settings-tab-mappings")).toBeNull();
    expect(screen.queryByTestId("settings-tab-channels")).toBeNull();
  });

  it("opens on what the process was started with, and keeps the search there", async () => {
    grantEverything();
    draw(<Settings />);
    await waitFor(() => expect(screen.getByTestId("settings-search")).toBeInTheDocument());
    expect(screen.getByText("What the process was started with")).toBeInTheDocument();
    fireEvent.change(screen.getByTestId("settings-search"), { target: { value: "lifetime" } });
    await waitFor(() => expect(areaTiles().length).toBe(1));
  });
});
