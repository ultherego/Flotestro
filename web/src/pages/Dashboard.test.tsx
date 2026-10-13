import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { Dashboard } from "./Dashboard";
import type { SetupChecklist, SetupState, SetupStep } from "../lib/setup";

/* The first-run card on a dashboard with no host. It is a condensed view of the
   server's checklist and holds no list of steps of its own, so what is asserted
   here is that the server decides what it says and in what order. */

let checklist: SetupChecklist;
let summary: { hosts: number };
/** What the security module answers, or refuses to. */
let security: Promise<unknown> = Promise.resolve({ checks: [], partial: false, unknown_hosts: 0 });

vi.mock("../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../lib/api")>("../lib/api");
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        if (path.startsWith("/api/v1/setup")) return Promise.resolve(checklist);
        if (path.startsWith("/api/v1/fleet/summary")) return Promise.resolve(summary);
        if (path.startsWith("/api/v1/fleet/activity")) return Promise.resolve(ACTIVITY);
        if (path.startsWith("/api/v1/security")) return security;
        return Promise.resolve({ items: [], total: 0 });
      },
      post: () => Promise.reject(new Error("the dashboard writes nothing")),
      put: () => Promise.reject(new Error("the dashboard writes nothing")),
      del: () => Promise.reject(new Error("the dashboard deletes nothing")),
    },
  };
});

/** An empty fleet: the one condition the card appears under. */
const EMPTY_FLEET = { hosts: 0, online: 0, offline: 0, active_sessions: 0 };

const ACTIVITY = {
  hours: [], succeeded: [], failed: [], other: [],
  by_os_family: [], by_site: [], by_environment: [], by_agent_version: [],
  by_connection_state: [], by_lifecycle_state: [],
};

function step(key: string, state: SetupState, detail: string, path = "/setup"): SetupStep {
  return { key, state, detail, path };
}

/** A checklist in the shape the server answers with: the steps and their tally. */
function list(steps: SetupStep[]): SetupChecklist {
  const counted = steps.filter((one) => one.state !== "optional");
  return {
    steps,
    done: counted.filter((one) => one.state === "done").length,
    total: counted.length,
    complete: !counted.some((one) => one.state === "undone"),
    bootstrap_live: false,
  };
}

/** The steps of the card, in the order it drew them. */
async function cardSteps(): Promise<string[]> {
  const title = await screen.findByText("No host is enrolled yet");
  const card = title.closest("section") as HTMLElement;
  const items = await within(card).findAllByRole("listitem");
  return items.map((item) => item.textContent ?? "");
}

function draw(node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  summary = { ...EMPTY_FLEET };
  security = Promise.resolve({ checks: [], partial: false, unknown_hosts: 0 });
});

afterEach(cleanup);

describe("the first-run card", () => {
  it("asks for the advertised address before the first host", async () => {
    checklist = list([
      step("identity_provider", "done", "keycloak answers with 2 signing keys", "/settings"),
      step("advertised_address", "undone", "the panel tells the agents to dial 127.0.0.1, which reaches only the machine it runs on"),
      step("hosts", "undone", "no host is enrolled yet; the add-host screen prints the one-line installation", "/hosts/new"),
    ]);
    draw(<Dashboard />);
    const steps = await cardSteps();
    expect(steps).toHaveLength(2);
    expect(steps[0]).toContain("Address the agents dial");
    expect(steps[0]).toContain("127.0.0.1");
    expect(steps[1]).toContain("First host");
  });

  it("follows the server's order rather than one of its own", async () => {
    // The same two steps the other way round. A card with a list of its own
    // would print them in its own order whatever the server said.
    checklist = list([
      step("hosts", "undone", "no host is enrolled yet", "/hosts/new"),
      step("advertised_address", "undone", "the panel tells the agents to dial 127.0.0.1"),
    ]);
    draw(<Dashboard />);
    const steps = await cardSteps();
    expect(steps[0]).toContain("First host");
    expect(steps[1]).toContain("Address the agents dial");
  });

  it("shows a step the server added that the panel has no words for yet", async () => {
    checklist = list([
      step("backup_target", "undone", "no backup target is configured", "/backups"),
      step("hosts", "undone", "no host is enrolled yet", "/hosts/new"),
    ]);
    draw(<Dashboard />);
    const steps = await cardSteps();
    expect(steps[0]).toContain("backup_target");
    expect(steps[0]).toContain("no backup target is configured");
  });

  it("demands no identity provider and no group mapping where there are none", async () => {
    checklist = list([
      step("identity_provider", "optional", "no identity provider is configured: the panel accepts API tokens alone", "/settings"),
      step("group_mapping", "optional", "there is no identity provider, so there is no login token to map", "/access?tab=mappings"),
      step("directory", "optional", "no directory connector", "/settings"),
      step("advertised_address", "done", "the agents dial panel.example.test, confirmed by admin", "/settings"),
      step("hosts", "undone", "no host is enrolled yet", "/hosts/new"),
    ]);
    draw(<Dashboard />);
    const steps = await cardSteps();
    expect(steps).toHaveLength(1);
    expect(steps[0]).toContain("First host");
    expect(screen.queryByText(/Identity provider/)).not.toBeInTheDocument();
    expect(screen.queryByText(/group mapping/i)).not.toBeInTheDocument();
  });

  it("keeps an issuer that is set and unreachable a fault", async () => {
    checklist = list([
      step("identity_provider", "warning", "the identity provider is configured but did not answer: dial tcp: connection refused"),
      step("hosts", "undone", "no host is enrolled yet", "/hosts/new"),
    ]);
    draw(<Dashboard />);
    const steps = await cardSteps();
    expect(steps[0]).toContain("Identity provider");
    expect(steps[0]).toContain("connection refused");
    expect(steps[0]).toContain("Warning");
  });

  it("says nothing about the first run once a host is in", async () => {
    summary = { ...EMPTY_FLEET, hosts: 3 };
    checklist = list([step("hosts", "done", "3 hosts enrolled", "/hosts")]);
    draw(<Dashboard />);
    await waitFor(() => expect(screen.getByText("3 hosts you can see")).toBeInTheDocument());
    expect(screen.queryByText("No host is enrolled yet")).not.toBeInTheDocument();
  });
});

/* ---------------------------------------------------------------------- */
/* The three zones. A dashboard of nine cards, three tables and twenty-one */
/* tiles said nothing until all of it had been read; the rule now is that  */
/* a zone with nothing in it is not drawn and a list stays closed.         */
/* ---------------------------------------------------------------------- */

describe("the dashboard's three zones", () => {
  const quietFleet = {
    hosts: 12, online: 12, offline: 0, active_sessions: 2,
    jobs_awaiting_approval: 0, campaigns_awaiting_approval: 0, directory_changes_pending: 0,
    hosts_drifted: 0, operations_unconfirmed: 0, failed_jobs_24h: 0, reboot_required: 0,
  };

  it("answers in one line when the fleet needs nothing", async () => {
    summary = quietFleet as typeof summary;
    draw(<Dashboard />);
    // The zone is drawn before the counters arrive, so the wait is for the
    // answer and not for the element.
    await waitFor(() => expect(screen.getByTestId("verdict")).toHaveTextContent("Nothing needs a decision"));
    expect(screen.getByTestId("verdict")).toHaveTextContent("12 hosts you can see");
    // The zone for what needs a person is not an empty heading: it is absent.
    expect(screen.queryByTestId("needs-attention")).toBeNull();
  });

  it("counts the decisions and the findings apart in its headline", async () => {
    summary = {
      ...quietFleet,
      jobs_awaiting_approval: 2, operations_unconfirmed: 1,
      failed_jobs_24h: 3, reboot_required: 4,
    } as typeof summary;
    draw(<Dashboard />);
    // Three waiting on a person, seven found on the hosts.
    await waitFor(() => expect(screen.getByTestId("verdict")).toHaveTextContent("3 decisions waiting"));
    expect(screen.getByTestId("verdict")).toHaveTextContent("7 things need a look");
    const zone = screen.getByTestId("needs-attention");
    expect(zone).toHaveTextContent("Decisions nobody has taken");
    expect(zone).toHaveTextContent("Found on the hosts");
  });

  /* The rule the whole panel keeps: a count nobody could take is not a
     count of zero. A refused security sweep has to keep the zone on the
     screen, with a dash where the number would be. */
  it("keeps the zone when a count could not be taken at all", async () => {
    summary = quietFleet as typeof summary;
    security = Promise.reject(new Error("the sweep is refused for this reader"));
    draw(<Dashboard />);
    await waitFor(() => expect(screen.getByTestId("needs-attention")).toBeInTheDocument());
    const zone = screen.getByTestId("needs-attention");
    expect(zone).toHaveTextContent("Security findings");
    expect(zone.textContent).toContain("\u2014");
  });

  it("keeps its lists closed, with the number of rows on the line", async () => {
    summary = quietFleet as typeof summary;
    draw(<Dashboard />);
    await waitFor(() => expect(screen.getAllByTestId("section-head").length).toBe(3));
    const heads = screen.getAllByTestId("section-head");
    const head = (name: string) => heads.find((one) => one.textContent?.includes(name));
    expect(head("Recent failures")).toHaveAttribute("aria-expanded", "false");
    expect(head("Recent access denials")).toHaveAttribute("aria-expanded", "false");
    // Nothing is in progress in this fleet, so that list is closed too.
    expect(head("Campaigns in progress")).toHaveAttribute("aria-expanded", "false");
    // And no table of any of the three is on the screen.
    expect(screen.queryByRole("table")).toBeNull();
  });
});
