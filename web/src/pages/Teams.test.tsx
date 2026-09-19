import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "@testing-library/jest-dom/vitest";
import { Teams, refusalText, teamHostsAddress, UNPLACED_HOSTS_ADDRESS, type Team } from "./Teams";

/*
 * The register of teams.
 *
 * A team is the only one of the three words a fleet is described with
 * that may decide who may touch what, so the screen is held to saying it:
 * an installation with no teams is told what a team would be for rather
 * than shown an empty table, a deletion says how many hosts it releases
 * and that they keep existing, and an identity without the permission
 * sees what the write takes instead of a screen with its buttons quietly
 * gone.
 */

/** The answers the server gives this test, by path. */
let answers: Record<string, unknown>;

vi.mock("../lib/api", async () => {
  // The real module is kept - ApiError and everything else the page reads
  // are the product's own - and only the calls are answered here.
  const actual = await vi.importActual<typeof import("../lib/api")>("../lib/api");
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        if (path in answers) return Promise.resolve(answers[path]);
        return Promise.reject(new Error(`no answer for ${path}`));
      },
      post: () => Promise.reject(new Error("the test writes nothing")),
      put: () => Promise.reject(new Error("the test writes nothing")),
      del: () => Promise.reject(new Error("the test writes nothing")),
    },
  };
});

const team: Team = {
  id: "8f2b1d3e-0000-4000-8000-000000000001",
  name: "payments platform",
  description: "the machines behind the payment API",
  created_by: "alice",
  hosts: 12,
  created_at: "2026-09-18T08:00:00Z",
  updated_at: "2026-09-18T08:00:00Z",
};

function open(teams: Team[], permissions: string[], unplaced = 40) {
  answers = {
    "/api/v1/whoami": { permissions },
    "/api/v1/teams": { items: teams, count: teams.length },
    "/api/v1/hosts?team=none&limit=1": { items: [], count: 0, total: unplaced },
  };
  return draw(<Teams />);
}

function draw(node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(cleanup);

describe("the register of an installation with no teams", () => {
  it("says what a team is for rather than showing an empty table", async () => {
    open([], ["team.binding.write"]);
    expect(await screen.findByText(/No teams\./)).toBeInTheDocument();
    expect(screen.getByText(/Draw a team where the division of the work is not the geography of the machines/)).toBeInTheDocument();
    expect(screen.queryAllByTestId("team-row")).toHaveLength(0);
  });

  it("counts the hosts nobody has placed, and leads to them", async () => {
    open([], ["team.binding.write"], 40);
    expect(await screen.findByText("40")).toBeInTheDocument();
    const link = screen.getByText("40").closest("a");
    expect(link).toHaveAttribute("href", UNPLACED_HOSTS_ADDRESS);
  });

  it("offers the creation to whoever holds the permission", async () => {
    open([], ["team.binding.write"]);
    // The button is drawn before the answer about the permissions arrives,
    // and the guarded one is replaced by a plain one when it does - so the
    // assertion asks the screen again rather than holding the first node.
    await waitFor(() => {
      expect(screen.getAllByRole("button", { name: "Create team" })[0]).toBeEnabled();
    });
    expect(screen.queryByTestId("teams-guard")).not.toBeInTheDocument();
  });

  it("keeps the creation on the screen and disabled for whoever does not, with what it takes", async () => {
    open([], ["host.read"]);
    const guard = await screen.findAllByTestId("teams-guard");
    expect(guard.length).toBeGreaterThan(0);
    expect(screen.getAllByText(/needs the permission team\.binding\.write/)[0]).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Create team" })[0]).toBeDisabled();
  });
});

describe("the register with teams in it", () => {
  it("lists a team with its hosts, and the count leads to them", async () => {
    open([team], ["team.binding.write"]);
    const row = await screen.findByTestId("team-row");
    expect(row).toHaveTextContent("payments platform");
    expect(row).toHaveTextContent("the machines behind the payment API");
    // The identifier is on the row because it is the boundary a binding
    // names; the name is not.
    expect(row).toHaveTextContent(team.id);
    // The same number stands in the tile above, so the link is looked for
    // inside the row rather than anywhere on the page.
    expect(within(row).getByText("12").closest("a"))
      .toHaveAttribute("href", teamHostsAddress(team.id));
  });

  it("says a description nobody wrote is missing rather than showing a blank", async () => {
    open([{ ...team, description: "" }], ["team.binding.write"]);
    expect(await screen.findByText("nobody wrote one")).toBeInTheDocument();
  });

  it("says how many hosts a deletion releases and that they keep existing", async () => {
    open([team], ["team.binding.write"]);
    fireEvent.click(await screen.findByRole("button", { name: "Delete" }));
    const text = await screen.findByTestId("team-delete-text");
    expect(text).toHaveTextContent("This releases 12 hosts.");
    expect(text).toHaveTextContent(/keep existing and stay reachable through their site/);
    expect(screen.getByText(/whoever held a role here and nowhere else loses it/)).toBeInTheDocument();
  });

  it("holds the deletion shut until the reason the trail requires is there", async () => {
    open([team], ["team.binding.write"]);
    fireEvent.click(await screen.findByRole("button", { name: "Delete" }));
    const confirm = screen.getByTestId("team-delete");
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByTestId("team-reason"), { target: { value: "short" } });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByTestId("team-reason"), { target: { value: "the payments group was disbanded" } });
    expect(confirm).toBeEnabled();
  });

  it("holds the creation shut until both the name and the reason are there", async () => {
    open([team], ["team.binding.write"]);
    fireEvent.click((await screen.findAllByRole("button", { name: "Create team" }))[0]);
    const save = screen.getByTestId("team-save");
    expect(save).toBeDisabled();
    fireEvent.change(screen.getByTestId("team-name"), { target: { value: "edge" } });
    expect(save).toBeDisabled();
    fireEvent.change(screen.getByTestId("team-reason"), { target: { value: "the edge hosts changed hands" } });
    expect(save).toBeEnabled();
  });
});

describe("refusalText", () => {
  it("says what a taken name means, rather than repeating the code", () => {
    expect(refusalText("team_name_taken", "another team already answers to that name"))
      .toMatch(/One name means one group/);
  });

  it("says a team deleted under the screen is gone and the register is stale", () => {
    expect(refusalText("team_not_found", "no such team")).toMatch(/deleted it while this screen was open/);
  });

  it("keeps the server's own wording for an invalid team, because it says what is wrong with it", () => {
    expect(refusalText("invalid_team", "invalid team: a team needs a name"))
      .toBe("invalid team: a team needs a name");
  });

  it("says the two vocabularies do not mix", () => {
    expect(refusalText("scope_conflict", "")).toBe("A binding names a team or a site, never both.");
  });

  it("shows a refusal nobody foresaw as the server worded it", () => {
    expect(refusalText("rate_limited", "too many requests")).toBe("too many requests");
  });
});

describe("the addresses the register hands on", () => {
  it("narrows the host list to one team by its identifier", () => {
    expect(teamHostsAddress(team.id)).toBe(`/hosts?team=${team.id}`);
  });

  it("asks for the hosts nobody placed with the server's own word", () => {
    expect(UNPLACED_HOSTS_ADDRESS).toBe("/hosts?team=none");
  });
});
