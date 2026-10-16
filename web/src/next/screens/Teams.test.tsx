import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import {
  HOST_TEAM_PERMISSION, TEAM_WRITE_PERMISSION, Teams, UNPLACED_HOSTS_ADDRESS, reasonGiven,
  refusalText, teamHostsAddress,
} from "./Teams";
import { ToastProvider } from "../../components/Toast";

/**
 * The register as an operator reads it, and the two writes it owns.
 *
 * The hosts nobody has placed are the number worth holding: a read that
 * failed is not a fleet where everybody has a team, so the tile says
 * unknown rather than nought.
 */

const asked: string[] = [];
const sent: { method: string; path: string; body?: unknown }[] = [];
const answers: Record<string, unknown> = {};

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  // The longest key that is a prefix of the path answers it: "/api/v1/hosts"
  // left to answer "/api/v1/hosts?team=none&limit=1" would hand the tile a
  // count of the whole fleet.
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
      post: (path: string, body?: unknown) => { sent.push({ method: "POST", path, body }); return Promise.resolve({ id: "t9" }); },
      put: (path: string, body?: unknown) => { sent.push({ method: "PUT", path, body }); return Promise.resolve({}); },
      del: (path: string, body?: unknown) => { sent.push({ method: "DELETE", path, body }); return Promise.resolve({ deleted: "t1" }); },
    },
  };
});

const team = (over: Record<string, unknown>) => ({
  id: "t1", name: "payments platform", description: "the machines the payments group runs",
  created_by: "tszymanski", hosts: 6, created_at: "2026-09-01T08:00:00Z", updated_at: "2026-10-01T08:00:00Z",
  ...over,
});

const admin = { subject: "t", kind: "user", roles: [], bindings: [], permissions: ["team.binding.write"] };
const reader = { subject: "t", kind: "user", roles: [], bindings: [], permissions: ["host.read"] };
/** Whoever may move a machine between boundaries, and nothing else. */
const placer = { subject: "t", kind: "user", roles: [], bindings: [], permissions: ["host.scope.write"] };

const host = (over: Record<string, unknown> = {}) => ({
  id: "h1", hostname: "db-01", machine_id: "m1", site: "waw", environment: "prod",
  tags: [], release_channel: "stable", lifecycle_state: "active", connection_state: "online",
  ...over,
});

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter></QueryClientProvider>
  );
  return render(<Teams />, { wrapper });
}

afterEach(() => {
  cleanup();
  asked.length = 0;
  sent.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("the register", () => {
  it("draws a team as its name, its identifier and the hosts placed in it", async () => {
    Object.assign(answers, {
      "/api/v1/teams": { items: [team({})], count: 1 },
      "/api/v1/hosts?team=none": { items: [], count: 0, total: 3 },
      "/api/v1/whoami": reader,
      "/api/v1/settings/layout": { widgets: [], present: false, revision: 0 },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("team-payments platform")).toBeInTheDocument());
    const row = screen.getByTestId("team-payments platform");
    expect(within(row).getByRole("link", { name: "payments platform" })).toHaveAttribute("href", "/hosts?team=t1");
    // The identifier is what a binding names; a rename does not move it.
    expect(row).toHaveTextContent("t1");
    expect(row).toHaveTextContent("6");
  });

  it("says a description nobody wrote is missing rather than leaving a blank", async () => {
    Object.assign(answers, {
      "/api/v1/teams": { items: [team({ description: "" })], count: 1 },
      "/api/v1/whoami": reader,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("team-payments platform")).toBeInTheDocument());
    expect(within(screen.getByTestId("team-payments platform")).getByText("nobody wrote one")).toBeInTheDocument();
  });

  it("counts the hosts nobody placed and leads to them", async () => {
    Object.assign(answers, {
      "/api/v1/teams": { items: [team({})], count: 1 },
      "/api/v1/hosts?team=none": { items: [], count: 0, total: 3 },
      "/api/v1/whoami": reader,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("kpi-Hosts in no team")).toHaveTextContent("3"));
    expect(screen.getByTestId("kpi-Hosts in no team")).toHaveAttribute("href", UNPLACED_HOSTS_ADDRESS);
  });

  it("says the hosts nobody placed are unknown when the count could not be read, never nought", async () => {
    // No answer is registered for the host count, so the read fails.
    Object.assign(answers, { "/api/v1/teams": { items: [team({})], count: 1 }, "/api/v1/whoami": reader });
    draw();
    await waitFor(() => expect(screen.getByTestId("team-payments platform")).toBeInTheDocument());
    const tile = screen.getByTestId("kpi-Hosts in no team");
    expect(tile).toHaveAttribute("data-state", "unknown");
    expect(within(tile).getByTitle("unknown")).toHaveTextContent("—");
    expect(tile).not.toHaveTextContent("0");
  });

  it("says what a team is for rather than showing an empty table", async () => {
    Object.assign(answers, { "/api/v1/teams": { items: [], count: 0 }, "/api/v1/whoami": admin });
    draw();
    await waitFor(() => expect(screen.getByText(/Draw a team where the division of the work/)).toBeInTheDocument());
  });
});

describe("drawing a team", () => {
  it("holds the button shut until both the name and the reason are there, then sends them", async () => {
    Object.assign(answers, { "/api/v1/teams": { items: [], count: 0 }, "/api/v1/whoami": admin });
    draw();
    await waitFor(() => expect(screen.getByTestId("new-team")).toBeEnabled());
    fireEvent.click(screen.getByTestId("new-team"));

    fireEvent.change(screen.getByTestId("team-name"), { target: { value: "payments platform" } });
    expect(screen.getByTestId("team-save")).toBeDisabled();
    fireEvent.change(screen.getByTestId("team-reason"), { target: { value: "short" } });
    expect(screen.getByTestId("team-save")).toBeDisabled();

    fireEvent.change(screen.getByTestId("team-description"), { target: { value: "the payments machines" } });
    fireEvent.change(screen.getByTestId("team-reason"), { target: { value: "the payments group took the database hosts" } });
    expect(screen.getByTestId("team-save")).toBeEnabled();
    fireEvent.click(screen.getByTestId("team-save"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0]).toMatchObject({
      method: "POST",
      path: "/api/v1/teams",
      body: {
        name: "payments platform",
        description: "the payments machines",
        reason: "the payments group took the database hosts",
      },
    });
  });

  it("starts a rename from the record as it is, and writes back on the identifier", async () => {
    Object.assign(answers, { "/api/v1/teams": { items: [team({})], count: 1 }, "/api/v1/whoami": admin });
    draw();
    await waitFor(() => expect(screen.getByTestId("rename-a-team")).toBeEnabled());
    fireEvent.click(screen.getByTestId("rename-a-team"));
    fireEvent.change(screen.getByTestId("team-to-rename"), { target: { value: "t1" } });
    expect(screen.getByTestId("team-name")).toHaveValue("payments platform");

    fireEvent.change(screen.getByTestId("team-name"), { target: { value: "payments" } });
    fireEvent.change(screen.getByTestId("team-reason"), { target: { value: "the group goes by one word now" } });
    fireEvent.click(screen.getByTestId("team-save"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0]).toMatchObject({ method: "PUT", path: "/api/v1/teams/t1", body: { name: "payments" } });
  });
});

describe("deleting a team", () => {
  it("asks first, says how many hosts it releases, and holds shut until the trail is told why", async () => {
    Object.assign(answers, { "/api/v1/teams": { items: [team({})], count: 1 }, "/api/v1/whoami": admin });
    draw();
    await waitFor(() => expect(screen.getByTestId("delete-a-team")).toBeEnabled());
    fireEvent.click(screen.getByTestId("delete-a-team"));
    // One team in the register, so it is the subject; nothing is sent yet.
    expect(sent).toHaveLength(0);
    expect(screen.getByText(/This releases 6 hosts/)).toBeInTheDocument();
    expect(screen.getByTestId("team-delete")).toBeDisabled();

    fireEvent.change(screen.getByTestId("team-delete-reason"), { target: { value: "the group was wound up" } });
    expect(screen.getByTestId("team-delete")).toBeEnabled();
    fireEvent.click(screen.getByTestId("team-delete"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0]).toMatchObject({
      method: "DELETE", path: "/api/v1/teams/t1", body: { reason: "the group was wound up" },
    });
  });

  it("says what the register refused in words, keeping the dialog's own wording out of it", async () => {
    Object.assign(answers, { "/api/v1/teams": { items: [team({})], count: 1 }, "/api/v1/whoami": admin });
    const failing = await import("../../lib/api");
    const del = vi.spyOn(failing.api, "del").mockRejectedValueOnce(
      new failing.ApiError(409, "team_name_taken", "taken"));
    draw();
    await waitFor(() => expect(screen.getByTestId("delete-a-team")).toBeEnabled());
    fireEvent.click(screen.getByTestId("delete-a-team"));
    fireEvent.change(screen.getByTestId("team-delete-reason"), { target: { value: "the group was wound up" } });
    fireEvent.click(screen.getByTestId("team-delete"));
    await waitFor(() => expect(screen.getByTestId("teams-refusal")).toBeInTheDocument());
    expect(screen.getByTestId("teams-refusal")).toHaveTextContent(/keeps the names unique/);
    del.mockRestore();
  });
});

describe("placing a host in a team", () => {
  const ready = (over: Record<string, unknown> = {}) => {
    Object.assign(answers, {
      "/api/v1/teams": { items: [team({})], count: 1 },
      "/api/v1/hosts?team=none": { items: [], count: 0, total: 3 },
      "/api/v1/hosts?limit=": { items: [host({ team_id: "", team_name: "" })], count: 1, total: 1 },
      "/api/v1/whoami": { ...admin, permissions: [TEAM_WRITE_PERMISSION, HOST_TEAM_PERMISSION] },
      ...over,
    });
  };

  it("asks for the host, the team and a reason, then writes the placement on the host", async () => {
    ready();
    draw();
    await waitFor(() => expect(screen.getByTestId("place-a-host")).toBeEnabled());
    fireEvent.click(screen.getByTestId("place-a-host"));
    await waitFor(() => expect(screen.getByTestId("host-to-place")).toBeInTheDocument());
    // Nothing is written by opening the question.
    expect(sent).toHaveLength(0);

    fireEvent.change(screen.getByTestId("host-to-place"), { target: { value: "h1" } });
    fireEvent.change(screen.getByTestId("host-team"), { target: { value: "t1" } });
    expect(screen.getByTestId("host-place")).toBeDisabled();
    fireEvent.change(screen.getByTestId("host-place-reason"), { target: { value: "short" } });
    expect(screen.getByTestId("host-place")).toBeDisabled();

    fireEvent.change(screen.getByTestId("host-place-reason"), { target: { value: "the payments group took the host over" } });
    expect(screen.getByTestId("host-place")).toBeEnabled();
    fireEvent.click(screen.getByTestId("host-place"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0]).toEqual({
      method: "PUT",
      path: "/api/v1/hosts/h1/team",
      body: { team: "t1", reason: "the payments group took the host over" },
    });
  });

  it("says what moving a host costs the people who had it, before it is moved", async () => {
    ready();
    draw();
    await waitFor(() => expect(screen.getByTestId("place-a-host")).toBeEnabled());
    fireEvent.click(screen.getByTestId("place-a-host"));
    expect(screen.getByText(/the operators of the old team may not/)).toBeInTheDocument();
  });

  it("will not write a move to the team the host is already in", async () => {
    ready({
      "/api/v1/hosts?limit=": {
        items: [host({ team_id: "t1", team_name: "payments platform" })], count: 1, total: 1,
      },
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("place-a-host")).toBeEnabled());
    fireEvent.click(screen.getByTestId("place-a-host"));
    await waitFor(() => expect(screen.getByTestId("host-to-place")).toBeInTheDocument());

    fireEvent.change(screen.getByTestId("host-to-place"), { target: { value: "h1" } });
    // The destination starts where the host is, so nothing is a move yet.
    expect(screen.getByTestId("host-team")).toHaveValue("t1");
    fireEvent.change(screen.getByTestId("host-place-reason"), { target: { value: "the payments group took the host over" } });
    expect(screen.getByTestId("host-place")).toBeDisabled();
    expect(screen.getByTestId("host-place-nothing")).toHaveTextContent("already in payments platform");

    // Out of the team is a move like any other.
    fireEvent.change(screen.getByTestId("host-team"), { target: { value: "" } });
    expect(screen.getByTestId("host-place")).toBeEnabled();
    fireEvent.click(screen.getByTestId("host-place"));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0]).toMatchObject({ method: "PUT", path: "/api/v1/hosts/h1/team", body: { team: "" } });
  });

  it("says what the server refused in words of its own", async () => {
    ready();
    const failing = await import("../../lib/api");
    const put = vi.spyOn(failing.api, "put").mockRejectedValueOnce(
      new failing.ApiError(404, "team_not_found", "no such team"));
    draw();
    await waitFor(() => expect(screen.getByTestId("place-a-host")).toBeEnabled());
    fireEvent.click(screen.getByTestId("place-a-host"));
    await waitFor(() => expect(screen.getByTestId("host-to-place")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("host-to-place"), { target: { value: "h1" } });
    fireEvent.change(screen.getByTestId("host-team"), { target: { value: "t1" } });
    fireEvent.change(screen.getByTestId("host-place-reason"), { target: { value: "the payments group took the host over" } });
    fireEvent.click(screen.getByTestId("host-place"));
    await waitFor(() => expect(screen.getByTestId("teams-refusal")).toBeInTheDocument());
    expect(screen.getByTestId("teams-refusal")).toHaveTextContent(/Read the register again/);
    put.mockRestore();
  });

  it("is a permission of its own: the register's write does not carry it", async () => {
    Object.assign(answers, {
      "/api/v1/teams": { items: [team({})], count: 1 },
      "/api/v1/whoami": admin,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("new-team")).toBeEnabled());
    expect(screen.getByTestId("place-a-host")).toBeDisabled();
    expect(screen.getByText(/This needs the permission host.scope.write/)).toBeInTheDocument();
    expect(sent).toHaveLength(0);
  });

  it("offers the placement to whoever holds it even where the register is read-only", async () => {
    Object.assign(answers, {
      "/api/v1/teams": { items: [team({})], count: 1 },
      "/api/v1/hosts?limit=": { items: [host({})], count: 1, total: 1 },
      "/api/v1/whoami": placer,
    });
    draw();
    await waitFor(() => expect(screen.getByTestId("place-a-host")).toBeEnabled());
    expect(screen.getByTestId("new-team")).toBeDisabled();
    expect(screen.getByText(/This needs the permission team.binding.write/)).toBeInTheDocument();
  });
});

describe("the permission the register takes", () => {
  it("keeps the controls on the screen and shut for whoever does not hold it, and says what it takes", async () => {
    Object.assign(answers, { "/api/v1/teams": { items: [team({})], count: 1 }, "/api/v1/whoami": reader });
    draw();
    await waitFor(() => expect(screen.getByTestId("new-team")).toBeInTheDocument());
    expect(screen.getByTestId("new-team")).toBeDisabled();
    expect(screen.getByTestId("delete-a-team")).toBeDisabled();
    expect(screen.getByText(/This needs the permission team.binding.write/)).toBeInTheDocument();
  });

  it("says a register it may not read is not an empty register", async () => {
    const api = await import("../../lib/api");
    const get = vi.spyOn(api.api, "get").mockRejectedValue(new api.ApiError(403, "forbidden", "no"));
    draw();
    await waitFor(() => expect(screen.getByText("You do not have permission to read the teams.")).toBeInTheDocument());
    get.mockRestore();
  });
});

describe("refusalText", () => {
  it("says what a taken name means rather than repeating the code", () => {
    expect(refusalText("team_name_taken", "conflict")).toContain("One name means one group");
  });

  it("says a team deleted under the screen is gone and the register is stale", () => {
    expect(refusalText("team_not_found", "404")).toContain("Read the register again");
  });

  it("keeps the server's own wording for an invalid team, because it says what is wrong", () => {
    expect(refusalText("invalid_team", "the name is 300 characters")).toBe("the name is 300 characters");
  });

  it("says the two vocabularies do not mix", () => {
    expect(refusalText("scope_conflict", "")).toContain("never both");
  });

  it("shows a refusal nobody foresaw as the server worded it", () => {
    expect(refusalText("teapot", "I am a teapot")).toBe("I am a teapot");
  });
});

describe("the addresses the register hands on", () => {
  it("narrows the host list to one team by its identifier", () => {
    expect(teamHostsAddress("t 1")).toBe("/hosts?team=t%201");
  });

  it("asks for the hosts nobody placed with the server's own word", () => {
    expect(UNPLACED_HOSTS_ADDRESS).toBe("/hosts?team=none");
  });

  it("takes a reason the trail will keep and no shorter one", () => {
    expect(reasonGiven("short")).toBe(false);
    expect(reasonGiven("  eight ch  ")).toBe(true);
  });
});
