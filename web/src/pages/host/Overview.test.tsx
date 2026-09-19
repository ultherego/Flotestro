import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "@testing-library/jest-dom/vitest";
import type { Host } from "../../lib/types";
import { HostTeam } from "./Overview";

/**
 * The team of a host, on the host's own page.
 */

const teams = {
  items: [
    { id: "8f2b1d3e-0000-4000-8000-000000000001", name: "payments platform", hosts: 12, created_at: "2026-09-18T08:00:00Z", updated_at: "2026-09-18T08:00:00Z" },
    { id: "8f2b1d3e-0000-4000-8000-000000000002", name: "edge", hosts: 3, created_at: "2026-09-18T08:00:00Z", updated_at: "2026-09-18T08:00:00Z" },
  ],
  count: 2,
};

// The mock records what the page asked for, so the test can say which
// address and which body the move really sent.
const put = vi.fn((_path: string, _body: unknown) => Promise.resolve({}));

vi.mock("../../lib/api", () => ({
  api: {
    get: (path: string) => {
      if (path === "/api/v1/teams") return Promise.resolve(teams);
      return Promise.reject(new Error(`no answer for ${path}`));
    },
    put: (path: string, body: unknown) => put(path, body),
  },
  ApiError: class extends Error {},
  loadedItems: () => [],
}));

function hostWith(fields: Record<string, unknown>): Host {
  return {
    id: "h1", hostname: "db-01", site: "lab", environment: "test",
    ...fields,
  } as unknown as Host;
}

function draw(node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

beforeEach(() => { put.mockClear(); });
afterEach(cleanup);

describe("the team of a host", () => {
  it("says a host nobody has placed is in no team, rather than showing a blank", () => {
    draw(<HostTeam host={hostWith({})} editable />);
    expect(screen.getByTestId("fact-team")).toHaveTextContent("no team");
  });

  it("names the team of a host somebody placed", () => {
    draw(<HostTeam host={hostWith({ team_id: teams.items[0].id, team_name: "payments platform" })} editable />);
    expect(screen.getByTestId("fact-team")).toHaveTextContent("payments platform");
  });

  it("offers no move to whoever does not hold the permission the server checks", () => {
    draw(<HostTeam host={hostWith({})} editable={false} />);
    expect(screen.getByTestId("fact-team")).toHaveTextContent("no team");
    expect(screen.queryByTestId("move-team")).not.toBeInTheDocument();
  });

  it("says once, in the form, that the move changes who may act on the host", async () => {
    draw(<HostTeam host={hostWith({})} editable />);
    fireEvent.click(screen.getByTestId("move-team"));
    expect(screen.getByText(/changes who may act on it/)).toBeInTheDocument();
    expect(screen.getByText(/the operators of the old team may not/)).toBeInTheDocument();
    // The teams are offered by name, with the way out of every team beside
    // them: a host may be taken out of a team without being put in another.
    await waitFor(() => expect(screen.getByTestId("edit-team")).toHaveTextContent("payments platform"));
    expect(screen.getByTestId("edit-team")).toHaveTextContent("no team");
  });

  it("keeps the move shut until the reason is there and the team really changes", async () => {
    draw(<HostTeam host={hostWith({ team_id: teams.items[0].id, team_name: "payments platform" })} editable />);
    fireEvent.click(screen.getByTestId("move-team"));
    const move = screen.getByRole("button", { name: "Move" });
    expect(move).toBeDisabled();
    fireEvent.change(screen.getByTestId("team-reason"), { target: { value: "the edge group took the host over" } });
    // The reason is there, but the team is the one the host is already in:
    // a write that moves nothing would only make the trail noisier.
    expect(move).toBeDisabled();
    await waitFor(() => expect(screen.getByTestId("edit-team")).toHaveTextContent("edge"));
    fireEvent.change(screen.getByTestId("edit-team"), { target: { value: teams.items[1].id } });
    expect(move).toBeEnabled();
  });

  it("places the move on the route of its own, with the team and the reason", async () => {
    draw(<HostTeam host={hostWith({})} editable />);
    fireEvent.click(screen.getByTestId("move-team"));
    await waitFor(() => expect(screen.getByTestId("edit-team")).toHaveTextContent("edge"));
    fireEvent.change(screen.getByTestId("edit-team"), { target: { value: teams.items[1].id } });
    fireEvent.change(screen.getByTestId("team-reason"), { target: { value: "the edge group took the host over" } });
    fireEvent.click(screen.getByRole("button", { name: "Move" }));
    await waitFor(() => expect(put).toHaveBeenCalled());
    expect(put).toHaveBeenCalledWith("/api/v1/hosts/h1/team", {
      team: teams.items[1].id, reason: "the edge group took the host over",
    });
  });

  it("takes a host out of its team with the empty team the route reads as none", async () => {
    draw(<HostTeam host={hostWith({ team_id: teams.items[0].id, team_name: "payments platform" })} editable />);
    fireEvent.click(screen.getByTestId("move-team"));
    fireEvent.change(screen.getByTestId("edit-team"), { target: { value: "" } });
    fireEvent.change(screen.getByTestId("team-reason"), { target: { value: "the payments group was disbanded" } });
    fireEvent.click(screen.getByRole("button", { name: "Move" }));
    await waitFor(() => expect(put).toHaveBeenCalled());
    expect(put).toHaveBeenCalledWith("/api/v1/hosts/h1/team", {
      team: "", reason: "the payments group was disbanded",
    });
  });
});
