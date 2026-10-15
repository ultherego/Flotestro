import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Roles, roleNames } from "./Access";

/**
 * The roles screen, now that an installation can define one of its own.
 *
 * The two kinds are not the same thing on this screen and must not look like
 * it: the product's six are compiled in and nobody here may edit them, and
 * the ones defined here are somebody's writing, with holders who lose access
 * when it is narrowed.
 */

const catalogue = {
  items: [
    { role: "viewer", built_in: true, permissions: ["host.read", "job.read"], bindings: 2, mappings: 0 },
    { role: "platform_admin", built_in: true, permissions: ["host.read", "principal.manage"], bindings: 1, mappings: 0 },
    {
      role: "shift_lead", built_in: false, description: "Restarts services on the night shift.",
      permissions: ["host.read", "unit.restart"], bindings: 3, mappings: 1, created_by: "ada",
    },
    {
      role: "report_reader", built_in: false, description: "",
      permissions: ["host.read"], bindings: 0, mappings: 0, created_by: "ada",
    },
  ],
  count: 4,
};

const vocabulary = {
  items: [
    { permission: "host.read", group: "host" },
    { permission: "host.decommission", group: "host" },
    { permission: "unit.restart", group: "unit" },
    { permission: "unit.stop", group: "unit" },
  ],
  count: 4,
};

/** What the server was asked, so a test can check what a form sent. */
const sent: { path: string; body: unknown }[] = [];

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        if (path === "/api/v1/roles") return Promise.resolve(catalogue);
        if (path === "/api/v1/permissions") return Promise.resolve(vocabulary);
        return Promise.reject(new actual.ApiError(404, "not_found", path));
      },
      post: (path: string, body: unknown) => { sent.push({ path, body }); return Promise.resolve({}); },
      put: (path: string, body: unknown) => { sent.push({ path, body }); return Promise.resolve({}); },
      del: (path: string) => { sent.push({ path, body: null }); return Promise.resolve({}); },
    },
  };
});

function draw(node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/access?tab=roles"]}>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => { cleanup(); sent.length = 0; });

/** The table of the roles defined here; the name also appears in the matrix. */
function ownTable(): HTMLElement {
  const card = screen.getByText("Roles of this installation").closest(".ui-panel");
  return card?.querySelector("table") as HTMLElement;
}

describe("roleNames", () => {
  it("is empty until the catalogue has been read, rather than a guess at six names", () => {
    // The form that offers these disables itself on an empty list. Filling it
    // with the product's own names would offer roles this installation may
    // not have and hide the ones it does.
    expect(roleNames(undefined)).toEqual([]);
    expect(roleNames([])).toEqual([]);
    expect(roleNames(catalogue.items)).toEqual(["viewer", "platform_admin", "shift_lead", "report_reader"]);
  });
});

describe("the roles screen", () => {
  it("manages the roles defined here and leaves the product's own out of that table", async () => {
    draw(<Roles />);
    await waitFor(() => expect(screen.getByText("Roles of this installation")).toBeInTheDocument());
    const body = within(ownTable());
    expect(body.getByText("shift_lead")).toBeInTheDocument();
    expect(body.getByText("report_reader")).toBeInTheDocument();
    // The product's roles have no Edit button here, because there is nothing
    // to edit: their permissions are in the code.
    expect(body.queryByText("platform_admin")).toBeNull();
    // They are in the matrix below, marked as what they are.
    expect(screen.getByText("What each role may do")).toBeInTheDocument();
    expect(screen.getAllByText("own")).toHaveLength(2);
  });

  it("says how much a role is used, and tells a count it has not got from nobody holding it", async () => {
    draw(<Roles />);
    await waitFor(() => expect(screen.getByText("Roles of this installation")).toBeInTheDocument());
    const row = within(ownTable()).getByText("shift_lead").closest("tr") as HTMLElement;
    // Three bindings and one mapping are four grants, not three.
    expect(within(row).getByText("4 grants")).toBeInTheDocument();
    const unused = within(ownTable()).getByText("report_reader").closest("tr") as HTMLElement;
    expect(within(unused).getByText("nobody")).toBeInTheDocument();
  });

  it("names what an edit takes away from everybody holding the role", async () => {
    draw(<Roles />);
    await waitFor(() => expect(screen.getByText("Roles of this installation")).toBeInTheDocument());
    const row = within(ownTable()).getByText("shift_lead").closest("tr") as HTMLElement;
    fireEvent.click(within(row).getByText("Edit"));
    await waitFor(() => expect(screen.getByTestId("permission-picker")).toBeInTheDocument());
    // The permissions it holds are ticked, read from the role and not guessed.
    expect(screen.getByTestId("permission-unit.restart")).toBeChecked();
    expect(screen.getByTestId("permission-host.decommission")).not.toBeChecked();

    fireEvent.click(screen.getByTestId("permission-unit.restart"));
    await waitFor(() =>
      expect(screen.getByText(/Everybody holding this role loses: unit.restart/)).toBeInTheDocument());

    // Saving needs a reason, like every change to the access rules.
    const save = screen.getByText("Save the role");
    expect(save).toBeDisabled();
    fireEvent.change(screen.getByPlaceholderText("e.g. the night shift needs no reboots"),
      { target: { value: "the night shift stops restarting services" } });
    await waitFor(() => expect(save).toBeEnabled());
    fireEvent.click(save);
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].path).toBe("/api/v1/roles/shift_lead");
    // The whole definition is sent, not the change: what is left out is taken
    // away, and the server is the one place that decides what the role is.
    expect((sent[0].body as { permissions: string[] }).permissions).toEqual(["host.read"]);
  });

  it("refuses to write a role with nothing in it, or a name the schema would not take", async () => {
    draw(<Roles />);
    await waitFor(() => expect(screen.getByText("Define a role")).toBeInTheDocument());
    fireEvent.click(screen.getAllByText("Define a role")[0]);
    await waitFor(() => expect(screen.getByPlaceholderText("shift_lead")).toBeInTheDocument());
    const define = screen.getByText("Define the role");
    fireEvent.change(screen.getByPlaceholderText("shift_lead"), { target: { value: "Night Shift" } });
    fireEvent.change(screen.getByPlaceholderText("e.g. the night shift needs no reboots"),
      { target: { value: "a role for the night shift" } });
    fireEvent.click(screen.getByTestId("permission-host.read"));
    // Capitals and a space: the database would refuse the name, so the form
    // does, rather than sending it and showing a 400.
    expect(define).toBeDisabled();
    fireEvent.change(screen.getByPlaceholderText("shift_lead"), { target: { value: "night_shift" } });
    await waitFor(() => expect(define).toBeEnabled());
    // And with no permission at all there is nothing to define.
    fireEvent.click(screen.getByTestId("permission-host.read"));
    await waitFor(() => expect(define).toBeDisabled());
  });
});
