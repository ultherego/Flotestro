import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Access } from "./Access";
import { ToastProvider } from "../../components/Toast";

/**
 * The roles: what this installation wrote, and what a role may be given.
 *
 * The catalogue is drawn over the server's own vocabulary rather than over
 * the roles, so a permission nobody has been given is on the list too -
 * which is the one a reader is usually looking for. A count the server
 * never sent is "not known" and never "nobody", because the difference
 * decides whether removing the role would be refused.
 */

const answers: Record<string, unknown> = {};
/** Every write the screen made, in the order it made them. */
const sent: { method: string; path: string; body?: unknown }[] = [];

vi.mock("../../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/api")>();
  const answer = (path: string) => {
    const key = Object.keys(answers)
      .filter((one) => path.startsWith(one))
      .sort((a, b) => b.length - a.length)[0];
    if (!key) return Promise.reject(new actual.ApiError(404, "not_found", "no"));
    const given = answers[key];
    return given instanceof Error ? Promise.reject(given) : Promise.resolve(given);
  };
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => answer(path),
      post: (path: string, body?: unknown) => { sent.push({ method: "POST", path, body }); return Promise.resolve({}); },
      put: (path: string, body?: unknown) => { sent.push({ method: "PUT", path, body }); return Promise.resolve({}); },
      del: (path: string, body?: unknown) => { sent.push({ method: "DELETE", path, body }); return Promise.resolve(undefined); },
    },
  };
});

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

const vocabulary = {
  items: [
    { permission: "host.read", group: "host" },
    { permission: "job.create", group: "job" },
    { permission: "unit.restart", group: "unit" },
    { permission: "secret.write", group: "secret" },
  ],
  count: 4,
};

function given(over: Record<string, unknown> = {}) {
  Object.assign(answers, {
    "/api/v1/roles": roles,
    "/api/v1/permissions": vocabulary,
    "/api/v1/teams": { items: [], count: 0 },
    "/api/v1/group-mappings": { items: [], count: 0 },
    "/api/v1/whoami": { permissions: ["principal.manage"] },
    "/api/v1/access/review": {
      items: [], count: 0, flagged: 0, reviewed_at: "2026-10-16T08:00:00Z",
      thresholds: { unused_days: 90, expires_soon_days: 7, token_max_days: 365 },
    },
    "/api/v1/access/holders": { items: [], count: 0, directory: { configured: false, read: false } },
    "/api/v1/principals": { items: [], count: 0, total: 0, limit: 50, offset: 0 },
    ...over,
  });
}

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter></QueryClientProvider>
  );
  return render(<Access />, { wrapper });
}

afterEach(() => {
  cleanup();
  sent.length = 0;
  for (const key of Object.keys(answers)) delete answers[key];
});

describe("what a role may be given", () => {
  it("lists the product's whole vocabulary, including a permission nobody holds", async () => {
    given();
    draw();
    await waitFor(() => expect(screen.getByTestId("permission-row-secret.write")).toBeInTheDocument());
    // Read along the row: operator and shift_lead carry it, viewer does not.
    expect(within(screen.getByTestId("permission-row-unit.restart")).getAllByText("yes")).toHaveLength(2);
    expect(within(screen.getByTestId("permission-row-secret.write")).queryByText("yes")).not.toBeInTheDocument();
  });

  it("names the installation's own roles among the product's, so the columns can be told apart", async () => {
    given();
    draw();
    await waitFor(() => expect(screen.getByTestId("permission-catalogue")).toBeInTheDocument());
    const head = screen.getByTestId("permission-catalogue").querySelector("thead") as HTMLElement;
    expect(within(head).getByText("shift_lead").closest("th")).toHaveTextContent("own");
    expect(within(head).getByText("viewer").closest("th")).not.toHaveTextContent("own");
  });

  it("narrows the catalogue on what is typed", async () => {
    given();
    draw();
    await waitFor(() => expect(screen.getByTestId("permission-row-secret.write")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("permission-search"), { target: { value: "unit." } });
    await waitFor(() => expect(screen.queryByTestId("permission-row-secret.write")).not.toBeInTheDocument());
    expect(screen.getByTestId("permission-row-unit.restart")).toBeInTheDocument();
  });
});

describe("the roles of this installation", () => {
  it("lists only the roles somebody here wrote, with how much each is used", async () => {
    given();
    draw();
    await waitFor(() => expect(screen.getByTestId("role-shift_lead")).toBeInTheDocument());
    expect(screen.queryByTestId("role-viewer")).not.toBeInTheDocument();
    expect(screen.queryByTestId("role-operator")).not.toBeInTheDocument();
    expect(screen.getByTestId("role-shift_lead")).toHaveTextContent("2 grants");
  });

  it("says a count the server never sent is not known, and never nobody", async () => {
    given({ "/api/v1/roles": { items: [{ role: "shift_lead", permissions: ["unit.restart"] }], count: 1 } });
    draw();
    await waitFor(() => expect(screen.getByTestId("role-shift_lead")).toBeInTheDocument());
    expect(screen.getByTestId("role-shift_lead")).toHaveTextContent("not known");
    expect(screen.getByTestId("role-shift_lead")).not.toHaveTextContent("nobody");
  });

  it("offers a reader who may not manage access nothing to press", async () => {
    given({ "/api/v1/whoami": { permissions: ["host.read"] } });
    draw();
    await waitFor(() => expect(screen.getByTestId("role-shift_lead")).toBeInTheDocument());
    expect(screen.queryByTestId("edit-role-shift_lead")).not.toBeInTheDocument();
    expect(within(screen.getByTestId("role-shift_lead")).getByText("read only")).toBeInTheDocument();
    // The catalogue is still readable; it is the writing that is withheld.
    expect(screen.getByTestId("permission-catalogue")).toBeInTheDocument();
  });

  it("opens the editor on the role it was asked for, and on nothing else", async () => {
    given();
    draw();
    fireEvent.click(await screen.findByTestId("edit-role-shift_lead"));
    await waitFor(() => expect(screen.getByText("Edit the role shift_lead")).toBeInTheDocument());
    expect(screen.getByTestId("edit-role-shift_lead")).toBeDisabled();
    // What the role carries is ticked; what it does not is offered unticked.
    expect(screen.getByRole("checkbox", { name: "unit.restart" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "secret.write" })).not.toBeChecked();
    fireEvent.click(screen.getByTestId("role-close"));
    await waitFor(() => expect(screen.queryByText("Edit the role shift_lead")).not.toBeInTheDocument());
  });

  /**
   * Defining a role and removing one were in the panel being replaced and
   * did not come across. Without the first, an installation whose job
   * nobody's role describes has nowhere to say so; without the second, a
   * role written by mistake stays on the list for good.
   */
  it("defines a role by name against the server's own vocabulary", async () => {
    given();
    draw();
    fireEvent.click(await screen.findByTestId("define-role"));
    await waitFor(() => expect(screen.getByTestId("role-name")).toBeInTheDocument());
    // Nothing is ticked on a role that does not exist yet.
    expect(screen.getByRole("checkbox", { name: "unit.restart" })).not.toBeChecked();
    expect(screen.getByTestId("role-save")).toBeDisabled();

    fireEvent.change(screen.getByTestId("role-name"), { target: { value: "night_shift" } });
    fireEvent.change(screen.getByTestId("role-description"), { target: { value: "the night shift" } });
    fireEvent.click(screen.getByRole("checkbox", { name: "unit.restart" }));
    expect(screen.getByTestId("role-save")).toBeEnabled();

    fireEvent.click(screen.getByTestId("role-save"));
    await waitFor(() => expect(screen.getByTestId("role-reason")).toBeInTheDocument());
    // Nothing is written before the reason the trail keeps.
    expect(screen.getByTestId("role-confirm")).toBeDisabled();
    fireEvent.change(screen.getByTestId("role-reason"), { target: { value: "the night shift needs no reboots" } });
    fireEvent.click(screen.getByTestId("role-confirm"));

    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0]).toEqual({
      method: "POST",
      path: "/api/v1/roles",
      body: {
        role: "night_shift",
        description: "the night shift",
        permissions: ["unit.restart"],
        reason: "the night shift needs no reboots",
      },
    });
  });

  it("refuses a name the server would refuse, and says what shape one takes", async () => {
    given();
    draw();
    fireEvent.click(await screen.findByTestId("define-role"));
    await waitFor(() => expect(screen.getByTestId("role-name")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("checkbox", { name: "unit.restart" }));
    fireEvent.change(screen.getByTestId("role-name"), { target: { value: "Night Shift" } });
    expect(screen.getByTestId("role-save")).toBeDisabled();
    expect(screen.getByText(/lower case letters, digits and underscores/)).toBeInTheDocument();
    fireEvent.change(screen.getByTestId("role-name"), { target: { value: "night_shift" } });
    expect(screen.getByTestId("role-save")).toBeEnabled();
  });

  it("removes a role through the one dialog, with its reason in the address", async () => {
    given();
    draw();
    fireEvent.click(await screen.findByTestId("remove-role-shift_lead"));
    await waitFor(() => expect(screen.getByText("Remove the role shift_lead")).toBeInTheDocument());
    // A role that is still granted says the removal will be refused.
    expect(screen.getByText(/the panel will refuse to remove it/)).toBeInTheDocument();
    expect(screen.getByTestId("ask-confirm")).toBeDisabled();
    fireEvent.change(screen.getByTestId("ask-reason"), { target: { value: "written by mistake" } });
    fireEvent.click(screen.getByTestId("ask-confirm"));

    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0].method).toBe("DELETE");
    expect(sent[0].path).toBe("/api/v1/roles/shift_lead?reason=written%20by%20mistake");
  });

  it("promises nothing about a role whose use the server never counted", async () => {
    given({ "/api/v1/roles": { items: [{ role: "shift_lead", permissions: ["unit.restart"] }], count: 1 } });
    draw();
    fireEvent.click(await screen.findByTestId("remove-role-shift_lead"));
    await waitFor(() => expect(screen.getByText(/not known here/)).toBeInTheDocument());
    expect(screen.queryByText(/nobody loses access by this/)).not.toBeInTheDocument();
  });

  it("offers a reader who may not manage access no way to define or remove one", async () => {
    given({ "/api/v1/whoami": { permissions: ["host.read"] } });
    draw();
    await waitFor(() => expect(screen.getByTestId("role-shift_lead")).toBeInTheDocument());
    expect(screen.queryByTestId("define-role")).not.toBeInTheDocument();
    expect(screen.queryByTestId("remove-role-shift_lead")).not.toBeInTheDocument();
  });

  it("will not write a role against a vocabulary that has not arrived", async () => {
    given({ "/api/v1/permissions": new Promise(() => { /* never */ }) });
    draw();
    fireEvent.click(await screen.findByTestId("edit-role-shift_lead"));
    await waitFor(() => expect(screen.getByTestId("role-save")).toBeInTheDocument());
    expect(screen.getByTestId("role-save")).toBeDisabled();
    // The shape of what is coming, never the word "Loading…".
    expect(screen.queryByText("Loading…")).not.toBeInTheDocument();
  });
});
