import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Identities } from "./Access";

/**
 * The list of identities, which an installation accumulates.
 *
 * The laboratory had 1803 of them after a month of suites, and the owner -
 * signed in as himself through the identity provider - could not find his own
 * name: the screen asked for every identity there was and drew them in order,
 * so his was somewhere past the leftovers. The search and the page belong to
 * the server now, and this is what says the screen asks for them.
 */

/** Every address the screen asked for, in order. */
const asked: string[] = [];
/** What a form wrote, so a test reads it rather than guessing. */
const sentWrites: { path: string; body: unknown }[] = [];

function page(subjects: string[], total: number) {
  return {
    items: subjects.map((subject, index) => ({
      id: `00000000-0000-4000-8000-00000000000${index}`,
      subject,
      display_name: "",
      kind: "user",
      bindings: [],
      tokens: [],
      // The second row has a password; the first has none. The difference
      // is what the row's button says.
      password: index === 1
        ? { set_at: "2026-10-16T08:00:00Z", set_by: "bootstrap-admin", must_change: true, failed_attempts: 0 }
        : undefined,
    })),
    count: subjects.length,
    total,
    by_kind: { user: total },
    by_role: { viewer: 2 },
    without_bindings: 1,
  };
}

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      put: (path: string, body: unknown) => { sentWrites.push({ path, body }); return Promise.resolve({}); },
      del: (path: string) => { sentWrites.push({ path, body: null }); return Promise.resolve({}); },
      get: (path: string) => {
        asked.push(path);
        if (path.startsWith("/api/v1/principals")) {
          const query = new URLSearchParams(path.split("?")[1] ?? "");
          if (query.get("q") === "tszymanski") return Promise.resolve(page(["tszymanski"], 1));
          const offset = Number(query.get("offset") ?? 0);
          return Promise.resolve(page([`identity-${offset}`, `identity-${offset + 1}`], 1803));
        }
        if (path === "/api/v1/roles") return Promise.resolve({ items: [], count: 0 });
        if (path === "/api/v1/whoami") return Promise.resolve({ permissions: ["principal.manage"] });
        return Promise.resolve({ items: [], count: 0 });
      },
    },
  };
});

function draw(node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/settings?tab=users"]}>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => { cleanup(); asked.length = 0; sentWrites.length = 0; });

describe("the identities list", () => {
  it("asks the server for a page, and says which page of how many", async () => {
    draw(<Identities initialSearch="" />);
    // The wait is on the answer, not on the bar: the pager draws "0 of 0"
    // until the first page arrives, and a test that read it then would pass
    // over a screen that never asked.
    await waitFor(() => expect(screen.getByTestId("page-of").textContent).toContain("1803"));
    expect(asked.some((path) => /\/api\/v1\/principals\?.*limit=\d+/.test(path))).toBe(true);
  });

  it("sends the search to the server rather than filtering the page it has", async () => {
    draw(<Identities initialSearch="" />);
    await waitFor(() => expect(screen.getByTestId("identity-search")).toBeInTheDocument());
    fireEvent.change(screen.getByTestId("identity-search"), { target: { value: "tszymanski" } });
    // The person signed in through the provider, who was past the leftovers.
    await waitFor(() => expect(screen.getByText("tszymanski")).toBeInTheDocument());
    expect(asked.some((path) => path.includes("q=tszymanski"))).toBe(true);
  });

  it("asks for the next page by its offset", async () => {
    draw(<Identities initialSearch="" />);
    await waitFor(() => expect(screen.getByTestId("page-next")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("page-next"));
    await waitFor(() => expect(asked.some((path) => /offset=(?!0)\d+/.test(path))).toBe(true));
  });
});

/*
 * The password of an identity, for an installation that signs people in
 * without a provider. What the row says before anything is clicked is the
 * part worth pinning: an identity with no password is not an identity whose
 * password is empty, and the button says which it is.
 */
describe("a row of the identity list", () => {
  it("carries no buttons but the name", async () => {
    const { container } = draw(<Identities initialSearch="" />);
    await waitFor(() => expect(screen.getByTestId("open-identity-0")).toBeInTheDocument());

    // The norm of 15.10: a row shows data and opens a record. Seven buttons
    // a row meant three hundred and fifty on a page of fifty, and none of
    // them was the important one. If this count grows, the wall is back.
    const row = screen.getByTestId("open-identity-0").closest("tr") as HTMLElement;
    const buttons = Array.from(row.querySelectorAll("button"));
    expect(buttons.map((button) => button.getAttribute("data-testid")))
      .toEqual(["open-identity-0"]);
    expect(container.querySelectorAll(".actions-cell")).toHaveLength(0);
  });

  it("opens the record on the name and sorts the rare acts into tabs", async () => {
    draw(<Identities initialSearch="" />);
    await waitFor(() => expect(screen.getByTestId("open-identity-1")).toBeInTheDocument());
    expect(screen.queryByTestId("record-identity-1")).toBeNull();

    fireEvent.click(screen.getByTestId("open-identity-1"));
    await waitFor(() => expect(screen.getByTestId("record-identity-1")).toBeInTheDocument());
    for (const tab of ["identity", "roles", "tokens", "password"]) {
      expect(screen.getByTestId(`record-tab-${tab}`)).toBeInTheDocument();
    }
    // The name closes what it opened: one record at a time.
    fireEvent.click(screen.getByTestId("open-identity-1"));
    await waitFor(() => expect(screen.queryByTestId("record-identity-1")).toBeNull());
  });
});

describe("the password of an identity", () => {
  it("says whether there is one in the row, as a fact and not as a button", async () => {
    draw(<Identities initialSearch="" />);
    await waitFor(() => expect(screen.getByTestId("password-state-identity-0")).toBeInTheDocument());
    // An identity with no password is not one whose password is empty, and
    // the column says which it is without inviting a click.
    expect(screen.getByTestId("password-state-identity-0")).toHaveTextContent("—");
    expect(screen.getByTestId("password-state-identity-1")).toHaveTextContent("set");
    expect(screen.queryByRole("button", { name: "Set a password" })).toBeNull();
  });

  it("asks for a reason before it stores one, and says who set the last", async () => {
    draw(<Identities initialSearch="" />);
    // The way in is the name, and the password is a tab of the record.
    await waitFor(() => expect(screen.getByTestId("open-identity-1")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("open-identity-1"));
    fireEvent.click(screen.getByTestId("record-tab-password"));

    await waitFor(() => expect(screen.getByTestId("set-password")).toBeInTheDocument());
    expect(screen.getByText(/Set by bootstrap-admin/)).toBeInTheDocument();
    expect(screen.getByText(/The owner has to replace it at their next sign-in/)).toBeInTheDocument();

    const save = screen.getByTestId("save-password");
    fireEvent.change(screen.getByTestId("set-password"), { target: { value: "a long enough passphrase" } });
    expect(save).toBeDisabled();
    fireEvent.change(screen.getByTestId("password-reason"), { target: { value: "new operator on the rota" } });
    await waitFor(() => expect(save).toBeEnabled());

    fireEvent.click(save);
    await waitFor(() => expect(sentWrites).toHaveLength(1));
    expect(sentWrites[0].path).toContain("/password");
    expect(sentWrites[0].body).toMatchObject({ must_change: true });
  });

  it("offers to take a password away only where there is one", async () => {
    draw(<Identities initialSearch="" />);
    await waitFor(() => expect(screen.getByTestId("open-identity-0")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("open-identity-0"));
    fireEvent.click(screen.getByTestId("record-tab-password"));
    await waitFor(() => expect(screen.getByTestId("set-password")).toBeInTheDocument());
    expect(screen.queryByTestId("clear-password")).toBeNull();
    expect(screen.getByText(/signs in through the identity provider, or not at all/)).toBeInTheDocument();
  });
});
