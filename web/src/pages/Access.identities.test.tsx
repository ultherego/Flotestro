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

function page(subjects: string[], total: number) {
  return {
    items: subjects.map((subject, index) => ({
      id: `00000000-0000-4000-8000-00000000000${index}`,
      subject,
      display_name: "",
      kind: "user",
      bindings: [],
      tokens: [],
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

afterEach(() => { cleanup(); asked.length = 0; });

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
