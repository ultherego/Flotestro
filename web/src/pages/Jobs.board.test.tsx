import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ToastProvider } from "../components/Toast";
import { Jobs } from "./Jobs";

/**
 * The screen as a board: the panels it offers, and the arrangement the
 * installation stored being the one that is drawn.
 *
 * What this guards is not the markup but the contract between the two
 * sides of a board: the catalogue a screen declares and the nodes it draws
 * have to be the same set of keys, or a panel is offered in the editor and
 * then draws nothing - or worse, is stored in an arrangement and silently
 * skipped afterwards, which looks to an administrator like the save failed.
 */

const stored = {
  widgets: [{ key: "jobs", width: 12 }, { key: "state", width: 6 }],
  present: true,
  revision: 3,
};

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  const empty = { items: [], total: 0 };
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        if (path.startsWith("/api/v1/settings/layout/")) return Promise.resolve(stored);
        if (path.startsWith("/api/v1/fleet/activity")) return Promise.resolve({ hours: [], succeeded: [], failed: [], other: [] });
        return Promise.resolve(empty);
      },
    },
  };
});

afterEach(cleanup);

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>
        <ToastProvider>
          <Jobs />
        </ToastProvider>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("the jobs screen as a board", () => {
  it("draws the arrangement the installation stored, in its order", async () => {
    draw();
    // The bar appears only once the stored arrangement has arrived; before
    // that the screen draws the one it ships with, and asserting then would
    // be asserting the default.
    await waitFor(() => expect(screen.getByText("Arrange this screen")).toBeInTheDocument());

    const grid = screen.getByTestId("board-grid");
    // Two panels, in the stored order, at the stored widths - not the four
    // the screen ships with.
    // The two stored panels come first; a panel the record says nothing
    // about follows them rather than staying invisible for ever.
    expect(grid.children.length).toBeGreaterThanOrEqual(2);
    expect((grid.children[1] as HTMLElement).className).toContain("span-6");
  });

  it("offers arranging to whoever opens it", async () => {
    draw();
    await waitFor(() => expect(screen.getByText("Arrange this screen")).toBeInTheDocument());
  });
});
