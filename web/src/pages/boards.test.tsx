import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ToastProvider } from "../components/Toast";
import { Tags } from "./Tags";
import { Policies } from "./Policies";
import { Reads } from "./Reads";

/**
 * The screens that were put on a board, drawn against an arrangement that
 * is not the one they ship with.
 *
 * One test per screen would be one test per commit and no more truth; what
 * is worth holding is the property all of them share. A board has two
 * halves - the catalogue a screen offers and the nodes it can draw - and
 * when they drift apart nothing fails loudly: a panel is offered in the
 * editor, stored in an arrangement, and then silently skipped, which to an
 * administrator looks like the save did not work. So each screen here is
 * handed an arrangement of its own and has to produce exactly it.
 */

const layouts: Record<string, { key: string; width: number }[]> = {
  tags: [{ key: "by_key", width: 5 }, { key: "catalogue", width: 7 }],
  policies: [{ key: "list", width: 8 }],
  reads: [{ key: "by_operation", width: 4 }, { key: "hosts_by_state", width: 8 }],
};

let screenAsked = "";

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => {
        const layout = path.match(/^\/api\/v1\/settings\/layout\/([a-z_]+)/);
        if (layout) {
          screenAsked = layout[1];
          return Promise.resolve({ widgets: layouts[layout[1]] ?? [], present: true, revision: 1 });
        }
        if (path.startsWith("/api/v1/whoami")) return Promise.resolve({ permissions: [], roles: [] });
        return Promise.resolve({ items: [], total: 0, policies: [], reads: [] });
      },
    },
  };
});

afterEach(cleanup);

function draw(node: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>
        <ToastProvider>{node}</ToastProvider>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("a screen that was put on a board", () => {
  const cases: { name: string; screen: string; node: React.ReactNode }[] = [
    { name: "Tags", screen: "tags", node: <Tags /> },
    { name: "Policies", screen: "policies", node: <Policies /> },
    { name: "Reads", screen: "reads", node: <Reads /> },
  ];

  for (const one of cases) {
    it(`${one.name} draws the arrangement it was given, not the one it ships with`, async () => {
      draw(one.node);
      await waitFor(() => expect(screen.getByText("Arrange this screen")).toBeInTheDocument());

      // It asked for its own screen, not somebody else's: a copied board
      // that kept the name it was copied from would arrange two screens
      // together and neither of them on purpose.
      expect(screenAsked).toBe(one.screen);

      const grid = screen.getByTestId("board-grid");
      const expected = layouts[one.screen];
      // Every stored panel is on the screen at its stored width, in the
      // order it was stored in - with the panels the record says nothing
      // about placed among them where the catalogue puts them, so a widget
      // an upgrade adds appears instead of staying invisible for ever.
      const widths = Array.from(grid.children).map((child) => (child as HTMLElement).className);
      expect(grid.children.length).toBeGreaterThanOrEqual(expected.length);
      const storedAt = expected.map((widget) => widths.findIndex((name) => name.includes(`ui-col-${widget.width}`)));
      expect(storedAt.every((at) => at !== -1)).toBe(true);
      expect([...storedAt].sort((a, b) => a - b)).toEqual(storedAt);
    });
  }
});
