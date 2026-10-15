import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { Board, settle } from "./Board";
import { ToastProvider } from "../components/Toast";
import { Card } from "./kit";

/**
 * Arranging a screen is a change that reaches everybody who opens it, so
 * what is held here is that it behaves like one: it carries a reason, it
 * carries the revision it was read at, and a container taken off the
 * screen is remembered as taken off rather than forgotten.
 *
 * And the part the owner asked for by name: a container is taken hold of
 * by its corner and made wider or taller on the grid.
 */

const stored: { board: Record<string, unknown> } = { board: { widgets: [], present: false, revision: 3 } };
const sent: { body?: Record<string, unknown> } = {};

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      get: (path: string) => path.startsWith("/api/v1/settings/layout")
        ? Promise.resolve(stored.board)
        : Promise.reject(new actual.ApiError(404, "not_found", "no")),
      put: (_path: string, body: Record<string, unknown>) => {
        sent.body = body;
        return Promise.resolve(stored.board);
      },
      del: () => Promise.resolve(undefined),
    },
  };
});

const CATALOGUE = [
  { key: "first", title: "First", width: 6, height: 2 },
  { key: "second", title: "Second", width: 6, height: 2 },
];

function draw() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter></QueryClientProvider>
  );
  return render(
    <Board
      screen="test"
      catalogue={CATALOGUE}
      drawn={{ first: <Card title="First">a</Card>, second: <Card title="Second">b</Card> }}
    />,
    { wrapper },
  );
}

/* jsdom has no PointerEvent, and fireEvent's own pointer events arrive
   without coordinates - which is how this test first read every drag as a
   move of NaN columns. A MouseEvent under the pointer event's name carries
   them, and React reads the native event. */
function point(element: Element, type: string, clientX: number, clientY: number) {
  fireEvent(element, new MouseEvent(type, { bubbles: true, cancelable: true, clientX, clientY }));
}

beforeEach(() => {
  stored.board = { widgets: [], present: false, revision: 3 };
  sent.body = undefined;
  // The grid's own box is what a column's width is read from.
  Object.defineProperty(HTMLElement.prototype, "getBoundingClientRect", {
    configurable: true,
    value: () => ({ width: 1200, height: 800, top: 0, left: 0, right: 1200, bottom: 800, x: 0, y: 0, toJSON: () => "" }),
  });
});
afterEach(cleanup);

describe("settling the grid", () => {
  const at = (key: string, x: number, y: number, width: number, height: number) => ({ key, x, y, width, height });

  it("leaves what the hand is holding where it was put", () => {
    const after = settle([at("held", 0, 0, 6, 3), at("other", 3, 0, 6, 2)], "held");
    expect(after.find((one) => one.key === "held")).toMatchObject({ x: 0, y: 0 });
  });

  it("moves what it landed on down, rather than letting one cover the other", () => {
    const after = settle([at("held", 0, 0, 6, 3), at("other", 3, 0, 6, 2)], "held");
    expect(after.find((one) => one.key === "other")?.y).toBe(3);
  });

  it("leaves a neighbour beside it alone", () => {
    const after = settle([at("held", 0, 0, 6, 3), at("other", 6, 0, 6, 2)], "held");
    expect(after.find((one) => one.key === "other")).toMatchObject({ x: 6, y: 0 });
  });

  it("keeps the order of the record, whatever moved", () => {
    const after = settle([at("a", 0, 0, 6, 2), at("b", 0, 0, 6, 2), at("c", 0, 4, 6, 2)], "b");
    expect(after.map((one) => one.key)).toEqual(["a", "b", "c"]);
  });
});

describe("arranging a screen", () => {
  it("draws what the catalogue names until somebody arranges it", async () => {
    draw();
    await waitFor(() => expect(screen.getByText("First")).toBeInTheDocument());
    expect(screen.getByText("Second")).toBeInTheDocument();
    // Nothing is held until the arrange mode is entered.
    expect(screen.queryByTestId("corner-first")).toBeNull();
  });

  it("gives every container a grip and a corner once the mode is entered", async () => {
    draw();
    await waitFor(() => expect(screen.getByTestId("arrange")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("arrange"));
    expect(screen.getByTestId("corner-first")).toBeInTheDocument();
    expect(screen.getByTestId("held-first")).toBeInTheDocument();
  });

  it("makes a container wider and taller when its corner is dragged", async () => {
    draw();
    await waitFor(() => expect(screen.getByTestId("arrange")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("arrange"));
    const corner = screen.getByTestId("corner-first");
    // A column is a twelfth of 1200 less the gaps; two columns to the
    // right and one row down makes a container of 8 by 3.
    const column = (1200 - 20 * 11) / 12;
    point(corner, "pointerdown", 600, 300);
    point(screen.getByTestId("board"), "pointermove", 600 + 2 * column, 300 + 80);
    point(screen.getByTestId("board"), "pointerup", 600 + 2 * column, 300 + 80);
    expect(screen.getByTestId("held-first")).toHaveTextContent("8×3");
  });

  it("will not store an arrangement without a reason for the trail", async () => {
    draw();
    await waitFor(() => expect(screen.getByTestId("arrange")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("arrange"));
    expect(screen.getByTestId("board-save")).toBeDisabled();
    fireEvent.change(screen.getByTestId("board-reason"), { target: { value: "short" } });
    expect(screen.getByTestId("board-save")).toBeDisabled();
    fireEvent.change(screen.getByTestId("board-reason"), { target: { value: "the failures belong at the top" } });
    expect(screen.getByTestId("board-save")).toBeEnabled();
  });

  it("sends the revision it read, so two administrators cannot overwrite each other silently", async () => {
    draw();
    await waitFor(() => expect(screen.getByTestId("arrange")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("arrange"));
    fireEvent.change(screen.getByTestId("board-reason"), { target: { value: "the failures belong at the top" } });
    fireEvent.click(screen.getByTestId("board-save"));
    await waitFor(() => expect(sent.body).toBeDefined());
    expect(sent.body?.revision).toBe(3);
    expect(sent.body?.reason).toBe("the failures belong at the top");
  });

  it("remembers a container taken off the screen as taken off, not as forgotten", async () => {
    draw();
    await waitFor(() => expect(screen.getByTestId("arrange")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("arrange"));
    fireEvent.click(screen.getAllByTitle("Take this container off the screen")[0]);
    expect(screen.queryByTestId("held-first")).toBeNull();
    fireEvent.change(screen.getByTestId("board-reason"), { target: { value: "the first one is not read here" } });
    fireEvent.click(screen.getByTestId("board-save"));
    await waitFor(() => expect(sent.body).toBeDefined());
    // Hidden, and still in the record: "somebody removed this" and "this
    // did not exist when the screen was arranged" stay two answers.
    const widgets = sent.body?.widgets as { key: string; hidden?: boolean }[];
    expect(widgets.find((one) => one.key === "first")?.hidden).toBe(true);
  });

  it("offers a container that is off the screen back", async () => {
    stored.board = { widgets: [{ key: "first", width: 6, hidden: true }, { key: "second", width: 6 }], present: true, revision: 1 };
    draw();
    await waitFor(() => expect(screen.getByTestId("arrange")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("arrange"));
    const add = screen.getByTestId("board-add");
    expect(add).toBeInTheDocument();
    fireEvent.change(add, { target: { value: "first" } });
    expect(screen.getByTestId("held-first")).toBeInTheDocument();
  });
});
