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
 * by its corner and made wider on the grid.
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

function draw(notices?: ReactNode, fixed = false) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}><MemoryRouter><ToastProvider>{children}</ToastProvider></MemoryRouter></QueryClientProvider>
  );
  return render(
    <Board
      fixed={fixed}
      screen="test"
      catalogue={CATALOGUE}
      notices={notices}
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

  it("makes a container wider, and only wider, when its corner is dragged", async () => {
    draw();
    await waitFor(() => expect(screen.getByTestId("arrange")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("arrange"));
    const corner = screen.getByTestId("corner-first");
    // A column is a twelfth of 1200 less the gaps; two columns to the
    // right make a container of 8; how tall it is, is what is in it.
    const column = (1200 - 20 * 11) / 12;
    point(corner, "pointerdown", 600, 300);
    point(screen.getByTestId("board"), "pointermove", 600 + 2 * column, 300 + 80);
    point(screen.getByTestId("board"), "pointerup", 600 + 2 * column, 300 + 80);
    expect(screen.getByTestId("held-first")).toHaveTextContent("8");
  });

  it("on a fixed board, a container is exactly the rows its bottom edge was pulled to", async () => {
    draw(undefined, true);
    await waitFor(() => expect(screen.getByTestId("arrange")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("arrange"));
    expect(screen.getByTestId("held-first").style.gridRow).toBe("1 / span 2");
    // A row is 76 and the gap 20: three rows down is 288 pixels.
    point(screen.getByTestId("low-first"), "pointerdown", 600, 300);
    point(screen.getByTestId("board"), "pointermove", 600, 300 + 3 * 96);
    point(screen.getByTestId("board"), "pointerup", 600, 300 + 3 * 96);
    expect(screen.getByTestId("held-first").style.gridRow).toBe("1 / span 5");
    expect(screen.getByTestId("held-first").style.gridColumn).toBe("1 / span 6");
  });

  it("on a fixed board, a container can be put in any column and under any other", async () => {
    draw(undefined, true);
    await waitFor(() => expect(screen.getByTestId("arrange")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("arrange"));
    const first = screen.getByTestId("held-first");
    point(screen.getByTestId("grip-first"), "pointerdown", 100, 100);
    // Two columns right and three rows down.
    point(screen.getByTestId("board"), "pointermove", 100 + 2 * 101.7, 100 + 3 * 96);
    point(screen.getByTestId("board"), "pointerup", 100 + 2 * 101.7, 100 + 3 * 96);
    expect(first.style.gridColumn).toBe("3 / span 6");
    expect(first.style.gridRow).toBe("4 / span 2");
  });

  it("on a page, a container is moved into the place of the one it is dragged over", async () => {
    draw();
    await waitFor(() => expect(screen.getByTestId("arrange")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("arrange"));
    const order = () => [...document.querySelectorAll("[data-held-key]")].map((one) => one.getAttribute("data-held-key"));
    expect(order().slice(0, 2)).toEqual(["first", "second"]);
    document.elementFromPoint = () => screen.getByTestId("held-second");
    point(screen.getByTestId("grip-first"), "pointerdown", 100, 100);
    point(screen.getByTestId("board"), "pointermove", 900, 100);
    point(screen.getByTestId("board"), "pointerup", 900, 100);
    expect(order().slice(0, 2)).toEqual(["second", "first"]);
  });

  it("widens and narrows a container by its arrows, to the column", async () => {
    draw();
    await waitFor(() => expect(screen.getByTestId("arrange")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("arrange"));
    const before = Number(screen.getByTestId("width-first").textContent?.split("/")[0]);
    fireEvent.click(screen.getByTestId("wider-first"));
    expect(screen.getByTestId("width-first")).toHaveTextContent(`${before + 1}/12`);
    fireEvent.click(screen.getByTestId("narrower-first"));
    fireEvent.click(screen.getByTestId("narrower-first"));
    expect(screen.getByTestId("width-first")).toHaveTextContent(`${before - 1}/12`);
  });

  it("stores an arrangement with one press and asks for nothing first", async () => {
    draw();
    await waitFor(() => expect(screen.getByTestId("arrange")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("arrange"));
    // Moving a container is cosmetic and is undone by the same control
    // that did it. Made to write a sentence first, an operator writes
    // "aaaaaaaa", and a trail of those is worse than a trail of none -
    // who arranged it, when, and the revision are recorded either way.
    expect(screen.queryByTestId("board-reason")).toBeNull();
    expect(screen.getByTestId("board-save")).toBeEnabled();
  });

  it("sends the revision it read, so two administrators cannot overwrite each other silently", async () => {
    draw();
    await waitFor(() => expect(screen.getByTestId("arrange")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("arrange"));
    fireEvent.click(screen.getByTestId("board-save"));
    await waitFor(() => expect(sent.body).toBeDefined());
    expect(sent.body?.revision).toBe(3);
  });

  it("remembers a container taken off the screen as taken off, not as forgotten", async () => {
    draw();
    await waitFor(() => expect(screen.getByTestId("arrange")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("arrange"));
    fireEvent.click(screen.getAllByTitle("Take this container off the screen")[0]);
    expect(screen.queryByTestId("held-first")).toBeNull();
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

describe("what has to be read first", () => {
  it("stands above the grid and is no part of it", async () => {
    draw(<p>the host returned no configuration</p>);
    const said = await screen.findByText("the host returned no configuration");
    expect(said).toBeInTheDocument();
    // A cell is a whole row tall whatever it holds, so a notice in one
    // opens the screen with a band of empty floor under it - and an
    // arrangement that hid that container would hide the warning.
    expect(screen.getByTestId("board").contains(said)).toBe(false);
  });

  it("draws nothing of its own where there is no notice", async () => {
    draw();
    await screen.findByTestId("board");
    expect(screen.queryByText("the host returned no configuration")).toBeNull();
  });
});

describe("a board with no holes in it", () => {
  it("lifts a container into the gap its short neighbour left", () => {
    // Two in a row, one tall and one short, and a third below the short
    // one. Settling alone leaves the third starting where the TALL one
    // ends, so half a row is empty floor - which is what made a board
    // read as a heap of cards rather than one board.
    const placed = settle([
      { key: "tall", x: 0, y: 0, width: 6, height: 6 },
      { key: "short", x: 6, y: 0, width: 6, height: 2 },
      { key: "under", x: 6, y: 6, width: 6, height: 2 },
    ], "");
    expect(placed.find((one) => one.key === "under")?.y).toBe(2);
  });

  it("leaves a container where it cannot rise", () => {
    const placed = settle([
      { key: "top", x: 0, y: 0, width: 12, height: 2 },
      { key: "below", x: 0, y: 2, width: 12, height: 2 },
    ], "");
    expect(placed.find((one) => one.key === "below")?.y).toBe(2);
  });
});

describe("what the hand is holding", () => {
  it("keeps the cell it was put on rather than rising to the top", () => {
    // The lift that closes holes is settled first for the held container,
    // when nothing is placed above it yet - so without this it rose to
    // row nought and the board threw whatever you grabbed to the top.
    const placed = settle([
      { key: "top", x: 0, y: 0, width: 12, height: 2 },
      { key: "held", x: 0, y: 6, width: 6, height: 2 },
    ], "held");
    expect(placed.find((one) => one.key === "held")?.y).toBe(6);
  });

  it("still lifts the ones it is not holding", () => {
    const placed = settle([
      { key: "held", x: 0, y: 0, width: 6, height: 6 },
      { key: "other", x: 6, y: 9, width: 6, height: 2 },
    ], "held");
    expect(placed.find((one) => one.key === "other")?.y).toBe(0);
  });
});
