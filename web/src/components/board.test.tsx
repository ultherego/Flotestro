import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ToastProvider } from "./Toast";
import { Board } from "./board";
import { boardToDraw, heightStep, widthStep, type BoardEntry } from "./board";

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    api: { ...actual.api, get: () => Promise.resolve({ widgets: [], present: false }) },
  };
});

afterEach(cleanup);

/**
 * Which widgets a screen draws is the installation's answer, and the panel's
 * own order until it gives one. The two rules worth holding: a widget this
 * panel cannot draw is skipped rather than refused, and a screen nobody has
 * arranged is the one the panel ships.
 */

const catalogue: BoardEntry[] = [
  { key: "first", title: "First", width: 12 },
  { key: "second", title: "Second", width: 6 },
];
const known = new Set(["first", "second"]);

describe("boardToDraw", () => {
  it("draws the panel's own arrangement until the installation stores one", () => {
    const own = [{ key: "first", width: 12 }, { key: "second", width: 6 }];
    expect(boardToDraw(undefined, catalogue, known)).toEqual(own);
    expect(boardToDraw({ widgets: [], present: false }, catalogue, known)).toEqual(own);
  });

  it("draws what was stored, in the order and the widths it was stored in", () => {
    const stored = { widgets: [{ key: "second", width: 4 }, { key: "first", width: 8 }], present: true };
    expect(boardToDraw(stored, catalogue, known)).toEqual(stored.widgets);
  });

  /* A record written by a newer panel - one that knows a widget this one
     does not - still has to draw here. The server deliberately does not
     refuse such a key, so the skipping happens on this side. */
  it("skips a widget this panel cannot draw instead of refusing the record", () => {
    const stored = {
      widgets: [{ key: "from_the_future", width: 6 }, { key: "first", width: 6 }],
      present: true,
    };
    expect(boardToDraw(stored, catalogue, known)).toEqual([{ key: "first", width: 6 }]);
  });

  /* A widget whose screen has nothing to draw for it - a card that renders
     nothing on this installation - is not placed, even when the record
     names it. */
  it("leaves out a widget this screen has nothing to draw for", () => {
    const stored = { widgets: [{ key: "first", width: 6 }, { key: "second", width: 6 }], present: true };
    expect(boardToDraw(stored, catalogue, new Set(["first"]))).toEqual([{ key: "first", width: 6 }]);
  });
});

/* ---------------------------------------------------------------------- */
/* Arranging with the hand.                                               */
/* ---------------------------------------------------------------------- */

const three: BoardEntry[] = [
  { key: "first", title: "First", width: 4 },
  { key: "second", title: "Second", width: 4 },
  { key: "third", title: "Third", width: 4 },
];

function drawBoard() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <ToastProvider>
          <Board
            screen="test"
            catalogue={three}
            drawn={{ first: <p>one</p>, second: <p>two</p>, third: <p>three</p> }}
          />
        </ToastProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

async function arrange() {
  const view = drawBoard();
  await waitFor(() => expect(screen.getByText("Arrange this screen")).toBeInTheDocument());
  fireEvent.click(screen.getByText("Arrange this screen"));
  return view;
}

/* The name of each tile, in the order the board draws them. The handle also
   holds the width select, so the name is read from its own element. */
function order() {
  return screen.getAllByTestId("widget-handle").map(
    (handle) => handle.querySelectorAll("span")[1]?.textContent,
  );
}

/* jsdom has no DataTransfer, and the handler only ever writes to it. */
function transfer() {
  return { dataTransfer: { setData: () => undefined, effectAllowed: "" } };
}

describe("arranging a board with the mouse", () => {
  it("lands the tile where it was dropped and shifts the rest along", async () => {
    await arrange();
    expect(order()).toEqual(["First", "Second", "Third"]);
    const tiles = screen.getAllByTestId("board-tile");
    // The first tile is picked up and dropped on the third.
    fireEvent.dragStart(tiles[0], transfer());
    fireEvent.dragOver(tiles[2]);
    fireEvent.drop(tiles[2]);
    // Moved, not swapped: the two it passed keep their order.
    expect(order()).toEqual(["Second", "Third", "First"]);
  });

  it("does nothing when a tile is dropped on itself", async () => {
    await arrange();
    const tiles = screen.getAllByTestId("board-tile");
    fireEvent.dragStart(tiles[1], transfer());
    fireEvent.drop(tiles[1]);
    expect(order()).toEqual(["First", "Second", "Third"]);
  });

  /* A board is mostly empty space, and a tile has to be droppable into it:
     dropped where no tile is, it goes to the end of the order, which is the
     free space at the bottom. */
  it("takes a tile dropped on the empty part of the board", async () => {
    await arrange();
    const tiles = screen.getAllByTestId("board-tile");
    fireEvent.dragStart(tiles[0], transfer());
    fireEvent.dragOver(screen.getByTestId("board-grid"));
    fireEvent.drop(screen.getByTestId("board-grid"));
    expect(order()).toEqual(["Second", "Third", "First"]);
  });

  it("sends a tile to where it was aimed, not to the end, when it lands on another", async () => {
    await arrange();
    const tiles = screen.getAllByTestId("board-tile");
    fireEvent.dragStart(tiles[2], transfer());
    fireEvent.drop(tiles[0]);
    expect(order()).toEqual(["Third", "First", "Second"]);
  });

  /* The hand is not the only way in: a tile has to be movable from the
     keyboard, or the arrangement is closed to anybody not using a mouse. */
  it("moves a tile with the arrow keys as well", async () => {
    await arrange();
    fireEvent.keyDown(screen.getAllByTestId("widget-keys")[0], { key: "ArrowRight" });
    expect(order()).toEqual(["Second", "First", "Third"]);
    fireEvent.keyDown(screen.getAllByTestId("widget-keys")[1], { key: "ArrowLeft" });
    expect(order()).toEqual(["First", "Second", "Third"]);
  });

  it("widens and narrows a tile along the widths the grid has", async () => {
    await arrange();
    const wider = () => screen.getAllByLabelText("Wider")[0];
    expect(screen.getAllByTestId("board-tile")[0].className).toContain("span-4");
    fireEvent.click(wider());
    expect(screen.getAllByTestId("board-tile")[0].className).toContain("span-6");
    fireEvent.click(screen.getAllByLabelText("Narrower")[0]);
    expect(screen.getAllByTestId("board-tile")[0].className).toContain("span-4");
  });

  /* Two short tiles one under another is the thing heights are for: a tile
     that holds little takes one row, and the space a taller neighbour leaves
     beside it is filled rather than left empty. */
  it("makes a tile taller and shorter, a row at a time", async () => {
    await arrange();
    const tile = () => screen.getAllByTestId("board-tile")[0];
    expect(tile().style.gridRow).toBe("span 1");
    fireEvent.click(screen.getAllByLabelText("Taller")[0]);
    expect(tile().style.gridRow).toBe("span 2");
    fireEvent.click(screen.getAllByLabelText("Shorter")[0]);
    expect(tile().style.gridRow).toBe("span 1");
  });

  it("stops at the ends of both ladders instead of going past them", async () => {
    await arrange();
    for (let i = 0; i < 10; i += 1) {
      const shorter = screen.getAllByLabelText("Shorter")[0] as HTMLButtonElement;
      if (!shorter.disabled) fireEvent.click(shorter);
      const narrower = screen.getAllByLabelText("Narrower")[0] as HTMLButtonElement;
      if (!narrower.disabled) fireEvent.click(narrower);
    }
    expect(screen.getAllByTestId("board-tile")[0].className).toContain("span-3");
    expect(screen.getAllByTestId("board-tile")[0].style.gridRow).toBe("span 1");
  });
});

describe("the ladders a tile is resized along", () => {
  it("steps the width between the widths the grid has a class for", () => {
    expect(widthStep(4, 1)).toBe(6);
    expect(widthStep(4, -1)).toBe(3);
    expect(widthStep(3, -1)).toBe(3);
    expect(widthStep(12, 1)).toBe(12);
    // A width from a record this panel has no class for lands on the ladder.
    expect(widthStep(5, 1)).toBe(6);
  });

  it("steps the height between one row and eight", () => {
    expect(heightStep(undefined, 1)).toBe(2);
    expect(heightStep(1, -1)).toBe(1);
    expect(heightStep(8, 1)).toBe(8);
  });
});
