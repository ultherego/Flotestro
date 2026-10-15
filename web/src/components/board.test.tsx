import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import { ToastProvider } from "./Toast";
import { Board } from "./board";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { boardToDraw, heightStep, isPlaced, placeAll, widthStep, type BoardEntry } from "./board";

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
    // The unknown key is skipped. "second" is in the catalogue and absent
    // from the record, so it is treated as a panel that arrived after the
    // arrangement was made and is placed at the end - see below.
    expect(boardToDraw(stored, catalogue, known))
      .toEqual([{ key: "first", width: 6 }, { key: "second", width: 6 }]);
  });

  /* A panel added by an upgrade has to appear. Until 15.10 it did not: the
     screen drew the stored list and nothing else, so every widget this
     product ever adds would have been invisible to every installation that
     had arranged that screen once - and nobody would know to go looking.
     A panel somebody took off carries `hidden` and stays off, which is how
     "removed" and "did not exist yet" stay two different answers. */
  describe("a panel the stored arrangement says nothing about", () => {
    it("lands where the product put it, not at the end", () => {
      // "first" ships before "second" in the catalogue and nothing earlier
      // than it is on the screen, so it goes to the front. At the end it
      // would be buried: a row of headline tiles added above six existing
      // panels would otherwise arrive under the tables at the bottom.
      const stored = { widgets: [{ key: "second", width: 4 }], present: true };
      expect(boardToDraw(stored, catalogue, known))
        .toEqual([{ key: "first", width: 12 }, { key: "second", width: 4 }]);
    });

    it("keeps the order somebody chose around it", () => {
      // The arrangement reversed the two it knows about; the newcomer
      // follows its own catalogue neighbour and leaves that reversal alone.
      const three = [...catalogue, { key: "third", title: "Third", width: 3 }];
      const stored = { widgets: [{ key: "second", width: 4 }, { key: "first", width: 8 }], present: true };
      expect(boardToDraw(stored, three, new Set(["first", "second", "third"])))
        .toEqual([{ key: "second", width: 4 }, { key: "first", width: 8 }, { key: "third", width: 3 }]);
    });

    it("stays away when it was taken off on purpose", () => {
      const stored = {
        widgets: [{ key: "second", width: 4 }, { key: "first", width: 12, hidden: true }],
        present: true,
      };
      expect(boardToDraw(stored, catalogue, known)).toEqual([{ key: "second", width: 4 }]);
    });
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

  it("widens and narrows a tile a column at a time", async () => {
    await arrange();
    const wider = () => screen.getAllByLabelText("Wider")[0];
    expect(screen.getAllByTestId("board-tile")[0].className).toContain("span-4");
    fireEvent.click(wider());
    expect(screen.getAllByTestId("board-tile")[0].className).toContain("span-5");
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
    for (let i = 0; i < 20; i += 1) {
      const shorter = screen.getAllByLabelText("Shorter")[0] as HTMLButtonElement;
      if (!shorter.disabled) fireEvent.click(shorter);
      const narrower = screen.getAllByLabelText("Narrower")[0] as HTMLButtonElement;
      if (!narrower.disabled) fireEvent.click(narrower);
    }
    // One column is the narrowest the grid has a class for.
    expect(screen.getAllByTestId("board-tile")[0].className).toContain("span-1");
    expect(screen.getAllByTestId("board-tile")[0].style.gridRow).toBe("span 1");
  });
});

describe("the ladders a tile is resized along", () => {
  it("steps the width by one column and stops at the edges of the grid", () => {
    // Every column from one to twelve since 15.10: the rows worth building
    // are the uneven ones, so the ladder is the grid itself.
    expect(widthStep(4, 1)).toBe(5);
    expect(widthStep(4, -1)).toBe(3);
    expect(widthStep(1, -1)).toBe(1);
    expect(widthStep(12, 1)).toBe(12);
    expect(widthStep(5, 1)).toBe(6);
  });

  it("steps the height between one row and sixteen", () => {
    expect(heightStep(undefined, 1)).toBe(2);
    expect(heightStep(1, -1)).toBe(1);
    expect(heightStep(16, 1)).toBe(16);
    // Eight used to be the ceiling; a tile holding a list is worth more.
    expect(heightStep(8, 1)).toBe(9);
  });
});

/**
 * The arrange mode has to show what leaving it will show. A renderer without
 * layout cannot see a box take half the room, so the rule is read where it
 * is written.
 */
describe("the arrange mode looks like the screen it is arranging", () => {
  const src = dirname(dirname(fileURLToPath(import.meta.url)));
  const css = readFileSync(join(src, "styles.css"), "utf8");

  it("gives the bar its own height and the widget the rest of the box", () => {
    expect(css).toContain(".widgets.arranged > div > .widget-handle { flex: 0 0 auto; }");
    expect(/\.widgets\.arranged > div > \* \{[^}]*flex: 1 1 auto/.test(css)).toBe(true);
  });
});

/* A panel whose condition is false renders nothing, and `{open && <Card/>}`
   hands the board `false` rather than undefined. Taken for a node it left a
   cell with nothing in it - a hole in the row where a closed form was. */
describe("a panel with nothing to draw", () => {
  it("is left out whether it is undefined, null or false", () => {
    const stored = {
      widgets: [{ key: "first", width: 6 }, { key: "second", width: 6 }],
      present: true,
    };
    for (const nothing of [undefined, null, false]) {
      const known = new Set(Object.keys({ first: <div />, second: nothing }).filter((key) => {
        const node = ({ first: <div />, second: nothing } as Record<string, unknown>)[key];
        return node !== undefined && node !== null && node !== false;
      }));
      expect(boardToDraw(stored, catalogue, known)).toEqual([{ key: "first", width: 6 }]);
    }
  });
});

/* Taking hold of a panel: the grid, the corner and what a first grab does
   to an arrangement that was only ever ordered. */
describe("placing a panel on the grid", () => {
  it("turns an order into places that look the same", () => {
    // Three panels of eight, four and twelve columns: the first two share
    // a row, the third takes the next one.
    const placed = placeAll([
      { key: "a", width: 8, height: 3 },
      { key: "b", width: 4, height: 2 },
      { key: "c", width: 12, height: 2 },
    ]);
    expect(placed.map((one) => [one.x, one.y])).toEqual([[0, 0], [8, 0], [0, 3]]);
  });

  it("leaves an arrangement that already has places alone", () => {
    const widgets = [{ key: "a", width: 6, height: 2, x: 6, y: 4 }];
    expect(isPlaced(widgets)).toBe(true);
    expect(placeAll(widgets)).toEqual(widgets);
  });

  it("knows an ordered arrangement has no places", () => {
    expect(isPlaced([{ key: "a", width: 6 }])).toBe(false);
  });

  it("starts a new row when the one it is on is full", () => {
    const placed = placeAll([
      { key: "a", width: 6 },
      { key: "b", width: 6 },
      { key: "c", width: 6 },
    ]);
    expect(placed.map((one) => one.y)).toEqual([0, 0, 2]);
  });
});
