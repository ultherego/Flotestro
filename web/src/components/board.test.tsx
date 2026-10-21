import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { boardToDraw, isPlaced, placeAll, type BoardEntry } from "./board";

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

/**
 * There is one board, `next/Board.tsx`, with its own row height. This file is the model
 * it draws from; a second component here, with a row height of its own, was left behind
 * when the panel was written again, and measured 80 pixels where the board measures 76.
 */
describe("the model file", () => {
  it("holds no component and no row height of its own", () => {
    const source = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "board.tsx"), "utf8");
    expect(source).not.toMatch(/export function Board\b/);
    expect(source).not.toMatch(/BOARD_ROW/);
  });
});
