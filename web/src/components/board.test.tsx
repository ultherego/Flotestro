import { describe, expect, it } from "vitest";
import { boardToDraw, type BoardEntry } from "./board";

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
