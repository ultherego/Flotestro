import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { Masonry, columnsFor } from "./masonry";

/**
 * The rule the board rests on: importance reads across. CSS columns fill one
 * column to the bottom before starting the next, which puts the second most
 * important tile underneath the first instead of beside it.
 */

describe("Masonry", () => {
  it("deals the tiles across the columns, not down them", () => {
    // Two columns at this width, so the deal is first/third left and
    // second/fourth right.
    const { container } = render(
      <Masonry min={360}>
        {["first", "second", "third", "fourth"].map((name) => <p key={name}>{name}</p>)}
      </Masonry>,
    );
    const columns = Array.from(container.querySelectorAll(".masonry-column"));
    expect(columns).toHaveLength(2);
    // The first two tiles are in different columns: side by side, not stacked.
    expect(columns[0].textContent).toContain("first");
    expect(columns[1].textContent).toContain("second");
    // And the next row carries on from the left.
    expect(columns[0].textContent).toContain("third");
    expect(columns[1].textContent).toContain("fourth");
  });

  it("keeps every tile exactly once", () => {
    const { container } = render(
      <Masonry min={360}>{Array.from({ length: 13 }, (_, i) => <p key={i}>tile {i}</p>)}</Masonry>,
    );
    expect(container.querySelectorAll("p")).toHaveLength(13);
  });
});

describe("columnsFor", () => {
  it("gives a wide screen four columns and a narrow one a single column", () => {
    expect(columnsFor(2200, 420)).toBe(4);
    expect(columnsFor(1600, 420)).toBe(3);
    expect(columnsFor(1100, 420)).toBe(1);
    expect(columnsFor(600, 420)).toBe(1);
  });

  it("never asks for a column that cannot exist", () => {
    expect(columnsFor(0, 420)).toBe(1);
    expect(columnsFor(-1, 420)).toBe(1);
  });
});
