import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import type { ReactElement } from "react";
import { Band, Bars, Kpi, Pill, Table, pageNumbers } from "./kit";

/**
 * The kit decides what the panel looks like, so the rules a screen must
 * not be able to re-decide are held here rather than in a review.
 */

afterEach(cleanup);

const draw = (element: ReactElement) => render(<MemoryRouter>{element}</MemoryRouter>);

describe("a headline number", () => {
  it("says unknown rather than drawing a nought", () => {
    draw(<Kpi label="Hosts" value={null} unit="%" />);
    const tile = screen.getByTestId("kpi-Hosts");
    expect(tile).toHaveTextContent("—");
    expect(within(tile).queryByText("0")).toBeNull();
    // The unit belongs to a measurement, and there is none.
    expect(within(tile).queryByText("%")).toBeNull();
    expect(tile.dataset.state).toBe("unknown");
  });

  it("keeps a real nought a nought", () => {
    draw(<Kpi label="Failed" value={0} tone="ok" />);
    expect(screen.getByTestId("kpi-Failed")).toHaveTextContent("0");
  });

  it("carries the state as a class and never as a frame of its own", () => {
    draw(<Kpi label="Offline" value={3} tone="error" />);
    const tile = screen.getByTestId("kpi-Offline");
    // The stylesheet paints the figure and its mark from the tone; a tile
    // that boxed itself in red would break the row it stands in.
    expect(tile.className).toContain("fl-error");
    expect(tile.getAttribute("style")).toBeNull();
  });

  it("drops a delta where there is nothing to compare", () => {
    draw(<Kpi label="Online" value={null} delta={{ text: "+3", good: true }} />);
    expect(screen.queryByText("+3")).toBeNull();
  });

  it("is a link as a whole when it leads somewhere", () => {
    draw(<Kpi label="Hosts" value={4} to="/next/hosts" />);
    expect(screen.getByRole("link")).toHaveAttribute("href", "/next/hosts");
  });
});

describe("a bar list", () => {
  it("gives the bar a track of its own beside the label, never under it", () => {
    const { container } = draw(<Bars items={[{ label: "debian", value: 2 }, { label: "arch", value: 1 }]} />);
    const rows = container.querySelectorAll(".fl-bars-row");
    expect(rows).toHaveLength(2);
    // Three cells in one row: the words, the bar, the number. Layered, the
    // text sat on the colour - which is the fault the rewrite began with.
    const first = rows[0];
    expect(first.querySelector("dt")).toHaveTextContent("debian");
    expect(first.querySelector("dd .fl-bar-fill")).not.toBeNull();
    expect(first.querySelector(".fl-bars-count")).toHaveTextContent("2");
  });

  it("draws the longest bar full and the rest in proportion", () => {
    const { container } = draw(<Bars items={[{ label: "a", value: 4 }, { label: "b", value: 1 }]} />);
    const fills = container.querySelectorAll<HTMLElement>(".fl-bar-fill");
    expect(fills[0].style.width).toBe("100%");
    expect(fills[1].style.width).toBe("25%");
  });
});

describe("a band of shares", () => {
  it("puts what is at zero under the band rather than drawing a sliver", () => {
    const { container } = draw(<Band segments={[
      { label: "Online", value: 4, tone: "ok" },
      { label: "Offline", value: 0, tone: "error" },
    ]} />);
    expect(container.querySelectorAll(".fl-band-seg")).toHaveLength(1);
    expect(container.querySelector(".fl-quiet-row")).toHaveTextContent("Offline");
  });

  it("says a count nobody took was not taken, and never calls it nought", () => {
    const { container } = draw(<Band segments={[
      { label: "Online", value: 4, tone: "ok" },
      { label: "Unknown", tone: "unknown" },
    ]} />);
    const quiet = container.querySelector(".fl-quiet-row");
    expect(quiet).toHaveTextContent("—");
    expect(quiet?.textContent).not.toContain("0");
  });

  it("shares the width by the counts", () => {
    const { container } = draw(<Band segments={[
      { label: "Online", value: 3, tone: "ok" },
      { label: "Offline", value: 1, tone: "error" },
    ]} />);
    const segments = container.querySelectorAll<HTMLElement>(".fl-band-seg");
    expect(segments[0].style.getPropertyValue("--fl-share")).toBe("0.75");
    expect(segments[1].style.getPropertyValue("--fl-share")).toBe("0.25");
  });
});

describe("a pill", () => {
  it("wears the tone it is given and nothing when it is given none", () => {
    const { container } = draw(<><Pill tone="warn">waiting</Pill><Pill>plain</Pill></>);
    const pills = container.querySelectorAll(".fl-pill");
    expect(pills[0].className).toContain("fl-warn");
    expect(pills[1].className).toBe("fl-pill");
  });
});

describe("the table", () => {
  it("says what an empty list means instead of drawing a head over nothing", () => {
    draw(<Table rows={[]} keyOf={(row: { id: string }) => row.id} empty="No host matches this."
                columns={[{ key: "a", head: "A", cell: () => null }]} />);
    expect(screen.getByText("No host matches this.")).toBeInTheDocument();
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("marks the columns that are numbers and the ones a narrow screen drops", () => {
    const { container } = draw(
      <Table
        rows={[{ id: "1", n: 7 }]}
        keyOf={(row) => row.id}
        columns={[
          { key: "n", head: "Count", num: true, cell: (row) => row.n },
          { key: "x", head: "Extra", minor: true, cell: () => "x" },
        ]}
      />,
    );
    const heads = container.querySelectorAll("th");
    expect(heads[0].className).toContain("fl-num");
    expect(heads[1].className).toContain("fl-minor");
    expect(container.querySelectorAll("td")[0].className).toContain("fl-num");
  });
});

describe("the pager", () => {
  it("names the first, the last and the ones around, with a gap for the rest", () => {
    expect(pageNumbers(1, 3)).toEqual([1, 2, 3]);
    expect(pageNumbers(10, 40)).toEqual([1, "gap", 8, 9, 10, 11, 12, "gap", 40]);
  });
});
