import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import type { ReactElement } from "react";
import { Band, Bars, Card, Chart, Find, Kpi, Needs, Pie, Pill, Screen, Squares, Table, Tile, Toolbar, pageNumbers } from "./kit";

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

describe("a whole divided", () => {
  it("draws a slice for what nobody has heard from, and the total inside", () => {
    draw(<Pie
      testId="condition"
      total={10}
      label="hosts"
      slices={[
        { label: "Online", value: 6, tone: "ok" },
        { label: "Offline", value: 1, tone: "error" },
        { label: "Unknown", value: 3, tone: "unknown" },
      ]}
    />);
    const pie = screen.getByTestId("condition");
    // Three states were counted, so three arcs are drawn - the unknown
    // among them. A ring that dropped it would read as a fleet of seven.
    expect(pie.querySelectorAll(".fl-pie-slice")).toHaveLength(3);
    expect(pie.querySelector(".fl-pie-total")).toHaveTextContent("10");
    expect(within(pie).getByText("Unknown")).toBeInTheDocument();
  });

  it("leaves the ring empty rather than drawing a whole of nothing", () => {
    draw(<Pie testId="empty" slices={[{ label: "Online", value: 0, tone: "ok" }]} />);
    const pie = screen.getByTestId("empty");
    expect(pie.querySelectorAll(".fl-pie-slice")).toHaveLength(0);
    expect(pie.querySelector(".fl-pie-total")).toHaveTextContent("—");
  });
});

describe("a chart", () => {
  const labels = ["00", "01", "02"];
  const series = [{ name: "Succeeded", tone: "ok" as const, values: [1, 5, 2] }];

  it("answers the pointer with a reading, and keeps it out of the drawing", () => {
    draw(<Chart testId="ops" labels={labels} series={series} everyLabel={1} />);
    const hit = screen.getByTestId("chart-hit");
    // jsdom draws nothing, so the pane has no width of its own; the
    // reading is still asked for, which is what this guards.
    hit.getBoundingClientRect = () => ({ left: 0, width: 600, top: 0, height: 160, right: 600, bottom: 160, x: 0, y: 0, toJSON: () => ({}) });
    fireEvent(hit, new MouseEvent("mousemove", { bubbles: true, clientX: 300 }));
    const read = screen.getByTestId("chart-read");
    expect(read).toHaveTextContent("01");
    expect(read).toHaveTextContent("5");
    // The reading lives in the chart's header, never over the bars.
    expect(screen.getByTestId("ops").querySelector(".fl-chart-plot .fl-chart-read")).toBeNull();
  });
});

describe("a fleet", () => {
  it("is one square per host, and the tally under it", () => {
    draw(<Squares
      testId="fleet"
      items={[
        { key: "a", tone: "ok" },
        { key: "b", tone: "unknown" },
      ]}
      tally={[{ label: "online", value: 1, tone: "ok" }]}
    />);
    expect(screen.getByTestId("fleet").querySelectorAll(".fl-square")).toHaveLength(2);
    expect(screen.getByTestId("fleet")).toHaveTextContent("online");
  });

  it("lets one tile say it has gone quiet while its neighbours work", () => {
    draw(<Tile testId="host-a" name="web-01" silent="No answer since 09:12"
               figures={[{ label: "CPU", value: null }]} />);
    const tile = screen.getByTestId("host-a");
    expect(tile.className).toContain("fl-tile-mute");
    expect(tile).toHaveTextContent("No answer since 09:12");
    // What it could not measure is a dash, never a nought.
    expect(tile.querySelector(".fl-tile-fig-value")).toHaveTextContent("—");
  });
});

describe("what needs somebody", () => {
  it("says a count nobody could take was not counted", () => {
    draw(<Needs items={[{ label: "Security findings", tone: "error" }]} />);
    const row = screen.getByText("Security findings").closest(".fl-needs-row");
    expect(row).toHaveTextContent("—");
    expect(row).toHaveTextContent("not counted");
  });
});

describe("a card holding a list", () => {
  it("takes the toolbar out of the part that scrolls", () => {
    draw(
      <Card title="Campaigns" flush>
        <Toolbar><Find value="" onChange={() => {}} placeholder="Requested by" /></Toolbar>
        <p>rows</p>
      </Card>,
    );
    const card = document.querySelector(".fl-card") as HTMLElement;
    // The bar that steers the list stands outside the body. Inside it,
    // the search and the filters scrolled away with the rows they
    // govern, and the table's head stuck at the wrong height.
    expect(card.querySelector(".fl-card-bar .fl-toolbar")).not.toBeNull();
    expect(card.querySelector(".fl-card-body .fl-toolbar")).toBeNull();
    expect(card.querySelector(".fl-card-body")).toHaveTextContent("rows");
  });

  it("draws a note even where there is no title above it", () => {
    draw(<Card note="Counted on the last report."><p>body</p></Card>);
    expect(document.querySelector(".fl-card-note")).toHaveTextContent("Counted on the last report.");
  });
});

describe("a screen that is filled in rather than scanned", () => {
  it("keeps a measure, so a 4k window does not stretch a form across the room", () => {
    draw(<Screen title="Settings" measure><p>fields</p></Screen>);
    const measured = document.querySelector(".fl-measure");
    expect(measured).not.toBeNull();
    expect(measured).toHaveTextContent("fields");
  });

  it("takes the whole window where it is a board", () => {
    draw(<Screen title="Hosts"><p>tiles</p></Screen>);
    expect(document.querySelector(".fl-measure")).toBeNull();
  });
});
