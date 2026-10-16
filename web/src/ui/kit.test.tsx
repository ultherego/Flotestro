import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { BarList, DataTable, Panel, Stat } from "./kit";

/**
 * The kit is where the panel's appearance is decided, so the rules that
 * must not be re-decided by a caller are held here.
 */

afterEach(cleanup);

describe("a measurement", () => {
  it("says unknown rather than drawing a nought", () => {
    render(<Stat label="Hosts" value={null} unit="%" />);
    expect(screen.getByTestId("stat-Hosts")).toHaveTextContent("—");
    expect(screen.queryByText("0")).toBeNull();
    // The unit belongs to a measurement, and there is none.
    expect(screen.queryByText("%")).toBeNull();
  });

  it("keeps a real nought a nought", () => {
    render(<Stat label="Failed" value={0} />);
    expect(screen.getByTestId("stat-Failed")).toHaveTextContent("0");
  });

  it("colours the figure for a state, and never boxes the tile", () => {
    render(<Stat label="Disk" value={94} unit="%" tone="error" />);
    const tile = screen.getByTestId("stat-Disk");
    expect(tile.className).toContain("ui-error");
    // A row of tiles with two of them framed in red stops being a row, so
    // the state is on the figure: the class is on the tile and the
    // stylesheet paints the value, not a border.
    expect(tile.className).not.toContain("border");
  });

  it("drops a delta where there is nothing to compare", () => {
    render(<Stat label="Online" value={null} delta={{ text: "+3", good: true }} />);
    expect(screen.queryByText("+3")).toBeNull();
  });
});

describe("a table", () => {
  const rows = [{ name: "agent-debian", failed: 0 }, { name: "agent-arch", failed: 2 }];
  const columns = [
    { head: "Host", cell: (row: typeof rows[0]) => row.name },
    { head: "Failed", cell: (row: typeof rows[0]) => row.failed, numeric: true },
  ];

  it("draws a row per item and marks the columns of figures", () => {
    const { container } = render(<DataTable columns={columns} rows={rows} keyOf={(row) => row.name} />);
    expect(container.querySelectorAll("tbody tr")).toHaveLength(2);
    expect(container.querySelectorAll("td.ui-numeric")).toHaveLength(2);
  });

  it("says what an empty list means instead of drawing an empty table", () => {
    render(<DataTable columns={columns} rows={[]} keyOf={() => "x"} empty="No host answers." />);
    expect(screen.getByText("No host answers.")).toBeInTheDocument();
    expect(screen.queryByRole("table")).toBeNull();
  });
});

describe("a list of bars", () => {
  it("gives the label, the bar and the number a track each", () => {
    const { container } = render(
      <BarList items={[{ label: "debian", value: 2 }, { label: "arch", value: 1 }]} />,
    );
    // Three cells to a row: the bar cannot run under the words, which is
    // what made the fleet composition unreadable.
    const row = container.querySelector(".ui-barlist-row");
    expect(row?.children).toHaveLength(3);
    expect(container.querySelectorAll(".ui-bar-fill")).toHaveLength(2);
  });
});

describe("a panel", () => {
  it("draws its head only when it has one", () => {
    const { container, rerender } = render(<Panel>body</Panel>);
    expect(container.querySelector(".ui-panel-head")).toBeNull();
    rerender(<Panel title="Hosts">body</Panel>);
    expect(container.querySelector(".ui-panel-title")).toHaveTextContent("Hosts");
  });
});
