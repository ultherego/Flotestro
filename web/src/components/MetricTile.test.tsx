import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MetricTile } from "./MetricTile";
import { SeverityBar } from "./SeverityBar";

/**
 * The two rules a tile is most tempted to break.
 */

afterEach(cleanup);

describe("a metric tile", () => {
  it("says unknown instead of drawing a zero", () => {
    render(<MetricTile label="Available memory" value={null} unit="MB" />);

    expect(screen.queryByText("0"), "a value nobody knows was drawn as zero").not.toBeInTheDocument();
    expect(screen.getByText("—")).toBeInTheDocument();
    // The unit belongs to a measurement; there is none.
    expect(screen.queryByText("MB")).not.toBeInTheDocument();
    expect(screen.getByTestId("metric-Available memory")).toHaveAttribute("data-state", "unknown");
  });

  it("keeps a real zero a zero", () => {
    render(<MetricTile label="Failed units" value={0} />);

    expect(screen.getByText("0")).toBeInTheDocument();
    expect(screen.getByTestId("metric-Failed units")).toHaveAttribute("data-state", "none");
  });

  it("carries a state as a mark, not as a filled tile", () => {
    const { container } = render(<MetricTile label="Disk" value={94} unit="%" state="error" />);

    const tile = screen.getByTestId("metric-Disk");
    expect(tile).toHaveAttribute("data-state", "error");
    expect(tile.className).toContain("metric-tile-error");
    // The filled tile is the hero's, and a hero carries no state.
    expect(container.querySelector(".metric-tile-hero")).toBeNull();
  });
});

describe("the severity bar", () => {
  it("keeps the block of a severity that is at zero", () => {
    render(<SeverityBar counts={{ critical: 0, warning: 3, info: 0 }} />);

    // "Nothing critical" is an answer, and a row that changes shape cannot
    // be read by position.
    expect(screen.getByTestId("severity-critical")).toBeInTheDocument();
    expect(screen.getByTestId("severity-critical").className).toContain("severity-empty");
    expect(screen.getByTestId("severity-warning").className).not.toContain("severity-empty");
  });

  it("shows unknown only where the caller counts it", () => {
    const { rerender } = render(<SeverityBar counts={{ critical: 1, warning: 0, info: 0 }} />);
    expect(screen.queryByTestId("severity-unknown")).not.toBeInTheDocument();

    rerender(<SeverityBar counts={{ critical: 1, warning: 0, info: 0, unknown: 7 }} />);
    expect(screen.getByTestId("severity-unknown")).toHaveTextContent("7");
  });
});

describe("a tile in a widget grid", () => {
  it("takes the columns it was given, because a grid child with none takes one", () => {
    render(<MetricTile label="Disk used" value={41} unit="%" span={4} />);
    expect(screen.getByTestId("metric-Disk used").className).toContain("span-4");
  });

  it("stands alone without a span, for a tile that is not in a grid", () => {
    render(<MetricTile label="Memory" value="16 GiB" />);
    expect(screen.getByTestId("metric-Memory").className).not.toMatch(/span-/);
  });
});
