import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import type { ReactElement } from "react";
import { AreaChart, BarChart, Breakdown, ChartLegend, Meter, StatusBar } from "./widgets";

/** A segment may be a router link, so the widgets render inside a router. */
function draw(element: ReactElement) {
  return render(<MemoryRouter>{element}</MemoryRouter>);
}

afterEach(cleanup);

describe("StatusBar", () => {
  it("shows an undefined count as a dash, because unknown is not zero", () => {
    const { getByRole } = draw(
      <StatusBar segments={[
        { label: "Online", value: 3, tone: "ok" },
        { label: "Unknown", value: undefined, tone: "unknown" },
      ]} />,
    );
    const items = within(getByRole("list")).getAllByRole("listitem");
    expect(items).toHaveLength(2);
    expect(within(items[0]).getByTestId("status-bar-value")).toHaveTextContent("3");
    expect(within(items[1]).getByTestId("status-bar-value")).toHaveTextContent("—");
    expect(items[1]).toHaveClass("unknown");
  });

  it("keeps a zero segment visible and marks it as zero", () => {
    const { getByRole } = draw(
      <StatusBar segments={[
        { label: "Online", value: 5, tone: "ok" },
        { label: "Stale", value: 0, tone: "warn" },
      ]} />,
    );
    const items = within(getByRole("list")).getAllByRole("listitem");
    expect(items[0]).not.toHaveClass("zero");
    expect(items[1]).toHaveClass("zero");
    expect(items[1]).toHaveClass("warn");
    expect(within(items[1]).getByTestId("status-bar-value")).toHaveTextContent("0");
    expect(within(items[1]).getByText("Stale")).toBeInTheDocument();
  });

  it("turns a segment with a destination into a link and leaves the rest plain", () => {
    const { getByRole } = draw(
      <StatusBar segments={[
        { label: "Online", value: 2, tone: "ok", to: "/hosts?connection_state=online" },
        { label: "Offline", value: 1, tone: "error" },
      ]} />,
    );
    const items = within(getByRole("list")).getAllByRole("listitem");
    expect(items[0].tagName).toBe("A");
    expect(items[0]).toHaveAttribute("href", "/hosts?connection_state=online");
    expect(items[1].tagName).toBe("DIV");
    expect(items[1]).not.toHaveAttribute("href");
  });

  it("gives the larger count the larger share", () => {
    const { getByRole } = draw(
      <StatusBar segments={[
        { label: "Online", value: 9, tone: "ok" },
        { label: "Offline", value: 1, tone: "error" },
      ]} />,
    );
    const items = within(getByRole("list")).getAllByRole("listitem");
    const share = (item: HTMLElement) => Number(item.style.getPropertyValue("--share"));
    expect(share(items[0])).toBeGreaterThan(share(items[1]));
    expect(share(items[1])).toBeGreaterThanOrEqual(1);
  });

  it("takes the compact form on request", () => {
    const { getByRole } = draw(<StatusBar compact segments={[{ label: "Online", value: 1, tone: "ok" }]} />);
    expect(getByRole("list")).toHaveClass("status-bar", "compact");
  });
});

describe("BarChart", () => {
  it("draws one rect per non-zero value and none for a zero", () => {
    const { container } = draw(
      <BarChart
        labels={["a", "b", "c"]}
        series={[{ name: "Succeeded", tone: "ok", values: [1, 0, 2] }]}
      />,
    );
    expect(container.querySelectorAll("rect.bar")).toHaveLength(2);
    expect(container.querySelectorAll("rect.bar.ok")).toHaveLength(2);
  });

  it("stacks several series on one bar and lists them in a legend", () => {
    const { container } = draw(
      <BarChart
        labels={["a", "b"]}
        series={[
          { name: "Succeeded", tone: "ok", values: [2, 0] },
          { name: "Failed", tone: "error", values: [1, 3] },
        ]}
      />,
    );
    expect(container.querySelectorAll("rect.bar")).toHaveLength(3);
    expect(container.querySelectorAll("rect.bar.error")).toHaveLength(2);
    const legend = container.querySelectorAll(".chart-legend li");
    expect(legend).toHaveLength(2);
    expect(legend[0]).toHaveTextContent("Succeeded");
    expect(legend[1]).toHaveTextContent("Failed");
  });

  it("has no legend for a single series and draws only every n-th label", () => {
    const { container, queryByRole } = draw(
      <BarChart
        labels={["00", "01", "02", "03", "04", "05"]}
        everyLabel={3}
        series={[{ name: "Succeeded", tone: "ok", values: [1, 1, 1, 1, 1, 1] }]}
      />,
    );
    expect(container.querySelector(".chart-legend")).toBeNull();
    const drawn = [...container.querySelectorAll("svg text")].map((node) => node.textContent);
    expect(drawn).toContain("00");
    expect(drawn).toContain("03");
    expect(drawn).not.toContain("01");
    expect(queryByRole("img")).not.toBeNull();
  });

  it("scales the tallest stacked bar to the top of the axis", () => {
    const { container } = draw(
      <BarChart
        labels={["a", "b"]}
        series={[{ name: "Succeeded", tone: "ok", values: [4, 8] }]}
      />,
    );
    const heights = [...container.querySelectorAll("rect.bar")].map((rect) => Number(rect.getAttribute("height")));
    expect(heights[1]).toBeCloseTo(heights[0] * 2, 5);
  });
});

describe("Breakdown", () => {
  it("draws every fill as its share of the largest value", () => {
    const { container } = draw(
      <Breakdown items={[
        { label: "debian", value: 4 },
        { label: "rhel", value: 2 },
        { label: "arch", value: 0 },
      ]} />,
    );
    const widths = [...container.querySelectorAll(".breakdown-fill")].map((fill) => (fill as HTMLElement).style.width);
    expect(widths).toEqual(["100%", "50%", "0%"]);
    const counts = [...container.querySelectorAll(".breakdown-count")].map((count) => count.textContent);
    expect(counts).toEqual(["4", "2", "0"]);
  });

  it("uses the tone of the row over the tone of the whole", () => {
    const { container } = draw(
      <Breakdown tone="neutral" items={[
        { label: "enabled", value: 3, tone: "ok" },
        { label: "static", value: 1 },
      ]} />,
    );
    const fills = container.querySelectorAll(".breakdown-fill");
    expect(fills[0]).toHaveClass("ok");
    expect(fills[1]).toHaveClass("neutral");
  });

  it("does not divide by zero when every value is zero", () => {
    const { container } = draw(<Breakdown items={[{ label: "none", value: 0 }]} />);
    expect((container.querySelector(".breakdown-fill") as HTMLElement).style.width).toBe("0%");
  });
});

describe("Meter", () => {
  it("fills its share of the maximum and shows the number", () => {
    const { container } = draw(<Meter value={5} max={10} tone="warn" />);
    const fill = container.querySelector(".meter-fill") as HTMLElement;
    expect(fill.style.width).toBe("50%");
    expect(fill).toHaveClass("warn");
    expect(container.querySelector(".meter-value")).toHaveTextContent("5");
  });

  it("stays empty without a maximum and never overflows", () => {
    const { container, rerender } = draw(<Meter value={5} max={0} />);
    expect((container.querySelector(".meter-fill") as HTMLElement).style.width).toBe("0%");
    rerender(<MemoryRouter><Meter value={20} max={10} text="20 of 10" /></MemoryRouter>);
    expect((container.querySelector(".meter-fill") as HTMLElement).style.width).toBe("100%");
    expect(container.querySelector(".meter-value")).toHaveTextContent("20 of 10");
  });
});

/* The chart is 600 by 160 with a left pad of 48 and a bottom pad of 22:
   the y labels stand at x = 42 and the time labels at y = 154. The tests
   sort the texts by those two places, because both share the element. */
const CHART_HEIGHT = 160;
const Y_LABEL_X = "42";
const X_LABEL_Y = String(CHART_HEIGHT - 6);

function yLabels(container: HTMLElement): string[] {
  return [...container.querySelectorAll("svg text")]
    .filter((node) => node.getAttribute("x") === Y_LABEL_X)
    .map((node) => node.textContent ?? "");
}

function xLabels(container: HTMLElement): string[] {
  return [...container.querySelectorAll("svg text")]
    .filter((node) => node.getAttribute("y") === X_LABEL_Y)
    .map((node) => node.textContent ?? "");
}

/** Instants a minute apart, as the agent samples them. */
function minutes(count: number): string[] {
  return Array.from({ length: count }, (_, i) => `2026-09-14T10:${String(i).padStart(2, "0")}:00Z`);
}

const clock = (iso: string) => iso.slice(11, 16);

describe("AreaChart", () => {
  it("draws one line per series and a fill only under the ones that are not lines", () => {
    const { container, getByRole } = draw(
      <AreaChart
        times={minutes(4)}
        series={[
          { name: "1 min", tone: "accent", values: [1, 2, 3, 4] },
          { name: "5 min", tone: "info", values: [2, 2, 2, 2], line: true },
        ]}
      />,
    );
    expect(container.querySelectorAll("path.line")).toHaveLength(2);
    expect(container.querySelectorAll("path.area")).toHaveLength(1);
    expect(container.querySelectorAll("circle")).toHaveLength(0);
    expect(getByRole("img")).toHaveClass("chart");
  });

  it("leaves a gap open where a value is missing instead of bridging it", () => {
    // The first run is one lone point: a dot, because a line needs two.
    // The second run has two points and is drawn as a line of its own.
    const { container } = draw(
      <AreaChart times={minutes(4)} series={[{ name: "CPU", tone: "accent", values: [1, undefined, 3, 4] }]} />,
    );
    expect(container.querySelectorAll("path.area")).toHaveLength(2);
    expect(container.querySelectorAll("circle")).toHaveLength(1);
    const lines = container.querySelectorAll("path.line");
    expect(lines).toHaveLength(1);
    // The line starts at the third instant, not at the first: a path that
    // began at x of the first point would have bridged the gap.
    const third = (48 + (2 / 3) * (600 - 48 - 10)).toFixed(1);
    expect(lines[0].getAttribute("d")?.startsWith(`M${third},`)).toBe(true);
    expect(lines[0].getAttribute("d")?.split(" ")).toHaveLength(2);
  });

  it("draws nothing but the axes for a series with no value at all", () => {
    const { container } = draw(
      <AreaChart times={minutes(3)} series={[{ name: "CPU", tone: "accent", values: [undefined, undefined, undefined] }]} />,
    );
    expect(container.querySelectorAll("path")).toHaveLength(0);
    expect(container.querySelectorAll("circle")).toHaveLength(0);
    expect(container.querySelector("line.axis")).not.toBeNull();
  });

  it("labels the y axis through the format on a fixed top", () => {
    const { container } = draw(
      <AreaChart times={minutes(2)} series={[{ name: "CPU", tone: "accent", values: [10, 20] }]} max={100} format={(value) => `${value}%`} />,
    );
    expect(yLabels(container)).toEqual(["0%", "25%", "50%", "75%", "100%"]);
  });

  it("rounds a top taken from the data up to a tick, so the largest value is off the edge", () => {
    // 7 is the largest value: the step is 2 and the axis ends at 8.
    const { container } = draw(
      <AreaChart times={minutes(2)} series={[{ name: "load", tone: "accent", values: [0, 7] }]} />,
    );
    expect(yLabels(container)).toEqual(["0", "2", "4", "6", "8"]);
  });

  it("does not let a fixed top of nothing make an axis of nothing", () => {
    const { container } = draw(
      <AreaChart times={minutes(2)} series={[{ name: "memory", tone: "accent", values: [3, 5] }]} max={0} />,
    );
    // The top comes from the data instead: the step is 2 and the axis ends at 6.
    expect(yLabels(container)).toEqual(["0", "2", "4", "6"]);
  });

  it("draws the peak as a dashed line of the first series and lets it raise the axis", () => {
    const { container } = draw(
      <AreaChart
        times={minutes(2)}
        series={[{ name: "CPU", tone: "accent", values: [10, 12] }]}
        peak={[30, 50]}
      />,
    );
    const dashed = container.querySelectorAll("path.line[stroke-dasharray]");
    expect(dashed).toHaveLength(1);
    expect(dashed[0].getAttribute("style")).toContain("var(--accent)");
    // The mean alone would end the axis at 20; the peak of 50 pushes it to 60.
    expect(yLabels(container)).toEqual(["0", "20", "40", "60"]);
    // The mean line is still there, without the dashes.
    expect(container.querySelectorAll("path.line:not([stroke-dasharray])")).toHaveLength(1);
  });

  it("leaves a gap in the peak line where the peak is unknown", () => {
    const { container } = draw(
      <AreaChart
        times={minutes(4)}
        series={[{ name: "CPU", tone: "accent", values: [1, 1, 1, 1] }]}
        peak={[2, undefined, 3, 4]}
      />,
    );
    // One dashed path per run: the lone first peak is a path of one point,
    // the second run a path of two.
    const dashed = container.querySelectorAll("path.line[stroke-dasharray]");
    expect(dashed).toHaveLength(2);
    expect(dashed[0].getAttribute("d")?.split(" ")).toHaveLength(1);
    expect(dashed[1].getAttribute("d")?.split(" ")).toHaveLength(2);
  });

  it("draws no peak line without a series to take its tone from", () => {
    const { container } = draw(<AreaChart times={minutes(2)} series={[]} peak={[1, 2]} />);
    expect(container.querySelectorAll("path")).toHaveLength(0);
  });

  it("clamps a value above a fixed top to the top edge instead of leaving the chart", () => {
    const { container } = draw(
      <AreaChart times={minutes(1)} series={[{ name: "CPU", tone: "accent", values: [150] }]} max={100} height={CHART_HEIGHT} />,
    );
    const dot = container.querySelector("circle");
    expect(dot).not.toBeNull();
    // The top pad is 8: the y of the top of the axis.
    expect(dot?.getAttribute("cy")).toBe("8");
  });

  it("writes five time labels along the x axis through the label function", () => {
    const times = minutes(9);
    const { container } = draw(
      <AreaChart times={times} series={[{ name: "CPU", tone: "accent", values: times.map(() => 1) }]} label={clock} />,
    );
    expect(xLabels(container)).toEqual(["10:00", "10:02", "10:04", "10:06", "10:08"]);
  });

  it("writes one time label for a single point", () => {
    const { container } = draw(
      <AreaChart times={minutes(1)} series={[{ name: "CPU", tone: "accent", values: [1] }]} label={clock} />,
    );
    expect(xLabels(container)).toEqual(["10:00"]);
  });

  it("colours a series by its tone", () => {
    const { container } = draw(
      <AreaChart
        times={minutes(2)}
        series={[
          { name: "received", tone: "info", values: [1, 2] },
          { name: "sent", tone: "warn", values: [1, 2], line: true },
        ]}
      />,
    );
    // The colour is a token of the theme, so the inline style names the
    // variable; the theme decides what it is.
    const lines = container.querySelectorAll("path.line");
    expect(lines[0].getAttribute("style")).toContain("var(--blue)");
    expect(lines[1].getAttribute("style")).toContain("var(--warn)");
    expect(container.querySelector("path.area")?.getAttribute("style")).toContain("var(--blue)");
  });
});

describe("ChartLegend", () => {
  it("lists every series with a swatch in its tone", () => {
    const { container } = draw(
      <ChartLegend items={[{ name: "Memory used", tone: "accent" }, { name: "Swap used", tone: "warn" }]} />,
    );
    const items = container.querySelectorAll(".chart-legend li");
    expect(items).toHaveLength(2);
    expect(items[0]).toHaveTextContent("Memory used");
    expect(items[1]).toHaveTextContent("Swap used");
    const swatch = (item: Element) => (item.querySelector(".swatch") as HTMLElement).style;
    expect(swatch(items[0]).getPropertyValue("--swatch")).toBe("var(--accent)");
    expect(swatch(items[1]).getPropertyValue("--swatch")).toBe("var(--warn)");
    expect(swatch(items[0]).opacity).toBe("1");
  });

  it("dims the swatch of a dashed item, which stands for a peak line", () => {
    const { container } = draw(
      <ChartLegend items={[{ name: "mean of the step", tone: "accent" }, { name: "peak of the step", tone: "accent", dashed: true }]} />,
    );
    const swatches = container.querySelectorAll(".swatch");
    expect((swatches[0] as HTMLElement).style.opacity).toBe("1");
    expect((swatches[1] as HTMLElement).style.opacity).toBe("0.55");
  });

  it("draws nothing for an empty list, without a bare list element", () => {
    const { container } = draw(<ChartLegend items={[]} />);
    expect(container.querySelectorAll(".chart-legend li")).toHaveLength(0);
  });
});
