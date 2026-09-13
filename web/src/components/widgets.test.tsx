import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import type { ReactElement } from "react";
import { BarChart, Breakdown, Meter, StatusBar } from "./widgets";

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
