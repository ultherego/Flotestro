import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { FactValue, Identifier, Pair, Pairs, Structured } from "./ui";

/**
 * The one way the panel draws a fact of the server. Every case here is one
 * the status screen used to get wrong: a structure drawn as a line of JSON,
 * an identifier drawn in full, a value with no way to wrap.
 */

afterEach(cleanup);

describe("Identifier", () => {
  it("shows the ends of a long value and keeps the whole of it on hover", () => {
    const whole = "9f2c1a4b8e7d6c5b4a39281706f5e4d3c2b1a0998877665544332211aabbccdd";
    const { getByRole } = render(<Identifier value={whole} />);
    const button = getByRole("button");
    expect(button).toHaveAttribute("title", whole);
    expect(button.textContent).toContain("…");
    expect(button.textContent?.length ?? 0).toBeLessThan(whole.length);
  });

  it("leaves a short value whole", () => {
    const { getByRole } = render(<Identifier value="panel-1" />);
    expect(getByRole("button").textContent).toContain("panel-1");
    expect(getByRole("button").textContent).not.toContain("…");
  });

  it("copies the whole value, not the shortened one", async () => {
    const written: string[] = [];
    Object.assign(navigator, {
      clipboard: { writeText: (text: string) => { written.push(text); return Promise.resolve(); } },
    });
    const whole = "a".repeat(20) + "b".repeat(20);
    const { getByRole } = render(<Identifier value={whole} />);
    fireEvent.click(getByRole("button"));
    await waitFor(() => expect(written).toEqual([whole]));
  });
});

describe("Structured", () => {
  it("draws a short record as a table of its own keys", () => {
    const { getByRole } = render(
      <Structured value={[
        { gateway_id: "panel-a", pool_max_conns: 10 },
        { gateway_id: "panel-b", pool_max_conns: 12 },
      ]} />,
    );
    const table = getByRole("table");
    expect(within(table).getByText("Gateway id")).toBeInTheDocument();
    expect(within(table).getByText("Pool max conns")).toBeInTheDocument();
    expect(within(table).getAllByRole("row")).toHaveLength(3);
  });

  it("draws a map as a nested list of pairs", () => {
    const { container } = render(<Structured value={{ pending_rewrap: 3, unreadable_versions: 0 }} />);
    const list = container.querySelector("dl.pairs.nested");
    expect(list).not.toBeNull();
    expect(within(list as HTMLElement).getByText("Pending rewrap")).toBeInTheDocument();
  });

  /* A map keyed by an identifier - the versions of each key of the
     installation - is keyed by that identifier and nothing else: a key read
     as a sentence is a different key. */
  it("leaves an identifier it is keyed by exactly as it came", () => {
    const { container } = render(<Structured value={{ "k-7f3a": 2 }} />);
    expect(within(container.querySelector("dl") as HTMLElement).getByText("k-7f3a")).toBeInTheDocument();
  });

  it("draws a list of words as words", () => {
    const { container } = render(<Structured value={["nvd", "osv"]} />);
    expect(container.textContent).toBe("nvd, osv");
  });

  it("says nothing is there for an empty structure", () => {
    expect(render(<Structured value={[]} />).container.textContent).toBe("—");
    expect(render(<Structured value={{}} />).container.textContent).toBe("—");
  });

  /* The defect this component exists for: the replicas of the control plane
     and the keys of the installation reached the screen as objects, were
     given to String() and left the card as one unbreakable line of JSON. */
  it("never prints a structure as JSON", () => {
    const { container } = render(
      <Pairs>
        <Pair label="Replicas" wide>
          <FactValue value={[{ gateway_id: "panel-a", started_at: "2026-10-13T08:00:00Z" }]} />
        </Pair>
      </Pairs>,
    );
    expect(container.textContent).not.toContain("{");
    expect(container.textContent).not.toContain('"gateway_id"');
    expect(container.querySelector("table")).not.toBeNull();
  });
});

describe("FactValue", () => {
  it("reads each kind in the units a person reads it in", () => {
    expect(render(<FactValue value={1536} kind="bytes" />).container.textContent).toBe("1.5 KiB");
    expect(render(<FactValue value={90} kind="seconds" />).container.textContent).toBe("1m 30s");
    expect(render(<FactValue value={"720h0m0s"} kind="duration" />).container.textContent).toBe("30 d");
    expect(render(<FactValue value={2.345} kind="ms" />).container.textContent).toBe("2.3 ms");
    expect(render(<FactValue value={7} kind="number" />).container.textContent).toBe("7");
  });

  it("draws a flag as its own answer, and an absent value as a dash", () => {
    expect(render(<FactValue value={true} kind="flag" />).container.textContent).toBe("yes");
    expect(render(<FactValue value={false} kind="flag" />).container.textContent).toBe("no");
    expect(render(<FactValue value={null} kind="text" />).container.textContent).toBe("—");
    expect(render(<FactValue value={""} kind="id" />).container.textContent).toBe("—");
  });

  it("gives an identifier the shortening and the copy", () => {
    const { getByRole } = render(<FactValue value={"b".repeat(40)} kind="id" />);
    expect(getByRole("button")).toHaveAttribute("title", "b".repeat(40));
  });
});

/**
 * The overflow itself cannot be seen in a renderer without layout, so the
 * rule is read where it is written. One grid, and it wraps.
 */
describe("the fact list has one definition", () => {
  const src = dirname(dirname(fileURLToPath(import.meta.url)));
  const css = readFileSync(join(src, "styles.css"), "utf8");

  it("lets every value wrap, whatever it holds", () => {
    // The base rule only: the narrow-screen copy is indented in its query.
    const rule = /^\.pairs dd \{[^}]*\}/m.exec(css)?.[0] ?? "";
    expect(rule).toContain("overflow-wrap: anywhere");
    expect(rule).toContain("min-width: 0");
  });

  it("stacks the pairs inside a narrow card instead of squeezing them", () => {
    expect(css).toContain("@container card (max-width: 420px)");
    expect(/\.card \{[^}]*container: card \/ inline-size/.test(css)).toBe(true);
  });

  it("keeps a table inside its card", () => {
    expect(/\.table-scroll \{[^}]*overflow-x: auto/.test(css)).toBe(true);
  });

  it("has no screen left on the wrapping class the panel used to carry", () => {
    // `fp-wrap` lived in a stylesheet of its own; a value that needed it was
    // the value that overflowed when somebody forgot it.
    const sources = ["pages/Settings.tsx", "pages/Status.tsx"].map((file) =>
      readFileSync(join(src, file), "utf8"));
    expect(sources.some((source) => source.includes("fp-wrap"))).toBe(false);
  });
});

describe("a record set too wide for a table", () => {
  it("becomes one little list per record once it passes four fields", () => {
    const { container, queryByRole } = render(
      <Structured value={[{ a: 1, b: 2, c: 3, d: 4, e: 5 }, { a: 6, b: 7, c: 8, d: 9, e: 10 }]} />,
    );
    expect(queryByRole("table")).toBeNull();
    expect(container.querySelectorAll(".records > dl")).toHaveLength(2);
  });
});
