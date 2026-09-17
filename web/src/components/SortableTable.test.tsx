import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { act, cleanup, fireEvent, render, renderHook, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import {
  ColumnChooser, formatSort, parseSort, sortRows, Td, Th, toggleSort, useColumns, usePageSize, useSort,
  withIdentityColumn, type ColumnDef,
} from "./SortableTable";

/* A storage of the test's own in place of the browser's: what the hooks
   remember is read back from it, and a test starts with it empty. */
class FakeStorage {
  private items = new Map<string, string>();
  get length() { return this.items.size; }
  clear() { this.items.clear(); }
  getItem(key: string) { return this.items.get(key) ?? null; }
  key(index: number) { return [...this.items.keys()][index] ?? null; }
  removeItem(key: string) { this.items.delete(key); }
  setItem(key: string, value: string) { this.items.set(key, value); }
}

let storage: FakeStorage;
const original = Object.getOwnPropertyDescriptor(window, "localStorage");

beforeEach(() => {
  storage = new FakeStorage();
  Object.defineProperty(window, "localStorage", { value: storage, configurable: true });
});

afterEach(() => {
  cleanup();
  if (original) Object.defineProperty(window, "localStorage", original);
});

describe("the sort in the address", () => {
  it("reads column and column:desc and writes them back the same way", () => {
    expect(parseSort("")).toBeNull();
    expect(parseSort("hostname")).toEqual({ column: "hostname", descending: false });
    expect(parseSort("last_seen_at:desc")).toEqual({ column: "last_seen_at", descending: true });
    expect(parseSort("last_seen_at:asc")).toEqual({ column: "last_seen_at", descending: false });
    expect(parseSort("last_seen_at:sideways")).toBeNull();
    expect(formatSort(null)).toBe("");
    expect(formatSort({ column: "site", descending: false })).toBe("site");
    expect(formatSort({ column: "site", descending: true })).toBe("site:desc");
  });

  it("goes ascending, descending, then back to the list's own order", () => {
    const first = toggleSort(null, "site");
    expect(first).toEqual({ column: "site", descending: false });
    const second = toggleSort(first, "site");
    expect(second).toEqual({ column: "site", descending: true });
    expect(toggleSort(second, "site")).toBeNull();
    // Another column starts over, ascending, whatever the previous one was.
    expect(toggleSort(second, "owner")).toEqual({ column: "owner", descending: false });
  });
});

type Row = { name: string; count: number | null; site: string };
const rows: Row[] = [
  { name: "web-2", count: 3, site: "krk" },
  { name: "db-1", count: null, site: "waw" },
  { name: "web-10", count: 3, site: "krk" },
  { name: "cache-1", count: 0, site: "waw" },
];
const keyOf = (row: Row, column: string) => row[column as keyof Row];

describe("sortRows", () => {
  it("keeps the list's own order between equal keys and turns it round as a whole", () => {
    const ascending = sortRows(rows, { column: "site", descending: false }, keyOf).map((row) => row.name);
    expect(ascending).toEqual(["web-2", "web-10", "db-1", "cache-1"]);
    const descending = sortRows(rows, { column: "site", descending: true }, keyOf).map((row) => row.name);
    expect(descending).toEqual(["db-1", "cache-1", "web-2", "web-10"]);
  });

  it("puts an unknown value below every known one, not among the zeros", () => {
    const ascending = sortRows(rows, { column: "count", descending: false }, keyOf).map((row) => row.name);
    expect(ascending).toEqual(["db-1", "cache-1", "web-2", "web-10"]);
    const descending = sortRows(rows, { column: "count", descending: true }, keyOf).map((row) => row.name);
    expect(descending).toEqual(["web-2", "web-10", "cache-1", "db-1"]);
  });

  it("orders names with numbers the way a person counts", () => {
    expect(sortRows(rows, { column: "name", descending: false }, keyOf).map((row) => row.name))
      .toEqual(["cache-1", "db-1", "web-2", "web-10"]);
  });

  it("leaves the rows as they came without an order", () => {
    expect(sortRows(rows, null, keyOf)).toBe(rows);
  });
});

describe("useSort", () => {
  it("toggles through the three orders of a column", () => {
    const { result } = renderHook(() => useSort(rows, keyOf));
    expect(result.current.sorted.map((row) => row.name)).toEqual(["web-2", "db-1", "web-10", "cache-1"]);
    act(() => result.current.toggle("name"));
    expect(result.current.sort).toEqual({ column: "name", descending: false });
    expect(result.current.sorted[0].name).toBe("cache-1");
    act(() => result.current.toggle("name"));
    expect(result.current.sorted[0].name).toBe("web-10");
    act(() => result.current.toggle("name"));
    expect(result.current.sort).toBeNull();
    expect(result.current.sorted.map((row) => row.name)).toEqual(["web-2", "db-1", "web-10", "cache-1"]);
  });
});

const columns: ColumnDef[] = [
  { key: "name", label: "Host", sort: "hostname", fixed: true },
  { key: "site", label: "Site", sort: "site", secondary: true },
  { key: "count", label: "Updates", className: "num" },
];

describe("useColumns", () => {
  it("shows every column by default, hides the ones taken off and remembers that in the storage", () => {
    const { result } = renderHook(() => useColumns("hosts", columns));
    expect(result.current.visible.map((column) => column.key)).toEqual(["name", "site", "count"]);
    expect(result.current.changed).toBe(false);
    act(() => result.current.toggle("site"));
    expect(result.current.shown("site")).toBe(false);
    expect(result.current.visible.map((column) => column.key)).toEqual(["name", "count"]);
    expect(result.current.changed).toBe(true);
    expect(JSON.parse(storage.getItem("flotestro.columns.hosts") ?? "null")).toEqual(["site"]);

    // A fresh screen reads the choice back; another table is untouched.
    const again = renderHook(() => useColumns("hosts", columns));
    expect(again.result.current.shown("site")).toBe(false);
    const other = renderHook(() => useColumns("jobs", columns));
    expect(other.result.current.shown("site")).toBe(true);

    act(() => again.result.current.reset());
    expect(again.result.current.visible).toHaveLength(3);
    expect(JSON.parse(storage.getItem("flotestro.columns.hosts") ?? "null")).toEqual([]);
  });

  it("never hides a fixed column, and a stored name of no column is ignored", () => {
    storage.setItem("flotestro.columns.hosts", JSON.stringify(["name", "gone"]));
    const { result } = renderHook(() => useColumns("hosts", columns));
    expect(result.current.shown("name")).toBe(true);
    expect(result.current.changed).toBe(false);
  });

  it("keeps a column hidden by default off the screen until it is chosen", () => {
    const withExtra: ColumnDef[] = [...columns, { key: "agent", label: "Agent", hidden: true }];
    const { result } = renderHook(() => useColumns("hosts", withExtra));
    expect(result.current.shown("agent")).toBe(false);
    expect(result.current.changed).toBe(false);
    act(() => result.current.toggle("agent"));
    expect(result.current.shown("agent")).toBe(true);
    expect(result.current.changed).toBe(true);
    expect(renderHook(() => useColumns("hosts", withExtra)).result.current.shown("agent")).toBe(true);
    act(() => result.current.reset());
    expect(result.current.shown("agent")).toBe(false);
  });

  it("falls back to every column when the storage holds something unreadable", () => {
    storage.setItem("flotestro.columns.hosts", "{not json");
    const { result } = renderHook(() => useColumns("hosts", columns));
    expect(result.current.visible).toHaveLength(3);
  });

  it("keeps one identity column on the screen whatever the preference says", () => {
    // A screen that names no fixed column gets its first one fixed; a
    // stored preference naming every column cannot empty the table.
    const unnamed: ColumnDef[] = [
      { key: "pid", label: "PID" }, { key: "user", label: "User" }, { key: "command", label: "Command" },
    ];
    storage.setItem("flotestro.columns.processes", JSON.stringify(["pid", "user", "command"]));
    const { result } = renderHook(() => useColumns("processes", unnamed));
    expect(result.current.visible.map((column) => column.key)).toEqual(["pid"]);
    expect(result.current.all.find((column) => column.key === "pid")?.fixed).toBe(true);
    act(() => result.current.toggle("pid"));
    expect(result.current.shown("pid")).toBe(true);

    // A screen that names its identity columns keeps them all, and the
    // first column is not made fixed on top of them.
    const named: ColumnDef[] = [
      { key: "age", label: "Age" }, { key: "unit", label: "Unit", fixed: true },
    ];
    storage.setItem("flotestro.columns.units", JSON.stringify(["age", "unit"]));
    const units = renderHook(() => useColumns("units", named));
    expect(units.result.current.visible.map((column) => column.key)).toEqual(["unit"]);
    expect(withIdentityColumn(named)).toBe(named);
  });
});

describe("usePageSize", () => {
  it("takes the fallback, remembers a chosen size and refuses a size the list does not offer", () => {
    const { result } = renderHook(() => usePageSize("hosts", 100));
    expect(result.current[0]).toBe(100);
    act(() => result.current[1](50));
    expect(result.current[0]).toBe(50);
    expect(storage.getItem("flotestro.page-size.hosts")).toBe("50");
    storage.setItem("flotestro.page-size.jobs", "7");
    expect(renderHook(() => usePageSize("jobs", 100)).result.current[0]).toBe(100);
  });
});

/* A table over the column set, with the header cells sortable. */
function Table({ onSort }: { onSort: (next: ReturnType<typeof parseSort>, column: string) => void }) {
  const set = useColumns("hosts", columns);
  const { sort } = useSort(rows, keyOf, { column: "site", descending: true });
  return (
    <>
      <ColumnChooser columns={set} />
      <table>
        <thead>
          <tr>
            <Th columns={set} name="name" sort={sort} onSort={onSort} />
            <Th columns={set} name="site" sort={sort} onSort={onSort} />
            <Th columns={set} name="count" sort={sort} onSort={onSort} />
          </tr>
        </thead>
        <tbody>
          <tr>
            <Td columns={set} name="name">web-2</Td>
            <Td columns={set} name="site" data-testid="site-cell">krk</Td>
            <Td columns={set} name="count">3</Td>
          </tr>
        </tbody>
      </table>
    </>
  );
}

describe("the header cells", () => {
  it("say the order out loud, mark the secondary columns and hide the ones taken off", () => {
    const sorts: [ReturnType<typeof parseSort>, string][] = [];
    render(<Table onSort={(next, column) => sorts.push([next, column])} />);
    const headers = screen.getAllByRole("columnheader");
    expect(headers.map((header) => header.getAttribute("aria-sort"))).toEqual(["none", "descending", null]);
    expect(headers[1]).toHaveClass("col-secondary");
    expect(screen.getByTestId("site-cell")).toHaveClass("col-secondary");
    expect(headers[2]).toHaveClass("num");

    // A click on the sorted column turns it round; a click on another
    // column starts that one ascending.
    fireEvent.click(screen.getByTestId("sort-site"));
    fireEvent.click(screen.getByTestId("sort-name"));
    expect(sorts).toEqual([[null, "site"], [{ column: "hostname", descending: false }, "hostname"]]);

    fireEvent.click(screen.getByTestId("column-chooser"));
    const boxes = screen.getAllByRole("checkbox");
    expect(boxes[0]).toBeDisabled();
    fireEvent.click(boxes[1]);
    expect(screen.queryByTestId("site-cell")).not.toBeInTheDocument();
    expect(screen.getAllByRole("columnheader")).toHaveLength(2);
    fireEvent.click(screen.getByTestId("reset-columns"));
    expect(screen.getByTestId("site-cell")).toBeInTheDocument();
  });
});
