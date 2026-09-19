import {
  useEffect, useId, useRef, useState,
  type CSSProperties, type ReactNode, type TdHTMLAttributes, type ThHTMLAttributes,
} from "react";
import { isStringList, readStored, useStoredState, writeStored } from "../lib/storage";
import { useT } from "../i18n";

/**
 * The order and the shape of a list screen: which column it is sorted by,
 * which columns are on the screen and how many rows a page holds.
 */

/** The order of a list: a column and a direction; null is the list's own order. */
export type SortValue = { column: string; descending: boolean } | null;

/** The sort as the address and the API carry it: column or column:desc; empty for none. */
export function parseSort(value: string): SortValue {
  const trimmed = value.trim();
  if (!trimmed) return null;
  const [column, direction] = trimmed.split(":");
  if (!column || (direction !== undefined && direction !== "asc" && direction !== "desc")) return null;
  return { column, descending: direction === "desc" };
}

export function formatSort(sort: SortValue): string {
  if (!sort) return "";
  return sort.descending ? `${sort.column}:desc` : sort.column;
}

/**
 * The order after a click on a column: a new column starts ascending, a
 * second click turns it round, a third lets the list's own order back.
 */
export function toggleSort(current: SortValue, column: string): SortValue {
  if (!current || current.column !== column) return { column, descending: false };
  if (!current.descending) return { column, descending: true };
  return null;
}

/** What a row is compared by; unknown (null or undefined) sorts below every value. */
export type SortKey = string | number | boolean | null | undefined;

function compareKeys(x: SortKey, y: SortKey): number {
  const xUnknown = x === null || x === undefined;
  const yUnknown = y === null || y === undefined;
  if (xUnknown || yUnknown) return xUnknown === yUnknown ? 0 : xUnknown ? -1 : 1;
  if (typeof x === "number" && typeof y === "number") return x - y;
  if (typeof x === "boolean" && typeof y === "boolean") return Number(x) - Number(y);
  return String(x).localeCompare(String(y), undefined, { numeric: true, sensitivity: "base" });
}

/**
 * The rows in the given order, the list's own order kept between equal keys:
 * a list sorted by state stays sorted by deadline inside each state, so a
 * click adds an order rather than shuffling the rest.
 */
export function sortRows<T>(rows: T[], sort: SortValue, keyOf: (row: T, column: string) => SortKey): T[] {
  if (!sort) return rows;
  const sign = sort.descending ? -1 : 1;
  return rows
    .map((row, index) => ({ row, index, key: keyOf(row, sort.column) }))
    .sort((x, y) => sign * compareKeys(x.key, y.key) || x.index - y.index)
    .map((entry) => entry.row);
}

/** The sort of a bounded list held in the component, with the rows in that order. */
export function useSort<T>(rows: T[], keyOf: (row: T, column: string) => SortKey, initial: SortValue = null) {
  const [sort, setSort] = useState<SortValue>(initial);
  return { sort, setSort, toggle: (column: string) => setSort(toggleSort(sort, column)), sorted: sortRows(rows, sort, keyOf) };
}

/** One column of a table as the chooser and the header cells know it. */
export type ColumnDef = {
  key: string;
  /** The heading, already translated. */
  label: string;
  /** The name the sort goes by - the server's column or the client key; absent on a column with no order. */
  sort?: string;
  /** Left out on a narrow screen: the columns an operator can do without on a phone. */
  secondary?: boolean;
  /** Cannot be taken off the screen: the name of the row, say. */
  fixed?: boolean;
  /** Off the screen until chosen: a column few operators need, kept out of the way of the rest. */
  hidden?: boolean;
  className?: string;
};

/** The columns of one table: which are on the screen, and the way to change that. */
export type Columns = {
  all: ColumnDef[];
  visible: ColumnDef[];
  shown: (key: string) => boolean;
  toggle: (key: string) => void;
  reset: () => void;
  /** Whether any column is off its default. */
  changed: boolean;
};

const columnsKey = (table: string) => `flotestro.columns.${table}`;

/**
 * The columns with at least one that cannot be taken off the screen.
 */
export function withIdentityColumn(columns: ColumnDef[]): ColumnDef[] {
  if (columns.length === 0 || columns.some((column) => column.fixed)) return columns;
  return columns.map((column, index) => (index === 0 ? { ...column, fixed: true, hidden: false } : column));
}

/**
 * The visible columns of a table, remembered per table in the browser.
 */
export function useColumns(table: string, definitions: ColumnDef[]): Columns {
  const columns = withIdentityColumn(definitions);
  const [switched, setSwitched] = useState<string[]>(() => readStored(columnsKey(table), [], isStringList));
  const isHidden = (key: string) => {
    const column = columns.find((entry) => entry.key === key);
    if (!column || column.fixed) return false;
    return Boolean(column.hidden) !== switched.includes(key);
  };
  const write = (next: string[]) => {
    setSwitched(next);
    writeStored(columnsKey(table), next);
  };
  const changed = columns.some((column) => switched.includes(column.key) && !column.fixed);
  return {
    all: columns,
    visible: columns.filter((column) => !isHidden(column.key)),
    shown: (key) => !isHidden(key),
    toggle: (key) => write(switched.includes(key) ? switched.filter((entry) => entry !== key) : [...switched, key]),
    reset: () => write([]),
    changed,
  };
}

/** The class of a cell: the column's own, and the mark of a secondary column the narrow screen leaves out. */
function cellClass(column: ColumnDef | undefined, extra?: string): string | undefined {
  const classes = [column?.className, column?.secondary ? "col-secondary" : undefined, extra].filter(Boolean);
  return classes.length ? classes.join(" ") : undefined;
}

const SORT_BUTTON: CSSProperties = {
  background: "none", border: 0, padding: 0, font: "inherit", color: "inherit",
  cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 4,
};

/**
 * A header cell of a column set.
 */
export function Th({ columns, name, sort, onSort, children, className, ...rest }: {
  columns: Columns;
  name: string;
  /** The current order, when the column set can be sorted. */
  sort?: SortValue;
  /** Told the order a click asks for and the column clicked, for a list whose own order is a column's. */
  onSort?: (next: SortValue, column: string) => void;
  children?: ReactNode;
} & ThHTMLAttributes<HTMLTableCellElement>) {
  const t = useT();
  const column = columns.all.find((entry) => entry.key === name);
  if (!column || !columns.shown(name)) return null;
  const label = children ?? column.label;
  const sortable = column.sort !== undefined && onSort !== undefined;
  const active = sortable && sort?.column === column.sort ? sort : null;
  const ariaSort = !sortable ? undefined : active ? (active.descending ? "descending" : "ascending") : "none";
  return (
    <th className={cellClass(column, className)} aria-sort={ariaSort} {...rest}>
      {sortable ? (
        <button
          type="button"
          style={SORT_BUTTON}
          className="sort-button"
          onClick={() => onSort(toggleSort(sort ?? null, column.sort ?? name), column.sort ?? name)}
          title={t("sort by {column}", { column: column.label })}
          data-testid={`sort-${name}`}
        >
          {label}
          <span className="sort-arrow" aria-hidden="true" style={active ? undefined : { opacity: 0.35 }}>
            {active ? (active.descending ? "▼" : "▲") : "⇅"}
          </span>
        </button>
      ) : label}
    </th>
  );
}

/** A body cell of a column set: nothing when the column is off the screen. */
export function Td({ columns, name, children, className, ...rest }: {
  columns: Columns;
  name: string;
  children?: ReactNode;
} & TdHTMLAttributes<HTMLTableCellElement>) {
  const column = columns.all.find((entry) => entry.key === name);
  if (!column || !columns.shown(name)) return null;
  return <td className={cellClass(column, className)} {...rest}>{children}</td>;
}

const POPOVER: CSSProperties = {
  position: "absolute", top: "calc(100% + 6px)", right: 0, zIndex: 40,
  minWidth: 200, padding: 10, display: "flex", flexDirection: "column", gap: 6,
  background: "var(--bg-raised)", border: "1px solid var(--border-strong)",
  borderRadius: "var(--radius)", boxShadow: "var(--shadow)", fontSize: 12, textAlign: "left",
};

/**
 * The column chooser: a button that opens the list of the columns with a box
 * each, and a way back to the default set.
 */
export function ColumnChooser({ columns }: { columns: Columns }) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const container = useRef<HTMLSpanElement>(null);
  const id = useId();
  // The popover closes on a click outside it or on Escape, like the menus of
  // the top bar; a checkbox inside it keeps it open, because the operator
  // usually changes more than one column at a time.
  useEffect(() => {
    if (!open) return;
    const onPointer = (event: MouseEvent) => {
      if (!container.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);
  return (
    <span ref={container} className="column-chooser" style={{ position: "relative", display: "inline-block" }}>
      <button
        type="button"
        className="secondary"
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen((current) => !current)}
        data-testid="column-chooser"
      >
        {columns.changed ? t("Columns ({n} of {total})", { n: columns.visible.length, total: columns.all.length }) : t("Columns")}
      </button>
      {open && (
        <div id={id} role="group" aria-label={t("Columns")} className="column-chooser-popover" style={POPOVER}>
          {columns.all.map((column) => (
            <label key={column.key} className="toggle" style={{ margin: 0 }}>
              <input
                type="checkbox"
                checked={columns.shown(column.key)}
                disabled={column.fixed}
                onChange={() => columns.toggle(column.key)}
              />
              {column.label}
            </label>
          ))}
          <button type="button" className="secondary" onClick={columns.reset} disabled={!columns.changed} data-testid="reset-columns">
            {t("Reset")}
          </button>
        </div>
      )}
    </span>
  );
}

/** The page sizes a list offers. */
export const PAGE_SIZES = [25, 50, 100, 200] as const;

const isPageSize = (value: unknown): value is number =>
  typeof value === "number" && (PAGE_SIZES as readonly number[]).includes(value);

/** The page size of a table, remembered per table in the browser. */
export function usePageSize(table: string, fallback: number): [number, (next: number) => void] {
  const [size, setSize] = useStoredState<number>(`flotestro.page-size.${table}`, fallback, isPageSize);
  return [size, setSize];
}

/** The select of a page size; the list refetches from its first page on a change. */
export function PageSizeSelect({ value, onChange }: { value: number; onChange: (next: number) => void }) {
  const t = useT();
  return (
    <label className="toggle" style={{ margin: 0 }}>
      <select value={value} onChange={(e) => onChange(Number(e.target.value))} aria-label={t("rows per page")} data-testid="page-size">
        {PAGE_SIZES.map((size) => <option key={size} value={size}>{size}</option>)}
      </select>
      {t("per page")}
    </label>
  );
}
