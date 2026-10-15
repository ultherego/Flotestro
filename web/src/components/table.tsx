import type { ReactNode } from "react";
import { Empty } from "./ui";

/**
 * The panel's data table.
 *
 * Forty-five screens wrote their own `<table>`, with 283 header cells typed
 * out one at a time: the same object, spelled forty-five ways. The owner read
 * the result on 15.10 - *"znów tabelki nie mają wspólnej klasy tylko wpisane
 * na sztywno"* - and he is right that a shared rule in the stylesheet is only
 * half of it. A column that should step aside on a phone, a count that should
 * line up on its digits, the cell that holds the row's actions: each of those
 * was a decision taken again on every screen, and taken differently.
 *
 * So a table is a list of columns and a list of rows. What a column is -
 * whether it names the row, whether it carries numbers, whether it waits for
 * a wider screen, whether it holds the actions - is said once, here, and the
 * markup follows from it.
 */

export type Column<Row> = {
  /** Distinguishes the column; also the key React draws the cells by. */
  key: string;
  /** What stands in the header. A column with no head still needs its key. */
  head?: ReactNode;
  cell: (row: Row) => ReactNode;
  /**
   * The column that names the row. Exactly one should carry it: a row whose
   * first cell is a <th> is a row a screen reader can read back.
   */
  rowHeader?: boolean;
  /** Numbers line up on their digits and sit to the right. */
  numeric?: boolean;
  /** The buttons at the end of a row. */
  actions?: boolean;
  /** Prose that squeezes the useful columns on a narrow screen. */
  wideOnly?: boolean;
};

export function DataTable<Row>({
  columns, rows, rowKey, rowTestId, empty, bodyTestId, rowClass,
}: {
  columns: Column<Row>[];
  rows: Row[];
  rowKey: (row: Row) => string;
  rowTestId?: (row: Row) => string;
  /** What to say instead of an empty body. */
  empty?: ReactNode;
  bodyTestId?: string;
  rowClass?: (row: Row) => string | undefined;
}) {
  if (rows.length === 0 && empty !== undefined) {
    return <Empty>{empty}</Empty>;
  }
  const classOf = (column: Column<Row>) => [
    column.numeric ? "num" : "",
    column.actions ? "actions-cell" : "",
    column.wideOnly ? "wide-only" : "",
  ].filter(Boolean).join(" ") || undefined;

  return (
    <table>
      <thead>
        <tr>
          {columns.map((column) => (
            <th key={column.key} scope="col" className={column.wideOnly ? "wide-only" : undefined}>
              {column.head}
            </th>
          ))}
        </tr>
      </thead>
      <tbody data-testid={bodyTestId}>
        {rows.map((row) => (
          <tr key={rowKey(row)} data-testid={rowTestId?.(row)} className={rowClass?.(row)}>
            {columns.map((column) =>
              column.rowHeader ? (
                <th key={column.key} scope="row" className={classOf(column)}>{column.cell(row)}</th>
              ) : (
                <td key={column.key} className={classOf(column)}>{column.cell(row)}</td>
              ),
            )}
          </tr>
        ))}
      </tbody>
    </table>
  );
}
