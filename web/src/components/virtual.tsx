import { useEffect, useRef, useState, type ReactNode } from "react";

/**
 * VirtualRows: a table whose body is windowed.
 *
 * Only the rows in view, plus a margin of `overscan` on each side, exist as
 * React elements; two spacer rows of computed height stand in for everything
 * above and below them, so the scrollbar has the length of the whole list.
 * A campaign of ten thousand hosts must not become ten thousand rows in the
 * browser: the targets already arrive page by page, and this keeps what the
 * pages add up to from turning into ten thousand elements and DOM nodes.
 *
 * The spacers are real <tr> elements inside a real <tbody>, not absolutely
 * positioned rows: the table keeps its own layout, so the header, the column
 * widths and the existing table styling work unchanged. The price is that
 * every row has to be the same height, which the callers enforce with a
 * single line of text per cell.
 */
export function VirtualRows<T>({
  items, rowHeight, height, overscan = 6, columns, head, rowKey, render, onNearEnd, loading = false,
}: {
  items: T[];
  /** The height every row is given, in pixels; a row must not grow past it. */
  rowHeight: number;
  /** The most the scroll container may take, in pixels. */
  height: number;
  /** Rows rendered beyond each edge of the viewport, so a scroll of a few pixels never shows a blank edge. */
  overscan?: number;
  /** The number of columns, for the spacer rows to span. */
  columns: number;
  /** The header row. */
  head: ReactNode;
  rowKey: (item: T) => string;
  /** The cells of one row. */
  render: (item: T, index: number) => ReactNode;
  /** Called when the scroll comes within two viewports of the end - once per list length, so a page is asked for once. */
  onNearEnd?: () => void;
  /** Whether the next page is already on its way; onNearEnd waits for it. */
  loading?: boolean;
}) {
  const container = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewport, setViewport] = useState(height);
  // The stride the browser actually drew. A table row does not honour a
  // pixel height to the pixel - the cell borders add their own - and one
  // pixel of drift per row is a whole screen off after a few hundred rows,
  // so the arithmetic uses the measured row and not the requested one.
  const [stride, setStride] = useState(rowHeight);
  // The list length at which the next page was last asked for: the scroll
  // handler fires many times before the fetch is reported as in flight.
  const asked = useRef(-1);

  const first = Math.min(items.length, Math.max(0, Math.floor(scrollTop / stride) - overscan));
  const last = Math.min(items.length, Math.ceil((scrollTop + viewport) / stride) + overscan);

  // The viewport is measured rather than taken from the prop: the container
  // is allowed to be shorter than `height` while the list is short, and it
  // grows as pages arrive. The measure is taken after every render and on a
  // resize of the window; a value that did not change renders nothing.
  useEffect(() => {
    const measure = () => {
      const node = container.current;
      if (!node) return;
      setViewport(node.clientHeight || height);
      const drawn = node.querySelector("tbody tr[data-row]")?.getBoundingClientRect().height;
      if (drawn && Math.abs(drawn - stride) > 0.5) setStride(drawn);
    };
    measure();
    window.addEventListener("resize", measure);
    return () => window.removeEventListener("resize", measure);
  });

  useEffect(() => {
    const node = container.current;
    if (!node || !onNearEnd || loading || asked.current === items.length) return;
    if (node.scrollTop + node.clientHeight < node.scrollHeight - 2 * node.clientHeight) return;
    asked.current = items.length;
    onNearEnd();
  }, [scrollTop, items.length, loading, onNearEnd]);

  // The scroll position is kept to the row, so a scroll of a few pixels that
  // changes nothing on screen does not render anything either.
  return (
    <div
      ref={container}
      className="virtual"
      style={{ maxHeight: height }}
      onScroll={(e) => setScrollTop(Math.floor(e.currentTarget.scrollTop / stride) * stride)}
    >
      <table>
        <thead>{head}</thead>
        <tbody>
          {first > 0 && (
            <tr className="spacer"><td colSpan={columns} style={{ height: first * stride }} /></tr>
          )}
          {items.slice(first, last).map((item, offset) => (
            <tr key={rowKey(item)} data-row style={{ height: rowHeight }}>
              {render(item, first + offset)}
            </tr>
          ))}
          {last < items.length && (
            <tr className="spacer"><td colSpan={columns} style={{ height: (items.length - last) * stride }} /></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
