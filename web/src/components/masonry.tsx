import { Children, isValidElement, useEffect, useState, type ReactNode } from "react";

/**
 * Tiles in columns, filled across rather than down.
 *
 * CSS columns pack tiles with no holes, but they fill one column to the
 * bottom before starting the next - so the second most important thing on
 * the screen ends up underneath the first instead of beside it. The reading
 * order of a board is left to right, and on a status board that order is
 * what says which part matters most.
 *
 * So the tiles are dealt out round-robin: the first to the first column, the
 * second to the second, and so on. Importance reads across the top, and the
 * columns still end at whatever height their own tiles make, with no holes
 * between them.
 */
export function Masonry({ children, min = 420 }: { children: ReactNode; min?: number }) {
  const count = useColumnCount(min);
  const tiles = Children.toArray(children).filter((child) => isValidElement(child) || child);
  const columns: ReactNode[][] = Array.from({ length: count }, () => []);
  tiles.forEach((tile, index) => columns[index % count].push(tile));
  return (
    <div className="masonry" data-columns={count}>
      {columns.map((column, index) => (
        <div className="masonry-column" key={index}>{column}</div>
      ))}
    </div>
  );
}

/**
 * How many columns fit. The browser cannot be asked to re-deal the tiles on
 * its own, because which column a tile is in is in the markup, so the count
 * is watched here.
 */
export function useColumnCount(min: number): number {
  const [count, setCount] = useState(() => columnsFor(width(), min));
  useEffect(() => {
    const onResize = () => setCount(columnsFor(width(), min));
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, [min]);
  return count;
}

/* The sidebar and the page padding are not the board's to use. */
const CHROME = 300;

function width(): number {
  return typeof window === "undefined" ? 1600 : window.innerWidth;
}

export function columnsFor(viewport: number, min: number): number {
  const usable = Math.max(viewport - CHROME, min);
  return Math.max(1, Math.min(4, Math.floor(usable / min)));
}
