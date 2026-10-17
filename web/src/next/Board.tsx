import { useEffect, useRef, useState, type PointerEvent as ReactPointerEvent, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../lib/api";
import {
  BOARD_COLUMNS, BOARD_HEIGHTS, boardToDraw, placeAll,
  type BoardEntry, type BoardWidget, type StoredBoard,
} from "../components/board";
import { useToast } from "../components/Toast";
import { useT } from "../i18n";
import { Icon } from "../components/icons";
import { HeadActions } from "./kit";

/**
 * A screen somebody lays out for themselves.
 *
 * The arrangement belongs to the installation rather than to each person.
 * An operations screen people talk to each other over - "look at the
 * second tile" - stops working when everyone sees a different second
 * tile, so storing one is a change like any other: it carries a reason,
 * it is kept in the trail, and the revision it was read at goes with it
 * so that two administrators cannot overwrite each other silently.
 *
 * Two boards, because two different things are asked of a screen:
 *
 *  - `fixed` is a wall of tiles, like a monitoring dashboard: a twelve
 *    column grid of fixed rows, every container exactly the size it was
 *    given and exactly where it was put, one under another if wanted.
 *    Arranging it and reading it are the very same grid, so what is laid
 *    out is what is stored is what is read. A container that holds more
 *    than its cell scrolls inside it.
 *  - Everything else is a page: containers take their width and stand in
 *    rows as tall as their tallest, in the order they were put. Only the
 *    order and the width are the reader's to choose, because a height is
 *    what is in the container.
 */

/**
 * Nothing stands on anything else, and nothing floats.
 *
 * What the hand is holding keeps the cell it was put on; everything it
 * landed on moves down until the grid is clear again, in the order it was
 * already in. Without this a container made wider simply covers its
 * neighbour, which reads as a panel that has broken rather than as a
 * grid that has been rearranged.
 *
 * Then everything rises as far as it can. A row holds containers of
 * different heights, so the short one would otherwise leave a hole
 * beneath it that the next container begins below rather than inside.
 */
export function settle(widgets: BoardWidget[], held: string): BoardWidget[] {
  const over = (a: BoardWidget, b: BoardWidget) => {
    const ax = a.x ?? 0, ay = a.y ?? 0, bx = b.x ?? 0, by = b.y ?? 0;
    const ah = a.height ?? 2, bh = b.height ?? 2;
    return ax < bx + b.width && bx < ax + a.width && ay < by + bh && by < ay + ah;
  };
  const order = [...widgets].sort((a, b) => {
    if (a.key === held) return -1;
    if (b.key === held) return 1;
    return (a.y ?? 0) - (b.y ?? 0) || (a.x ?? 0) - (b.x ?? 0);
  });
  const settled: BoardWidget[] = [];
  for (const one of order) {
    const placed = { ...one };
    // A row at a time, downwards: the grid has no ceiling, so this ends.
    while (settled.some((other) => over(placed, other))) {
      placed.y = (placed.y ?? 0) + 1;
    }
    // Then back up as far as it will go. Containers in one row are rarely
    // the same height, and without this the short one leaves a hole under
    // itself that the next container cannot enter - it starts where its
    // tall neighbour ends. Half a row of empty floor, over and over, is
    // what made a board read as a heap of cards rather than one board.
    //
    // Never the one in the hand. It is settled first, so at that moment
    // the grid is empty above it and it would rise to the very top - the
    // owner saw exactly that: taking hold of any container threw it to
    // the top of the screen instead of moving it where it was put.
    while (one.key !== held && (placed.y ?? 0) > 0) {
      const lifted = { ...placed, y: (placed.y ?? 0) - 1 };
      if (settled.some((other) => over(lifted, other))) break;
      placed.y = lifted.y;
    }
    settled.push(placed);
  }
  // The record keeps the order it had; only the places changed.
  return widgets.map((one) => settled.find((other) => other.key === one.key) ?? one);
}


/** The height of one row of a fixed board, in pixels; `--row` of the stylesheet says the same. */
export const ROW = 76;

/** The containers in the order a reader meets them: by row, then by column. */
export function sequenced(widgets: BoardWidget[]): BoardWidget[] {
  return [...widgets].sort((a, b) => (a.y ?? 0) - (b.y ?? 0) || (a.x ?? 0) - (b.x ?? 0));
}

/**
 * The shared half of both boards: what is stored, what is being edited,
 * and the three things that can be done with it.
 */
function useArrangement(screen: string, catalogue: BoardEntry[], drawn: Record<string, ReactNode>) {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const known = new Set(Object.keys(drawn).filter((key) => {
    const node = drawn[key];
    return node !== undefined && node !== null && node !== false;
  }));
  const [editing, setEditing] = useState<BoardWidget[] | null>(null);

  const layout = useQuery({
    queryKey: ["screen-layout", screen],
    queryFn: () => api.get<StoredBoard>(`/api/v1/settings/layout/${screen}`),
    retry: false,
  });
  const save = useMutation({
    mutationFn: (widgets: BoardWidget[]) =>
      api.put<StoredBoard>(`/api/v1/settings/layout/${screen}`, {
        widgets, revision: layout.data?.revision ?? 0,
      }),
    onSuccess: () => {
      setEditing(null);
      void queryClient.invalidateQueries({ queryKey: ["screen-layout", screen] });
      toast.success(t("The screen is arranged this way for everybody who opens it."));
    },
    onError: (error) => {
      if (error instanceof ApiError && error.status === 409) {
        void queryClient.invalidateQueries({ queryKey: ["screen-layout", screen] });
        toast.error(t("Somebody else arranged this screen while you were editing it. What they stored is on screen now; make your change again on top of it."));
        setEditing(null);
        return;
      }
      toast.error(error instanceof Error ? error.message : String(error));
    },
  });
  const reset = useMutation({
    mutationFn: () => api.del(`/api/v1/settings/layout/${screen}`),
    onSuccess: () => {
      setEditing(null);
      void queryClient.invalidateQueries({ queryKey: ["screen-layout", screen] });
      toast.success(t("The screen is back to the arrangement the panel ships with."));
    },
    onError: (error) => toast.error(error instanceof Error ? error.message : String(error)),
  });

  const stored = boardToDraw(layout.data, catalogue, known);
  const current = editing ?? stored;
  const shown = current.filter((one) => !one.hidden);
  const hidden = current.filter((one) => one.hidden);
  const absent = catalogue.filter((one) => known.has(one.key) && !shown.some((on) => on.key === one.key));
  const titleOf = (key: string) => catalogue.find((one) => one.key === key)?.title ?? key;
  return { layout, save, reset, editing, setEditing, current, shown, hidden, absent, titleOf, known };
}

type Arrangement = ReturnType<typeof useArrangement>;

/** The bar above a board being arranged: what to do, save, back, add, reset. */
function ArrangeBar({ a, catalogue, hint }: { a: Arrangement; catalogue: BoardEntry[]; hint: string }) {
  const t = useT();
  if (a.editing === null) return null;
  const editing = a.editing;
  return (
    <div className="fl-arrange">
      <span className="fl-arrange-what">{hint}</span>
      <button
        type="button"
        onClick={() => a.save.mutate(editing)}
        disabled={a.save.isPending || editing.length === 0}
        data-testid="board-save"
      >
        {a.save.isPending ? t("storing…") : t("Save")}
      </button>
      <button type="button" className="fl-quiet" onClick={() => a.setEditing(null)}>
        {t("Back")}
      </button>
      {a.absent.length > 0 && (
        <select
          value=""
          onChange={(event) => {
            const one = catalogue.find((item) => item.key === event.target.value);
            if (!one) return;
            // It may be in the record already, hidden: putting it back is
            // unhiding it, not placing a second copy.
            a.setEditing(editing.some((on) => on.key === one.key)
              ? editing.map((on) => (on.key === one.key ? { ...on, hidden: false } : on))
              : [...editing, { key: one.key, width: one.width, height: one.height }]);
          }}
          data-testid="board-add"
        >
          <option value="">{t("Add a container…")}</option>
          {a.absent.map((one) => <option key={one.key} value={one.key}>{t(one.title)}</option>)}
        </select>
      )}
      {a.layout.data?.present && (
        <button
          type="button"
          className="fl-danger"
          disabled={a.reset.isPending}
          onClick={() => a.reset.mutate()}
          data-testid="board-reset"
          title={t("Everybody goes back to the arrangement the panel ships with.")}
        >
          {t("Back to the panel's own")}
        </button>
      )}
    </div>
  );
}

function ArrangeButton({ a, begin }: { a: Arrangement; begin: () => void }) {
  const t = useT();
  if (a.layout.data === undefined || a.editing !== null) return null;
  return (
    <HeadActions>
      <button type="button" className="fl-quiet" onClick={begin} data-testid="arrange">
        <Icon name="dashboard" />
        {t("Arrange this screen")}
      </button>
    </HeadActions>
  );
}

type Props = {
  /**
   * The name the arrangement is stored under. The server takes lower-case
   * letters, digits and underscores and refuses anything else, and a
   * refused name leaves the screen with no arrange bar at all.
   */
  screen: string;
  catalogue: BoardEntry[];
  /** What each container draws, by key. A key with nothing to draw -
      undefined, null, or the false of `{open && <Card/>}` - is left out
      rather than placed as an empty cell. */
  drawn: Record<string, ReactNode>;
  /** What has to be read before the board is read at all; it stands above the grid. */
  notices?: ReactNode;
  /** A wall of tiles on a fixed grid, rather than a page. */
  fixed?: boolean;
};

export function Board(props: Props) {
  return props.fixed ? <FixedBoard {...props} /> : <PageBoard {...props} />;
}

/* ================================================================ fixed */

/** Whether the window is wide enough for twelfths to mean anything. */
function useWide(): boolean {
  const query = "(min-width: 1000px)";
  const [wide, setWide] = useState(() => (typeof window.matchMedia === "function" ? window.matchMedia(query).matches : true));
  useEffect(() => {
    if (typeof window.matchMedia !== "function") return;
    const media = window.matchMedia(query);
    const on = () => setWide(media.matches);
    media.addEventListener?.("change", on);
    return () => media.removeEventListener?.("change", on);
  }, []);
  return wide;
}

type Hold = { key: string; mode: "move" | "width" | "height" | "size"; fromX: number; fromY: number; start: BoardWidget };

function FixedBoard({ screen, catalogue, drawn, notices }: Props) {
  const t = useT();
  const a = useArrangement(screen, catalogue, drawn);
  const wide = useWide();
  const gridRef = useRef<HTMLDivElement | null>(null);
  const [hold, setHold] = useState<Hold | null>(null);

  // Every container has a place: the stored one, or the shipped shapes
  // packed into rows. Reading and arranging draw this same list.
  const base = settle(placeAll(a.shown), "");
  const placed = a.editing !== null ? a.shown : base;
  const heightOf = (one: BoardWidget) => Math.max(one.height ?? 2, 1);

  const steps = () => {
    const grid = gridRef.current;
    if (!grid) return { column: 0, row: 0 };
    const style = getComputedStyle(grid);
    const gap = parseFloat(style.columnGap || "20") || 20;
    const rowGap = parseFloat(style.rowGap || "20") || gap;
    const column = (grid.getBoundingClientRect().width - gap * (BOARD_COLUMNS - 1)) / BOARD_COLUMNS;
    return { column: column + gap, row: ROW + rowGap };
  };

  const begin = () => a.setEditing([...base, ...a.hidden]);

  const take = (event: ReactPointerEvent, key: string, mode: Hold["mode"]) => {
    if (a.editing === null) return;
    const start = placed.find((one) => one.key === key);
    if (!start) return;
    (event.target as Element).setPointerCapture?.(event.pointerId);
    setHold({ key, mode, fromX: event.clientX, fromY: event.clientY, start });
    event.preventDefault();
  };

  const moveTo = (event: ReactPointerEvent) => {
    if (!hold || a.editing === null) return;
    const { column, row } = steps();
    if (column <= 0 || row <= 0) return;
    const dx = Math.round((event.clientX - hold.fromX) / column);
    const dy = Math.round((event.clientY - hold.fromY) / row);
    const from = hold.start;
    const clampWidth = (width: number, x: number) => Math.min(Math.max(width, 1), BOARD_COLUMNS - x);
    const clampHeight = (height: number) => Math.min(Math.max(height, 1), BOARD_HEIGHTS.max);
    const one = (w: BoardWidget): BoardWidget => {
      const x = from.x ?? 0, y = from.y ?? 0;
      if (hold.mode === "move") {
        return { ...w, x: Math.min(Math.max(x + dx, 0), BOARD_COLUMNS - from.width), y: Math.max(y + dy, 0) };
      }
      return {
        ...w,
        width: hold.mode === "height" ? from.width : clampWidth(from.width + dx, x),
        height: hold.mode === "width" ? heightOf(from) : clampHeight(heightOf(from) + dy),
      };
    };
    const moved = a.shown.map((w) => (w.key === hold.key ? one(w) : w));
    const next = settle(moved, hold.key);
    const same = next.every((n) => {
      const was = a.shown.find((w) => w.key === n.key);
      return was?.x === n.x && was?.y === n.y && was?.width === n.width && was?.height === n.height;
    });
    if (!same) a.setEditing([...next, ...a.hidden]);
  };

  const letGo = () => setHold(null);
  const editing = a.editing !== null;

  return (
    <>
      {notices}
      {wide && <ArrangeButton a={a} begin={begin} />}
      {a.layout.data !== undefined && wide && (
        <ArrangeBar a={a} catalogue={catalogue} hint={t("Hold a name to move a container; pull its right edge, its bottom edge or the corner to size it.")} />
      )}
      <div
        ref={gridRef}
        className={["fl-grid", "fl-placed", "fl-pin", editing ? "fl-editing" : "", hold ? "fl-holding" : ""].join(" ").trim()}
        onPointerMove={hold ? moveTo : undefined}
        onPointerUp={hold ? letGo : undefined}
        onPointerCancel={hold ? letGo : undefined}
        data-testid="board"
      >
        {placed.map((one) => (
          <div
            key={one.key}
            className={["fl-held", hold?.key === one.key ? "fl-dragging" : ""].join(" ").trim()}
            style={{
              gridColumn: `${(one.x ?? 0) + 1} / span ${one.width}`,
              gridRow: `${(one.y ?? 0) + 1} / span ${heightOf(one)}`,
            }}
            data-held-key={one.key}
            data-testid={editing ? `held-${one.key}` : undefined}
          >
            <div className="fl-held-body">{a.known.has(one.key) ? drawn[one.key] : null}</div>
            {editing && (
              <>
                <div className="fl-grip">
                  <span
                    className="fl-grip-handle"
                    onPointerDown={(event) => take(event, one.key, "move")}
                    title={t("Hold to move this container")}
                    data-testid={`grip-${one.key}`}
                  >
                    <span aria-hidden="true">⠿</span>
                    <span className="fl-grip-name">{t(a.titleOf(one.key))}</span>
                  </span>
                  <span className="fl-grip-size" data-testid={`width-${one.key}`}>{one.width}×{heightOf(one)}</span>
                  <button
                    type="button"
                    className="fl-word"
                    onClick={() => a.setEditing(a.current.map((on) => (on.key === one.key ? { ...on, hidden: true } : on)))}
                    title={t("Take this container off the screen")}
                  >
                    {t("Remove")}
                  </button>
                </div>
                <span className="fl-edge" role="separator" aria-label={t("Drag to resize")} data-testid={`corner-${one.key}`}
                  onPointerDown={(event) => take(event, one.key, "width")} />
                <span className="fl-edge-low" role="separator" aria-label={t("Drag to change the height")} data-testid={`low-${one.key}`}
                  onPointerDown={(event) => take(event, one.key, "height")} />
                <span className="fl-edge-corner" aria-label={t("Drag to resize")} data-testid={`both-${one.key}`}
                  onPointerDown={(event) => take(event, one.key, "size")} />
              </>
            )}
          </div>
        ))}
      </div>
    </>
  );
}

/* ================================================================= page */

function PageBoard({ screen, catalogue, drawn, notices }: Props) {
  const t = useT();
  const a = useArrangement(screen, catalogue, drawn);
  const gridRef = useRef<HTMLDivElement | null>(null);
  const [hold, setHold] = useState<Hold | null>(null);
  const lastSwap = useRef(0);

  // The order in which a reader meets them. The stored places only decide
  // that and the width; a container is as tall as what is in it.
  const placed = a.editing !== null ? sequenced(a.shown) : sequenced(settle(placeAll(a.shown), ""));

  const columnWidth = () => {
    const grid = gridRef.current;
    if (!grid) return 0;
    const gap = parseFloat(getComputedStyle(grid).columnGap || "20") || 20;
    return (grid.getBoundingClientRect().width - gap * (BOARD_COLUMNS - 1)) / BOARD_COLUMNS;
  };

  const begin = () => a.setEditing([
    ...sequenced(settle(placeAll(a.shown), "")).map((one, index) => ({ ...one, y: index, x: 0 })),
    ...a.hidden,
  ]);

  const take = (event: ReactPointerEvent, key: string, mode: Hold["mode"]) => {
    if (a.editing === null) return;
    const start = placed.find((one) => one.key === key);
    if (!start) return;
    (event.target as Element).setPointerCapture?.(event.pointerId);
    setHold({ key, mode, fromX: event.clientX, fromY: event.clientY, start });
    event.preventDefault();
  };

  const widen = (key: string, by: number) => {
    if (a.editing === null) return;
    a.setEditing(a.current.map((one) => (
      one.key === key ? { ...one, width: Math.min(Math.max(one.width + by, 1), BOARD_COLUMNS) } : one
    )));
  };

  const moveTo = (event: ReactPointerEvent) => {
    if (!hold || a.editing === null) return;
    if (hold.mode !== "move") {
      const column = columnWidth();
      if (column <= 0) return;
      const width = Math.min(Math.max(hold.start.width + Math.round((event.clientX - hold.fromX) / column), 1), BOARD_COLUMNS);
      a.setEditing(a.current.map((one) => (one.key === hold.key ? { ...one, width } : one)));
      return;
    }
    // The container takes the place of the one under the pointer and the
    // rest close up around it. Not faster than a person can see: a tall
    // container dragged over a short one reflows what is under the
    // pointer, and without this it swapped back and forth every frame.
    if (lastSwap.current !== 0 && event.timeStamp - lastSwap.current < 140) return;
    const under = document.elementFromPoint?.(event.clientX, event.clientY)?.closest("[data-held-key]");
    const target = under?.getAttribute("data-held-key");
    if (!target || target === hold.key) return;
    const order = sequenced(a.shown);
    const from = order.findIndex((one) => one.key === hold.key);
    const to = order.findIndex((one) => one.key === target);
    if (from < 0 || to < 0) return;
    const [moving] = order.splice(from, 1);
    order.splice(to, 0, moving);
    lastSwap.current = event.timeStamp;
    a.setEditing([...order.map((one, index) => ({ ...one, y: index, x: 0 })), ...a.hidden]);
  };

  const letGo = () => setHold(null);
  const editing = a.editing !== null;

  return (
    <>
      {notices}
      <ArrangeButton a={a} begin={begin} />
      {a.layout.data !== undefined && (
        <ArrangeBar a={a} catalogue={catalogue} hint={t("Hold a name to move a container; widen it with the arrows or by its right edge.")} />
      )}
      <div
        ref={gridRef}
        className={["fl-grid", "fl-placed", "fl-flowing", editing ? "fl-editing" : "", hold ? "fl-holding" : ""].join(" ").trim()}
        onPointerMove={hold ? moveTo : undefined}
        onPointerUp={hold ? letGo : undefined}
        onPointerCancel={hold ? letGo : undefined}
        data-testid="board"
      >
        {placed.map((one) => (
          <div
            key={one.key}
            className={["fl-held", hold?.key === one.key ? "fl-dragging" : ""].join(" ").trim()}
            style={{ gridColumn: `span ${one.width}` }}
            data-held-key={one.key}
            data-testid={editing ? `held-${one.key}` : undefined}
          >
            {editing && (
              <div className="fl-grip">
                <span
                  className="fl-grip-handle"
                  onPointerDown={(event) => take(event, one.key, "move")}
                  title={t("Hold to move this container")}
                  data-testid={`grip-${one.key}`}
                >
                  <span aria-hidden="true">⠿</span>
                  <span className="fl-grip-name">{t(a.titleOf(one.key))}</span>
                </span>
                <span className="fl-grip-width" role="group" aria-label={t("Width")}>
                  <button type="button" className="fl-plain" disabled={one.width <= 1} onClick={() => widen(one.key, -1)}
                    aria-label={t("Narrower")} data-testid={`narrower-${one.key}`}>−</button>
                  <span className="fl-grip-size" data-testid={`width-${one.key}`}>{one.width}/{BOARD_COLUMNS}</span>
                  <button type="button" className="fl-plain" disabled={one.width >= BOARD_COLUMNS} onClick={() => widen(one.key, 1)}
                    aria-label={t("Wider")} data-testid={`wider-${one.key}`}>+</button>
                </span>
                <button
                  type="button"
                  className="fl-word"
                  onClick={() => a.setEditing(a.current.map((on) => (on.key === one.key ? { ...on, hidden: true } : on)))}
                  title={t("Take this container off the screen")}
                >
                  {t("Remove")}
                </button>
              </div>
            )}
            <div className="fl-held-body">{drawn[one.key]}</div>
            {editing && (
              <span className="fl-edge" role="separator" aria-label={t("Drag to resize")} data-testid={`corner-${one.key}`}
                onPointerDown={(event) => take(event, one.key, "width")} />
            )}
          </div>
        ))}
      </div>
    </>
  );
}

