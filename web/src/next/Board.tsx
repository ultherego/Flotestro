import { useRef, useState, type PointerEvent as ReactPointerEvent, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../lib/api";
import {
  BOARD_COLUMNS, boardToDraw, placeAll,
  type BoardEntry, type BoardWidget, type StoredBoard,
} from "../components/board";
import { useToast } from "../components/Toast";
import { useT } from "../i18n";
import { Icon } from "../components/icons";
import { HeadActions, Problem } from "./kit";

/**
 * A screen somebody lays out for themselves: the containers are put where
 * they are wanted on a twelve-column grid, and each is made wider,
 * narrower, taller or shorter by its own corner.
 *
 * The arrangement belongs to the installation rather than to each person.
 * An operations screen people talk to each other over - "look at the
 * second tile" - stops working when everyone sees a different second
 * tile, so storing one is a change like any other: it carries a reason,
 * it is kept in the trail, and the revision it was read at goes with it
 * so that two administrators cannot overwrite each other silently.
 *
 * The model and the server's contract are the panel's own and are shared
 * with the screen this replaces; what is written here is how it is taken
 * hold of and how it looks while it is being done.
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

/**
 * The containers in the order a reader meets them: by row, then by column.
 *
 * It is the whole of an arrangement now. A container's height is what is
 * in it, so the only things a person can say about one are WHERE it comes
 * and HOW WIDE it is - and that is the same thing in the editor and on the
 * screen, because both lay it out the same way. Until 17.10 the editor
 * snapped containers to fixed rows while the screen laid them out by their
 * content, so a person arranged one board and saved another.
 */
export function sequenced(widgets: BoardWidget[]): BoardWidget[] {
  return [...widgets].sort((a, b) => (a.y ?? 0) - (b.y ?? 0) || (a.x ?? 0) - (b.x ?? 0));
}

/** Positions that say nothing but the order: row i, column 0. */
export function renumbered(widgets: BoardWidget[]): BoardWidget[] {
  return sequenced(widgets).map((one, index) => ({ ...one, x: 0, y: index }));
}

/**
 * The height of one row of the board, in pixels.
 *
 * It is here and in `--row` of the stylesheet, and the two must
 * agree: the grid draws by the first and the corner measures by the
 * second, so a difference makes a container jump as it is sized.
 *
 * It was 152px until 17.10 - the height of a headline tile, on the
 * reasoning that a tile is the smallest thing anybody puts on a board.
 * The reasoning was wrong, and the measurement said so: a cell could
 * only be 152, 324 or 496 tall, so a container whose words ended at
 * 180px had to take 324 and carry a hand's width of empty floor under
 * them. Half of every board was built that way. The row is half that
 * now and a tile is two of them, so a container can be the size of what
 * it holds to within a line of text.
 */
export const ROW = 76;

export function Board({ screen, catalogue, drawn, notices }: {
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
  /**
   * What has to be read before the board is read at all.
   *
   * It stands above the grid rather than in a cell of its own. A notice
   * is not a container somebody arranges, and a cell is a whole row tall
   * whatever it holds - so a one-line banner on the board opened the
   * screen with a hand's width of empty floor under it.
   */
  notices?: ReactNode;
}) {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const known = new Set(Object.keys(drawn).filter((key) => {
    const node = drawn[key];
    return node !== undefined && node !== null && node !== false;
  }));

  const [editing, setEditing] = useState<BoardWidget[] | null>(null);
  const gridRef = useRef<HTMLDivElement | null>(null);
  const [hold, setHold] = useState<
    { key: string; mode: "move" | "size" | "width" | "height"; fromX: number; fromY: number; start: BoardWidget; startPx: number } | null
  >(null);

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

  const current = editing ?? boardToDraw(layout.data, catalogue, known);
  const shown = current.filter((one) => !one.hidden);
  /* Every screen stands on the grid from the first time it is opened,
     with the shape each container ships with. Left to flow, the row of
     containers took whatever height its contents happened to want, and a
     wide screen then read as blocks thrown down rather than as a panel -
     the owner's words, and he is right. A container is as tall as its
     cell and its content scrolls inside it; the corner is there to
     change that. */
  const placed = sequenced(editing !== null ? shown : settle(placeAll(shown), ""));
  const titleOf = (key: string) => catalogue.find((one) => one.key === key)?.title ?? key;
  const absent = catalogue.filter((one) => known.has(one.key) && !shown.some((on) => on.key === one.key));

  /* ------------------------------------------------------------------
     Taking hold.

     The grid's own box gives the width of a column and a row is a
     constant, so a pointer's travel divides into cells. Nothing here is
     a library, and nothing goes stale when the stylesheet changes,
     because the stylesheet is the thing being asked.
     ------------------------------------------------------------------ */

  const columnWidth = () => {
    const box = gridRef.current?.getBoundingClientRect();
    if (!box || !gridRef.current) return 0;
    const gap = parseFloat(getComputedStyle(gridRef.current).columnGap || "20") || 20;
    return (box.width - gap * (BOARD_COLUMNS - 1)) / BOARD_COLUMNS;
  };

  const take = (event: ReactPointerEvent, key: string, mode: "move" | "size" | "width" | "height") => {
    if (editing === null) return;
    const start = placed.find((one) => one.key === key);
    if (!start) return;
    (event.target as Element).setPointerCapture?.(event.pointerId);
    // Where the container is NOW, in pixels: a height is dragged from what
    // is drawn, not from a number the catalogue guessed.
    const box = (event.currentTarget as HTMLElement).closest("[data-held-key]")?.getBoundingClientRect();
    setHold({ key, mode, fromX: event.clientX, fromY: event.clientY, start, startPx: box?.height ?? 0 });
    event.preventDefault();
  };

  const lastSwap = useRef(0);

  const widen = (key: string, by: number) => {
    if (editing === null) return;
    setEditing(current.map((one) => (
      one.key === key ? { ...one, width: Math.min(Math.max(one.width + by, 1), BOARD_COLUMNS) } : one
    )));
  };

  const moveTo = (event: ReactPointerEvent) => {
    if (!hold || editing === null) return;

    if (hold.mode !== "move") {
      // The edges size: the right one widens, the bottom one makes the
      // container at least so tall (what is in it can still push it
      // taller), the corner does both.
      const column = columnWidth();
      const widthWanted = hold.mode === "width" || hold.mode === "size";
      const heightWanted = hold.mode === "height" || hold.mode === "size";
      const width = widthWanted && column > 0
        ? Math.min(Math.max(hold.start.width + Math.round((event.clientX - hold.fromX) / column), 1), BOARD_COLUMNS)
        : hold.start.width;
      const rows = Math.max(Math.round((hold.startPx + event.clientY - hold.fromY) / ROW), 1);
      setEditing(current.map((one) => (
        one.key === hold.key ? { ...one, width, ...(heightWanted ? { height: rows } : {}) } : one
      )));
      return;
    }

    // Moving: the container takes the place of the one under the pointer,
    // and the rest close up around it. Not faster than a person can see -
    // a tall container dragged over a short one reflows what is under the
    // pointer, and without this it swapped back and forth every frame.
    if (event.timeStamp - lastSwap.current < 140) return;
    const under = document.elementFromPoint?.(event.clientX, event.clientY)?.closest("[data-held-key]");
    const target = under?.getAttribute("data-held-key");
    if (!target || target === hold.key) return;
    const visible = sequenced(current.filter((one) => !one.hidden));
    const from = visible.findIndex((one) => one.key === hold.key);
    const to = visible.findIndex((one) => one.key === target);
    if (from < 0 || to < 0) return;
    const [moving] = visible.splice(from, 1);
    visible.splice(to, 0, moving);
    lastSwap.current = event.timeStamp;
    setEditing([...renumbered(visible), ...current.filter((one) => one.hidden)]);
  };

  const letGo = () => setHold(null);

  return (
    <>
      {notices}

      {layout.error instanceof ApiError && layout.error.status >= 500 && (
        <Problem>{t("The stored arrangement could not be read; this is the one the panel ships with.")}</Problem>
      )}

      {layout.data !== undefined && editing === null && (
        <HeadActions>
          <button type="button" className="fl-quiet" onClick={() => setEditing([...renumbered(settle(placeAll(shown), "")), ...current.filter((one) => one.hidden)])} data-testid="arrange">
            <Icon name="dashboard" />
            {t("Arrange this screen")}
          </button>
        </HeadActions>
      )}

      {layout.data !== undefined && editing !== null && (
        <div className="fl-arrange">
          {(
            <>
              <span className="fl-arrange-what">{t("Hold a name to move a container; size it by its right edge, its bottom edge or the corner.")}</span>
              <button
                type="button"
                onClick={() => save.mutate(current)}
                disabled={save.isPending || current.length === 0}
                data-testid="board-save"
              >
                {save.isPending ? t("storing…") : t("Save")}
              </button>
              <button type="button" className="fl-quiet" onClick={() => setEditing(null)}>
                {t("Back")}
              </button>
              {absent.length > 0 && (
                <select
                  value=""
                  onChange={(event) => {
                    const one = catalogue.find((item) => item.key === event.target.value);
                    if (!one) return;
                    // It may be in the record already, hidden: putting it
                    // back is unhiding it, not placing a second copy.
                    setEditing(current.some((on) => on.key === one.key)
                      ? current.map((on) => (on.key === one.key ? { ...on, hidden: false } : on))
                      : [...current, { key: one.key, width: one.width }]);
                  }}
                  data-testid="board-add"
                >
                  <option value="">{t("Add a container…")}</option>
                  {absent.map((one) => <option key={one.key} value={one.key}>{t(one.title)}</option>)}
                </select>
              )}
              {layout.data?.present && (
                <button
                  type="button"
                  className="fl-danger"
                  disabled={reset.isPending}
                  onClick={() => reset.mutate()}
                  data-testid="board-reset"
                  title={t("Everybody goes back to the arrangement the panel ships with.")}
                >
                  {t("Back to the panel's own")}
                </button>
              )}
            </>
          )}
        </div>
      )}

      <div
        ref={gridRef}
        className={[
          "fl-grid",
          "fl-placed",
          "fl-flowing",
          editing !== null ? "fl-editing" : "",
          hold ? "fl-holding" : "",
        ].join(" ").trim()}
        onPointerMove={hold ? moveTo : undefined}
        onPointerUp={hold ? letGo : undefined}
        onPointerCancel={hold ? letGo : undefined}
        data-testid="board"
      >
        {placed.map((one) => {
          // Reading, a container is as tall as what is in it; arranging, it
          // is a cell of fixed rows. The saved places still decide the ORDER
          // and the WIDTH either way - only the height stops being a number
          // somebody had to guess. A guessed number cannot be right: measured
          // at three window widths, 65 of 318 containers changed height by
          // more than a line, one of them from 171px to 843px.
          // The same layout whether the board is read or arranged: a width
          // in columns, and the height the content makes.
          const wanted = one.height !== undefined && one.height !== catalogue.find((on) => on.key === one.key)?.height
            ? one.height : undefined;
          const style = {
            gridColumn: `span ${one.width}`,
            ...(wanted !== undefined ? { minHeight: wanted * ROW } : {}),
          };
          return (
            <div
              key={one.key}
              className={["fl-held", hold?.key === one.key ? "fl-dragging" : ""].join(" ").trim()}
              style={style}
              data-held-key={one.key}
              data-testid={editing !== null ? `held-${one.key}` : undefined}
            >
              {editing !== null && (
                <div className="fl-grip">
                  <span
                    className="fl-grip-handle"
                    onPointerDown={(event) => take(event, one.key, "move")}
                    title={t("Hold to move this container")}
                    data-testid={`grip-${one.key}`}
                  >
                    <span aria-hidden="true">⠿</span>
                    <span className="fl-grip-name">{t(titleOf(one.key))}</span>
                  </span>
                  <span className="fl-grip-width" role="group" aria-label={t("Width")}>
                    <button
                      type="button"
                      className="fl-plain"
                      disabled={one.width <= 1}
                      onClick={() => widen(one.key, -1)}
                      aria-label={t("Narrower")}
                      data-testid={`narrower-${one.key}`}
                    >−</button>
                    <span className="fl-grip-size" data-testid={`width-${one.key}`}>{one.width}/{BOARD_COLUMNS}</span>
                    <button
                      type="button"
                      className="fl-plain"
                      disabled={one.width >= BOARD_COLUMNS}
                      onClick={() => widen(one.key, 1)}
                      aria-label={t("Wider")}
                      data-testid={`wider-${one.key}`}
                    >+</button>
                  </span>
                  <button
                    type="button"
                    className="fl-word"
                    onClick={() => setEditing(current.map((on) => (on.key === one.key ? { ...on, hidden: true } : on)))}
                    title={t("Take this container off the screen")}
                  >
                    {t("Remove")}
                  </button>
                </div>
              )}
              <div className="fl-held-body">{drawn[one.key]}</div>
              {editing !== null && (
                <span
                  className="fl-edge"
                  role="separator"
                  aria-label={t("Drag to resize")}
                  title={t("Drag to resize")}
                  data-testid={`corner-${one.key}`}
                  onPointerDown={(event) => take(event, one.key, "width")}
                />
              )}
              {editing !== null && (
                <>
                  <span
                    className="fl-edge-low"
                    role="separator"
                    aria-label={t("Drag to change the height")}
                    title={t("Drag to change the height")}
                    data-testid={`low-${one.key}`}
                    onPointerDown={(event) => take(event, one.key, "height")}
                  />
                  <span
                    className="fl-edge-corner"
                    aria-label={t("Drag to resize")}
                    title={t("Drag to resize")}
                    data-testid={`both-${one.key}`}
                    onPointerDown={(event) => take(event, one.key, "size")}
                  />
                </>
              )}
            </div>
          );
        })}
      </div>
    </>
  );
}
