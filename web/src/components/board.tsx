import { useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../lib/api";
import { useToast } from "./Toast";
import { useT } from "../i18n";

/**
 * A screen the installation arranges for itself: which widgets it draws, in
 * what order and how wide each one is.
 *
 * The arrangement belongs to the installation rather than to each person. An
 * operations screen people talk to each other over ("look at the second
 * tile") stops working when everyone sees a different second tile, and a
 * per-person layout would have to be taught to every new account.
 */

export type BoardWidget = {
  key: string;
  /** Of the twelve columns. */
  width: number;
  /** In rows of the board; absent means the one row every tile starts with. */
  height?: number;
  /**
   * Taken off the screen on purpose. It stays in the arrangement so that
   * "somebody removed this" and "this did not exist when the arrangement
   * was made" remain two different answers - which is what lets a panel
   * added by an upgrade appear without undoing anybody's decision.
   */
  hidden?: boolean;
};

export type StoredBoard = {
  widgets: BoardWidget[];
  present: boolean;
  updated_at?: string;
  updated_by?: string;
  revision?: number;
  reason?: string;
};

/** One widget the screen can draw: how it is named when picked, and its own width. */
export type BoardEntry = { key: string; title: string; width: number };

/**
 * The widths the twelve-column grid has a class for: every one of them.
 *
 * It was five - 3, 4, 6, 8, 12 - because the stylesheet had five classes,
 * and the server refused the rest. The rows worth building are the uneven
 * ones, so the ladder is now every column from one to twelve, and the server
 * holds to the same twelve.
 */
export const BOARD_WIDTHS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
/** How many rows of the board a tile may take. Its content scrolls inside. */
export const BOARD_HEIGHTS = { min: 1, max: 16 };

/** The next width up or down, staying on the grid at the ends. */
export function widthStep(width: number, by: number): number {
  return Math.max(BOARD_WIDTHS[0], Math.min(BOARD_WIDTHS[BOARD_WIDTHS.length - 1], width + by));
}

export function heightStep(height: number | undefined, by: number): number {
  return Math.max(BOARD_HEIGHTS.min, Math.min(BOARD_HEIGHTS.max, (height ?? 1) + by));
}

/**
 * What is drawn: the stored arrangement, with the widgets this panel cannot
 * draw left out, and the panel's own order when nothing is stored.
 *
 * A key the panel does not know is skipped rather than refused - that is what
 * lets a record written by a newer panel still draw on an older one - and a
 * widget the record does not carry is simply not on the screen.
 */
export function boardToDraw(
  stored: StoredBoard | undefined, catalogue: BoardEntry[], known: Set<string>,
): BoardWidget[] {
  if (!stored || !stored.present || stored.widgets.length === 0) {
    return catalogue.filter((one) => known.has(one.key)).map((one) => ({ key: one.key, width: one.width }));
  }
  const placed = stored.widgets.filter((one) => known.has(one.key) && !one.hidden);
  const decided = new Set(stored.widgets.map((one) => one.key));

  // A panel the stored arrangement says nothing about did not exist when
  // somebody arranged this screen: it arrived with an upgrade. Leaving it
  // out would make every panel this product ever adds invisible to every
  // installation that has arranged that screen once, and nobody would know
  // to go looking. A panel somebody removed carries hidden and stays away:
  // the two are deliberately not the same record.
  //
  // Where it goes matters as much as that it appears. At the end it would
  // be buried: a row of headline tiles added above six existing panels
  // would arrive under the tables at the bottom. So it lands beside the
  // catalogue neighbour it shipped next to - after the nearest earlier
  // panel that is on the screen, or at the front when there is none - and
  // an arrangement somebody made keeps its own order around it.
  const result = [...placed];
  for (let i = 0; i < catalogue.length; i += 1) {
    const entry = catalogue[i];
    if (!known.has(entry.key) || decided.has(entry.key)) continue;
    // After everything that ships before it and is on the screen - not
    // merely after the nearest one. With the nearest, a newcomer jumped
    // over a panel somebody had deliberately moved earlier.
    let at = 0;
    for (let before = 0; before < i; before += 1) {
      const neighbour = result.findIndex((one) => one.key === catalogue[before].key);
      if (neighbour !== -1 && neighbour + 1 > at) at = neighbour + 1;
    }
    result.splice(at, 0, { key: entry.key, width: entry.width });
  }
  return result;
}

export function Board({
  screen, catalogue, drawn,
}: {
  /** The name the arrangement is stored under. */
  screen: string;
  catalogue: BoardEntry[];
  /** What each widget draws, by key. A key with nothing to draw - undefined,
      null or the false of a `{condition && ...}` - is not shown. */
  drawn: Record<string, ReactNode>;
}) {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  // What this screen has to draw right now. A panel that renders nothing -
  // because the condition behind it is false, as a form that is not open -
  // is not placed at all, rather than placed as an empty cell. `false` is
  // among those: `{open && <Card/>}` yields false, not undefined, and a
  // board that took it for a node left a hole in the row where a closed
  // form used to be.
  const known = new Set(Object.keys(drawn).filter((key) => {
    const node = drawn[key];
    return node !== undefined && node !== null && node !== false;
  }));
  const [editing, setEditing] = useState<BoardWidget[] | null>(null);
  // Which tile is under the hand, and which one it is over: dragging is how
  // a board is arranged, and the arrows it replaced were a click per place.
  const [dragging, setDragging] = useState<number | null>(null);
  const [over, setOver] = useState<number | null>(null);
  const [reason, setReason] = useState("");
  const [showEarlier, setShowEarlier] = useState(false);

  const layout = useQuery({
    queryKey: ["screen-layout", screen],
    queryFn: () => api.get<StoredBoard>(`/api/v1/settings/layout/${screen}`),
    retry: false,
  });
  // The arrangement changes what everybody sees, so the write carries the
  // reason the trail will keep and the revision it was read at. A second
  // administrator who saved meanwhile wins, and this one is told rather than
  // having their work vanish.
  const save = useMutation({
    mutationFn: (widgets: BoardWidget[]) =>
      api.put<StoredBoard>(`/api/v1/settings/layout/${screen}`, {
        widgets, reason: reason.trim(), revision: layout.data?.revision ?? 0,
      }),
    onSuccess: () => {
      setEditing(null);
      setReason("");
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
  // Back to the arrangement the panel ships with. It is a change like any
  // other: a reason, the trail, and the previous one kept.
  const reset = useMutation({
    mutationFn: () => api.del(`/api/v1/settings/layout/${screen}?reason=${encodeURIComponent(reason.trim())}`),
    onSuccess: () => {
      setEditing(null);
      setReason("");
      void queryClient.invalidateQueries({ queryKey: ["screen-layout", screen] });
      toast.success(t("The screen is back to the arrangement the panel ships with."));
    },
    onError: (error) => toast.error(error instanceof Error ? error.message : String(error)),
  });

  const current = editing ?? boardToDraw(layout.data, catalogue, known);
  // The editor works on what is on the screen; the hidden ones ride along
  // in the saved record so the decision to remove them is not lost.
  const shown = current.filter((one) => !one.hidden);
  const titleOf = (key: string) => catalogue.find((one) => one.key === key)?.title ?? key;
  const move = (index: number, by: number) => reorder(index, index + by);
  // The editor's indices are into what is on the screen; the record also
  // holds the hidden ones, so a change is applied by key rather than by
  // position - with hidden panels in the list, position lies.
  const resize = (index: number, change: Partial<BoardWidget>) => {
    const key = shown[index]?.key;
    if (!key) return;
    setEditing(current.map((one) => (one.key === key ? { ...one, ...change } : one)));
  };
  /**
   * The tile that was picked up lands where it was dropped, and everything
   * between shifts up or down by one - the way a card moves in a hand, not
   * the way two cards swap places. Swapping is what the arrows did, and over
   * three places it leaves the ones in between where they were.
   */
  const reorder = (from: number, to: number) => {
    if (to < 0 || to >= shown.length || from === to) return;
    const order = [...shown];
    const [moved] = order.splice(from, 1);
    order.splice(to, 0, moved);
    // The visible ones in their new order, then the hidden ones, so the
    // record keeps every decision and the screen keeps the arrangement.
    setEditing([...order, ...current.filter((one) => one.hidden)]);
  };
  // What the editor may add back: a panel this screen can draw that is not
  // on it - whether it was never placed or deliberately taken off.
  const absent = catalogue.filter(
    (one) => known.has(one.key) && !shown.some((placed) => placed.key === one.key),
  );

  return (
    <>
      {layout.data !== undefined && (
        <div className="layout-bar">
          {editing === null ? (
            <button className="secondary" onClick={() => setEditing(current)}>{t("Arrange this screen")}</button>
          ) : (
            <>
              {/* A reason, because the trail keeps one for every change that
                  reaches other people, and this one reaches all of them. */}
              <input
                className="layout-reason"
                placeholder={t("why this arrangement (for the trail)")}
                value={reason}
                onChange={(event) => setReason(event.target.value)}
                data-testid="board-reason"
              />
              <button
                onClick={() => save.mutate(current)}
                disabled={save.isPending || current.length === 0 || reason.trim().length < 8}
                data-testid="board-save"
              >
                {save.isPending ? t("storing…") : t("Store this arrangement for everybody")}
              </button>
              <button className="secondary" onClick={() => { setEditing(null); setReason(""); }}>{t("Back")}</button>
              {layout.data?.present && (
                <button
                  className="danger"
                  disabled={reset.isPending || reason.trim().length < 8}
                  onClick={() => reset.mutate()}
                  data-testid="board-reset"
                  title={t("Everybody goes back to the arrangement the panel ships with.")}
                >
                  {t("Back to the panel's own")}
                </button>
              )}
              {absent.length > 0 && (
                <select
                  value=""
                  onChange={(event) => {
                    const one = catalogue.find((item) => item.key === event.target.value);
                    if (!one) return;
                    // It may be in the record already, hidden; putting it
                    // back is unhiding it, not placing a second copy.
                    setEditing(current.some((placed) => placed.key === one.key)
                      ? current.map((placed) => placed.key === one.key ? { ...placed, hidden: false } : placed)
                      : [...current, { key: one.key, width: one.width }]);
                  }}
                  data-testid="board-add"
                >
                  <option value="">{t("Add a widget…")}</option>
                  {absent.map((one) => <option key={one.key} value={one.key}>{t(one.title)}</option>)}
                </select>
              )}
              <button className="secondary" onClick={() => setShowEarlier(!showEarlier)} data-testid="board-earlier">
                {t("Earlier arrangements")}
              </button>
              <span className="source">{t("Drag a tile by its bar to move it. The arrangement is the installation's: everybody sees it.")}</span>
            </>
          )}
        </div>
      )}
      <div
        className={["widgets", "arranged", dragging !== null ? "dragging-over" : ""].join(" ").trim()}
        /* The empty part of the board is a place to drop a tile too: dropped
           where nothing is, it goes to the end of the order, and the dense
           flow then pulls it into the first hole it fits. Without this a
           tile could only be dropped onto another tile. */
        onDragOver={(event) => { if (dragging !== null) event.preventDefault(); }}
        onDrop={(event) => {
          event.preventDefault();
          if (dragging !== null) reorder(dragging, current.length - 1);
          setDragging(null);
          setOver(null);
        }}
        data-testid="board-grid"
      >
        {shown.map((placed, index) => (
          <div
            key={placed.key}
            style={{ gridRow: `span ${placed.height ?? 1}` }}
            /* A height somebody chose is a box of that height, and the
               content scrolls inside it: a list that grows by ten rows must
               not push every panel below it down the screen. A tile nobody
               gave a height to is still as tall as what it holds. */
            data-rows={placed.height ? placed.height : undefined}
            className={[
              `span-${placed.width}`,
              dragging === index ? "dragging" : "",
              over === index && dragging !== null && dragging !== index ? "drop-here" : "",
            ].join(" ").trim()}
            draggable={editing !== null}
            onDragStart={(event) => {
              setDragging(index);
              // Firefox starts no drag at all without something to carry.
              event.dataTransfer.setData("text/plain", placed.key);
              event.dataTransfer.effectAllowed = "move";
            }}
            onDragOver={(event) => {
              if (dragging === null) return;
              event.preventDefault();
              setOver(index);
            }}
            onDrop={(event) => {
              event.preventDefault();
              // The board behind would otherwise take the same drop and send
              // the tile to the end instead of to the place it was aimed at.
              event.stopPropagation();
              if (dragging !== null) reorder(dragging, index);
              setDragging(null);
              setOver(null);
            }}
            onDragEnd={() => { setDragging(null); setOver(null); }}
            data-testid={editing !== null ? "board-tile" : undefined}
          >
            {editing !== null && (
              <div className="widget-handle" data-testid="widget-handle">
                <span className="widget-grip" aria-hidden="true">⠿</span>
                <span>{t(titleOf(placed.key))}</span>
                {/* Wider and narrower, taller and shorter. A tile that holds
                    little is given one row, and two of them stand one under
                    another in the space a taller neighbour leaves. */}
                <span className="widget-size">
                  <button
                    className="secondary" aria-label={t("Narrower")} title={t("Narrower")}
                    disabled={placed.width === BOARD_WIDTHS[0]}
                    onClick={() => resize(index, { width: widthStep(placed.width, -1) })}
                  >←</button>
                  <span className="widget-size-value">{t("{n} of 12", { n: placed.width })}</span>
                  <button
                    className="secondary" aria-label={t("Wider")} title={t("Wider")}
                    disabled={placed.width === BOARD_WIDTHS[BOARD_WIDTHS.length - 1]}
                    onClick={() => resize(index, { width: widthStep(placed.width, 1) })}
                  >→</button>
                </span>
                <span className="widget-size">
                  <button
                    className="secondary" aria-label={t("Shorter")} title={t("Shorter")}
                    disabled={(placed.height ?? 1) <= BOARD_HEIGHTS.min}
                    onClick={() => resize(index, { height: heightStep(placed.height, -1) })}
                  >↑</button>
                  <span className="widget-size-value">{t("{n} rows", { n: placed.height ?? 1 })}</span>
                  <button
                    className="secondary" aria-label={t("Taller")} title={t("Taller")}
                    disabled={(placed.height ?? 1) >= BOARD_HEIGHTS.max}
                    onClick={() => resize(index, { height: heightStep(placed.height, 1) })}
                  >↓</button>
                </span>
                {/* The mouse drags; the keyboard still has to be able to
                    move a tile, so the handle answers the arrow keys. */}
                <span
                  className="widget-keys"
                  tabIndex={0}
                  role="button"
                  aria-label={t("Move with the arrow keys")}
                  onKeyDown={(event) => {
                    if (event.key === "ArrowLeft") { event.preventDefault(); move(index, -1); }
                    if (event.key === "ArrowRight") { event.preventDefault(); move(index, 1); }
                  }}
                  data-testid="widget-keys"
                >
                  ← →
                </span>
                <button
                  className="secondary"
                  onClick={() => setEditing(current.map((one) =>
                    one.key === placed.key ? { ...one, hidden: true } : one))}
                >
                  {t("Remove")}
                </button>
              </div>
            )}
            {drawn[placed.key]}
          </div>
        ))}
      </div>
    </>
  );
}
