import { useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useToast } from "./Toast";
import { Masonry } from "./masonry";
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

export type BoardWidget = { key: string; width: number };

export type StoredBoard = {
  widgets: BoardWidget[];
  present: boolean;
  updated_at?: string;
  updated_by?: string;
  revision?: number;
};

/** One widget the screen can draw: how it is named when picked, and its own width. */
export type BoardEntry = { key: string; title: string; width: number };

/** The widths the twelve-column grid has a class for. */
export const BOARD_WIDTHS = [3, 4, 6, 8, 12];

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
  return stored.widgets.filter((one) => known.has(one.key));
}

export function Board({
  screen, catalogue, drawn, weights,
}: {
  /** The name the arrangement is stored under. */
  screen: string;
  catalogue: BoardEntry[];
  /** What each widget draws, by key. A key with nothing to draw is not shown. */
  drawn: Record<string, ReactNode>;
  /**
   * How tall each widget of the catalogue is, for the screen nobody has
   * arranged yet: the tiles are then packed into columns so the board has no
   * holes in it. Once there is an arrangement the widths in it decide, and
   * a hole is what somebody chose.
   */
  weights?: Record<string, number>;
}) {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const known = new Set(Object.keys(drawn).filter((key) => drawn[key] !== undefined && drawn[key] !== null));
  const [editing, setEditing] = useState<BoardWidget[] | null>(null);
  // Which tile is under the hand, and which one it is over: dragging is how
  // a board is arranged, and the arrows it replaced were a click per place.
  const [dragging, setDragging] = useState<number | null>(null);
  const [over, setOver] = useState<number | null>(null);

  const layout = useQuery({
    queryKey: ["screen-layout", screen],
    queryFn: () => api.get<StoredBoard>(`/api/v1/settings/layout/${screen}`),
    retry: false,
  });
  const save = useMutation({
    mutationFn: (widgets: BoardWidget[]) =>
      api.put<StoredBoard>(`/api/v1/settings/layout/${screen}`, { widgets }),
    onSuccess: () => {
      setEditing(null);
      void queryClient.invalidateQueries({ queryKey: ["screen-layout", screen] });
      toast.success(t("The screen is arranged this way for everybody who opens it."));
    },
    onError: (error) => toast.error(error instanceof Error ? error.message : String(error)),
  });

  const current = editing ?? boardToDraw(layout.data, catalogue, known);
  // Packed only while nothing is stored and nobody is arranging: the moment
  // a width means something, the grid has to be the thing drawing it.
  const packed = weights !== undefined && editing === null && !(layout.data?.present ?? false);
  const titleOf = (key: string) => catalogue.find((one) => one.key === key)?.title ?? key;
  const move = (index: number, by: number) => reorder(index, index + by);
  /**
   * The tile that was picked up lands where it was dropped, and everything
   * between shifts up or down by one - the way a card moves in a hand, not
   * the way two cards swap places. Swapping is what the arrows did, and over
   * three places it leaves the ones in between where they were.
   */
  const reorder = (from: number, to: number) => {
    if (to < 0 || to >= current.length || from === to) return;
    const next = [...current];
    const [moved] = next.splice(from, 1);
    next.splice(to, 0, moved);
    setEditing(next);
  };
  const absent = catalogue.filter(
    (one) => known.has(one.key) && !current.some((placed) => placed.key === one.key),
  );

  return (
    <>
      {layout.data !== undefined && (
        <div className="layout-bar">
          {editing === null ? (
            <button className="secondary" onClick={() => setEditing(current)}>{t("Arrange this screen")}</button>
          ) : (
            <>
              <button onClick={() => save.mutate(current)} disabled={save.isPending || current.length === 0}>
                {save.isPending ? t("storing…") : t("Store this arrangement for everybody")}
              </button>
              <button className="secondary" onClick={() => setEditing(null)}>{t("Back")}</button>
              {absent.length > 0 && (
                <select
                  value=""
                  onChange={(event) => {
                    const one = catalogue.find((item) => item.key === event.target.value);
                    if (one) setEditing([...current, { key: one.key, width: one.width }]);
                  }}
                  data-testid="board-add"
                >
                  <option value="">{t("Add a widget…")}</option>
                  {absent.map((one) => <option key={one.key} value={one.key}>{t(one.title)}</option>)}
                </select>
              )}
              <span className="source">{t("Drag a tile by its bar to move it. The arrangement is the installation's: everybody sees it.")}</span>
            </>
          )}
        </div>
      )}
      {packed ? (
        <Masonry weights={current.map((placed) => weights?.[placed.key] ?? 1)}>
          {current.map((placed) => <div key={placed.key}>{drawn[placed.key]}</div>)}
        </Masonry>
      ) : (
      <div className="widgets">
        {current.map((placed, index) => (
          <div
            key={placed.key}
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
                <select
                  aria-label={t("Width")}
                  value={placed.width}
                  onChange={(event) => {
                    const next = [...current];
                    next[index] = { ...placed, width: Number(event.target.value) };
                    setEditing(next);
                  }}
                >
                  {BOARD_WIDTHS.map((width) => (
                    <option key={width} value={width}>{t("{n} of 12", { n: width })}</option>
                  ))}
                </select>
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
                <button className="secondary" onClick={() => setEditing(current.filter((one) => one.key !== placed.key))}>
                  {t("Remove")}
                </button>
              </div>
            )}
            {drawn[placed.key]}
          </div>
        ))}
      </div>
      )}
    </>
  );
}
