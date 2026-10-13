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
  const move = (index: number, by: number) => {
    const next = [...current];
    const target = index + by;
    if (target < 0 || target >= next.length) return;
    [next[index], next[target]] = [next[target], next[index]];
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
              <span className="source">{t("The arrangement is the installation's: everybody sees it.")}</span>
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
          <div key={placed.key} className={`span-${placed.width}`}>
            {editing !== null && (
              <div className="widget-handle" data-testid="widget-handle">
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
                <button className="secondary" onClick={() => move(index, -1)} disabled={index === 0}>←</button>
                <button className="secondary" onClick={() => move(index, 1)} disabled={index === current.length - 1}>→</button>
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
