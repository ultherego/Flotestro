import { useRef, useState, type PointerEvent as ReactPointerEvent, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../lib/api";
import {
  BOARD_COLUMNS, BOARD_HEIGHTS, BOARD_ROW, boardToDraw, isPlaced, placeAll,
  type BoardEntry, type BoardWidget, type StoredBoard,
} from "../components/board";
import { useToast } from "../components/Toast";
import { useT } from "../i18n";
import { Problem } from "./kit";

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

export function Board({ screen, catalogue, drawn }: {
  /** The name the arrangement is stored under. */
  screen: string;
  catalogue: BoardEntry[];
  /** What each container draws, by key. A key with nothing to draw -
      undefined, null, or the false of `{open && <Card/>}` - is left out
      rather than placed as an empty cell. */
  drawn: Record<string, ReactNode>;
}) {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const known = new Set(Object.keys(drawn).filter((key) => {
    const node = drawn[key];
    return node !== undefined && node !== null && node !== false;
  }));

  const [editing, setEditing] = useState<BoardWidget[] | null>(null);
  const [reason, setReason] = useState("");
  const gridRef = useRef<HTMLDivElement | null>(null);
  const [hold, setHold] = useState<
    { key: string; mode: "move" | "size"; fromX: number; fromY: number; start: BoardWidget } | null
  >(null);

  const layout = useQuery({
    queryKey: ["screen-layout", screen],
    queryFn: () => api.get<StoredBoard>(`/api/v1/settings/layout/${screen}`),
    retry: false,
  });
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
  const shown = current.filter((one) => !one.hidden);
  const placed = placeAll(shown);
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

  const take = (event: ReactPointerEvent, key: string, mode: "move" | "size") => {
    if (editing === null) return;
    const start = placed.find((one) => one.key === key);
    if (!start) return;
    // The first hold on an arrangement that was only ever ordered fixes
    // everybody's place, so nothing jumps as it is picked up.
    if (!isPlaced(current)) {
      setEditing([...placeAll(shown), ...current.filter((one) => one.hidden)]);
    }
    (event.target as Element).setPointerCapture?.(event.pointerId);
    setHold({ key, mode, fromX: event.clientX, fromY: event.clientY, start });
    event.preventDefault();
  };

  const moveTo = (event: ReactPointerEvent) => {
    if (!hold || editing === null) return;
    const column = columnWidth();
    if (column <= 0) return;
    const dx = Math.round((event.clientX - hold.fromX) / column);
    const dy = Math.round((event.clientY - hold.fromY) / BOARD_ROW);
    const start = hold.start;
    const next = { ...start };
    if (hold.mode === "move") {
      next.x = Math.min(Math.max((start.x ?? 0) + dx, 0), BOARD_COLUMNS - start.width);
      next.y = Math.max((start.y ?? 0) + dy, 0);
    } else {
      // The corner: never off the grid, and never smaller than something
      // a person can take hold of again.
      next.width = Math.min(Math.max(start.width + dx, 1), BOARD_COLUMNS - (start.x ?? 0));
      next.height = Math.min(Math.max((start.height ?? 2) + dy, BOARD_HEIGHTS.min), BOARD_HEIGHTS.max);
    }
    setEditing(current.map((one) => (one.key === hold.key ? { ...one, ...next } : one)));
  };

  const letGo = () => setHold(null);

  const ready = reason.trim().length >= 8;

  return (
    <>
      {layout.error instanceof ApiError && layout.error.status >= 500 && (
        <Problem>{t("The stored arrangement could not be read; this is the one the panel ships with.")}</Problem>
      )}

      {layout.data !== undefined && (
        <div className="fl-arrange">
          {editing === null ? (
            <button type="button" className="fl-plain" onClick={() => setEditing(current)} data-testid="arrange">
              {t("Arrange this screen")}
            </button>
          ) : (
            <>
              <input
                className="fl-arrange-reason"
                placeholder={t("why this arrangement (for the trail)")}
                value={reason}
                onChange={(event) => setReason(event.target.value)}
                data-testid="board-reason"
              />
              <button
                type="button"
                onClick={() => save.mutate(current)}
                disabled={save.isPending || current.length === 0 || !ready}
                data-testid="board-save"
              >
                {save.isPending ? t("storing…") : t("Store this arrangement for everybody")}
              </button>
              <button type="button" className="fl-quiet" onClick={() => { setEditing(null); setReason(""); }}>
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
                  disabled={reset.isPending || !ready}
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
          isPlaced(current) ? "fl-placed" : "",
          editing !== null ? "fl-editing" : "",
          hold ? "fl-holding" : "",
        ].join(" ").trim()}
        onPointerMove={hold ? moveTo : undefined}
        onPointerUp={hold ? letGo : undefined}
        onPointerCancel={hold ? letGo : undefined}
        data-testid="board"
      >
        {placed.map((one) => {
          const style = isPlaced(current)
            ? {
                gridColumn: `${(one.x ?? 0) + 1} / span ${one.width}`,
                gridRow: `${(one.y ?? 0) + 1} / span ${one.height ?? 2}`,
              }
            : { gridColumn: `span ${one.width}` };
          return (
            <div
              key={one.key}
              className={["fl-held", hold?.key === one.key ? "fl-dragging" : ""].join(" ").trim()}
              style={style}
              data-testid={editing !== null ? `held-${one.key}` : undefined}
            >
              {editing !== null && (
                <div className="fl-grip" onPointerDown={(event) => take(event, one.key, "move")}>
                  <span className="fl-grip-dots" aria-hidden="true">⠿</span>
                  <span className="fl-grip-name">{t(titleOf(one.key))}</span>
                  <span className="fl-grip-size">{one.width}×{one.height ?? 2}</span>
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
              {drawn[one.key]}
              {editing !== null && (
                <button
                  type="button"
                  className="fl-corner"
                  aria-label={t("Drag to resize")}
                  title={t("Drag to resize")}
                  data-testid={`corner-${one.key}`}
                  onPointerDown={(event) => take(event, one.key, "size")}
                />
              )}
            </div>
          );
        })}
      </div>
    </>
  );
}
