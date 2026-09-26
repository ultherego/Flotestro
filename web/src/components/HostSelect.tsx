import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { useMatch, useNavigate } from "react-router-dom";
import { keepPreviousData, useQueries, useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { Host } from "../lib/types";
import { useCapabilities } from "../lib/capabilities";
import { useDebounced } from "../lib/debounce";
import { isStringList, readStored, useStoredState } from "../lib/storage";
import { DEFAULT_MODULE } from "../lib/modules";
import { hostPath } from "./HostPicker";
import { useT } from "../i18n";
import { Icon } from "./icons";

/** How many hosts of the fleet one answer of the server holds; more is a narrower query away. */
export const LIMIT = 20;
/** How many recently opened hosts are kept; the key is the palette's, so the number is too. */
const RECENT = 8;
/** How many starred hosts the selector resolves before a letter is typed. */
const FAVOURITES_SHOWN = 12;
/** The pause in typing before the server is asked. */
const DEBOUNCE = 250;
/** The browser keys of the remembered hosts, shared with the command palette. */
export const RECENT_KEY = "flotestro.hosts.recent";
export const FAVOURITES_KEY = "flotestro.hosts.favourites";

/** The heading of a group of rows; English, translated when drawn. */
export type HostGroup = "Favourites" | "Recent" | "Hosts";

/** A row of the selector: always a host, under one of three headings. */
export type HostRow = {
  key: string;
  group: HostGroup;
  host: Host;
};

/** The site and the environment of a host as one line, whichever of them is known. */
export function hostMeta(host: Pick<Host, "site" | "environment">): string {
  return [host.site, host.environment].filter(Boolean).join(" / ");
}

/**
 * Whether a host answers the query by its name or its management address:
 * the two things an operator types when they mean a host.
 */
export function matchesHost(host: Pick<Host, "hostname" | "management_address">, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  return host.hostname.toLowerCase().includes(needle) || (host.management_address ?? "").toLowerCase().includes(needle);
}

/**
 * The rows of the selector: the starred hosts first, then the ones opened
 * last, then the fleet as the server listed it, each host once under the
 * first heading it belongs to.
 */
export function selectRows(
  favourites: string[],
  recent: string[],
  byID: Map<string, Host>,
  fleet: Host[],
  query: string,
): HostRow[] {
  const rows: HostRow[] = [];
  const seen = new Set<string>();
  const add = (host: Host | undefined, group: HostGroup) => {
    if (!host || seen.has(host.id)) return;
    seen.add(host.id);
    rows.push({ key: `${group}:${host.id}`, group, host });
  };
  for (const id of favourites) {
    const host = byID.get(id);
    if (host && matchesHost(host, query)) add(host, "Favourites");
  }
  for (const id of recent) {
    const host = byID.get(id);
    if (host && matchesHost(host, query)) add(host, "Recent");
  }
  for (const host of fleet) add(host, "Hosts");
  return rows;
}

/** The list with the host at its front and the oldest dropped past the limit. */
export function remember(list: string[], id: string, limit = RECENT): string[] {
  return [id, ...list.filter((entry) => entry !== id)].slice(0, limit);
}

/** The list with the host starred if it was not, and unstarred if it was. */
export function toggled(list: string[], id: string): string[] {
  return list.includes(id) ? list.filter((entry) => entry !== id) : [...list, id];
}

/**
 * Where the highlight goes for a key of the list: one row up or down,
 * clamped to the ends, or the first or the last row.
 */
export function step(key: string, index: number, length: number): number | undefined {
  if (length === 0) return undefined;
  switch (key) {
    case "ArrowDown": return Math.min(length - 1, index + 1);
    case "ArrowUp": return Math.max(0, index - 1);
    case "Home": return 0;
    case "End": return length - 1;
    default: return undefined;
  }
}

/** The first segment of the rest of a host address: the open module, or "" on the overview. */
export function moduleSegment(rest: string | undefined): string {
  return (rest ?? "").split("/")[0] ?? "";
}

/**
 * The host selector: the second box of the top bar, beside the command
 * palette.
 */
export function HostSelect() {
  const t = useT();
  const navigate = useNavigate();
  const installation = useCapabilities();

  // The address says whether the operator works on a host and in which
  // module: /hosts/<id>/<segment>. "new" is a screen, not an identifier.
  const match = useMatch("/hosts/:id/*");
  const urlID = match?.params.id ?? "";
  const onHost = urlID !== "" && urlID !== "new";
  const segment = onHost ? (moduleSegment(match?.params["*"]) || DEFAULT_MODULE) : "";

  // The host in the address, under the key the host workspace and the
  // shell use, so this is a read of the cache rather than a request.
  const fromAddress = useQuery({
    queryKey: ["host", urlID],
    queryFn: () => api.get<Host>(`/api/v1/hosts/${urlID}`),
    enabled: onHost,
  });
  const selected = onHost ? fromAddress.data : undefined;

  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [highlight, setHighlight] = useState(0);
  const [armed, setArmed] = useState(false);
  const container = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const listID = useId();

  // The remembered hosts are the palette's: the same keys, so a star here is
  // a star there.
  const [favourites, setFavourites] = useStoredState<string[]>(FAVOURITES_KEY, [], isStringList);
  const [recent, setRecent] = useStoredState<string[]>(RECENT_KEY, [], isStringList);

  const toggleFavourite = (id: string) => setFavourites(toggled(readStored(FAVOURITES_KEY, favourites, isStringList), id));

  // The remembered hosts are read one by one under the key the host
  // workspace uses, so a host just visited costs nothing; the requests go
  // out once the list is first opened, not on every screen.
  const remembered = useMemo(() => {
    const ids = [...favourites.slice(0, FAVOURITES_SHOWN)];
    for (const id of recent) if (!ids.includes(id)) ids.push(id);
    return ids;
  }, [favourites, recent]);
  const records = useQueries({
    queries: remembered.map((id) => ({
      queryKey: ["host", id],
      queryFn: () => api.get<Host>(`/api/v1/hosts/${id}`),
      staleTime: 60_000,
      retry: false,
      enabled: armed,
    })),
  });
  const byID = new Map<string, Host>();
  records.forEach((record, index) => { if (record.data) byID.set(remembered[index], record.data); });

  // The fleet, by name, narrowed by the text once the typing pauses; the
  // last answer stays on the screen while the next is on its way, so the
  // list does not empty between keystrokes.
  const settled = useDebounced(query.trim(), DEBOUNCE);
  const fleet = useQuery({
    queryKey: ["hosts", "select", settled, LIMIT],
    queryFn: () => api.get<{ items: Host[] }>(
      `/api/v1/hosts?${settled ? `q=${encodeURIComponent(settled)}&` : ""}limit=${LIMIT}&sort=hostname`,
    ),
    enabled: armed,
    staleTime: 30_000,
    retry: false,
    placeholderData: keepPreviousData,
  });

  const rows = useMemo(
    () => selectRows(favourites.slice(0, FAVOURITES_SHOWN), recent, byID, fleet.data?.items ?? [], query),
    [favourites, recent, records, fleet.data, query], // eslint-disable-line react-hooks/exhaustive-deps
  );

  // Ctrl+Shift+K (Cmd+Shift+K on a Mac) opens the selector from anywhere.
  useEffect(() => {
    const onKeyDown = (event: globalThis.KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.shiftKey && event.key.toLowerCase() === "k") {
        event.preventDefault();
        event.stopPropagation();
        show();
      }
    };
    document.addEventListener("keydown", onKeyDown, true);
    return () => document.removeEventListener("keydown", onKeyDown, true);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // The highlight follows the rows: the first one is the one Enter takes,
  // so it must never point past the end of a shorter list.
  useEffect(() => {
    setHighlight(0);
  }, [settled, fleet.data]);

  useEffect(() => {
    if (!open) return;
    input.current?.focus();
    const onPointer = (event: MouseEvent) => {
      if (!container.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onPointer);
    return () => document.removeEventListener("mousedown", onPointer);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    document.getElementById(`${listID}-${highlight}`)?.scrollIntoView({ block: "nearest" });
  }, [open, highlight, listID]);

  function show() {
    // The palette may have starred or opened a host since this list last
    // looked; its copy in the browser is the one that counts.
    setFavourites(readStored(FAVOURITES_KEY, [], isStringList));
    setRecent(readStored(RECENT_KEY, [], isStringList));
    setArmed(true);
    setQuery("");
    setOpen(true);
  }

  function choose(row: HostRow) {
    setOpen(false);
    setRecent(remember(readStored(RECENT_KEY, recent, isStringList), row.host.id));
    if (selected && row.host.id === selected.id) return;
    const target = hostPath({ id: row.host.id, host: row.host }, segment, installation);
    navigate(target.path, target.state ? { state: target.state } : undefined);
  }

  function onKey(event: KeyboardEvent) {
    if (event.key === "Escape") {
      event.preventDefault();
      setOpen(false);
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      const target = rows[highlight];
      if (target) choose(target);
      return;
    }
    const next = step(event.key, highlight, rows.length);
    if (next !== undefined) {
      event.preventDefault();
      setHighlight(next);
    }
  }

  const loadingRemembered = remembered.length > 0 && records.some((record) => record.isLoading);
  const truncated = (fleet.data?.items.length ?? 0) >= LIMIT;
  const label = selected ? selected.hostname : t("Select host…");

  return (
    <div className="host-picker host-select" ref={container}>
      <button
        type="button"
        className={selected ? "host-picker-trigger host-select-trigger on-host" : "host-picker-trigger host-select-trigger"}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={t("Select a host")}
        title={`${t("Select a host")} (Ctrl Shift K)`}
        onClick={() => (open ? setOpen(false) : show())}
      >
        <Icon name="hosts" />
        <span className="host-picker-placeholder">{label}</span>
        <kbd className="host-picker-key">Ctrl ⇧ K</kbd>
      </button>

      {open && (
        <div className="host-picker-popover">
          <div className="host-picker-search">
            <Icon name="search" />
            <input
              ref={input}
              type="text"
              value={query}
              placeholder={t("Host name or address…")}
              aria-label={t("Select a host")}
              aria-controls={listID}
              aria-activedescendant={rows.length ? `${listID}-${highlight}` : undefined}
              onChange={(event) => setQuery(event.target.value)}
              onKeyDown={onKey}
            />
          </div>
          <ul id={listID} role="listbox" className="host-picker-list" aria-label={t("Hosts")}>
            {rows.map((row, index) => {
              const current = selected?.id === row.host.id;
              const starred = favourites.includes(row.host.id);
              return (
                <li
                  key={row.key}
                  id={`${listID}-${index}`}
                  role="option"
                  aria-selected={current}
                  className={[
                    "host-picker-item",
                    index === highlight ? "highlighted" : "",
                    current ? "current" : "",
                    // The first row of a group carries the heading.
                    index === 0 || rows[index - 1].group !== row.group ? `group-start group-${row.group.toLowerCase()}` : "",
                  ].join(" ").trim()}
                  data-group={t(row.group)}
                  data-kind="hosts"
                  onMouseEnter={() => setHighlight(index)}
                  onMouseDown={(event) => event.preventDefault()}
                  onClick={() => choose(row)}
                >
                  <ConnectionDot state={row.host.connection_state} />
                  <span className="host-picker-name">{row.host.hostname}</span>
                  {row.host.management_address && <span className="host-picker-address">{row.host.management_address}</span>}
                  <span className="host-picker-meta">{hostMeta(row.host)}</span>
                  <button
                    type="button"
                    className={starred ? "host-picker-star on" : "host-picker-star"}
                    aria-pressed={starred}
                    title={starred ? t("Remove from favourites") : t("Add to favourites")}
                    onMouseDown={(event) => event.preventDefault()}
                    onClick={(event) => { event.stopPropagation(); toggleFavourite(row.host.id); }}
                  >
                    <Icon name="star" />
                  </button>
                </li>
              );
            })}
          </ul>
          {/* The states of the list stand where the rows would: a silent
              empty box does not say whether nothing matched or nothing
              arrived. */}
          {(loadingRemembered || fleet.isLoading) && <p className="host-picker-note">{t("Loading…")}</p>}
          {fleet.error && (
            <p className="host-picker-note error">
              {t("Could not load hosts: {message}", { message: fleet.error instanceof Error ? fleet.error.message : String(fleet.error) })}
            </p>
          )}
          {fleet.data && rows.length === 0 && (
            <p className="host-picker-note">{settled ? t("No host matches the query.") : t("No host is enrolled yet")}</p>
          )}
          {truncated && (
            <p className="host-picker-note">{t("Showing the first {count} hosts; a longer query narrows the rest.", { count: LIMIT })}</p>
          )}
        </div>
      )}
    </div>
  );
}

/** The connection state as a dot, in the same colours as the badge. */
function ConnectionDot({ state }: { state: Host["connection_state"] }) {
  const kind = state === "online" ? "ok" : state === "offline" ? "error" : state === "stale" ? "warn" : "unknown";
  return <span className={`dot ${kind}`} title={state} />;
}
