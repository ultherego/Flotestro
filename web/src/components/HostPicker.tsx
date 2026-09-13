import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, type Collection } from "../lib/api";
import type { Host } from "../lib/types";
import { useCapabilities } from "../lib/capabilities";
import { isStringList, useStoredState } from "../lib/storage";
import { module as findModule, DEFAULT_MODULE } from "../pages/host/modules";
import { useT } from "../i18n";
import { Icon } from "./icons";

/** The page size asked of the server; past it the operator narrows the filter. */
const PAGE = 200;
/** How many recently opened hosts are kept; more than a screenful is noise. */
const RECENT = 8;
const RECENT_KEY = "flotestro.hosts.recent";
const FAVOURITES_KEY = "flotestro.hosts.favourites";

/** A row of the list: a host under the heading of its group. */
type Row = { host: Host; group: "favourites" | "recent" | "all" };

const GROUP_TITLES: Record<Row["group"], string> = {
  favourites: "Favourites", recent: "Recent", all: "All hosts",
};

/**
 * The host picker: the search field of the top bar, and the one control
 * for jumping between machines. It reads as a search rather than as the
 * name of the open host, because the trail beside it already names the
 * host; on a narrow screen it folds to an icon that opens the same list.
 *
 * The switch keeps the open module if the new host supports it. Otherwise
 * it leads to the overview and says what was missing - a quiet tab change
 * would look like an interface bug.
 */
export function HostPicker() {
  const t = useT();
  const navigate = useNavigate();
  const location = useLocation();
  const installation = useCapabilities();

  // The address says whether the operator works on a host and in which
  // module: /hosts/<id>/<segment>. "new" is a screen, not an identifier.
  const [, root, urlID = "", urlSegment = ""] = location.pathname.split("/");
  const onHost = root === "hosts" && urlID !== "" && urlID !== "new";
  const segment = onHost ? (urlSegment || DEFAULT_MODULE) : "";

  // The picker has no host in hand, so it asks for the one in the address.
  // The key is the one the host workspace uses, so the request is shared
  // with it rather than doubled.
  const fromAddress = useQuery({
    queryKey: ["host", urlID],
    queryFn: () => api.get<Host>(`/api/v1/hosts/${urlID}`),
    enabled: onHost,
  });
  const selected = onHost ? fromAddress.data : undefined;

  const [open, setOpen] = useState(false);
  // The list is fetched once the picker is first opened, not on every
  // screen: most visits never touch it, and it is one more query the
  // panel would otherwise keep refreshing in the background.
  const [armed, setArmed] = useState(false);
  const [filter, setFilter] = useState("");
  const [highlight, setHighlight] = useState(0);
  const container = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const listID = useId();

  const list = useQuery({
    queryKey: ["hosts", "picker"],
    queryFn: () => api.get<Collection<Host>>(`/api/v1/hosts?limit=${PAGE}`),
    staleTime: 30_000,
    enabled: armed,
  });

  // The hosts this person keeps coming back to, remembered in the browser:
  // the ones they starred and the ones they opened last. Neither is fleet
  // data, so neither goes to the server.
  const [favourites, setFavourites] = useStoredState<string[]>(FAVOURITES_KEY, [], isStringList);
  const [recent, setRecent] = useStoredState<string[]>(RECENT_KEY, [], isStringList);
  useEffect(() => {
    if (!selected) return;
    setRecent((current) => [selected.id, ...current.filter((id) => id !== selected.id)].slice(0, RECENT));
  }, [selected?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  const toggleFavourite = (host: Host) =>
    setFavourites((current) => current.includes(host.id)
      ? current.filter((id) => id !== host.id)
      : [...current, host.id]);

  // With an empty filter the list is grouped: the starred hosts, the recent
  // ones, then everything. A filter flattens it - the operator is looking
  // for a name, not browsing.
  const items = useMemo<Row[]>(() => {
    const all = list.data?.items ?? [];
    const needle = filter.trim().toLowerCase();
    if (needle) {
      return all
        .filter((host) => [host.hostname, host.management_address, host.site, host.environment]
          .some((field) => (field ?? "").toLowerCase().includes(needle)))
        .map((host) => ({ host, group: "all" as const }));
    }
    const byID = new Map(all.map((host) => [host.id, host]));
    const starred = favourites.flatMap((id) => { const host = byID.get(id); return host ? [host] : []; });
    const seen = new Set(starred.map((host) => host.id));
    const opened = recent.flatMap((id) => {
      const host = byID.get(id);
      if (!host || seen.has(id)) return [];
      seen.add(id);
      return [host];
    });
    return [
      ...starred.map((host) => ({ host, group: "favourites" as const })),
      ...opened.map((host) => ({ host, group: "recent" as const })),
      ...all.filter((host) => !seen.has(host.id)).map((host) => ({ host, group: "all" as const })),
    ];
  }, [list.data, filter, favourites, recent]);

  // Ctrl+K (Cmd+K on a Mac) opens the picker from anywhere: switching
  // hosts is the most frequent move in the panel, and it should not need
  // the mouse. The top bar holds the only picker, so one listener is all.
  useEffect(() => {
    const onKeyDown = (event: globalThis.KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        show();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // The highlight follows the filter: the first match is the one Enter
  // takes, so it must never point past the end of a shorter list.
  useEffect(() => {
    setHighlight(0);
  }, [filter, list.data]);

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
    setArmed(true);
    setFilter("");
    setOpen(true);
  }

  function choose(target: Host) {
    setOpen(false);
    if (selected && target.id === selected.id) return;
    const openModule = segment ? findModule(segment) : undefined;
    const reason = openModule ? openModule.reason(target, installation) : "";
    if (reason) {
      navigate(`/hosts/${target.id}/${DEFAULT_MODULE}`, {
        state: { rejected: openModule?.name, reason },
      });
      return;
    }
    navigate(`/hosts/${target.id}/${segment || DEFAULT_MODULE}`);
  }

  function onKey(event: KeyboardEvent) {
    if (event.key === "Escape") {
      event.preventDefault();
      setOpen(false);
      return;
    }
    if (items.length === 0) return;
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setHighlight((index) => Math.min(items.length - 1, index + 1));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setHighlight((index) => Math.max(0, index - 1));
    } else if (event.key === "Home") {
      event.preventDefault();
      setHighlight(0);
    } else if (event.key === "End") {
      event.preventDefault();
      setHighlight(items.length - 1);
    } else if (event.key === "Enter") {
      event.preventDefault();
      const target = items[highlight];
      if (target) choose(target.host);
    }
  }

  const truncated = (list.data?.items.length ?? 0) >= PAGE;

  return (
    <div className="host-picker" ref={container}>
      <button
        type="button"
        className="host-picker-trigger"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={t("Search hosts")}
        title={`${t("Search hosts")} (Ctrl K)`}
        onClick={() => (open ? setOpen(false) : show())}
      >
        <Icon name="search" />
        <span className="host-picker-placeholder">{t("Search hosts…")}</span>
        <kbd className="host-picker-key">Ctrl K</kbd>
      </button>

      {open && (
        <div className="host-picker-popover">
          <div className="host-picker-search">
            <Icon name="search" />
            <input
              ref={input}
              type="text"
              value={filter}
              placeholder={t("Filter by name, address, site…")}
              aria-label={t("Filter hosts")}
              aria-controls={listID}
              aria-activedescendant={items.length ? `${listID}-${highlight}` : undefined}
              onChange={(event) => setFilter(event.target.value)}
              onKeyDown={onKey}
            />
          </div>
          <ul id={listID} role="listbox" className="host-picker-list" aria-label={t("Hosts")}>
            {items.map(({ host, group }, index) => (
              <li
                key={host.id}
                id={`${listID}-${index}`}
                role="option"
                aria-selected={selected?.id === host.id}
                className={[
                  "host-picker-item",
                  index === highlight ? "highlighted" : "",
                  selected?.id === host.id ? "current" : "",
                  // The first row of a group carries the heading.
                  index === 0 || items[index - 1].group !== group ? `group-start group-${group}` : "",
                ].join(" ").trim()}
                data-group={t(GROUP_TITLES[group])}
                onMouseEnter={() => setHighlight(index)}
                onMouseDown={(event) => event.preventDefault()}
                onClick={() => choose(host)}
              >
                <ConnectionDot state={host.connection_state} />
                <span className="host-picker-name">{host.hostname}</span>
                <span className="host-picker-address">{host.management_address || "—"}</span>
                <span className="host-picker-meta">
                  {host.site} / {host.environment}{host.os_family ? ` · ${host.os_family}` : ""}
                </span>
                <button
                  type="button"
                  className={favourites.includes(host.id) ? "host-picker-star on" : "host-picker-star"}
                  aria-pressed={favourites.includes(host.id)}
                  title={favourites.includes(host.id) ? t("Remove from favourites") : t("Add to favourites")}
                  onMouseDown={(event) => event.preventDefault()}
                  onClick={(event) => { event.stopPropagation(); toggleFavourite(host); }}
                >
                  <Icon name="star" />
                </button>
              </li>
            ))}
          </ul>
          {/* The states of the list stand where the rows would: a silent
              empty box does not say whether nothing matched or nothing
              arrived. */}
          {list.isLoading && <p className="host-picker-note">{t("Loading…")}</p>}
          {list.error && (
            <p className="host-picker-note error">
              {t("Could not load the hosts: {message}", { message: list.error instanceof Error ? list.error.message : String(list.error) })}
            </p>
          )}
          {list.data && items.length === 0 && (
            <p className="host-picker-note">{t("No host matches the filter.")}</p>
          )}
          {truncated && (
            <p className="host-picker-note">
              {t("Showing the first {count} hosts; narrow the filter to reach the rest.", { count: PAGE })}
            </p>
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
