import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { keepPreviousData, useQueries, useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { Host, Whoami } from "../lib/types";
import { useCapabilities, type Capabilities } from "../lib/capabilities";
import { useDebounced } from "../lib/debounce";
import { isStringList, useStoredState } from "../lib/storage";
import { module as findModule, DEFAULT_MODULE } from "../pages/host/modules";
import { useT } from "../i18n";
import { Icon, type IconName } from "./icons";

/** How many recently opened hosts are kept; more than a screenful is noise. */
const RECENT = 8;
/** How many starred hosts the empty palette resolves; the rest are a filter away. */
const FAVOURITES_SHOWN = 12;
/** The pause in typing before the server is asked. */
const DEBOUNCE = 250;
/** The shortest query the server answers; below it the palette shows the shortcuts. */
const MINIMUM = 2;
/** How many hits of each kind the server is asked for. */
const LIMIT = 8;
const RECENT_KEY = "flotestro.hosts.recent";
const FAVOURITES_KEY = "flotestro.hosts.favourites";

/** What the server can find: every kind has a page of its own. */
export type SearchKind = "host" | "campaign" | "job" | "policy" | "group" | "relay" | "secret" | "principal" | "cve";

/** One hit of the server search: what it is, its name and where its page is. */
export type SearchItem = {
  kind: SearchKind;
  id: string;
  title: string;
  subtitle: string;
  path: string;
};

/** A place of the panel the palette can jump to: a sidebar entry. */
export type Command = {
  to: string;
  /** The English label; it goes through the translation catalogue. */
  label: string;
  icon: IconName;
};

/** The heading of a group of rows; English, translated when drawn. */
export type RowGroup =
  | "Favourites" | "Recent" | "Hosts" | "Campaigns" | "Jobs" | "Policies" | "Groups"
  | "Relays" | "Secrets" | "Identities" | "Vulnerabilities" | "Go to";

/** A row of the palette, whatever it came from. */
export type Row = {
  key: string;
  group: RowGroup;
  icon: IconName;
  title: string;
  subtitle: string;
  path: string;
  /** Set on a host row the palette has the record of; the star and the module switch need it. */
  host?: Host;
  /** Set on a host row: the identifier, whether the record is at hand or not. */
  hostID?: string;
  /** Set on a command: the label is translated when drawn, a name from the server is not. */
  command?: boolean;
};

/** The order the kinds stand in, and the heading and icon of each. */
const KINDS: Record<SearchKind, { group: RowGroup; icon: IconName }> = {
  host: { group: "Hosts", icon: "hosts" },
  campaign: { group: "Campaigns", icon: "campaigns" },
  job: { group: "Jobs", icon: "jobs" },
  policy: { group: "Policies", icon: "security" },
  group: { group: "Groups", icon: "groups" },
  relay: { group: "Relays", icon: "relays" },
  secret: { group: "Secrets", icon: "secrets" },
  principal: { group: "Identities", icon: "access" },
  cve: { group: "Vulnerabilities", icon: "vulnerabilities" },
};

const KIND_ORDER: SearchKind[] = ["host", "campaign", "job", "policy", "group", "relay", "secret", "principal", "cve"];

/**
 * The places of the panel this person may go to: the sidebar entries,
 * gated the way the sidebar gates them. The list is written here again
 * rather than read from the sidebar, because the sidebar is drawn from the
 * application shell and the palette sits in the top bar; the two must
 * agree, and the gating is by the same permissions.
 */
export function navigationCommands(permissions: Iterable<string>, capabilities: Pick<Capabilities, "directory">): Command[] {
  const has = new Set(permissions);
  const managesAccess = has.has("principal.manage");
  const commands: Command[] = [
    { to: "/dashboard", label: "Dashboard", icon: "dashboard" },
    { to: "/hosts", label: "Hosts", icon: "hosts" },
  ];
  if (has.has("host.enroll.create")) commands.push({ to: "/hosts/new", label: "Add host", icon: "add-host" });
  commands.push({ to: "/groups", label: "Groups", icon: "groups" });
  if (has.has("host.enroll.read")) commands.push({ to: "/relays", label: "Relays", icon: "relays" });
  commands.push({ to: "/jobs", label: "Jobs", icon: "jobs" }, { to: "/reads", label: "Reads", icon: "reads" });
  if (has.has("campaign.read")) {
    commands.push({ to: "/bulk", label: "Bulk Workspace", icon: "bulk" }, { to: "/campaigns", label: "Campaigns", icon: "campaigns" });
  }
  if (has.has("policy.read")) commands.push({ to: "/policies", label: "Policies", icon: "security" });
  if (has.has("budget.read")) commands.push({ to: "/budgets", label: "Budgets", icon: "overview" });
  if (has.has("security.read")) commands.push({ to: "/security", label: "Security", icon: "security" });
  if (has.has("vulnerability.read")) commands.push({ to: "/vulnerabilities", label: "Vulnerabilities", icon: "vulnerabilities" });
  if (has.has("certificate.read")) commands.push({ to: "/certificates", label: "Certificates", icon: "certificates" });
  if (has.has("secret.read")) commands.push({ to: "/secrets", label: "Secrets", icon: "secrets" });
  if (has.has("backup.read")) commands.push({ to: "/backups", label: "Backups", icon: "backups" });
  if (has.has("monitoring.read")) commands.push({ to: "/monitoring", label: "Monitoring", icon: "monitoring" });
  if (capabilities.directory) commands.push({ to: "/directory", label: "Directory", icon: "directory" });
  if (managesAccess) commands.push({ to: "/access", label: "Access", icon: "access" });
  if (has.has("audit.read")) commands.push({ to: "/audit", label: "Audit", icon: "audit" });
  if (has.has("settings.read") || managesAccess) commands.push({ to: "/settings", label: "Settings", icon: "settings" });
  return commands;
}

/**
 * How well a title answers the query: the whole of it, its beginning, the
 * beginning of one of its words, somewhere inside, or not at all. The
 * server already found the row; the rank only orders a group, so the one
 * the operator most likely meant stands first.
 */
export function rank(title: string, query: string): number {
  const needle = query.trim().toLowerCase();
  const name = title.toLowerCase();
  if (!needle) return 4;
  if (name === needle) return 0;
  if (name.startsWith(needle)) return 1;
  if (name.includes(" " + needle) || name.includes("-" + needle) || name.includes("." + needle)) return 2;
  if (name.includes(needle)) return 3;
  return 4;
}

/**
 * The hits of the server as rows, in the order of the kinds and, inside a
 * kind, by how well the title answers the query; the server's own order
 * decides between equals, so two hosts named alike keep their names in
 * order.
 */
export function groupResults(items: SearchItem[], query: string): Row[] {
  // A kind this build does not know has no heading and no page; a newer
  // server may answer with one, and the row is left out rather than drawn
  // without a place to go.
  const ordered = items
    .filter((item) => item.kind in KINDS)
    .map((item, index) => ({ item, index, rank: rank(item.title, query) }))
    .sort((a, b) =>
      KIND_ORDER.indexOf(a.item.kind) - KIND_ORDER.indexOf(b.item.kind)
      || a.rank - b.rank
      || a.index - b.index);
  return ordered.map(({ item }) => ({
    key: `${item.kind}:${item.id}`,
    group: KINDS[item.kind].group,
    icon: KINDS[item.kind].icon,
    title: item.title,
    subtitle: item.subtitle,
    path: item.path,
    hostID: item.kind === "host" ? item.id : undefined,
  }));
}

/**
 * The commands the query names, by their label in either language: the
 * operator types what they read on the screen, and the catalogue is what
 * they read. An empty query keeps every command.
 */
export function matchCommands(commands: Command[], query: string, translate: (label: string) => string): Row[] {
  const needle = query.trim().toLowerCase();
  return commands
    .map((command) => ({
      command,
      rank: needle ? Math.min(rank(command.label, needle), rank(translate(command.label), needle)) : 4,
    }))
    .filter(({ rank: value }) => !needle || value < 4)
    .sort((a, b) => a.rank - b.rank)
    .map(({ command }) => ({
      key: `command:${command.to}`,
      group: "Go to" as const,
      icon: command.icon,
      title: command.label,
      subtitle: command.to,
      path: command.to,
      command: true,
    }));
}

/**
 * Where a host switch leads: the same module on the new host if the module
 * is known to work there, otherwise the overview with the reason. A host
 * the palette has no record of keeps the module too; the host workspace
 * then says itself when the module has no backing there, on the module's
 * own address.
 */
export function hostPath(target: { id: string; host?: Host }, segment: string, installation: Capabilities):
  { path: string; state?: { rejected: string; reason: string } } {
  const wanted = segment || DEFAULT_MODULE;
  const openModule = segment && target.host ? findModule(segment) : undefined;
  const reason = openModule && target.host ? openModule.reason(target.host, installation) : "";
  if (openModule && reason) {
    return { path: `/hosts/${target.id}/${DEFAULT_MODULE}`, state: { rejected: openModule.name, reason } };
  }
  return { path: `/hosts/${target.id}/${wanted}` };
}

/** A host of the recent or favourite lists as a row of the palette. */
function hostRow(host: Host, group: "Favourites" | "Recent"): Row {
  const meta = [`${host.site} / ${host.environment}`, host.os_family].filter(Boolean).join(" · ");
  return {
    key: `${group}:${host.id}`,
    group,
    icon: "hosts",
    title: host.hostname,
    subtitle: host.management_address ? `${host.management_address} · ${meta}` : meta,
    path: `/hosts/${host.id}/${DEFAULT_MODULE}`,
    host,
    hostID: host.id,
  };
}

/**
 * The command palette: the search field of the top bar, and the one
 * control for jumping anywhere in the panel. It reads as a search rather
 * than as the name of the open host, because the trail beside it already
 * names the host; on a narrow screen it folds to an icon that opens the
 * same list.
 *
 * Empty, it shows the hosts this person starred and opened last, and the
 * places of the panel. With a query it asks the server, which answers with
 * everything the text names - hosts, campaigns, jobs, policies, groups,
 * relays, secrets, identities, a CVE - each with the address of its page,
 * and only of the kinds this person may read.
 *
 * A host switch keeps the open module if the new host supports it.
 * Otherwise it leads to the overview and says what was missing - a quiet
 * tab change would look like an interface bug.
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

  // The palette has no host in hand, so it asks for the one in the
  // address. The key is the one the host workspace uses, so the request
  // is shared with it rather than doubled.
  const fromAddress = useQuery({
    queryKey: ["host", urlID],
    queryFn: () => api.get<Host>(`/api/v1/hosts/${urlID}`),
    enabled: onHost,
  });
  const selected = onHost ? fromAddress.data : undefined;

  // The commands are gated by the permissions the shell already fetched;
  // the key is shared with it, so this is a read of the cache.
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    retry: false,
    refetchInterval: false,
    staleTime: 60_000,
  });
  const commands = useMemo(
    () => navigationCommands(whoami.data?.permissions ?? [], installation),
    [whoami.data?.permissions, installation.directory], // eslint-disable-line react-hooks/exhaustive-deps
  );

  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [highlight, setHighlight] = useState(0);
  const container = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const listID = useId();

  // The hosts this person keeps coming back to, remembered in the browser:
  // the ones they starred and the ones they opened last. Neither is fleet
  // data, so neither goes to the server.
  const [favourites, setFavourites] = useStoredState<string[]>(FAVOURITES_KEY, [], isStringList);
  const [recent, setRecent] = useStoredState<string[]>(RECENT_KEY, [], isStringList);
  useEffect(() => {
    if (!selected) return;
    setRecent((current) => [selected.id, ...current.filter((id) => id !== selected.id)].slice(0, RECENT));
  }, [selected?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  const toggleFavourite = (id: string) =>
    setFavourites((current) => current.includes(id) ? current.filter((entry) => entry !== id) : [...current, id]);

  // The remembered hosts are read one by one under the key the host
  // workspace uses, so a host just visited costs nothing; the requests go
  // out once the palette is first opened, not on every screen. A host that
  // is gone since it was starred is left out rather than shown as an error.
  const remembered = useMemo(() => {
    const ids = [...favourites.slice(0, FAVOURITES_SHOWN)];
    for (const id of recent) if (!ids.includes(id)) ids.push(id);
    return ids;
  }, [favourites, recent]);
  const [armed, setArmed] = useState(false);
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

  // The server is asked after a pause in typing, and the last answer stays
  // on the screen while the next one is on its way: a list that empties
  // between keystrokes looks like nothing matched.
  const settled = useDebounced(query.trim(), DEBOUNCE);
  const search = useQuery({
    queryKey: ["search", settled],
    queryFn: () => api.get<{ items: SearchItem[] }>(`/api/v1/search?q=${encodeURIComponent(settled)}&limit=${LIMIT}`),
    enabled: open && settled.length >= MINIMUM,
    staleTime: 30_000,
    placeholderData: keepPreviousData,
  });
  const searching = settled.length >= MINIMUM;

  // Empty, the palette is the starred hosts, the recent ones and the
  // places of the panel. With a query it is what the server found, in
  // groups by kind, and the places whose name the query matches.
  const rows = useMemo<Row[]>(() => {
    if (!searching) {
      const starred = favourites.slice(0, FAVOURITES_SHOWN).flatMap((id) => { const host = byID.get(id); return host ? [hostRow(host, "Favourites")] : []; });
      const seen = new Set(starred.map((row) => row.hostID));
      const opened = recent.flatMap((id) => {
        const host = byID.get(id);
        if (!host || seen.has(id)) return [];
        seen.add(id);
        return [hostRow(host, "Recent")];
      });
      // A query too short for the server still narrows the places: one
      // letter is enough to tell the audit from the access.
      return [...starred, ...opened, ...matchCommands(commands, query, t)];
    }
    return [...groupResults(search.data?.items ?? [], settled), ...matchCommands(commands, settled, t)];
  }, [searching, settled, query, search.data, favourites, recent, records, commands, t]); // eslint-disable-line react-hooks/exhaustive-deps

  // Ctrl+K (Cmd+K on a Mac) opens the palette from anywhere: jumping
  // between places is the most frequent move in the panel, and it should
  // not need the mouse. The top bar holds the only palette, so one
  // listener is all.
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

  // The highlight follows the rows: the first one is the one Enter takes,
  // so it must never point past the end of a shorter list.
  useEffect(() => {
    setHighlight(0);
  }, [settled, search.data]);

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
    setQuery("");
    setOpen(true);
  }

  function choose(row: Row) {
    setOpen(false);
    if (row.hostID) {
      if (selected && row.hostID === selected.id) return;
      const target = hostPath({ id: row.hostID, host: row.host ?? byID.get(row.hostID) }, segment, installation);
      navigate(target.path, target.state ? { state: target.state } : undefined);
      return;
    }
    navigate(row.path);
  }

  function onKey(event: KeyboardEvent) {
    if (event.key === "Escape") {
      event.preventDefault();
      setOpen(false);
      return;
    }
    if (rows.length === 0) return;
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setHighlight((index) => Math.min(rows.length - 1, index + 1));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setHighlight((index) => Math.max(0, index - 1));
    } else if (event.key === "Home") {
      event.preventDefault();
      setHighlight(0);
    } else if (event.key === "End") {
      event.preventDefault();
      setHighlight(rows.length - 1);
    } else if (event.key === "Enter") {
      event.preventDefault();
      const target = rows[highlight];
      if (target) choose(target);
    }
  }

  const loadingRemembered = !searching && remembered.length > 0 && records.some((record) => record.isLoading);
  // The server bounds every kind on its own, so the note about the rest
  // is due when any one kind filled its share.
  const truncated = searching && KIND_ORDER.some((kind) =>
    (search.data?.items.filter((item) => item.kind === kind).length ?? 0) >= LIMIT);

  return (
    <div className="host-picker" ref={container}>
      <button
        type="button"
        className="host-picker-trigger"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={t("Search the panel")}
        title={`${t("Search the panel")} (Ctrl K)`}
        onClick={() => (open ? setOpen(false) : show())}
      >
        <Icon name="search" />
        <span className="host-picker-placeholder">{t("Search…")}</span>
        <kbd className="host-picker-key">Ctrl K</kbd>
      </button>

      {open && (
        <div className="host-picker-popover">
          <div className="host-picker-search">
            <Icon name="search" />
            <input
              ref={input}
              type="text"
              value={query}
              placeholder={t("Host, campaign, job, policy, CVE…")}
              aria-label={t("Search the panel")}
              aria-controls={listID}
              aria-activedescendant={rows.length ? `${listID}-${highlight}` : undefined}
              onChange={(event) => setQuery(event.target.value)}
              onKeyDown={onKey}
            />
          </div>
          <ul id={listID} role="listbox" className="host-picker-list" aria-label={t("Results")}>
            {rows.map((row, index) => {
              const current = row.hostID !== undefined && selected?.id === row.hostID;
              const starred = row.hostID !== undefined && favourites.includes(row.hostID);
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
                    index === 0 || rows[index - 1].group !== row.group ? `group-start group-${row.group.toLowerCase().replace(/\s+/g, "-")}` : "",
                  ].join(" ").trim()}
                  data-group={t(row.group)}
                  data-kind={row.command ? "command" : row.icon}
                  onMouseEnter={() => setHighlight(index)}
                  onMouseDown={(event) => event.preventDefault()}
                  onClick={() => choose(row)}
                >
                  {/* A host row keeps the connection dot the host list shows;
                      every other kind stands behind its icon. */}
                  {row.host ? (
                    <ConnectionDot state={row.host.connection_state} />
                  ) : (
                    <span className="host-picker-kind" style={{ gridArea: "dot", display: "inline-flex", color: "var(--text-muted)" }}>
                      <Icon name={row.icon} />
                    </span>
                  )}
                  <span className="host-picker-name">{row.command ? t("Go to {place}", { place: t(row.title) }) : row.title}</span>
                  <span className="host-picker-meta">{row.subtitle}</span>
                  {row.hostID !== undefined && (
                    <button
                      type="button"
                      className={starred ? "host-picker-star on" : "host-picker-star"}
                      aria-pressed={starred}
                      title={starred ? t("Remove from favourites") : t("Add to favourites")}
                      onMouseDown={(event) => event.preventDefault()}
                      onClick={(event) => { event.stopPropagation(); toggleFavourite(row.hostID as string); }}
                    >
                      <Icon name="star" />
                    </button>
                  )}
                </li>
              );
            })}
          </ul>
          {/* The states of the list stand where the rows would: a silent
              empty box does not say whether nothing matched or nothing
              arrived. */}
          {(loadingRemembered || (searching && search.isLoading)) && <p className="host-picker-note">{t("Loading…")}</p>}
          {search.error && searching && (
            <p className="host-picker-note error">
              {t("Could not search: {message}", { message: search.error instanceof Error ? search.error.message : String(search.error) })}
            </p>
          )}
          {searching && search.data && rows.length === 0 && (
            <p className="host-picker-note">{t("Nothing matches the query.")}</p>
          )}
          {!searching && query.trim().length > 0 && (
            <p className="host-picker-note">{t("Type at least {count} characters to search the fleet.", { count: MINIMUM })}</p>
          )}
          {truncated && (
            <p className="host-picker-note">
              {t("Showing the first {count} of each kind; a longer query narrows the rest.", { count: LIMIT })}
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
