import {
  useEffect, useRef, useState,
  type KeyboardEvent as ReactKeyboardEvent, type MouseEvent as ReactMouseEvent, type ReactNode,
} from "react";
import { Link, NavLink, useLocation, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, BEARER_TOKEN_KEY, type Collection } from "../lib/api";
import { isBoolean, isStringList, useStoredState } from "../lib/storage";
import { useDebounced } from "../lib/debounce";
import { REFRESH_INTERVAL } from "../lib/stream";
import { usePreferences } from "../lib/preferences";
import { SCALES } from "../lib/scale";
import { THEMES } from "../lib/theme";
import { useLook } from "./look";
import { LOCALES, useLocale } from "../i18n";
import { useCapabilities } from "../lib/capabilities";
import { fleetNavigation, type NavGroup } from "../lib/navigation";
import type { IconName } from "../components/icons";
import type { Host, Whoami } from "../lib/types";
import { Icon } from "../components/icons";
import { LogoMark } from "../components/Logo";
import { useT } from "../i18n";
import { Pill, Problem, toneClass, type Tone } from "./kit";

/**
 * The shell of the panel: a rail of places down the left, a bar across the
 * top saying where the reader is and who they are, and the page under it.
 *
 * It is written beside the shell it replaces rather than over it, so the
 * panel in the laboratory goes on working while the screens are moved one
 * at a time. The two share one thing - the navigation model, in
 * lib/navigation - because a copied navigation drifts.
 */

/** Where the reader is, for the bar: the section, and the host if on one. */
export type Trail = {
  section: string;
  to?: string;
  here?: string;
  /** Set on a machine's screen, once the machine is known. */
  host?: Host;
  /** The English name of the open module, where the address names one. */
  module?: string;
};

/** What the panel last heard from a machine, as a tone. */
function connectionTone(state?: string | null): Tone {
  if (state === "online") return "ok";
  if (state === "stale") return "warn";
  if (state === "offline") return "error";
  return "unknown";
}

/** Several class names into one, dropping what is not there. */
const join = (...parts: (string | false | undefined)[]) => parts.filter(Boolean).join(" ");

/** One place the rail leads to. */
export type RailItem = {
  to: string;
  label: string;
  icon: IconName;
  /** The reason it leads nowhere here; it stays listed, dimmed. */
  unavailable?: string;
};

/**
 * The rail has two faces and never both at once: the fleet, and one host.
 *
 * A host page replaces the places of the fleet with the modules of that
 * machine, and offers the way back. Two rails side by side would be two
 * answers to "where am I", which is the one question a rail exists for.
 */
export type Face = {
  groups: { key: string; label?: string; icon?: IconName; items: RailItem[] }[];
  back?: { to: string; label: string };
};

export function Shell({ trail, face, children }: { trail: Trail; face?: Face; children: ReactNode }) {
  const t = useT();
  const capabilities = useCapabilities();
  const location = useLocation();
  const [folded, setFolded] = useState(false);
  const [drawer, setDrawer] = useState(false);

  // The drawer closes behind the reader: a tap on a place is an answer to
  // "where to", and the panel that answered it should not stay in the way.
  useEffect(() => { setDrawer(false); }, [location.pathname]);

  const me = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    retry: false,
  });
  const permissions = new Set(me.data?.permissions ?? []);
  // Every place of the new panel lives under /next while it is being
  // written; the fleet's navigation model names the addresses it will have.
  const fleet: Face = {
    groups: fleetNavigation(permissions, capabilities)
      .filter((group) => group.items.length > 0)
      .map((group: NavGroup) => ({
        key: group.key,
        label: group.label,
        icon: group.icon,
        items: group.items.map((item) => ({ to: item.to, label: item.label, icon: item.icon })),
      })),
  };
  const shown = face ?? fleet;
  const name = me.data?.display_name || me.data?.subject || "";
  const [finding, setFinding] = useState(false);
  /* What this browser keeps and what it opened last live here rather
     than in the finder: the finder is unmounted the instant a row is
     opened, and a write made inside the state updater of a component
     that is going away never runs. */
  const [recent, setRecent] = useStoredState<string[]>(RECENT_KEY, [], isStringList);
  const [favourite, setFavourite] = useStoredState<string[]>(FAVOURITE_KEY, [], isStringList);
  // Which module of a machine is open, if one is: picking another host
  // from the finder lands on the same one. An operator comparing the
  // packages of two machines should not be sent back to the overview.
  const onModule = /^\/hosts\/(?!new$)([^/]+)\/([^/]+)/.exec(location.pathname);
  const mac = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform || "");
  const keyHint = mac ? "\u2318 K" : "Ctrl K";

  // One key opens the way to anywhere. Every panel in the look has it, and
  // a fleet of a thousand hosts is unreachable by rail alone.
  useEffect(() => {
    const down = (event: globalThis.KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setFinding(true);
      }
    };
    document.addEventListener("keydown", down);
    return () => document.removeEventListener("keydown", down);
  }, []);

  return (
    <div className="fl-app">
      <div className={folded ? "fl-shell fl-folded" : "fl-shell"}>
        <a href="#fl-main" className="fl-skip">{t("Skip to content")}</a>

        <aside className={drawer ? "fl-rail fl-open" : "fl-rail"}>
          <Link to="/" className="fl-brand">
            <span className="fl-brand-mark" aria-hidden="true">
              {/* The holes of the mark are cut in the badge it sits on, and the
                  badge is the brand's colour in every theme. */}
              <LogoMark size={26} ground="var(--fl-brand)" />
            </span>
            <span className="fl-brand-name">Flotestro</span>
          </Link>
          <nav className="fl-nav" aria-label={t("Main navigation")}>
            {shown.back && (
              <Link to={shown.back.to} className="fl-navitem fl-back">
                <Icon name="back" />
                <span className="fl-navitem-label">{t(shown.back.label)}</span>
              </Link>
            )}
            {shown.groups.map((group) => <Rail key={group.key} group={group} />)}
          </nav>
          <div className="fl-whoami">
            <UserMenu name={name} roles={me.data?.roles ?? []} subject={me.data?.subject ?? ""} />
          </div>
          <button
            type="button"
            className="fl-fold"
            onClick={() => setFolded((on) => !on)}
            aria-label={t("Show or hide the navigation")}
            title={t("Show or hide the navigation")}
            data-testid="fold-rail"
          >
            <Icon name={folded ? "expand" : "collapse"} />
          </button>
        </aside>
        {drawer && <div className="fl-rail-backdrop" onClick={() => setDrawer(false)} />}

        <div className="fl-page">
        <header className="fl-bar">
          <button
            type="button"
            className="fl-iconbtn"
            onClick={() => { setFolded((on) => !on); setDrawer((on) => !on); }}
            aria-label={t("Show or hide the navigation")}
            data-testid="fold"
          >
            <Icon name="menu" />
          </button>
          <nav className="fl-crumbs" aria-label={t("Breadcrumb")}>
            {trail.to ? <Link to={trail.to}>{t(trail.section)}</Link> : <span>{t(trail.section)}</span>}
            {/* On a machine the trail names the machine itself, with how
                it is answering and the address somebody would type -
                the two things that tell one host from another. */}
            {trail.host ? (
              <>
                <Icon name="chevron" />
                <Link
                  to={`/hosts/${trail.host.id}`}
                  className={trail.module ? "fl-crumbs-host" : "fl-crumbs-host fl-crumbs-here"}
                  title={t("Open the host overview")}
                >
                  <span className={join("fl-dot", toneClass(connectionTone(trail.host.connection_state)))} />
                  <span className="fl-crumbs-name">{trail.host.hostname}</span>
                  <span className="fl-crumbs-where">
                    {trail.host.management_address || t("address unknown")}
                  </span>
                </Link>
                {trail.module && (
                  <><Icon name="chevron" /><span className="fl-crumbs-here">{t(trail.module)}</span></>
                )}
              </>
            ) : trail.here ? (
              <><Icon name="chevron" /><span className="fl-crumbs-here">{trail.here}</span></>
            ) : null}
          </nav>
          <span className="fl-bar-spacer" />
          {/* Two boxes of one look, as the panel being replaced has: the
              host selector, which lists machines and nothing else, and
              the finder, which reaches anything. An operator moving
              between machines should not have to think of a search. */}
          <HostSelect
            host={trail.host}
            module={onModule?.[2]}
            recent={recent}
            setRecent={setRecent}
            favourite={favourite}
            setFavourite={setFavourite}
          />
          <button
            type="button"
            className="fl-search"
            onClick={() => setFinding(true)}
            aria-label={t("Search the fleet…")}
            data-testid="open-finder"
          >
            <Icon name="search" />
            <span className="fl-search-text">{t("Search the fleet…")}</span>
            <span className="fl-search-key">{keyHint}</span>
          </button>
          <Bell />
          <Link to="/settings" className="fl-iconbtn" aria-label={t("Settings")}><Icon name="settings" /></Link>
        </header>

        <main className="fl-screen" id="fl-main" tabIndex={-1}>
          {me.error ? <Problem>{t("Error: {message}", { message: String(me.error) })}</Problem> : children}
        </main>
        </div>
      </div>
      {finding && (
        <Finder
          places={fleet.groups}
          module={onModule?.[2]}
          recent={recent}
          setRecent={setRecent}
          favourite={favourite}
          setFavourite={setFavourite}
          onClose={() => setFinding(false)}
        />
      )}
    </div>
  );
}

/**
 * What the bell counts: the messages nobody received.
 *
 * It is the figure the notifications screen itself reads, off the same
 * answer - `dead_letters` is the whole installation's, not the page's, so
 * a filter on that screen cannot make the bell disagree with it. A row
 * that is still being tried is not waiting on anybody; a dead letter is,
 * and it stays there until an operator puts it back in the queue.
 */
const WAITING = "/api/v1/notifications/deliveries?limit=1";

/**
 * The bell, and how many are waiting behind it.
 *
 * A count nobody could take is not a count of none. Where the read is
 * refused - no right to read the notifications, or an installation with
 * them switched off - and where it simply failed, the bell carries no
 * figure at all rather than a nought that would read as "all clear".
 */
function Bell() {
  const t = useT();
  const waiting = useQuery({
    queryKey: ["bell", "waiting"],
    queryFn: () => api.get<{ dead_letters?: number }>(WAITING),
    refetchInterval: REFRESH_INTERVAL,
    retry: false,
  });
  const counted = waiting.data?.dead_letters;
  const known = typeof counted === "number";
  const label = !known
    ? t("Notifications")
    : counted > 0
      ? t("Notifications: {n} waiting", { n: counted })
      : t("Notifications: nothing waiting");
  return (
    <>
      <Link to="/notifications" className="fl-iconbtn" aria-label={label} title={label} data-testid="bell">
        <Icon name="notifications" />
      </Link>
      {known && counted > 0 && (
        <Pill tone="error" dot={false} title={label}>{counted}</Pill>
      )}
    </>
  );
}

/**
 * Who is at the screen, and everything they set for themselves: the
 * theme, the size of the text, the language, and the way out.
 *
 * The theme and the language are kept on the server under the person's
 * identity, so they follow them to another browser; the size of the text
 * is this browser's, because it answers to this screen and no other. Both
 * are written through the same places the panel already keeps them - a
 * second copy of either would be a second answer.
 */
function UserMenu({ name, roles, subject }: { name: string; roles: string[]; subject: string }) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const holder = useRef<HTMLDivElement>(null);
  const { theme, setTheme, scale, setScale } = useLook();
  const { locale, setLocale } = useLocale();
  const { save } = usePreferences();

  useEffect(() => {
    if (!open) return;
    const away = (event: globalThis.MouseEvent) => {
      if (!holder.current?.contains(event.target as Node)) setOpen(false);
    };
    const escape = (event: globalThis.KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", away);
    document.addEventListener("keydown", escape);
    return () => {
      document.removeEventListener("mousedown", away);
      document.removeEventListener("keydown", escape);
    };
  }, [open]);

  return (
    <div className="fl-menu-anchor fl-menu-up" ref={holder}>
      <button
        type="button"
        className="fl-user"
        onClick={() => setOpen((on) => !on)}
        aria-expanded={open}
        aria-haspopup="menu"
        data-testid="user"
      >
        <span className="fl-avatar" aria-hidden="true">{(name || "?").slice(0, 1).toUpperCase()}</span>
        <span className="fl-user-name">
          {name}
          <small>{roles[0] ?? t("no roles")}</small>
        </span>
        <Icon name="chevron" />
      </button>
      {open && (
        <div className="fl-menu" role="menu" data-testid="user-menu">
          <div className="fl-menu-who">
            <span className="fl-name">{name}</span>
            <span className="fl-menu-subject">{subject}</span>
            <span className="fl-tags">
              {roles.length > 0
                ? roles.map((role) => <span className="fl-tag" key={role}>{role}</span>)
                : <span className="fl-tag">{t("no roles")}</span>}
            </span>
          </div>

          <div className="fl-menu-set">
            <span className="fl-menu-label">{t("Theme")}</span>
            <div className="fl-seg">
              {THEMES.map((one) => (
                <button
                  key={one.code}
                  type="button"
                  className={one.code === theme ? "fl-on" : undefined}
                  title={t(one.description)}
                  data-testid={`theme-${one.code}`}
                  onClick={() => { setTheme(one.code); void save({ theme: one.code }); }}
                >
                  {t(one.label)}
                </button>
              ))}
            </div>
          </div>

          <div className="fl-menu-set">
            <span className="fl-menu-label">{t("Text size")}</span>
            <div className="fl-seg">
              {SCALES.map((one) => (
                <button
                  key={one.code}
                  type="button"
                  className={one.code === scale ? "fl-on" : undefined}
                  title={t(one.description)}
                  data-testid={`scale-${one.code}`}
                  onClick={() => setScale(one.code)}
                >
                  {one.label}
                </button>
              ))}
            </div>
          </div>

          <div className="fl-menu-set">
            <span className="fl-menu-label">{t("Language")}</span>
            <div className="fl-seg">
              {LOCALES.map((one) => (
                <button
                  key={one.code}
                  type="button"
                  className={one.code === locale ? "fl-on" : undefined}
                  data-testid={`locale-${one.code}`}
                  onClick={() => { setLocale(one.code); void save({ language: one.code }); }}
                >
                  {one.label}
                </button>
              ))}
            </div>
          </div>

          <Link to="/profile" className="fl-menu-item" role="menuitem">
            {t("All of my settings")}
          </Link>
          <button type="button" className="fl-quiet fl-menu-out" onClick={signOut} data-testid="sign-out">
            <Icon name="sign-out" />
            {t("Sign out")}
          </button>
        </div>
      )}
    </div>
  );
}

/**
 * Leaving. Dropping the panel's own session is not enough: without
 * signing out at the provider the next visit signs the person straight
 * back in without asking, which is not what anybody means by "sign out".
 */
async function signOut(event: ReactMouseEvent) {
  event.preventDefault();
  try { sessionStorage.removeItem(BEARER_TOKEN_KEY); } catch { /* nothing kept */ }
  const result = await api.post<{ logout_url: string }>("/auth/logout");
  window.location.href = result.logout_url || "/";
}

/**
 * One group of the rail. The heading names what the places below are for;
 * an item that is where the reader already is wears the accent and a bar
 * at its edge, and nothing else on the screen wears that.
 */
function Rail({ group }: { group: Face["groups"][number] }) {
  const t = useT();
  const location = useLocation();
  const [shut, setShut] = useStoredState<boolean>(`fl-group-${group.key}`, false, isBoolean);
  const holding = group.items.some((item) => location.pathname.startsWith(item.to));
  // A group the reader folded stays folded - except the one they are
  // standing in, which would otherwise hide where they are.
  const folded = shut && !holding;
  return (
    <div className={folded ? "fl-navgroup fl-navgroup-shut" : "fl-navgroup"}>
      {group.label && (
        <button
          type="button"
          className="fl-navgroup-label"
          onClick={() => setShut(!shut)}
          aria-expanded={!folded}
          data-testid={`group-${group.key}`}
        >
          {group.icon && <Icon name={group.icon} />}
          <span>{t(group.label)}</span>
          <i className="fl-navgroup-fold" aria-hidden="true"><Icon name="chevron" /></i>
        </button>
      )}
      {!folded && group.items.map((item) => {
        // /next alone is the dashboard, so the item that leads there is the
        // one the reader is standing on.
        const here = location.pathname === "/" ? "/dashboard" : location.pathname;
        const on = here === item.to;
        if (item.unavailable) {
          return (
            <span key={item.to} className="fl-navitem fl-off" title={t(item.unavailable)}>
              <Icon name={item.icon} />
              <span className="fl-navitem-label">{t(item.label)}</span>
            </span>
          );
        }
        return (
          <NavLink key={item.to} to={item.to} className={on ? "fl-navitem fl-on" : "fl-navitem"} title={t(item.label)}>
            <Icon name={item.icon} />
            <span className="fl-navitem-label">{t(item.label)}</span>
          </NavLink>
        );
      })}
    </div>
  );
}

/** One thing the fleet-wide search found, as the server describes it. */
export type Found = {
  kind: string;
  id: string;
  title: string;
  subtitle: string;
  /** Where the panel this replaces keeps it; the new one has its own. */
  path: string;
};

type SearchAnswer = { items: Found[]; truncated?: string[] };

/** One tag of the catalogue and how many hosts carry it. */
type TagCount = { tag: string; hosts: number };

/**
 * The kinds of thing the finder leads to, and where each one lives in the
 * new panel.
 *
 * The server's own `path` is the old panel's address, so it is not used:
 * every address here is written again under `/`. A kind the new panel
 * has no screen for is left out rather than offered as a row that leads
 * to a page saying the screen is not written yet.
 */
const FOUND: Record<string, { to: (one: Found) => string; icon: IconName; kind: string }> = {
  host: { to: (one) => `/hosts/${encodeURIComponent(one.id)}`, icon: "server", kind: "host" },
  job: { to: (one) => `/jobs/${encodeURIComponent(one.id)}`, icon: "jobs", kind: "job" },
  campaign: { to: (one) => `/campaigns/${encodeURIComponent(one.id)}`, icon: "campaigns", kind: "campaign" },
  // A group has no screen of its own under /next; the list is where one
  // is read, so that is honestly where the row leads.
  group: { to: () => "/groups", icon: "groups", kind: "group" },
};

/** How many of one kind the finder shows before the rest wait on a narrower query. */
const FINDER_LIMIT = 6;

/** The fewest characters worth asking the server about. */
const FINDER_MINIMUM = 2;

/**
 * The machines this browser opened last, and the ones it was told to
 * keep. They are this browser's, not the installation's: which hosts a
 * person works on is theirs, and it follows nobody to another seat.
 *
 * A row is kept as "id\u0000name" so the list can be drawn without
 * asking the server for eight names every time the finder opens.
 */
const RECENT_KEY = "flotestro.next.hosts.recent";
const FAVOURITE_KEY = "flotestro.next.hosts.favourite";
const RECENT = 8;

/** How many machines the selector lists at once; more is a narrower query away. */
const HOSTS_SHOWN = 20;

type Kept = { id: string; name: string };

function keep(list: string[]): Kept[] {
  return list.map((one) => {
    const cut = one.indexOf("\u0000");
    return cut < 0 ? { id: one, name: one } : { id: one.slice(0, cut), name: one.slice(cut + 1) };
  });
}

const packed = (one: Kept) => `${one.id}\u0000${one.name}`;

/**
 * The way to anywhere, from the keyboard.
 *
 * A rail reaches the places of the panel; it cannot reach the thousandth
 * host, nor a job by the identifier somebody pasted out of a report. This
 * reaches both: the places are matched on their names here, and anything
 * longer than a letter is put to the fleet - hosts, jobs, campaigns and
 * groups through the panel's own search, tags through the catalogue,
 * which takes no query of its own. What comes back is a list the arrow
 * keys walk and Enter opens, which is the one interaction everybody
 * already knows from every other panel.
 *
 * Nothing older can overwrite anything newer: each query is its own cache
 * entry, keyed by what was typed, so an answer that arrives late lands
 * beside the question it answered and the screen goes on drawing the
 * answer to the question that is actually in the box.
 */
function Finder({ places, module, recent, setRecent, favourite, setFavourite, onClose }: {
  places: Face["groups"];
  /** The module of a machine the reader is standing in, if any. */
  module?: string;
  recent: string[];
  setRecent: (next: string[] | ((current: string[]) => string[])) => void;
  favourite: string[];
  setFavourite: (next: string[] | ((current: string[]) => string[])) => void;
  onClose: () => void;
}) {
  const t = useT();
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [at, setAt] = useState(0);
  const field = useRef<HTMLInputElement>(null);

  /** A machine opens on the module the reader was already reading. */
  const hostAddress = (id: string) =>
    `/hosts/${encodeURIComponent(id)}${module ? `/${module}` : ""}`;

  const remember = (one: Kept) =>
    setRecent((current) => [packed(one), ...current.filter((other) => keep([other])[0].id !== one.id)].slice(0, RECENT));

  const star = (one: Kept) =>
    setFavourite((current) => current.some((other) => keep([other])[0].id === one.id)
      ? current.filter((other) => keep([other])[0].id !== one.id)
      : [...current, packed(one)]);

  useEffect(() => { field.current?.focus(); }, []);

  const asked = query.trim();
  // Typing is not a question: the fleet is asked once the hand stops, so
  // a pasted identifier is one read and not thirty-six.
  const settled = useDebounced(asked, 200);
  const enough = settled.length >= FINDER_MINIMUM;

  const search = useQuery({
    queryKey: ["finder", "search", settled],
    queryFn: () => api.get<SearchAnswer>(
      `/api/v1/search?limit=${FINDER_LIMIT}&q=${encodeURIComponent(settled)}`),
    enabled: enough,
    retry: false,
  });
  // The tag catalogue takes no query and answers with the whole of what
  // the reader may see, so it is read once and matched here. It is still
  // asked for only once there is something to look for.
  const tags = useQuery({
    queryKey: ["finder", "tags"],
    queryFn: () => api.get<Collection<TagCount>>("/api/v1/tags"),
    enabled: enough,
    retry: false,
  });

  // With nothing typed the finder is the host picker: what this browser
  // keeps, then what it opened last.
  const kept: { key: string; to: string; label: string; kind: string; note?: string; icon: IconName; host?: Kept }[] =
    asked === ""
      ? [
          ...keep(favourite).map((one) => ({
            key: `favourite:${one.id}`,
            to: hostAddress(one.id),
            label: one.name,
            kind: t("kept"),
            icon: "star" as IconName,
            host: one,
          })),
          ...keep(recent)
            .filter((one) => !favourite.some((other) => keep([other])[0].id === one.id))
            .map((one) => ({
              key: `recent:${one.id}`,
              to: hostAddress(one.id),
              label: one.name,
              kind: t("lately"),
              icon: "server" as IconName,
              host: one,
            })),
        ]
      : [];

  const matched = places
    .flatMap((group) => group.items.map((item) => ({ ...item, group: group.label })))
    .filter((item) => !item.unavailable && t(item.label).toLowerCase().includes(asked.toLowerCase()))
    .slice(0, 8);

  const lower = settled.toLowerCase();
  const found: { key: string; to: string; label: string; kind: string; note?: string; icon: IconName; host?: Kept }[] = [
    ...kept,
    ...matched.map((item) => ({
      key: `place:${item.to}`,
      to: item.to,
      label: t(item.label),
      kind: t("place"),
      note: item.group ? t(item.group) : undefined,
      icon: item.icon,
    })),
    ...(search.data?.items ?? []).flatMap((one) => {
      const where = FOUND[one.kind];
      if (!where) return [];
      return [{
        key: `${one.kind}:${one.id}`,
        to: one.kind === "host" ? hostAddress(one.id) : where.to(one),
        label: one.title || one.id,
        kind: t(where.kind),
        note: one.subtitle || undefined,
        icon: where.icon,
        host: one.kind === "host" ? { id: one.id, name: one.title || one.id } : undefined,
      }];
    }),
    ...(enough ? (tags.data?.items ?? []) : [])
      .filter((one) => one.tag.toLowerCase().includes(lower))
      .slice(0, FINDER_LIMIT)
      .map((one) => ({
        key: `tag:${one.tag}`,
        to: "/tags",
        label: one.tag,
        kind: t("tag"),
        note: t("{n} hosts", { n: one.hosts }),
        icon: "groups" as IconName,
      })),
  ];
  const here = Math.min(at, Math.max(0, found.length - 1));

  const key = (event: ReactKeyboardEvent<HTMLInputElement>) => {
    if (event.key === "Escape") { onClose(); return; }
    if (event.key === "ArrowDown") { event.preventDefault(); setAt((n) => Math.min(n + 1, found.length - 1)); return; }
    if (event.key === "ArrowUp") { event.preventDefault(); setAt((n) => Math.max(n - 1, 0)); return; }
    if (event.key === "Enter" && found[here]) {
      if (found[here].host) remember(found[here].host);
      navigate(found[here].to);
      onClose();
    }
  };

  return (
    <div
      className="fl-modal-backdrop fl-finder-backdrop"
      onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}
      data-testid="finder"
    >
      <div className="fl-finder" role="dialog" aria-modal="true" aria-label={t("Search the fleet…")}>
        <div className="fl-finder-field">
          <Icon name="search" />
          <input
            ref={field}
            value={query}
            onChange={(event) => { setQuery(event.target.value); setAt(0); }}
            onKeyDown={key}
            placeholder={t("A place, a host, a job, a campaign, a group or a tag…")}
            aria-label={t("A place, a host, a job, a campaign, a group or a tag…")}
            data-testid="finder-field"
          />
          <span className="fl-search-key">esc</span>
        </div>
        <div className="fl-finder-found" role="listbox">
          {found.length === 0 ? (
            <p className="fl-finder-none">
              {asked.length === 0
                ? t("Type to look for a place, a host, a job, a campaign, a group or a tag.")
                : t("Nothing here answers to that.")}
            </p>
          ) : found.map((one, index) => (
            <div
              key={one.key}
              className={index === here ? "fl-finder-row fl-on" : "fl-finder-row"}
              onMouseEnter={() => setAt(index)}
            >
              <Link
                to={one.to}
                role="option"
                aria-selected={index === here}
                className="fl-finder-open"
                onClick={() => { if (one.host) remember(one.host); onClose(); }}
                data-testid={`finder-${one.key}`}
              >
                <Icon name={one.icon} />
                <span className="fl-finder-name">{one.label}</span>
                {/* Every row says what kind of thing it is: a name alone
                    does not tell a campaign from the group it runs over. */}
                <Pill tone="neutral" dot={false}>{one.kind}</Pill>
                {one.note && <span className="fl-finder-note">{one.note}</span>}
              </Link>
              {/* A machine somebody keeps stays at the top of this list
                  whether or not they opened it lately. */}
              {one.host && (
                <button
                  type="button"
                  className="fl-plain fl-finder-keep"
                  aria-pressed={favourite.some((other) => keep([other])[0].id === one.host?.id)}
                  title={t("Keep this machine at the top of the list")}
                  onClick={() => star(one.host as Kept)}
                  data-testid={`finder-keep-${one.host.id}`}
                >
                  <Icon name="star" />
                </button>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/**
 * The selector of machines: the one box in the bar that lists hosts and
 * nothing else.
 *
 * The finder reaches anything and is opened from the keyboard; this is
 * for the hand, and for the question an operator asks twenty times a
 * day - "the same thing, on that other machine". It opens on what this
 * browser keeps and what it opened lately, narrows on what is typed by
 * asking the fleet, and lands on the module already open.
 */
function HostSelect({ host, module, recent, setRecent, favourite, setFavourite }: {
  host?: Host;
  module?: string;
  recent: string[];
  setRecent: (next: string[] | ((current: string[]) => string[])) => void;
  favourite: string[];
  setFavourite: (next: string[] | ((current: string[]) => string[])) => void;
}) {
  const t = useT();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const holder = useRef<HTMLDivElement>(null);
  const field = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) return;
    field.current?.focus();
    const away = (event: globalThis.MouseEvent) => {
      if (!holder.current?.contains(event.target as Node)) setOpen(false);
    };
    const escape = (event: globalThis.KeyboardEvent) => { if (event.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", away);
    document.addEventListener("keydown", escape);
    return () => {
      document.removeEventListener("mousedown", away);
      document.removeEventListener("keydown", escape);
    };
  }, [open]);

  const asked = useDebounced(query.trim(), 200);
  const fleet = useQuery({
    queryKey: ["host-select", asked],
    queryFn: () => api.get<Collection<Host>>(
      `/api/v1/hosts?limit=${HOSTS_SHOWN}${asked ? `&q=${encodeURIComponent(asked)}` : ""}`),
    enabled: open,
    retry: false,
  });

  const address = (id: string) => `/hosts/${encodeURIComponent(id)}${module ? `/${module}` : ""}`;
  const kept = keep(favourite);
  const lately = keep(recent).filter((one) => !kept.some((other) => other.id === one.id));
  const asking = asked !== "";

  const go = (one: Kept) => {
    setRecent((current) => [packed(one), ...current.filter((other) => keep([other])[0].id !== one.id)].slice(0, RECENT));
    setOpen(false);
    setQuery("");
    navigate(address(one.id));
  };

  const star = (one: Kept) =>
    setFavourite((current) => current.some((other) => keep([other])[0].id === one.id)
      ? current.filter((other) => keep([other])[0].id !== one.id)
      : [...current, packed(one)]);

  const group = (title: string, rows: Kept[], states?: Map<string, string>) => rows.length === 0 ? null : (
    <div className="fl-pick-group" key={title}>
      <span className="fl-pick-head">{title}</span>
      {rows.map((one) => (
        <div className="fl-pick-row" key={one.id}>
          <button type="button" className="fl-pick-open" onClick={() => go(one)} data-testid={`pick-${one.id}`}>
            <span className={join("fl-dot", toneClass(connectionTone(states?.get(one.id))))} />
            <span className="fl-pick-name">{one.name}</span>
          </button>
          <button
            type="button"
            className="fl-plain fl-pick-keep"
            aria-pressed={kept.some((other) => other.id === one.id)}
            title={t("Keep this machine at the top of the list")}
            onClick={() => star(one)}
          >
            <Icon name="star" />
          </button>
        </div>
      ))}
    </div>
  );

  const states = new Map((fleet.data?.items ?? []).map((one) => [one.id, one.connection_state as string]));

  return (
    <div className="fl-menu-anchor" ref={holder}>
      <button
        type="button"
        className="fl-pick"
        onClick={() => setOpen((on) => !on)}
        aria-expanded={open}
        aria-haspopup="listbox"
        data-testid="host-select"
      >
        <Icon name="server" />
        <span className="fl-pick-current">
          {host ? host.hostname : t("Pick a machine")}
        </span>
        <Icon name="chevron" />
      </button>
      {open && (
        <div className="fl-menu fl-pick-menu" role="listbox" data-testid="host-select-open">
          <div className="fl-finder-field fl-pick-field">
            <Icon name="search" />
            <input
              ref={field}
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder={t("A machine by name or address…")}
              aria-label={t("A machine by name or address…")}
              data-testid="host-select-field"
            />
          </div>
          <div className="fl-pick-list">
            {!asking && group(t("Kept"), kept, states)}
            {!asking && group(t("Lately"), lately, states)}
            {fleet.isLoading ? (
              <p className="fl-finder-none">{t("Reading the fleet…")}</p>
            ) : (fleet.data?.items ?? []).length === 0 ? (
              <p className="fl-finder-none">{t("No machine answers to that.")}</p>
            ) : (
              group(
                asking ? t("Found") : t("The fleet"),
                (fleet.data?.items ?? []).map((one) => ({ id: one.id, name: one.hostname || one.id })),
                states,
              )
            )}
          </div>
        </div>
      )}
    </div>
  );
}
