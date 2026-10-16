import { useEffect, useRef, useState, type MouseEvent as ReactMouseEvent, type ReactNode } from "react";
import { Link, NavLink, useLocation } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, BEARER_TOKEN_KEY } from "../lib/api";
import { usePreferences } from "../lib/preferences";
import { useScale, SCALES } from "../lib/scale";
import { useTheme, THEMES } from "../lib/theme";
import { LOCALES, useLocale } from "../i18n";
import { useCapabilities } from "../lib/capabilities";
import { fleetNavigation, type NavGroup } from "../lib/navigation";
import type { IconName } from "../components/icons";
import type { Whoami } from "../lib/types";
import { Icon } from "../components/icons";
import { LogoMark } from "../components/Logo";
import { useT } from "../i18n";
import { Problem } from "./kit";

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
export type Trail = { section: string; to?: string; here?: string };

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
  groups: { key: string; label?: string; items: RailItem[] }[];
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
        items: group.items.map((item) => ({ to: `/next${item.to}`, label: item.label, icon: item.icon })),
      })),
  };
  const shown = face ?? fleet;
  const name = me.data?.display_name || me.data?.subject || "";

  return (
    <div className="fl-app">
      <div className={folded ? "fl-shell fl-folded" : "fl-shell"}>
        <a href="#fl-main" className="fl-skip">{t("Skip to content")}</a>

        <aside className={drawer ? "fl-rail fl-open" : "fl-rail"}>
          <Link to="/next" className="fl-brand">
            <span className="fl-brand-mark" aria-hidden="true">
              <LogoMark size={26} ground="color-mix(in srgb, var(--accent) 14%, transparent)" />
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
            {trail.here && <><Icon name="chevron" /><span className="fl-crumbs-here">{trail.here}</span></>}
          </nav>
          <span className="fl-bar-spacer" />
          <span className="fl-search">
            <Icon name="search" />
            <input placeholder={t("Search the fleet…")} aria-label={t("Search the fleet…")} />
            <span className="fl-search-key">Ctrl K</span>
          </span>
          <Link to="/next/settings" className="fl-iconbtn" aria-label={t("Settings")}><Icon name="settings" /></Link>
          <UserMenu name={name} roles={me.data?.roles ?? []} subject={me.data?.subject ?? ""} />
        </header>

        <main className="fl-screen" id="fl-main" tabIndex={-1}>
          {me.error ? <Problem>{t("Error: {message}", { message: String(me.error) })}</Problem> : children}
        </main>
        </div>
      </div>
    </div>
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
  const { theme, setTheme } = useTheme();
  const { scale, setScale } = useScale();
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
    <div className="fl-menu-anchor" ref={holder}>
      <button
        type="button"
        className="fl-user"
        onClick={() => setOpen((on) => !on)}
        aria-expanded={open}
        aria-haspopup="menu"
        data-testid="user"
      >
        <span className="fl-avatar" aria-hidden="true">{(name || "?").slice(0, 1).toUpperCase()}</span>
        <span className="fl-user-name">{name}</span>
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

          <Link to="/next/profile" className="fl-menu-item" role="menuitem">
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
  return (
    <div className="fl-navgroup">
      {group.label && <span className="fl-navgroup-label">{t(group.label)}</span>}
      {group.items.map((item) => {
        // /next alone is the dashboard, so the item that leads there is the
        // one the reader is standing on.
        const here = location.pathname === "/next" ? "/next/dashboard" : location.pathname;
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
