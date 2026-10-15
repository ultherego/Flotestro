import { useEffect, useState, type ReactNode } from "react";
import { Link, NavLink, useLocation } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useCapabilities } from "../lib/capabilities";
import { fleetNavigation, type NavGroup } from "../lib/navigation";
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

export function Shell({ trail, children }: { trail: Trail; children: ReactNode }) {
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
  const groups = fleetNavigation(permissions, capabilities);
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
            {groups.filter((group) => group.items.length > 0).map((group) => (
              <Rail key={group.key} group={group} />
            ))}
          </nav>
        </aside>
        {drawer && <div className="fl-rail-backdrop" onClick={() => setDrawer(false)} />}

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
          <button type="button" className="fl-user" data-testid="user">
            <span className="fl-avatar" aria-hidden="true">{(name || "?").slice(0, 1).toUpperCase()}</span>
            <span className="fl-user-name">{name}</span>
          </button>
        </header>

        <main className="fl-main" id="fl-main" tabIndex={-1}>
          {me.error ? <Problem>{t("Error: {message}", { message: String(me.error) })}</Problem> : children}
        </main>
      </div>
    </div>
  );
}

/**
 * One group of the rail. The heading names what the places below are for;
 * an item that is where the reader already is wears the accent and a bar
 * at its edge, and nothing else on the screen wears that.
 */
function Rail({ group }: { group: NavGroup }) {
  const t = useT();
  const location = useLocation();
  return (
    <div className="fl-navgroup">
      {group.label && <span className="fl-navgroup-label">{t(group.label)}</span>}
      {group.items.map((item) => {
        // Every place of the new panel lives under /next while it is being
        // written; the navigation model names the addresses it will have.
        const to = `/next${item.to}`;
        const on = item.active ? item.active(location.pathname.replace(/^\/next/, "")) : location.pathname === to;
        return (
          <NavLink key={item.to} to={to} className={on ? "fl-navitem fl-on" : "fl-navitem"} title={t(item.label)}>
            <Icon name={item.icon} />
            <span className="fl-navitem-label">{t(item.label)}</span>
          </NavLink>
        );
      })}
    </div>
  );
}
