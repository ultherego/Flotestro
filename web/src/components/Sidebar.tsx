import type { MouseEvent } from "react";
import { NavLink, useLocation } from "react-router-dom";
import type { Whoami } from "../lib/types";
import { LOCALES, useLocale, useT } from "../i18n";
import { THEMES, type Theme } from "../lib/theme";
import { useStoredState } from "../lib/storage";
import { HostPicker } from "./HostPicker";
import { Icon, type IconName } from "./icons";

export type NavItem = {
  to: string;
  /** The English label; it goes through the translation catalogue. */
  label: string;
  icon: IconName;
  /** Overrides the router's prefix match where two items share a prefix. */
  active?: (pathname: string) => boolean;
};

export type NavGroup = {
  /** The storage key of the fold state; it must not change between versions. */
  key: string;
  /** The English heading; a group without one is a single top-level item. */
  label?: string;
  items: NavItem[];
};

const GROUPS_KEY = "flotestro.sidebar.groups";

function isFoldMap(value: unknown): value is Record<string, boolean> {
  return typeof value === "object" && value !== null
    && Object.values(value as object).every((entry) => typeof entry === "boolean");
}

/**
 * The application sidebar: the brand, the host picker, the grouped
 * navigation and the footer with the session controls. It folds to a rail
 * of icons on demand and becomes a drawer on a narrow screen; both are
 * layout decisions, so the pages know nothing about them.
 */
export function Sidebar({
  groups, user, collapsed, onToggleCollapsed, open, onClose, onSignOut, theme, setTheme,
}: {
  groups: NavGroup[];
  user: Whoami | undefined;
  /** The rail of icons, remembered between visits. */
  collapsed: boolean;
  onToggleCollapsed: () => void;
  /** The drawer on a narrow screen. */
  open: boolean;
  onClose: () => void;
  onSignOut: (event: MouseEvent) => void;
  theme: Theme;
  setTheme: (theme: Theme) => void;
}) {
  const t = useT();
  const location = useLocation();
  // The fold map holds only the groups somebody closed: a group absent
  // from it is open, so a group added in a later version starts open.
  const [folded, setFolded] = useStoredState<Record<string, boolean>>(GROUPS_KEY, {}, isFoldMap);

  const toggleGroup = (key: string) =>
    setFolded((current) => ({ ...current, [key]: !current[key] }));

  return (
    <aside className={["sidebar", collapsed ? "collapsed" : "", open ? "open" : ""].join(" ").trim()}>
      <div className="sidebar-brand">
        <span className="sidebar-mark" aria-hidden="true">F</span>
        <span className="sidebar-title">Flotestro</span>
        <button
          type="button"
          className="sidebar-fold"
          onClick={onToggleCollapsed}
          title={collapsed ? t("Expand the sidebar") : t("Collapse the sidebar")}
          aria-label={collapsed ? t("Expand the sidebar") : t("Collapse the sidebar")}
        >
          <Icon name={collapsed ? "expand" : "collapse"} />
        </button>
      </div>

      <div className="sidebar-picker">
        <HostPicker compact={collapsed} />
      </div>

      <nav className="sidebar-nav" aria-label={t("Main navigation")}>
        {groups.map((group) => {
          if (group.items.length === 0) return null;
          const closed = folded[group.key] === true;
          const holdsActive = group.items.some((item) =>
            item.active ? item.active(location.pathname) : location.pathname.startsWith(item.to));
          return (
            <div key={group.key} className={["sidebar-group", closed ? "closed" : ""].join(" ").trim()}>
              {group.label && (
                <button
                  type="button"
                  className="sidebar-group-head"
                  onClick={() => toggleGroup(group.key)}
                  aria-expanded={!closed}
                  title={t(group.label)}
                >
                  <span className="sidebar-group-label">{t(group.label)}</span>
                  {/* A closed group with the open page inside keeps a mark,
                      so the operator can still see where they are. */}
                  {closed && holdsActive && <span className="sidebar-group-dot" aria-hidden="true" />}
                  <Icon name="chevron" className="sidebar-group-chevron" />
                </button>
              )}
              <ul className="sidebar-items">
                {group.items.map((item) => (
                  <li key={item.to}>
                    <NavLink
                      to={item.to}
                      className={({ isActive }) => {
                        const on = item.active ? item.active(location.pathname) : isActive;
                        return on ? "sidebar-item active" : "sidebar-item";
                      }}
                      title={t(item.label)}
                      onClick={onClose}
                    >
                      <Icon name={item.icon} />
                      <span className="sidebar-item-label">{t(item.label)}</span>
                    </NavLink>
                  </li>
                ))}
              </ul>
            </div>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <div className="sidebar-user" title={`${user?.display_name || user?.subject || ""}\n${user?.roles.join(", ") || t("no roles")}`}>
          <span className="sidebar-avatar" aria-hidden="true">
            {initial(user?.display_name || user?.subject || "")}
          </span>
          <span className="sidebar-user-text">
            <span className="sidebar-user-name">{user?.display_name || user?.subject}</span>
            <span className="sidebar-user-roles">{user?.roles.join(", ") || t("no roles")}</span>
          </span>
        </div>
        <div className="sidebar-switches">
          <LanguageSwitch />
          <ThemeSwitch theme={theme} setTheme={setTheme} />
        </div>
        <div className="sidebar-session">
          {/* The identity provider may have an active session of another
              user and sign in with it quietly. Without this link there is
              no way out of that other than clearing the browser cookies. */}
          <a href={`/auth/login?force=1&redirect=${encodeURIComponent(window.location.pathname)}`}>
            {t("Switch account")}
          </a>
          <a href="#" onClick={onSignOut} className="sidebar-signout" title={t("Sign out")}>
            <Icon name="sign-out" />
            <span className="sidebar-item-label">{t("Sign out")}</span>
          </a>
        </div>
      </div>
    </aside>
  );
}

function initial(name: string): string {
  const letter = name.trim().charAt(0);
  return letter ? letter.toUpperCase() : "?";
}

/** The interface language; the choice is remembered in the browser. */
export function LanguageSwitch() {
  const { locale, setLocale } = useLocale();
  const t = useT();
  return (
    <div className="language-switch" role="group" aria-label={t("Language")}>
      {LOCALES.map((entry) => (
        <button
          key={entry.code}
          type="button"
          className={entry.code === locale ? "active" : ""}
          aria-pressed={entry.code === locale}
          onClick={() => setLocale(entry.code)}
        >
          {entry.label}
        </button>
      ))}
    </div>
  );
}

/** The colour theme; the choice is remembered in the browser. */
export function ThemeSwitch({ theme, setTheme }: { theme: Theme; setTheme: (theme: Theme) => void }) {
  const t = useT();
  return (
    <div className="theme-switch" role="group" aria-label={t("Theme")}>
      {THEMES.map((entry) => (
        <button
          key={entry.code}
          type="button"
          className={entry.code === theme ? "active" : ""}
          aria-pressed={entry.code === theme}
          title={t(entry.description)}
          onClick={() => setTheme(entry.code)}
        >
          <span className={`theme-swatch ${entry.code}`} aria-hidden="true" />
          {t(entry.label)}
        </button>
      ))}
    </div>
  );
}
