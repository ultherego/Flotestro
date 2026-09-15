import { useEffect, useRef, useState, type MouseEvent } from "react";
import { Link } from "react-router-dom";
import type { Host, Whoami } from "../lib/types";
import { LOCALES, useLocale, useT } from "../i18n";
import { THEMES, type Theme } from "../lib/theme";
import { SCALES, type Scale } from "../lib/scale";
import { usePreferences } from "../lib/preferences";
import { HostPicker } from "./HostPicker";
import { Icon } from "./icons";

/**
 * Where the operator is, as the top bar tells it. The section is the
 * navigation item the page belongs to; on a host page the host stands
 * between the section and the module, so the target of every operation
 * is named at the top of the screen whatever the module shows.
 */
export type Trail = {
  /** The English label of the section; it goes through the translation catalogue. */
  section: string;
  /** Where the section label leads when the page sits deeper than the section. */
  to?: string;
  /** Set on a host page once the host is known. */
  host?: Host;
  /** Set on a host page: the English name of the open module, if the address names one. */
  module?: string;
};

/**
 * The top bar: the sidebar fold, the trail, the host search and the user
 * menu, across the whole width above the content. The navigation stays in
 * the sidebar; everything about the session and the person at the screen
 * lives here, so the sidebar can be only a list of places.
 */
export function Topbar({
  trail, user, collapsed, onToggleCollapsed, onOpenDrawer, onSignOut, theme, setTheme, scale, setScale,
}: {
  trail: Trail;
  user: Whoami | undefined;
  collapsed: boolean;
  onToggleCollapsed: () => void;
  /** Opens the sidebar drawer on a narrow screen. */
  onOpenDrawer: () => void;
  onSignOut: (event: MouseEvent) => void;
  theme: Theme;
  setTheme: (theme: Theme) => void;
  scale: Scale;
  setScale: (scale: Scale) => void;
}) {
  const t = useT();
  const host = trail.host;
  return (
    <header className="topbar">
      {/* Two buttons for the same edge: the fold on a wide screen, the
          drawer on a narrow one. The stylesheet shows one at a time. */}
      <button
        type="button"
        className="topbar-fold"
        onClick={onToggleCollapsed}
        title={collapsed ? t("Expand the sidebar") : t("Collapse the sidebar")}
        aria-label={collapsed ? t("Expand the sidebar") : t("Collapse the sidebar")}
      >
        <Icon name={collapsed ? "expand" : "collapse"} />
      </button>
      <button
        type="button"
        className="topbar-menu"
        onClick={onOpenDrawer}
        aria-label={t("Open the navigation")}
        title={t("Open the navigation")}
      >
        <Icon name="menu" />
      </button>

      <nav className={host ? "topbar-trail on-host" : "topbar-trail"} aria-label={t("Breadcrumb")}>
        {trail.to ? (
          <Link to={trail.to} className="topbar-crumb">{t(trail.section)}</Link>
        ) : (
          <h1 className="topbar-crumb current">{t(trail.section)}</h1>
        )}
        {host && (
          <>
            <Icon name="chevron" className="topbar-sep" />
            <Link
              to={`/hosts/${host.id}`}
              className={trail.module ? "topbar-host" : "topbar-host current"}
              title={t("Open the host overview")}
            >
              <ConnectionDot state={host.connection_state} />
              <span className="topbar-host-name">{host.hostname}</span>
              <span className="topbar-host-address">{host.management_address || t("address unknown")}</span>
            </Link>
            {trail.module && (
              <>
                <Icon name="chevron" className="topbar-sep" />
                <span className="topbar-crumb current">{t(trail.module)}</span>
              </>
            )}
          </>
        )}
      </nav>

      <div className="topbar-search">
        <HostPicker />
      </div>

      <UserMenu user={user} onSignOut={onSignOut} theme={theme} setTheme={setTheme} scale={scale} setScale={setScale} />
    </header>
  );
}

/** The connection state as a dot, in the same colours as the badge. */
function ConnectionDot({ state }: { state: Host["connection_state"] }) {
  const kind = state === "online" ? "ok" : state === "offline" ? "error" : state === "stale" ? "warn" : "unknown";
  return <span className={`dot ${kind}`} title={state} />;
}

/**
 * The person at the screen and their settings: the identity with its
 * roles, the language, the theme and the text size, and the way out of
 * the session. A popover rather than a page, because none of it needs
 * more than a glance.
 */
function UserMenu({ user, onSignOut, theme, setTheme, scale, setScale }: {
  user: Whoami | undefined;
  onSignOut: (event: MouseEvent) => void;
  theme: Theme;
  setTheme: (theme: Theme) => void;
  scale: Scale;
  setScale: (scale: Scale) => void;
}) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const container = useRef<HTMLDivElement>(null);
  const name = user?.display_name || user?.subject || "";
  const roles = user?.roles.join(", ") || t("no roles");

  useEffect(() => {
    if (!open) return;
    const onPointer = (event: globalThis.MouseEvent) => {
      if (!container.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: globalThis.KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div className="topbar-user" ref={container}>
      <button
        type="button"
        className="topbar-user-trigger"
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-label={t("Account menu")}
        title={`${name}\n${roles}`}
        onClick={() => setOpen((current) => !current)}
      >
        <span className="topbar-avatar" aria-hidden="true">{initial(name)}</span>
        <span className="topbar-user-name">{name}</span>
        <Icon name="chevron" className="topbar-user-chevron" />
      </button>

      {open && (
        <div className="user-menu" role="dialog" aria-label={t("Account menu")}>
          <div className="user-menu-identity">
            <span className="topbar-avatar" aria-hidden="true">{initial(name)}</span>
            <span className="user-menu-text">
              <span className="user-menu-name">{name}</span>
              {/* The subject is shown only when a display name hides it:
                  it is what the audit trail and the bindings refer to. */}
              {user?.display_name && user.subject !== user.display_name && (
                <span className="user-menu-subject">{user.subject}</span>
              )}
              <span className="user-menu-roles">{roles}</span>
            </span>
          </div>
          <div className="user-menu-section">
            <span className="user-menu-label">{t("Language")}</span>
            <LanguageSwitch />
          </div>
          <div className="user-menu-section">
            <span className="user-menu-label">{t("Theme")}</span>
            <ThemeSwitch theme={theme} setTheme={setTheme} />
          </div>
          <div className="user-menu-section">
            <span className="user-menu-label">{t("Text size")}</span>
            <ScaleSwitch scale={scale} setScale={setScale} />
          </div>
          <div className="user-menu-session">
            {/* The rest of the person's settings - the zone, the page size,
                the landing page - and their roles, sessions and tokens
                need a page, not a popover. */}
            <Link to="/profile" onClick={() => setOpen(false)}>{t("Profile and preferences")}</Link>
            {/* The identity provider may have an active session of another
                user and sign in with it quietly. Without this link there is
                no way out of that other than clearing the browser cookies. */}
            <a href={`/auth/login?force=1&redirect=${encodeURIComponent(window.location.pathname)}`}>
              {t("Switch account")}
            </a>
            <a href="#" onClick={onSignOut} className="user-menu-signout" title={t("Sign out")}>
              <Icon name="sign-out" />
              <span>{t("Sign out")}</span>
            </a>
          </div>
        </div>
      )}
    </div>
  );
}

function initial(name: string): string {
  const letter = name.trim().charAt(0);
  return letter ? letter.toUpperCase() : "?";
}

/**
 * The interface language; the choice is remembered in the browser and,
 * for a signed-in person, under their identity on the server, so it
 * follows them to the next browser. A server that cannot take the write
 * changes nothing here: the browser's copy already applies.
 */
export function LanguageSwitch() {
  const { locale, setLocale } = useLocale();
  const { save } = usePreferences();
  const t = useT();
  return (
    <div className="language-switch" role="group" aria-label={t("Language")}>
      {LOCALES.map((entry) => (
        <button
          key={entry.code}
          type="button"
          className={entry.code === locale ? "active" : ""}
          aria-pressed={entry.code === locale}
          onClick={() => {
            setLocale(entry.code);
            save({ language: entry.code }).catch(() => {});
          }}
        >
          {entry.label}
        </button>
      ))}
    </div>
  );
}

/** The colour theme; the choice is remembered in the browser and on the server, like the language. */
export function ThemeSwitch({ theme, setTheme }: { theme: Theme; setTheme: (theme: Theme) => void }) {
  const t = useT();
  const { save } = usePreferences();
  return (
    <div className="theme-switch" role="group" aria-label={t("Theme")}>
      {THEMES.map((entry) => (
        <button
          key={entry.code}
          type="button"
          className={entry.code === theme ? "active" : ""}
          aria-pressed={entry.code === theme}
          title={t(entry.description)}
          onClick={() => {
            setTheme(entry.code);
            save({ theme: entry.code }).catch(() => {});
          }}
        >
          <span className={`theme-swatch ${entry.code}`} aria-hidden="true" />
          {t(entry.label)}
        </button>
      ))}
    </div>
  );
}

/** The text size; the choice is remembered in the browser, like the theme. */
export function ScaleSwitch({ scale, setScale }: { scale: Scale; setScale: (scale: Scale) => void }) {
  const t = useT();
  return (
    <div className="theme-switch scale-switch" role="group" aria-label={t("Text size")}>
      {SCALES.map((entry) => (
        <button
          key={entry.code}
          type="button"
          className={entry.code === scale ? "active" : ""}
          aria-pressed={entry.code === scale}
          title={t(entry.description)}
          onClick={() => setScale(entry.code)}
        >
          {entry.label}
        </button>
      ))}
    </div>
  );
}
