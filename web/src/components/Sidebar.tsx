import { Link, NavLink, useLocation } from "react-router-dom";
import { useT } from "../i18n";
import { useStoredState } from "../lib/storage";
import { Icon, type IconName } from "./icons";

export type NavItem = {
  to: string;
  /** The English label; it goes through the translation catalogue. */
  label: string;
  icon: IconName;
  /** Overrides the router's prefix match where two items share a prefix. */
  active?: (pathname: string) => boolean;
  /** The reason the item has no backing here; it stays listed, dimmed. */
  unavailable?: string;
};

export type NavGroup = {
  /** The storage key of the fold state; it must not change between versions. */
  key: string;
  /** The English heading; a group without one is a single top-level item. */
  label?: string;
  items: NavItem[];
};

/**
 * The navigation has two faces, never both at once: the fleet, and one
 * host. Two columns of links side by side confused more than they helped,
 * so a host page replaces the fleet groups with the host's modules and a
 * way back; the brand above stays the same in both.
 */
export type NavFace = {
  groups: NavGroup[];
  /** Set on a host page: the address of the fleet view the modules replace. */
  back?: { to: string; label: string };
};

const GROUPS_KEY = "flotestro.sidebar.groups";

function isFoldMap(value: unknown): value is Record<string, boolean> {
  return typeof value === "object" && value !== null
    && Object.values(value as object).every((entry) => typeof entry === "boolean");
}

/**
 * The application sidebar: the brand and the grouped navigation, nothing
 * else - the session, the search and the settings live in the top bar, so
 * this column is only a list of places. It folds to a rail of icons on
 * demand and becomes a drawer on a narrow screen; both are layout
 * decisions, so the pages know nothing about them.
 */
export function Sidebar({ face, collapsed, open, onClose }: {
  face: NavFace;
  /** The rail of icons, remembered between visits. */
  collapsed: boolean;
  /** The drawer on a narrow screen. */
  open: boolean;
  onClose: () => void;
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
      {/* The brand is a link to the dashboard: the one place every page
          can be left for, and the drawer closes behind it like behind any
          other item. */}
      <Link to="/dashboard" className="sidebar-brand" onClick={onClose} title={t("Fleet dashboard")}>
        <span className="sidebar-mark" aria-hidden="true">F</span>
        <span className="sidebar-title">Flotestro</span>
      </Link>

      <nav className="sidebar-nav" aria-label={t("Main navigation")}>
        {face.back && (
          <NavLink to={face.back.to} className="sidebar-item sidebar-back" onClick={onClose} title={t(face.back.label)}>
            <Icon name="back" />
            <span className="sidebar-item-label">{t(face.back.label)}</span>
          </NavLink>
        )}
        {face.groups.map((group) => {
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
                        return ["sidebar-item", on ? "active" : "", item.unavailable ? "unavailable" : ""].join(" ").trim();
                      }}
                      title={item.unavailable ?? t(item.label)}
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
    </aside>
  );
}

