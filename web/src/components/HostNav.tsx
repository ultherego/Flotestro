import { NavLink, useLocation, useNavigate } from "react-router-dom";
import type { Host } from "../lib/types";
import { groupedModules, type VisibleModule } from "../pages/host/modules";
import { Icon } from "./icons";
import { useT } from "../i18n";

/**
 * The host module navigation: the modules under their group headings in a
 * column beside the content. Two dozen modules in one horizontal strip
 * were read by scanning the whole strip every time; grouped in a column
 * the operator goes to the heading they need and reads five names.
 *
 * Every entry is a link, because every module has an address of its own.
 * A module without backing on this host stays in the list, dimmed, with
 * the reason on hover: a vanished entry would look like a missing product
 * feature, and the reason tells whether it is the host or the installation.
 *
 * On a narrow screen the column would push the content below the fold, so
 * the same list becomes one select above the content; the stylesheet shows
 * one or the other.
 */
export function HostNav({ host, list, segment }: { host: Host; list: VisibleModule[]; segment: string }) {
  const t = useT();
  const location = useLocation();
  const navigate = useNavigate();
  const groups = groupedModules(list);
  // The search keeps the way back to a campaign across module switches.
  const target = (item: VisibleModule) => `/hosts/${host.id}/${item.segment}${location.search}`;

  return (
    <>
      <nav className="host-nav" aria-label={t("Host modules")}>
        {groups.map((group) => (
          <div key={group.key} className="host-nav-group">
            <h3 className="host-nav-heading">{t(group.title)}</h3>
            <ul className="host-nav-items">
              {group.items.map((item) => (
                <li key={item.segment}>
                  <NavLink
                    to={target(item)}
                    className={({ isActive }) =>
                      ["host-nav-item", isActive ? "active" : "", item.available ? "" : "unavailable"].join(" ").trim()
                    }
                    title={item.available ? t(item.name) : item.missingReason}
                  >
                    <Icon name={item.icon} />
                    <span className="host-nav-label">{t(item.name)}</span>
                  </NavLink>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>

      <div className="host-nav-select">
        <label>
          <span>{t("Module")}</span>
          <select
            value={list.some((item) => item.segment === segment) ? segment : ""}
            onChange={(event) => {
              const chosen = list.find((item) => item.segment === event.target.value);
              if (chosen) navigate(target(chosen));
            }}
          >
            {/* An address outside the registry has no option to select, so
                the select shows a blank entry rather than lying about the
                open module. */}
            {!list.some((item) => item.segment === segment) && <option value="">—</option>}
            {groups.map((group) => (
              <optgroup key={group.key} label={t(group.title)}>
                {group.items.map((item) => (
                  <option key={item.segment} value={item.segment} title={item.available ? undefined : item.missingReason}>
                    {item.available ? t(item.name) : `${t(item.name)} (${t("unavailable")})`}
                  </option>
                ))}
              </optgroup>
            ))}
          </select>
        </label>
      </div>
    </>
  );
}
