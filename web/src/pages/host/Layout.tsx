import { useEffect } from "react";
import { Link, NavLink, Outlet, useLocation, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Host } from "../../lib/types";
import { ErrorBox, Empty } from "../../components/ui";
import { useCapabilities } from "../../lib/capabilities";
import { ContextBar } from "./ContextBar";
import { modules, DEFAULT_MODULE } from "./modules";
import { REFRESH_INTERVAL } from "../../lib/stream";
import { useT } from "../../i18n";

/**
 * The host workspace. The active module is a segment of the address, not
 * component state: thanks to that a refresh, the browser history, a direct
 * link and opening in a new tab all work.
 */
export function HostLayout() {
  const t = useT();
  const { id = "" } = useParams();
  const location = useLocation();
  const installation = useCapabilities();

  const host = useQuery({
    queryKey: ["host", id],
    queryFn: () => api.get<Host>(`/api/v1/hosts/${id}`),
    // The context bar carries the connection state and the data freshness,
    // so it must refresh itself: a stale target state is worse than none.
    refetchInterval: REFRESH_INTERVAL,
  });

  const data = host.data;
  const segment = location.pathname.split("/")[3] || DEFAULT_MODULE;

  // The tab title carries the operation target. An operator with several
  // open tabs recognises the machine by the title before looking at it.
  useEffect(() => {
    if (!data) return;
    const address = data.management_address ? ` ${data.management_address}` : "";
    document.title = `${data.hostname}${address} · ${segment} · Flotestro`;
    return () => {
      document.title = "Flotestro";
    };
  }, [data, segment]);

  if (host.error) return <ErrorBox error={host.error} />;
  if (!data) return <Empty>{t("Loading…")}</Empty>;

  const list = modules(data, installation);
  const active = list.find((item) => item.segment === segment);
  const rejected = location.state as { rejected?: string; reason?: string } | null;
  // A host opened from a campaign keeps the way back in the address: the
  // operator came here to look at one host of a change, not to leave it.
  const fromCampaign = new URLSearchParams(location.search).get("campaign");

  return (
    <>
      {fromCampaign && (
        <p className="source" style={{ margin: "0 0 8px" }}>
          <Link to={`/campaigns/${fromCampaign}`}>← {t("Back to the campaign")}</Link>
        </p>
      )}
      <ContextBar host={data} segment={segment} installation={installation} />

      <div className="tabs">
        {list.map((item) => (
          <NavLink
            key={item.segment}
            to={`/hosts/${data.id}/${item.segment}${location.search}`}
            className={({ isActive }) =>
              [isActive ? "active" : "", item.available ? "" : "unavailable"].join(" ").trim()
            }
            title={item.available ? undefined : item.missingReason}
          >
            {t(item.name)}
          </NavLink>
        ))}
      </div>

      {/* A host switch that changed the module says why. Without that the
          operator sees a different screen than they opened and does not
          know what happened. */}
      {rejected?.rejected && (
        <p className="warning">
          <span>
            {t("{module} is not available on {host}: {reason}", { module: t(rejected.rejected), host: data.hostname, reason: rejected.reason ?? "" })}
          </span>
        </p>
      )}

      {/* An address outside the module registry must not end with empty
          content: the operator is to see that no such module exists. */}
      {!active ? (
        <Empty>
          {t("There is no module named \"{segment}\". Pick one of the tabs above.", { segment })}
        </Empty>
      ) : /* A module without backing on this host keeps its route and gives
             the reason. A vanished tab would look like a missing feature in
             the product. */
      !active.available ? (
        <Empty>
          {t("{module} is not available on this host: {reason}.", { module: t(active.name), reason: active.missingReason })}
        </Empty>
      ) : (
        <Outlet context={{ host: data }} />
      )}
    </>
  );
}
