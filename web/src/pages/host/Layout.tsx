import { Link, Outlet, useLocation, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Host } from "../../lib/types";
import { ErrorBox, Empty } from "../../components/ui";
import { EmptyState } from "../../components/layout";
import { ModuleHeader } from "./shared";
import { useCapabilities } from "../../lib/capabilities";
import { ContextBar } from "./ContextBar";
import { modules, DEFAULT_MODULE } from "../../lib/modules";
import { REFRESH_INTERVAL } from "../../lib/stream";
import { useT } from "../../i18n";

/**
 * The host workspace.
 */
export function HostLayout() {
  const t = useT();
  const { id = "" } = useParams();
  const location = useLocation();
  const installation = useCapabilities();

  const host = useQuery({
    queryKey: ["host", id],
    queryFn: () => api.get<Host>(`/api/v1/hosts/${id}`),
    // The header carries the connection state and the data freshness, so
    // it must refresh itself: a stale target state is worse than none.
    refetchInterval: REFRESH_INTERVAL,
  });

  const data = host.data;
  const segment = location.pathname.split("/")[3] || DEFAULT_MODULE;

  // The tab title is set by the context bar, which knows the host and the
  // module by name; nothing here, or it would win over it.

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
      <ContextBar host={data} segment={segment} campaign={fromCampaign} />

      {/* The modules of the host are in the sidebar, which App feeds from
          the same registry; the page holds the header and the content. */}
      <div className="host-content">
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
            {t("There is no module named \"{segment}\". Pick one from the module list.", { segment })}
          </Empty>
        ) : /* A module without backing on this host keeps its route and gives
               the reason. A vanished entry would look like a missing feature
               in the product. */
        !active.available ? (
          // A module the host cannot serve is still a page with a header:
          // a bare sentence in a blank area reads as a broken screen.
          <div className="hm-page">
            <ModuleHeader
              title={t(active.name)}
              icon={active.icon}
              description={t("{module} is not available on this host: {reason}.", { module: t(active.name), reason: active.missingReason })}
            />
            <EmptyState action={<Link className="button" to={`/hosts/${data.id}/overview`}>{t("Back to the overview")}</Link>}>
              {t("The module appears once the host reports the adapter it needs; the agent checks for it at every report, so nothing has to be re-enrolled.")}
            </EmptyState>
          </div>
        ) : (
          <Outlet context={{ host: data }} />
        )}
      </div>
    </>
  );
}
