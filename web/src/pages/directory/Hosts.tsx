import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, ApiError, type Collection } from "../../lib/api";
import type { DirectoryHost, Host } from "../../lib/types";
import { ErrorBox, Empty } from "../../components/ui";
import { Card, Toolbar } from "../../components/layout";
import { useT } from "../../i18n";
import { Forbidden } from "./shared";

/**
 * The host entries of the directory next to the fleet. An entry and a
 * panel host are two records with separate lifecycles: the directory knows
 * a host by FQDN, the panel by its machine identifier, and the name is the
 * only bridge between them. A directory host the fleet does not have is a
 * fact worth showing, not an error.
 */
export function Hosts() {
  const t = useT();
  const [filter, setFilter] = useState("");

  const { data, error } = useQuery({
    queryKey: ["identity-hosts"],
    queryFn: () => api.get<Collection<DirectoryHost>>("/api/v1/identity/hosts"),
    retry: false,
  });
  // The fleet is read once for the whole table; a lookup per row would be
  // a query per host, and the fleet list is paged by the same limit the
  // host list uses.
  const fleet = useQuery({
    queryKey: ["hosts", "directory-link"],
    queryFn: () => api.get<Collection<Host>>("/api/v1/hosts?limit=500"),
    retry: false,
  });
  if (error instanceof ApiError && error.forbidden) return <Forbidden />;
  if (error) return <ErrorBox error={error} />;

  const byName = new Map<string, Host>();
  for (const host of fleet.data?.items ?? []) {
    byName.set(host.hostname.toLowerCase(), host);
    if (host.identity?.domain) byName.set(`${host.hostname}.${host.identity.domain}`.toLowerCase(), host);
  }
  const linked = (fqdn: string) => byName.get(fqdn.toLowerCase());

  const needle = filter.trim().toLowerCase();
  const items = (data?.items ?? []).filter((host) => !needle || host.fqdn.toLowerCase().includes(needle));

  return (
    <>
      <p className="subtitle">
        {t("The host entries of the directory. An enrolled entry holds a host key; the fleet host of the same name, when there is one, is linked - the two records have separate lifecycles and the name is the only bridge.")}
      </p>

      <Toolbar end={<span>{t("{n} hosts", { n: items.length })}</span>}>
        <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder={t("filter by name")} />
      </Toolbar>

      <Card flush>
        {!items.length ? (
          <Empty>{data?.items.length ? t("No host matches the filter.") : t("The directory has no host entries.")}</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>{t("Host")}</th><th>{t("Enrolled")}</th><th>{t("Host groups")}</th><th>{t("Managed by")}</th><th>{t("Fleet host")}</th><th></th>
              </tr>
            </thead>
            <tbody>
              {items.map((host) => {
                const panelHost = linked(host.fqdn);
                return (
                  <tr key={host.fqdn}>
                    <td className="mono">
                      {host.fqdn}
                      {host.description && <div className="source">{host.description}</div>}
                    </td>
                    <td>
                      {host.enrolled
                        ? <span className="badge ok" title={host.enrolled_at}>{t("enrolled")}</span>
                        : <span className="badge">{t("entry only")}</span>}
                      {host.enrolled_at && <div className="source mono">{host.enrolled_at}</div>}
                    </td>
                    <td>{(host.member_of ?? []).join(", ") || "—"}</td>
                    <td className="mono">{(host.managed_by ?? []).join(", ") || "—"}</td>
                    <td>
                      {panelHost
                        ? <Link to={`/hosts/${panelHost.id}`}>{panelHost.hostname}</Link>
                        : fleet.isPending ? t("Checking…") : <span className="source">{t("not in the fleet")}</span>}
                    </td>
                    <td className="num">
                      {panelHost && <Link className="button" to={`/hosts/${panelHost.id}/identity`}>{t("Join")}</Link>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}
