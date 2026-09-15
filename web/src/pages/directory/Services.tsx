import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../../lib/api";
import type { DirectoryService } from "../../lib/types";
import { ErrorBox, Empty } from "../../components/ui";
import { Card, Toolbar } from "../../components/layout";
import { useT } from "../../i18n";
import { Forbidden, TriState } from "./shared";

/**
 * The Kerberos service principals of the directory, read only. Whether a
 * principal holds a keytab is what the directory said; a directory that
 * did not say leaves the column unknown rather than "no". The keytab
 * itself never leaves the directory for a browser.
 */
export function Services() {
  const t = useT();
  const [filter, setFilter] = useState("");

  const { data, error } = useQuery({
    queryKey: ["identity-services"],
    queryFn: () => api.get<Collection<DirectoryService>>("/api/v1/identity/services"),
    retry: false,
  });
  if (error instanceof ApiError && error.forbidden) return <Forbidden />;
  if (error) return <ErrorBox error={error} />;

  const needle = filter.trim().toLowerCase();
  const items = (data?.items ?? []).filter((service) =>
    !needle || service.principal.toLowerCase().includes(needle) || service.host.toLowerCase().includes(needle));

  return (
    <>
      <p className="subtitle">
        {t("The service principals of the directory, one per service and host. A keytab is never exported to the browser: this view says whether one is on record, nothing more.")}
      </p>

      <Toolbar end={<span>{t("{n} services", { n: items.length })}</span>}>
        <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder={t("filter by principal or host")} />
      </Toolbar>

      <Card flush>
        {!items.length ? (
          <Empty>{data?.items.length ? t("No service matches the filter.") : t("The directory has no service principals the panel can read.")}</Empty>
        ) : (
          <table>
            <thead><tr><th>{t("Principal")}</th><th>{t("Service")}</th><th>{t("Host")}</th><th>{t("Keytab")}</th><th>{t("Managed by")}</th></tr></thead>
            <tbody>
              {items.map((service) => (
                <tr key={service.principal}>
                  <td className="mono">
                    {service.principal}
                    {(service.aliases ?? []).length > 0 && (
                      <div className="source">{t("aliases: {names}", { names: (service.aliases ?? []).join(", ") })}</div>
                    )}
                  </td>
                  <td className="mono">{service.service}</td>
                  <td className="mono">{service.host}</td>
                  <td><TriState value={service.has_keytab} yes={t("on record")} no={t("none")} /></td>
                  <td className="mono">{(service.managed_by ?? []).join(", ") || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}
