import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../../lib/api";
import type { DirectoryService } from "../../lib/types";
import { ErrorBox, Empty } from "../../components/ui";
import { Card, Toolbar } from "../../components/layout";
import { useT } from "../../i18n";
import { DirectoryConfirmation, Forbidden, PlanImpact, TriState, useDirectoryChange } from "./shared";

/**
 * The Kerberos service principals of the directory. Whether a principal
 * holds a keytab is what the directory said; a directory that did not say
 * leaves the column unknown rather than "no". The keytab itself never
 * leaves the directory for a browser: the one change here, a rotation,
 * retires the keytab in the directory and has the fleet host fetch its
 * own new one - under a permission of its own, a reason, fresh
 * authentication and a second person's approval, like every change of
 * access.
 */
export function Services() {
  const t = useT();
  const [filter, setFilter] = useState("");
  const [rotating, setRotating] = useState<DirectoryService | null>(null);
  const { mutation, change, message } = useDirectoryChange(["identity-services"]);

  const { data, error } = useQuery({
    queryKey: ["identity-services"],
    queryFn: () => api.get<Collection<DirectoryService>>("/api/v1/identity/services"),
    retry: false,
  });
  // The rotation column is drawn for holders of the permission alone:
  // a button the server would refuse is a promise the page cannot keep.
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<{ permissions: string[] }>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const canRotate = (whoami.data?.permissions ?? []).includes("identity.keytab.rotate");

  if (error instanceof ApiError && error.forbidden) return <Forbidden />;
  if (error) return <ErrorBox error={error} />;

  const needle = filter.trim().toLowerCase();
  const items = (data?.items ?? []).filter((service) =>
    !needle || service.principal.toLowerCase().includes(needle) || service.host.toLowerCase().includes(needle));
  // The host's own principal is not rotated here: its keytab is replaced
  // by a re-join, and retiring it would cut the host off from the
  // directory it fetches from.
  const rotatable = (service: DirectoryService) => service.service.toLowerCase() !== "host" && service.host !== "";

  return (
    <>
      <p className="subtitle">
        {t("The service principals of the directory, one per service and host. A keytab is never exported to the browser: this view says whether one is on record, and a rotation retires it in the directory while the host fetches its own new one.")}
      </p>

      <Toolbar end={<span>{t("{n} services", { n: items.length })}</span>}>
        <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder={t("filter by principal or host")} />
      </Toolbar>

      {rotating && (
        <DirectoryConfirmation
          target={rotating.principal}
          danger
          label={t("Plan keytab rotation")}
          description={t("The directory retires the current keytab of the principal - the keytab and the certificates issued to the service are revoked, the entry stays - and the fleet host of that name is ordered to fetch a new one with its own credentials. Between the two the service cannot authenticate. A second person approves the change; the task on the host reports the old and the new key version.")}
          busy={mutation.isPending}
          onConfirm={(why) => mutation.mutate(
            { action: "identity.keytab.rotate", reason: why, payload: { keytab: { principal: rotating.principal } } },
            { onSuccess: () => setRotating(null) },
          )}
          onCancel={() => setRotating(null)}
        />
      )}
      {message && <p className="page-error">{message}</p>}
      {change && <PlanImpact change={change} />}

      <Card flush>
        {!items.length ? (
          <Empty>{data?.items.length ? t("No service matches the filter.") : t("The directory has no service principals the panel can read.")}</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>{t("Principal")}</th><th>{t("Service")}</th><th>{t("Host")}</th><th>{t("Keytab")}</th><th>{t("Managed by")}</th>
                {canRotate && <th></th>}
              </tr>
            </thead>
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
                  {canRotate && (
                    <td>
                      {rotatable(service) ? (
                        <button className="secondary" onClick={() => setRotating(service)} disabled={mutation.isPending}>
                          {t("Rotate keytab")}
                        </button>
                      ) : (
                        <span className="source" title={t("The host's own keytab is replaced by a re-join, not a rotation.")}>—</span>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}
