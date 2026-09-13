import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { ErrorBox, Time, Empty } from "../components/ui";
import { useT } from "../i18n";

type Item = {
  host_id: string;
  hostname: string;
  path: string;
  subject?: string;
  issuer?: string;
  not_after?: string;
  days_to_expiry?: number;
  status: string;
  renewal: string;
  owner_service?: string;
  unavailable_reason?: string;
};

type View = {
  items: Item[];
  counts: Record<string, number>;
  truncated: boolean;
  hosts_total: number;
  hosts_without_certificates: number;
  // The expiry timeline: how many certificates end in which time window.
  timeline?: { reason: string; count: number }[];
  thresholds: { critical_days: number; warning_days: number };
};

function ExpiryBadge({ status, days }: { status: string; days?: number }) {
  const t = useT();
  const cls =
    status === "valid" ? "ok" : status === "expired" || status === "critical" ? "error"
      : status === "warning" ? "warn" : "unknown";
  const caption =
    status === "expired"
      ? days === undefined ? t("expired") : t("expired {n} d ago", { n: Math.abs(days) })
      : status === "unknown" ? t("unknown")
        : days === undefined ? status : `${days} d`;
  return <span className={`badge ${cls}`}>{caption}</span>;
}

/**
 * The certificate deadlines of the whole fleet.
 *
 * A certificate expires quietly and always at the worst moment. The only
 * defence is a list on which all the deadlines stand next to each other,
 * sorted from the nearest - and on which one can see whether anything will
 * renew those certificates.
 */
export function FleetCertificates() {
  const t = useT();
  const { data, error } = useQuery({
    queryKey: ["certificates", "fleet"],
    queryFn: () => api.get<View>("/api/v1/certificates"),
  });

  if (error) return <ErrorBox error={error} />;
  if (!data) return <Empty>{t("Reading certificates…")}</Empty>;

  const counts = data.counts ?? {};
  return (
    <>
      <h1>{t("Certificates")}</h1>
      <p className="subtitle">
        {t("Expiry dates from the paths the panel watches and from everything certmonger tracks. Warning at {warning} days, urgent at {critical}. A host that reports no certificate is not a host without them — it is a host nobody has pointed at a path yet.", {
          warning: data.thresholds.warning_days, critical: data.thresholds.critical_days,
        })}
      </p>

      <div className="filters">
        <span className="badge error">{t("{n} expired", { n: counts.expired ?? 0 })}</span>
        <span className="badge error">{t("{n} urgent", { n: counts.critical ?? 0 })}</span>
        <span className="badge warn">{t("{n} expiring", { n: counts.warning ?? 0 })}</span>
        <span className="badge unknown">{t("{n} unknown", { n: counts.unknown ?? 0 })}</span>
        <span className="badge ok">{t("{n} valid", { n: counts.valid ?? 0 })}</span>
        <span className="source">
          {t("{n} of {total} hosts report none", { n: data.hosts_without_certificates, total: data.hosts_total })}
        </span>
      </div>

      <ExpiryTimeline timeline={data.timeline ?? []} />

      <Trust leaves={data.items} />

      {!data.items.length ? (
        <Empty>
          {t("No host reports a certificate yet. Open a host, watch a path and scan it.")}
        </Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th>{t("Expires")}</th><th>{t("Host")}</th><th>{t("Path")}</th><th>{t("Subject")}</th>
              <th>{t("Issuer")}</th><th>{t("Renewal")}</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((item) => (
              <tr key={`${item.host_id}-${item.path}`}>
                <td>
                  <ExpiryBadge status={item.status} days={item.days_to_expiry} />
                  {item.not_after && (
                    <div className="source"><Time value={item.not_after} /></div>
                  )}
                </td>
                <td>
                  <Link to={`/hosts/${item.host_id}/certificates`}>{item.hostname}</Link>
                </td>
                <td className="source">
                  {item.path}
                  {item.owner_service && <div>{item.owner_service}</div>}
                </td>
                <td>
                  {item.unavailable_reason ? (
                    <span className="badge unknown">{item.unavailable_reason}</span>
                  ) : (
                    item.subject
                  )}
                </td>
                <td className="source">{item.issuer}</td>
                <td>
                  {/* "Manual" is a finding, "unknown" a missing answer - and
                      the two must not look the same. */}
                  {item.renewal === "tracked" ? (
                    <span className="badge ok">certmonger</span>
                  ) : item.renewal === "manual" ? (
                    <span className="badge warn">{t("manual")}</span>
                  ) : (
                    <span className="badge unknown">{t("unknown")}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {data.truncated && (
        <p className="source">
          {t("Only the closest {n} certificates are listed. The counts above cover all of them.", { n: data.items.length })}
        </p>
      )}
    </>
  );
}

type TrustView = {
  items: {
    fingerprint_sha256?: string;
    subject?: string;
    anchor_id?: string;
    not_after?: string;
    hosts: number;
    sample?: string[];
    unavailable_reason?: string;
  }[];
  hosts_total: number;
  hosts_unknown: number;
  hosts_without_trust_store?: { reason: string; count: number }[];
};

/**
 * The authorities the fleet trusts.
 *
 * This is the rotation screen: during one, some hosts trust the old and the
 * new authority at once, and only this view says whether the old one may be
 * withdrawn yet. Only the anchors placed by the panel are shown - the store
 * holds hundreds of distribution authorities, and they are no information
 * here.
 */
function Trust({ leaves }: { leaves: Item[] }) {
  const t = useT();
  const { data } = useQuery({
    queryKey: ["certificates", "trust"],
    queryFn: () => api.get<TrustView>("/api/v1/certificates/trust"),
  });
  if (!data) return null;
  const withoutStore = data.hosts_without_trust_store ?? [];

  // The rotation goes in four stages - distribute the trust, verify it
  // reached every host, rotate the leaves, withdraw the old trust - and
  // every stage is an ordinary campaign. The table says where each
  // authority stands: how many hosts trust it and how many leaves still
  // hang on it, because the last stage is only safe at zero.
  const issuedBy = (anchor: TrustView["items"][number]) =>
    leaves.filter((leaf) => anchor.subject && leaf.issuer === anchor.subject).length;
  const bulk = (action: string, name: string, payload: Record<string, unknown>) =>
    `/bulk?action=${encodeURIComponent(action)}&name=${encodeURIComponent(name)}&payload=${encodeURIComponent(JSON.stringify(payload, null, 2))}`;

  return (
    <section style={{ marginTop: 16 }}>
      <h2>{t("Trusted authorities")}</h2>
      <p className="subtitle">
        {t("Anchors the panel put on hosts. During a rotation a host trusts both the old and the new authority; the old one may only be withdrawn once nothing signs with it any more.")}
      </p>
      <p className="source">
        {t("Rotation in four stages, each an ordinary campaign: distribute the new authority, verify it reached every host, rotate the leaves, withdraw the old authority. A withdrawal is refused while any host is unverified or still holds a certificate issued by it.")}{" "}
        <Link to={bulk("certificate.trust.ensure", t("Distribute a new authority"), {
          certificate: { anchor_id: "fleet-ca-" + new Date().getFullYear(), certificate: "-----BEGIN CERTIFICATE-----\nREPLACE WITH THE AUTHORITY CERTIFICATE\n-----END CERTIFICATE-----\n" },
        })}>{t("Distribute a new authority")}</Link>
      </p>
      {!data.items.length ? (
        <Empty>{t("No panel-managed authority on any host.")}</Empty>
      ) : (
        <table>
          <thead>
            <tr><th>{t("Authority")}</th><th>{t("Hosts")}</th><th>{t("Leaves issued by it")}</th><th>{t("Valid until")}</th><th>{t("Fingerprint")}</th><th>{t("Stage")}</th></tr>
          </thead>
          <tbody>
            {data.items.map((anchor) => {
              const covered = anchor.hosts >= data.hosts_total && data.hosts_unknown === 0;
              const issued = issuedBy(anchor);
              return (
              <tr key={(anchor.fingerprint_sha256 || anchor.anchor_id) ?? ""}>
                <td>
                  {anchor.subject || anchor.anchor_id || "—"}
                  {anchor.unavailable_reason && (
                    <div className="source">{anchor.unavailable_reason}</div>
                  )}
                </td>
                <td>
                  {t("{n} of {total}", { n: anchor.hosts, total: data.hosts_total })}
                  <div className="source">{(anchor.sample ?? []).join(", ")}</div>
                </td>
                <td>
                  {issued}
                  {issued > 0 && <div className="source">{t("rotate the leaves before withdrawing")}</div>}
                </td>
                <td>{anchor.not_after ? <Time value={anchor.not_after} /> : "—"}</td>
                <td className="source">{(anchor.fingerprint_sha256 ?? "").slice(0, 16) || "—"}</td>
                <td>
                  {!covered ? (
                    <>
                      <span className="badge warn">{t("distributing")}</span>{" "}
                      <Link to={bulk("certificate.trust.ensure", t("Distribute {anchor}", { anchor: anchor.anchor_id ?? anchor.subject ?? "" }), {
                        certificate: { anchor_id: anchor.anchor_id ?? "", certificate: "-----BEGIN CERTIFICATE-----\nREPLACE WITH THE AUTHORITY CERTIFICATE\n-----END CERTIFICATE-----\n" },
                      })}>{t("distribute to the rest")}</Link>
                    </>
                  ) : issued > 0 ? (
                    <span className="badge ok">{t("in use")}</span>
                  ) : (
                    <>
                      <span className="badge">{t("withdrawable")}</span>{" "}
                      <Link to={bulk("certificate.trust.remove", t("Withdraw {anchor}", { anchor: anchor.anchor_id ?? anchor.subject ?? "" }), {
                        certificate: { anchor_id: anchor.anchor_id ?? "" },
                      })}>{t("withdraw")}</Link>
                    </>
                  )}
                </td>
              </tr>
              );
            })}
          </tbody>
        </table>
      )}
      <div className="source">
        {t("{n} hosts have not reported a trust store yet", { n: data.hosts_unknown })}
        {withoutStore.map((group) => `; ${group.count}: ${group.reason}`).join("")}
      </div>
    </section>
  );
}

/**
 * The expiry timeline of the fleet's certificates.
 *
 * The list sorted by deadline says what burns now. The timeline says when
 * the next wave comes - and that is what decides whether the rotation is
 * planned for this week or for the quarter.
 */
function ExpiryTimeline({ timeline }: { timeline: { reason: string; count: number }[] }) {
  if (!timeline.length) return null;
  const total = timeline.reduce((sum, window) => sum + window.count, 0);
  if (total === 0) return null;
  return (
    <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginTop: 12 }}>
      {timeline.map((window) => (
        <div key={window.reason}>
          <strong>{window.count}</strong>
          <div className="source">{window.reason}</div>
        </div>
      ))}
    </div>
  );
}
