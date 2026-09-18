import { useState } from "react";
import { Link } from "react-router-dom";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { api, loadedItems, LIST_PAGE } from "../lib/api";
import { FleetCoverage, type Coverage } from "../components/FleetCoverage";
import { ErrorBox, Empty } from "../components/ui";
import { absoluteTime, relativeTime } from "../lib/format";
import { Card, PageHeader, Toolbar } from "../components/layout";
import { ExportButton } from "../components/ExportButton";
import { ColumnChooser, Td, Th, useColumns, useSort, type ColumnDef } from "../components/SortableTable";
import { Breakdown, StatusBar } from "../components/widgets";
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

/** One page of the fleet list with the counts over all of it.
 *
 *  The counts, the timeline and the coverage are the server's, taken over
 *  every certificate of every host in scope; the items are one page,
 *  keyed by the cursor. The two must never be confused: the list is what
 *  fits on the screen, the counts are what the fleet has. */
type View = Coverage & {
  items: Item[];
  count: number;
  total: number;
  next_cursor?: string;
  counts: Record<string, number>;
  hosts_total: number;
  hosts_without_certificates: number;
  // The expiry timeline: how many certificates end in which time window.
  timeline?: { reason: string; count: number }[];
  thresholds: { critical_days: number; warning_days: number };
};

/**
 * A deadline is read as a date, not as a distance: the badge beside it
 * already says how many days are left, and a rotation is planned on the
 * calendar. The exact time and the distance are on hover.
 */
function Deadline({ value }: { value: string }) {
  const absolute = absoluteTime(value);
  if (!absolute) return <>—</>;
  return <span title={`${absolute} · ${relativeTime(value)}`}>{absolute.slice(0, 10)}</span>;
}

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
  // The list grows page by page with the cursor the server hands back;
  // the counters above it come from the first page and describe the whole
  // fleet, whatever part of the list is loaded.
  const list = useInfiniteQuery({
    queryKey: ["certificates", "fleet"],
    queryFn: ({ pageParam }) => api.get<View>(
      `/api/v1/certificates?limit=${LIST_PAGE}${pageParam ? `&cursor=${encodeURIComponent(pageParam)}` : ""}`),
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor || undefined,
  });
  const error = list.error;
  const data = list.data?.pages[0];
  const items = loadedItems<Item>(list.data);
  // A heading reorders the rows already loaded, in the browser; the
  // server's order - the nearest deadline first - is the one a cleared
  // sort goes back to. A deadline nobody could read sorts as unknown,
  // apart from the far ones.
  const columns = useColumns("certificates", [
    { key: "expires", label: t("Expires"), sort: "expires" },
    { key: "host", label: t("Host"), sort: "host", fixed: true },
    { key: "path", label: t("Path"), sort: "path" },
    { key: "subject", label: t("Subject"), secondary: true },
    { key: "issuer", label: t("Issuer"), sort: "issuer", secondary: true },
    { key: "renewal", label: t("Renewal"), sort: "renewal" },
  ] satisfies ColumnDef[]);
  const { sort, setSort, sorted } = useSort(items, (item, column) => {
    switch (column) {
      case "expires": return item.not_after ?? null;
      case "host": return item.hostname;
      case "path": return item.path;
      case "issuer": return item.issuer ?? null;
      default: return item.renewal;
    }
  });

  if (error) return <ErrorBox error={error} />;
  if (!data) return <Empty>{t("Reading certificates…")}</Empty>;

  const counts = data.counts ?? {};
  const expired = counts.expired ?? 0;
  const critical = counts.critical ?? 0;
  const warning = counts.warning ?? 0;
  // The hosts that reported a certificate: the judged ones minus the ones
  // that reported an empty list. A host nobody has pointed at a path is
  // not a host without certificates, and neither is one that never
  // reported at all - the coverage line above counts the second kind.
  const reporting = Math.max(0, data.evaluated_hosts - data.hosts_without_certificates);
  // What renews the loaded certificates: the list starts at the closest
  // deadlines, so this says whether the next wave renews itself.
  const renewal = (kind: string) => items.filter((item) => item.renewal === kind).length;
  const listed = t("among the {n} listed", { n: items.length });
  return (
    <>
      <PageHeader
        title={t("Certificates")}
        description={t("Expiry dates from the paths the panel watches and from everything certmonger tracks. Warning at {warning} days, urgent at {critical}. A host that reports no certificate is not a host without them — it is a host nobody has pointed at a path yet.", {
          warning: data.thresholds.warning_days, critical: data.thresholds.critical_days,
        })}
        actions={<ExportButton path="/api/v1/certificates" />}
      />
      <FleetCoverage coverage={data} />

      <div className="widgets">
        {/* The counts cover every certificate the fleet reports, not only
            the listed ones; the nearest deadline is the leftmost segment. */}
        <Card className="span-9" title={t("Expiry")} description={t("Every certificate the fleet reports, by how close its deadline is.")}>
          <StatusBar segments={[
            { label: t("Expired"), value: expired, tone: "error" },
            { label: t("Urgent"), value: critical, tone: "error" },
            { label: t("Expiring"), value: warning, tone: "warn" },
            { label: t("Unknown"), value: counts.unknown ?? 0, tone: "unknown" },
            { label: t("Valid"), value: counts.valid ?? 0, tone: "ok" },
          ]} />
        </Card>

        {/* A host that reports none is not a host without certificates: it
            is a host nobody has pointed at a path yet. */}
        <Card className="span-3" title={t("Hosts")} description={t("{n} of {total} hosts report none", { n: data.hosts_without_certificates, total: data.total_hosts })}>
          <Breakdown items={[
            { label: t("Reporting certificates"), value: reporting, tone: "ok" },
            { label: t("Reporting none"), value: data.hosts_without_certificates, tone: "warn" },
            // A host nobody has heard from is not a host without
            // certificates: its deadline may be tomorrow.
            { label: t("Nothing known"), value: data.unknown_hosts, tone: "unknown" },
          ]} />
        </Card>

        <Trust leaves={items} />

        <Card
          className="span-9"
          flush
          footer={list.hasNextPage && (
            <p>
              <button className="secondary" onClick={() => list.fetchNextPage()} disabled={list.isFetchingNextPage}>
                {t("Load more ({n} left)", { n: data.total - items.length })}
              </button>
            </p>
          )}
        >
          <Toolbar end={<ColumnChooser columns={columns} />}>
            <span className="source">{t("Sorted from the nearest deadline; a heading reorders the listed rows.")}</span>
          </Toolbar>
          {!items.length ? (
            <Empty>
              {t("No host reports a certificate yet. Open a host, watch a path and scan it.")}
            </Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  {columns.visible.map((column) => (
                    <Th key={column.key} columns={columns} name={column.key} sort={sort} onSort={setSort} />
                  ))}
                </tr>
              </thead>
              <tbody>
                {sorted.map((item) => (
                  <tr key={`${item.host_id}-${item.path}`}>
                    <Td columns={columns} name="expires">
                      <ExpiryBadge status={item.status} days={item.days_to_expiry} />
                      {item.not_after && (
                        <div className="source"><Deadline value={item.not_after} /></div>
                      )}
                    </Td>
                    <Td columns={columns} name="host">
                      <Link to={`/hosts/${item.host_id}/certificates`}>{item.hostname}</Link>
                    </Td>
                    <Td columns={columns} name="path" className="source mono">
                      {item.path}
                      {item.owner_service && <div>{item.owner_service}</div>}
                    </Td>
                    <Td columns={columns} name="subject">
                      {item.unavailable_reason ? (
                        <span className="badge unknown">{item.unavailable_reason}</span>
                      ) : (
                        item.subject
                      )}
                    </Td>
                    <Td columns={columns} name="issuer" className="source">{item.issuer}</Td>
                    <Td columns={columns} name="renewal">
                      {/* "Manual" is a finding, "unknown" a missing answer - and
                          the two must not look the same. */}
                      {item.renewal === "tracked" ? (
                        <span className="badge ok">certmonger</span>
                      ) : item.renewal === "manual" ? (
                        <span className="badge warn">{t("manual")}</span>
                      ) : (
                        <span className="badge unknown">{t("unknown")}</span>
                      )}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        <Card className="span-3" title={t("Expires")} description={t("When the next waves of deadlines come.")}>
          <ExpiryTimeline timeline={data.timeline ?? []} />
          <h4 className="widget-subhead">{t("Renewal")}</h4>
          {/* "Manual" is a finding, "unknown" a missing answer - and the
              two must not look the same. */}
          <div className="fp-tones">
            <Breakdown items={[
              { label: "certmonger", value: renewal("tracked"), tone: "ok" },
              { label: t("manual"), value: renewal("manual"), tone: "warn" },
              { label: t("unknown"), value: renewal("unknown"), tone: "unknown" },
            ]} />
          </div>
          <p className="fp-rest">{listed}</p>
        </Card>
      </div>
    </>
  );
}

type TrustView = Coverage & {
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

/** How many authorities the trust table names before it folds the rest. */
const AUTHORITIES_SHOWN = 8;

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
  const [allAuthorities, setAllAuthorities] = useState(false);
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

  // A rotation involves two authorities, three at most; a table of fifty
  // is a lab that has rotated fifty times, and it folds so the page under
  // it is still reached. The nearest to withdrawal stand first as the
  // server lists them.
  const folded = !allAuthorities && data.items.length > AUTHORITIES_SHOWN;
  const shown = folded ? data.items.slice(0, AUTHORITIES_SHOWN) : data.items;

  return (
    <Card
      className="span-12"
      title={t("Trusted authorities")}
      description={t("Anchors the panel put on hosts. During a rotation a host trusts both the old and the new authority; the old one may only be withdrawn once nothing signs with it any more.")}
      actions={
        <Link className="button" to={bulk("certificate.trust.ensure", t("Distribute a new authority"), {
          certificate: { anchor_id: "fleet-ca-" + new Date().getFullYear(), certificate: "-----BEGIN CERTIFICATE-----\nREPLACE WITH THE AUTHORITY CERTIFICATE\n-----END CERTIFICATE-----\n" },
        })}>{t("Distribute a new authority")}</Link>
      }
      footer={
        <div>
          <p className="source">
            {t("Rotation in four stages, each an ordinary campaign: distribute the new authority, verify it reached every host, rotate the leaves, withdraw the old authority. A withdrawal is refused while any host is unverified or still holds a certificate issued by it.")}
          </p>
          <div className="source">
            {t("{n} hosts have not reported a trust store yet", { n: data.hosts_unknown })}
            {withoutStore.map((group) => `; ${group.count}: ${group.reason}`).join("")}
          </div>
          {/* The store is read host by host, so a fleet big enough can run
              the sweep out of its budget; the answer then says so rather
              than letting a part of the fleet pass for all of it. */}
          <FleetCoverage coverage={data} />
        </div>
      }
      flush
    >
      {!data.items.length ? (
        <Empty>{t("No panel-managed authority on any host.")}</Empty>
      ) : (
        <table>
          <thead>
            <tr><th>{t("Authority")}</th><th>{t("Hosts")}</th><th className="num">{t("Leaves issued by it")}</th><th>{t("Valid until")}</th><th>{t("Fingerprint")}</th><th>{t("Stage")}</th></tr>
          </thead>
          <tbody>
            {shown.map((anchor) => {
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
                <td className="num">
                  {issued}
                  {issued > 0 && <div className="source">{t("rotate the leaves before withdrawing")}</div>}
                </td>
                <td>{anchor.not_after ? <Deadline value={anchor.not_after} /> : "—"}</td>
                <td className="source mono">{(anchor.fingerprint_sha256 ?? "").slice(0, 16) || "—"}</td>
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
      {data.items.length > AUTHORITIES_SHOWN && (
        <div className="card-body">
          <button className="secondary" onClick={() => setAllAuthorities((current) => !current)} aria-expanded={!folded}>
            {folded
              ? t("Show all {n} authorities", { n: data.items.length })
              : t("Show the first {n} only", { n: AUTHORITIES_SHOWN })}
          </button>
        </div>
      )}
    </Card>
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
  const t = useT();
  const total = timeline.reduce((sum, window) => sum + window.count, 0);
  if (!timeline.length || total === 0) return <p className="fp-blank">{t("No deadline in the windows watched.")}</p>;
  return (
    <Breakdown tone="warn" items={timeline.map((window) => ({ label: t(window.reason), value: window.count }))} />
  );
}
