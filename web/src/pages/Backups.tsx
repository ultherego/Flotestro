import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { ErrorBox, Time, Empty } from "../components/ui";
import { useT } from "../i18n";

type Item = {
  host_id: string;
  hostname: string;
  definition: string;
  tool: string;
  repository?: string;
  status: string;
  last_success_at?: string;
  age_hours?: number;
  unverified: boolean;
  last_restore_at?: string;
};

type View = {
  items: Item[];
  counts: Record<string, number>;
  unverified: number;
  never_restored?: number;
  hosts_total: number;
  thresholds: { warning_hours: number; critical_hours: number; verification_days: number };
  repositories?: Repository[];
};

type Repository = {
  repository: string;
  hosts: number;
  unverified: number;
  oldest_age_hours?: number;
  budget_key: string;
  capacity?: number;
  used?: number;
  claimants?: number;
};

function AgeBadge({ status, age }: { status: string; age?: number }) {
  const t = useT();
  const cls =
    status === "ok" ? "ok" : status === "warning" ? "warn" : status === "unknown" ? "unknown" : "error";
  const caption =
    status === "never"
      ? t("no backup")
      : age === undefined
        ? status
        : age < 48
          ? `${Math.round(age)} h`
          : `${Math.round(age / 24)} d`;
  return <span className={`badge ${cls}`}>{caption}</span>;
}

/**
 * Fleet backups.
 *
 * A backup breaks quietly: nobody notices there has been no new copy for
 * three weeks until one has to be restored. That is why the fleet view is
 * the primary mode here, with the worst rows on top.
 */
export function FleetBackups() {
  const t = useT();
  const { data, error } = useQuery({
    queryKey: ["backups", "fleet"],
    queryFn: () => api.get<View>("/api/v1/backups"),
  });

  if (error) return <ErrorBox error={error} />;
  if (!data) return <Empty>{t("Reading backup state…")}</Empty>;
  const counts = data.counts ?? {};

  return (
    <>
      <h1>{t("Backups")}</h1>
      <p className="subtitle">
        {t("What is copied, where to and how old the newest copy is. Warning after {warning} h, urgent after {critical} h. A copy nobody has ever read back is a promise, not a safeguard — that is what the verification column says, with a {days}-day limit.", {
          warning: data.thresholds.warning_hours, critical: data.thresholds.critical_hours, days: data.thresholds.verification_days,
        })}
      </p>

      <div className="filters">
        <span className="badge error">{t("{n} never ran", { n: counts.never ?? 0 })}</span>
        <span className="badge error">{t("{n} stale", { n: counts.critical ?? 0 })}</span>
        <span className="badge warn">{t("{n} ageing", { n: counts.warning ?? 0 })}</span>
        <span className="badge ok">{t("{n} fresh", { n: counts.ok ?? 0 })}</span>
        <span className="badge warn">{t("{n} unverified", { n: data.unverified })}</span>
        {/* A copy nobody has ever restored is a hope, not a copy. The panel
            does not force a trial - it is to say there was none. */}
        <span className="badge unknown">{t("{n} never restored", { n: data.never_restored ?? 0 })}</span>
        <span className="source">{t("{n} hosts visible", { n: data.hosts_total })}</span>
      </div>

      <Calendar items={data.items} />

      <Repositories repositories={data.repositories ?? []} />

      {!data.items.length ? (
        <Empty>
          {t("No host has a backup definition yet. Open a host and describe what to copy, where to and how long it stays.")}
        </Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th>{t("Age")}</th><th>{t("Host")}</th><th>{t("Definition")}</th><th>{t("Tool")}</th>
              <th>{t("Destination")}</th><th>{t("Verified")}</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((item) => (
              <tr key={`${item.host_id}-${item.definition}`}>
                <td>
                  <AgeBadge status={item.status} age={item.age_hours} />
                  {item.last_success_at && (
                    <div className="source"><Time value={item.last_success_at} /></div>
                  )}
                </td>
                <td>
                  <Link to={`/hosts/${item.host_id}/backups`}>{item.hostname}</Link>
                </td>
                <td>{item.definition}</td>
                <td className="source">{item.tool}</td>
                <td className="source">{item.repository}</td>
                <td>
                  {item.unverified ? (
                    <span className="badge warn">{t("not verified")}</span>
                  ) : (
                    <span className="badge ok">{t("verified")}</span>
                  )}
                  <div className="source">
                    {item.last_restore_at ? (
                      <>{t("restored")} <Time value={item.last_restore_at} /></>
                    ) : (
                      t("never restored")
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

/**
 * The backends the fleet writes to.
 *
 * The backup list says which host has an old copy. It does not say which
 * backend is the bottleneck - and that is what decides how many copies run
 * at once. An unset capacity is a missing policy here, not zero: then
 * nothing limits the parallelism, and that had better be visible.
 */
function Repositories({ repositories }: { repositories: Repository[] }) {
  const t = useT();
  if (!repositories.length) return null;
  return (
    <section style={{ marginTop: 16 }}>
      <h2>{t("Repositories")}</h2>
      <table>
        <thead>
          <tr><th>{t("Repository")}</th><th>{t("Hosts")}</th><th>{t("Oldest backup")}</th><th>{t("Parallel writes")}</th></tr>
        </thead>
        <tbody>
          {repositories.map((item) => (
            <tr key={item.repository}>
              <td>
                {item.repository}
                <div className="source">{item.budget_key}</div>
              </td>
              <td>
                {item.hosts}
                {item.unverified > 0 && (
                  <div className="source">{t("{n} unverified", { n: item.unverified })}</div>
                )}
              </td>
              <td>
                {item.oldest_age_hours === undefined
                  ? "—"
                  : `${Math.round(item.oldest_age_hours)} h`}
              </td>
              <td>
                {item.capacity === undefined ? (
                  <span className="badge unknown">{t("no limit set")}</span>
                ) : (
                  <>
                    {item.used ?? 0} / {item.capacity}
                    {(item.claimants ?? 0) > 0 && (
                      <div className="source">{t("{n} campaigns want it", { n: item.claimants ?? 0 })}</div>
                    )}
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

/**
 * The last two weeks of copies, day by day.
 *
 * The list says which host has an old copy; the calendar says whether the
 * fleet backs up at all and when it stopped. A row of full days followed by
 * empty ones is a broken schedule, and that shows here before any single
 * copy is old enough to turn red.
 */
function Calendar({ items }: { items: Item[] }) {
  const t = useT();
  const days = 14;
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const counts = new Array<number>(days).fill(0);
  for (const item of items) {
    if (!item.last_success_at) continue;
    const day = new Date(item.last_success_at);
    day.setHours(0, 0, 0, 0);
    const back = Math.round((today.getTime() - day.getTime()) / 86400000);
    if (back >= 0 && back < days) counts[days - 1 - back]++;
  }
  const most = Math.max(1, ...counts);
  if (!items.length) return null;
  return (
    <section style={{ marginTop: 16 }}>
      <h2>{t("Last {n} days", { n: days })}</h2>
      <p className="subtitle">
        {t("How many definitions had their newest successful copy on each day. Empty days in a row are a schedule that stopped, visible before any copy is old enough to turn red.")}
      </p>
      <div style={{ display: "flex", gap: 4, alignItems: "flex-end", height: 60 }}>
        {counts.map((count, index) => {
          const date = new Date(today.getTime() - (days - 1 - index) * 86400000);
          const label = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
          return (
            <div key={label} title={`${label}: ${count}`} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 2 }}>
              <div style={{
                width: "100%", height: `${Math.max(2, (count / most) * 44)}px`,
                background: count ? "var(--ok)" : "var(--border)", borderRadius: 2,
              }} />
              <span className="source" style={{ fontSize: 10 }}>{date.getDate()}</span>
            </div>
          );
        })}
      </div>
    </section>
  );
}
