import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { ErrorBox, Time, Empty } from "../components/ui";
import { Card, PageHeader } from "../components/layout";
import { Breakdown, StatusBar } from "../components/widgets";
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
  const never = counts.never ?? 0;
  const stale = counts.critical ?? 0;
  const ageing = counts.warning ?? 0;
  const neverRestored = data.never_restored ?? 0;
  // The listed definitions by tool and by verification: which backup
  // program the fleet leans on, and how many copies anybody has read back.
  const tally = (key: (item: Item) => string) => Object.entries(
    data.items.reduce<Record<string, number>>((acc, item) => { const k = key(item); acc[k] = (acc[k] ?? 0) + 1; return acc; }, {}),
  ).sort((x, y) => y[1] - x[1]);
  const byTool = tally((item) => item.tool || "—");
  const verified = data.items.filter((item) => !item.unverified).length;
  const restored = data.items.filter((item) => !!item.last_restore_at).length;
  const listed = t("among the {n} listed", { n: data.items.length });

  return (
    <>
      <PageHeader
        title={t("Backups")}
        description={t("What is copied, where to and how old the newest copy is. Warning after {warning} h, urgent after {critical} h. A copy nobody has ever read back is a promise, not a safeguard — that is what the verification column says, with a {days}-day limit.", {
          warning: data.thresholds.warning_hours, critical: data.thresholds.critical_hours, days: data.thresholds.verification_days,
        })}
      />

      <div className="widgets">
        {/* The age of the newest copy, one segment per verdict, and beside
            it what nobody has checked: a copy nobody has ever restored is a
            hope, not a copy. The panel does not force a trial - it is to
            say there was none. */}
        <Card className="span-8" title={t("Age")} description={t("{n} hosts visible", { n: data.hosts_total })}>
          <StatusBar segments={[
            { label: t("Never ran"), value: never, tone: "error" },
            { label: t("Stale"), value: stale, tone: "error" },
            { label: t("Ageing"), value: ageing, tone: "warn" },
            { label: t("Fresh"), value: counts.ok ?? 0, tone: "ok" },
            { label: t("Unknown"), value: counts.unknown ?? 0, tone: "unknown" },
          ]} />
        </Card>
        <Card className="span-4" title={t("Verified")} description={t("A copy is a safeguard once somebody has read it back.")}>
          <StatusBar segments={[
            { label: t("Unverified"), value: data.unverified, tone: "warn" },
            { label: t("Never restored"), value: neverRestored, tone: "unknown" },
          ]} />
        </Card>

        {/* The calendar and the backends are two short blocks: side by side
            they make one row above the list instead of two thin strips. */}
        <Calendar items={data.items} wide={!(data.repositories ?? []).length} />
        <Repositories repositories={data.repositories ?? []} />

        <Card className="span-9" flush>
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
                    <td className="source mono">{item.repository}</td>
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
        </Card>

        <Card className="span-3" title={t("By tool")} description={listed}>
          {!data.items.length ? (
            <p className="fp-blank">{t("No backup definition yet.")}</p>
          ) : (
            <>
              <Breakdown tone="info" items={byTool.map(([tool, n]) => ({ label: <span className="mono">{tool}</span>, value: n }))} />
              <h4 className="widget-subhead">{t("Verification")}</h4>
              <Breakdown items={[
                { label: t("verified"), value: verified, tone: "ok" },
                { label: t("not verified"), value: data.items.length - verified, tone: "warn" },
                { label: t("restored"), value: restored, tone: "ok" },
                { label: t("never restored"), value: data.items.length - restored, tone: "warn" },
              ]} />
            </>
          )}
        </Card>
      </div>
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
    <Card className="span-6" title={t("Repositories")} flush>
      <table>
        <thead>
          <tr><th>{t("Repository")}</th><th className="num">{t("Hosts")}</th><th className="num">{t("Oldest backup")}</th><th className="num">{t("Parallel writes")}</th></tr>
        </thead>
        <tbody>
          {repositories.map((item) => (
            <tr key={item.repository}>
              <td>
                <span className="mono">{item.repository}</span>
                <div className="source">{item.budget_key}</div>
              </td>
              <td className="num">
                {item.hosts}
                {item.unverified > 0 && (
                  <div className="source">{t("{n} unverified", { n: item.unverified })}</div>
                )}
              </td>
              <td className="num">
                {item.oldest_age_hours === undefined
                  ? "—"
                  : `${Math.round(item.oldest_age_hours)} h`}
              </td>
              <td className="num">
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
    </Card>
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
function Calendar({ items, wide }: { items: Item[]; wide: boolean }) {
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
    <Card
      className={wide ? "span-12" : "span-6"}
      title={t("Last {n} days", { n: days })}
      description={t("How many definitions had their newest successful copy on each day. Empty days in a row are a schedule that stopped, visible before any copy is old enough to turn red.")}
    >
      <div className="calendar">
        {counts.map((count, index) => {
          const date = new Date(today.getTime() - (days - 1 - index) * 86400000);
          const label = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
          return (
            <div key={label} title={`${label}: ${count}`} className="calendar-day">
              <div className={count ? "calendar-bar filled" : "calendar-bar"} style={{ height: `${Math.max(2, (count / most) * 44)}px` }} />
              <span className="calendar-label">{date.getDate()}</span>
            </div>
          );
        })}
      </div>
    </Card>
  );
}
