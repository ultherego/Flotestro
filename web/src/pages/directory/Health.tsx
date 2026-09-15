import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../../lib/api";
import type { IdentityStatus } from "../../lib/types";
import { ErrorBox, Empty, Pair, Pairs, Time } from "../../components/ui";
import { Card, Columns, Stat, StatGrid } from "../../components/layout";
import { useT } from "../../i18n";

/**
 * The health of the integration, in two independent halves. The connector
 * half is what the panel itself can say: its keytab, its last call, its
 * cache. The fleet half is what the hosts reported: which of them lost
 * the directory and what the panel makes of their logins. A directory the
 * panel cannot reach says nothing about the hosts, and the reverse.
 */
export function Health() {
  const t = useT();
  const status = useQuery({
    queryKey: ["identity-status"],
    queryFn: () => api.get<IdentityStatus>("/api/v1/identity/status"),
    retry: false,
  });
  if (status.error) return <ErrorBox error={status.error} />;
  const data = status.data;
  if (!data) return <Card><Empty>{t("Checking…")}</Empty></Card>;

  const connector = data.connector;
  const fleet = data.hosts;
  const verdicts = fleet?.by_verdict ?? {};
  // Every verdict has its label; a verdict the panel adds later is shown by its code.
  const verdictLabel: Record<string, string> = {
    cached_logins_until: t("cached logins until a date"),
    cached_logins_indefinitely: t("cached logins indefinitely"),
    no_cached_logins: t("no cached logins"),
    unknown: t("unknown"),
  };

  return (
    <>
      <p className="subtitle">
        {t("Two independent halves: what the panel can say about its own connection to the directory, and what the hosts reported about theirs. One being red does not colour the other.")}
      </p>

      <Columns wide>
        <Card
          title={t("Connector")}
          tone={!data.configured ? undefined : data.reachable ? undefined : "error"}
          description={!data.configured
            ? t("No directory connector is configured.")
            : data.reachable
              ? data.summary
              : t("Directory unavailable: {error}", { error: data.error ?? "" })}
        >
          {data.configured && (
            <Pairs>
              <Pair label={t("Principal")}><span className="mono">{data.principal ?? connector?.principal ?? "—"}</span></Pair>
              <Pair label={t("Reachable")}>
                {data.reachable ? <span className="badge ok">{t("yes")}</span> : <span className="badge error">{t("no")}</span>}
              </Pair>
              <Pair label={t("Last successful call")}><Time value={connector?.last_success_at ?? null} /></Pair>
              <Pair label={t("Last error")}>
                {connector?.last_error
                  ? <><span className="source">{connector.last_error}</span> · <Time value={connector.last_error_at ?? null} /></>
                  : "—"}
              </Pair>
              <Pair label={t("Cache")}>
                {connector
                  ? <>
                      {t("{n} entries", { n: connector.cache_entries })}
                      {" · "}{t("oldest")}: <Time value={connector.cache_oldest_at ?? null} />
                      {" · "}{t("TTL {seconds} s", { seconds: connector.cache_ttl_seconds })}
                    </>
                  : "—"}
              </Pair>
            </Pairs>
          )}
        </Card>

        <Card
          title={t("Keytab")}
          tone={connector && !connector.keytab_readable ? "warn" : undefined}
          description={t("The connector's own keytab as the panel reads it. A keytab file carries no expiry date - only the key version and the stamp of its last write - so none is shown.")}
        >
          {!connector ? (
            <Empty>{t("No directory connector is configured.")}</Empty>
          ) : !connector.keytab_readable ? (
            <p className="warning"><span>{connector.keytab_detail || t("The keytab could not be read.")}</span></p>
          ) : !connector.keytab_entries.length ? (
            <Empty>{t("The keytab holds no entries.")}</Empty>
          ) : (
            <table>
              <thead><tr><th>{t("Principal")}</th><th className="num">KVNO</th><th>{t("Written")}</th></tr></thead>
              <tbody>
                {connector.keytab_entries.map((entry, index) => (
                  <tr key={index}>
                    <td className="mono">{entry.principal}</td>
                    <td className="num">{entry.kvno}</td>
                    <td><Time value={entry.timestamp ?? null} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </Columns>

      <Card
        title={t("Hosts offline from the directory")}
        description={t("Enrolled hosts whose SSSD last reported itself cut off from the directory, with the panel's verdict on their logins from the facts each host reported.")}
      >
        <StatGrid compact>
          <Stat label={t("Offline from the directory")} value={fleet ? fleet.offline_count : "—"} tone={fleet?.offline_count ? "warn" : undefined} />
          {Object.keys(verdicts).sort().map((verdict) => (
            <Stat key={verdict} label={verdictLabel[verdict] ?? verdict} value={verdicts[verdict]}
                  tone={verdict === "no_cached_logins" && verdicts[verdict] ? "error" : undefined} />
          ))}
        </StatGrid>
        {!fleet || !fleet.offline_from_directory.length ? (
          <Empty>{t("Every enrolled host last reported the directory reachable.")}</Empty>
        ) : (
          <table>
            <thead><tr><th>{t("Host")}</th><th>{t("Site / environment")}</th><th>{t("Checked")}</th><th>{t("Verdict")}</th></tr></thead>
            <tbody>
              {fleet.offline_from_directory.map((host) => (
                <tr key={host.id}>
                  <td><Link to={`/hosts/${host.id}/identity`}>{host.hostname}</Link></td>
                  <td>{[host.site, host.environment].filter(Boolean).join(" / ") || "—"}</td>
                  <td><Time value={host.checked_at ?? null} /></td>
                  <td>
                    <span className={host.offline_verdict.verdict === "no_cached_logins" ? "badge error" : host.offline_verdict.verdict === "unknown" ? "badge unknown" : "badge warn"}>
                      {verdictLabel[host.offline_verdict.verdict] ?? host.offline_verdict.verdict}
                    </span>
                    {host.offline_verdict.reason && <div className="source">{host.offline_verdict.reason}</div>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}
