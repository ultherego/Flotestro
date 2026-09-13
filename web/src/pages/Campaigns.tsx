import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, type Collection } from "../lib/api";
import type { Campaign } from "../lib/types";
import { ErrorBox, Time, Empty, JobState } from "../components/ui";
import { useT } from "../i18n";

export function Campaigns() {
  const t = useT();
  const [building, setBuilding] = useState(false);
  const { data, error } = useQuery({
    queryKey: ["campaigns"],
    queryFn: () => api.get<Collection<Campaign>>("/api/v1/campaigns?limit=50"),
  });
  if (error) return <ErrorBox error={error} />;

  return (
    <>
      <h1>{t("Campaigns")}</h1>
      <p className="subtitle">{t("Campaigns are the main mechanism for fleet-wide change.")}</p>

      <button onClick={() => setBuilding(!building)}>
        {building ? t("Hide the wizard") : t("New campaign")}
      </button>

      {building && <Wizard onDone={() => setBuilding(false)} />}

      <h2>{t("List")}</h2>
      {!data?.items.length ? (
        <Empty>{t("No campaigns.")}</Empty>
      ) : (
        <table>
          <thead>
            <tr><th>{t("Name")}</th><th>{t("State")}</th><th>{t("Operation")}</th><th>{t("Canary/wave")}</th><th>{t("Requested by")}</th><th>{t("Approved by")}</th><th>{t("Created")}</th></tr>
          </thead>
          <tbody>
            {data.items.map((campaign) => (
              <tr key={campaign.id}>
                <td><Link to={`/campaigns/${campaign.id}`}>{campaign.name}</Link></td>
                <td><JobState state={campaign.state} /></td>
                <td>{campaign.action_type}</td>
                <td>{campaign.canary_size} / {campaign.wave_size}</td>
                <td>{campaign.created_by}</td>
                <td>{campaign.approved_by || "—"}</td>
                <td><Time value={campaign.created_at} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

/** An operation in the registry: the server says what may be done in bulk. */
type Operation = {
  action: string;
  mutating: boolean;
  campaign_mode: string;
  campaign_ready: boolean;
};

/**
 * The operations the wizard can build a payload for. The registry may allow
 * more than this form can describe - then the operation is visible but
 * inactive. Hiding it would look like a missing feature.
 */
const WIZARD_OPERATIONS = [
  "unit.start", "unit.stop", "unit.restart", "unit.reload", "packages.upgrade",
];

/** The operations that take a systemd unit name. */
const UNIT_OPERATIONS = ["unit.start", "unit.stop", "unit.restart", "unit.reload"];

/**
 * The campaign wizard. The last step shows exactly how many hosts the change
 * will cover before anything is created.
 */
function Wizard({ onDone }: { onDone: () => void }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [action, setAction] = useState("unit.restart");
  const [unit, setUnit] = useState("");
  const [site, setSite] = useState("");
  const [environment, setEnvironment] = useState("");
  const [canary, setCanary] = useState(1);
  const [wave, setWave] = useState(5);
  const [concurrent, setConcurrent] = useState(2);
  const [thresholdPercent, setThresholdPercent] = useState(20);
  const [thresholdCount, setThresholdCount] = useState(0);
  const [rebootPolicy, setRebootPolicy] = useState("never");
  const [securityOnly, setSecurityOnly] = useState(true);
  const [errorMessage, setErrorMessage] = useState("");

  // The list of bulk operations comes from the server, not from this file.
  // The operation registry decides what may be done fleet-wide, and it knows
  // that a new operation does not open itself for bulk use on its own.
  const operations = useQuery({
    queryKey: ["actions"],
    queryFn: () => api.get<{ items: Operation[] }>("/api/v1/actions"),
  });
  const bulk = (operations.data?.items ?? []).filter((item) => item.campaign_ready);

  // Target preview: the server counts, not the length of the first page of
  // the host list. The operator approves a change on as many machines as
  // they were shown.
  const params = new URLSearchParams();
  if (site) params.set("site", site);
  if (environment) params.set("environment", environment);
  const preview = useQuery({
    queryKey: ["campaign-preview", params.toString()],
    queryFn: () =>
      api.get<{ count: number; sample: string[]; limit: number }>(
        `/api/v1/campaigns/preview?${params}`,
      ),
  });

  const create = useMutation({
    mutationFn: () =>
      api.post<Campaign>("/api/v1/campaigns", {
        name,
        action,
        payload: UNIT_OPERATIONS.includes(action)
          ? { unit: { unit } }
          : { package_upgrade: { security_only: securityOnly } },
        selector: { site: site || undefined, environment: environment || undefined },
        canary_size: canary,
        wave_size: wave,
        max_concurrent: concurrent,
        failure_threshold_percent: thresholdPercent,
        failure_threshold_absolute: thresholdCount,
        reboot_policy: rebootPolicy,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["campaigns"] });
      onDone();
    },
    onError: (error) => setErrorMessage(error instanceof Error ? error.message : String(error)),
  });

  const targetCount = preview.data?.count ?? 0;
  const sample = preview.data?.sample ?? [];
  const needsUnit = UNIT_OPERATIONS.includes(action);
  const ready = name && (!needsUnit || unit) && targetCount > 0;

  return (
    <div className="tile" style={{ marginTop: 16, maxWidth: 760 }}>
      <h2 style={{ marginTop: 0 }}>{t("New campaign")}</h2>
      <div className="filters">
        <input placeholder={t("campaign name")} value={name} onChange={(e) => setName(e.target.value)} style={{ minWidth: 240 }} />
        <select value={action} onChange={(e) => setAction(e.target.value)}>
          {bulk.map((item) => (
            <option
              key={item.action}
              value={item.action}
              disabled={!WIZARD_OPERATIONS.includes(item.action)}
            >
              {item.action}
              {WIZARD_OPERATIONS.includes(item.action) ? "" : ` — ${t("no bulk form yet")}`}
            </option>
          ))}
        </select>
        {needsUnit ? (
          <input placeholder={t("unit, e.g. cron.service")} value={unit} onChange={(e) => setUnit(e.target.value)} />
        ) : (
          <label>
            <input
              type="checkbox"
              checked={securityOnly}
              onChange={(e) => setSecurityOnly(e.target.checked)}
            />{" "}
            {t("security updates only")}
          </label>
        )}
      </div>
      {/* An operation that computes a different plan on every host goes
          through a planning phase - it does not pretend to be one payload.
          Operations the panel has no planner for yet are not hidden: they
          are refused with a reason. */}
      <p className="subtitle">
        {needsUnit
          ? t("The same payload means the same thing on every host; each host still runs its own preflight.")
          : t("Every host computes its own plan first. You approve the set of plans, not one payload, and a host whose plan changed in the meantime refuses the change.")}
      </p>
      <div className="filters">
        <input placeholder={t("site")} value={site} onChange={(e) => setSite(e.target.value)} />
        <input placeholder={t("environment")} value={environment} onChange={(e) => setEnvironment(e.target.value)} />
      </div>
      <div className="filters">
        <label>{t("canary")} <input type="number" min={0} value={canary} onChange={(e) => setCanary(+e.target.value)} style={{ width: 70 }} /></label>
        <label>{t("wave")} <input type="number" min={1} value={wave} onChange={(e) => setWave(+e.target.value)} style={{ width: 70 }} /></label>
        <label>{t("concurrent")} <input type="number" min={1} value={concurrent} onChange={(e) => setConcurrent(+e.target.value)} style={{ width: 70 }} /></label>
        <label>{t("threshold %")} <input type="number" min={0} max={100} value={thresholdPercent} onChange={(e) => setThresholdPercent(+e.target.value)} style={{ width: 70 }} /></label>
        <label>{t("threshold count")} <input type="number" min={0} value={thresholdCount} onChange={(e) => setThresholdCount(+e.target.value)} style={{ width: 70 }} /></label>
        <select value={rebootPolicy} onChange={(e) => setRebootPolicy(e.target.value)}>
          <option value="never">{t("reboot: never")}</option>
          <option value="if_required">{t("reboot: when required")}</option>
          <option value="always">{t("reboot: always")}</option>
        </select>
      </div>

      <h2>{t("Targets")}</h2>
      {preview.isLoading ? (
        <Empty>{t("Counting targets…")}</Empty>
      ) : (
        <>
          <p className="subtitle">
            {t("The selector matches {n} hosts. The snapshot is taken when the campaign is created; hosts added later will not join it.", { n: targetCount })}
          </p>
          <div className="source">
            {sample.join(", ")}
            {targetCount > sample.length && ` ${t("and {n} more", { n: targetCount - sample.length })}`}
          </div>
        </>
      )}

      {errorMessage && <p className="page-error" style={{ marginTop: 12 }}>{errorMessage}</p>}
      <div style={{ marginTop: 16 }}>
        <button onClick={() => create.mutate()} disabled={!ready || create.isPending}>
          {create.isPending ? t("Creating…") : t("Create a campaign on {n} hosts", { n: targetCount })}
        </button>{" "}
        <button className="secondary" onClick={onDone}>{t("Cancel")}</button>
      </div>
    </div>
  );
}
