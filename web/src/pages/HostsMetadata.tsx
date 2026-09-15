import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { Host } from "../lib/types";
import { Actions, Card, Field, FieldGrid } from "../components/layout";
import { FacetList, useFleetFacets } from "./Bulk";
import { useT } from "../i18n";

/**
 * The answer for one host of a bulk edit: applied, or the code the host's
 * own route would have refused with. The list is the whole point of the
 * route - three hosts out of the operator's scope are answered, not
 * hidden behind a refusal of the whole selection or a silent skip.
 */
type Outcome = { host_id: string; ok: boolean; code: string; detail?: string };
type BulkResponse = { results: Outcome[]; applied: number; failed: number };

/** The draft of the panel; every field is optional and an untouched one changes nothing. */
type Draft = {
  tagsAdd: string;
  tagsRemove: string;
  owner: string;
  setOwner: boolean;
  failureDomain: string;
  setFailureDomain: boolean;
  site: string;
  environment: string;
  maintenance: "keep" | "open" | "close";
  maintenanceUntil: string;
  maintenanceReason: string;
  reason: string;
};

const EMPTY: Draft = {
  tagsAdd: "", tagsRemove: "", owner: "", setOwner: false, failureDomain: "", setFailureDomain: false,
  site: "", environment: "", maintenance: "keep", maintenanceUntil: "", maintenanceReason: "", reason: "",
};

/** The tags typed in one box: separated by commas or whitespace. */
function splitTags(text: string): string[] {
  return text.split(/[\s,]+/).map((tag) => tag.trim()).filter(Boolean);
}

/** A local date-time from the input as an RFC 3339 instant. */
function instantOf(local: string): string {
  return new Date(local).toISOString();
}

/**
 * The inline panel of the fleet list that edits what the panel records
 * about the selected hosts by hand: tags, the owner, the failure domain,
 * the placement and the maintenance window. One call, one reason, and an
 * answer per host; the outcomes stay on the screen until the panel is
 * closed, so the operator reads which hosts were refused and why before
 * the selection is cleared.
 */
export function HostsMetadata({ hosts, permissions, onClose }: {
  hosts: Host[];
  permissions: string[];
  onClose: () => void;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const facets = useFleetFacets();
  const [draft, setDraft] = useState<Draft>(EMPTY);
  const change = (delta: Partial<Draft>) => setDraft((previous) => ({ ...previous, ...delta }));
  const canTag = permissions.includes("host.tag.write");
  const canMaintain = permissions.includes("host.maintenance.write");
  const byID = new Map(hosts.map((host) => [host.id, host]));

  const submit = useMutation({
    mutationFn: () => {
      const set: Record<string, unknown> = {};
      const add = splitTags(draft.tagsAdd);
      const remove = splitTags(draft.tagsRemove);
      if (add.length > 0) set.tags_add = add;
      if (remove.length > 0) set.tags_remove = remove;
      if (draft.setOwner) set.owner = draft.owner.trim();
      if (draft.setFailureDomain) set.failure_domain = draft.failureDomain.trim();
      if (draft.site.trim() !== "") set.site = draft.site.trim();
      if (draft.environment.trim() !== "") set.environment = draft.environment.trim();
      if (draft.maintenance === "close") set.maintenance = null;
      if (draft.maintenance === "open") {
        set.maintenance = { until: instantOf(draft.maintenanceUntil), reason: draft.maintenanceReason.trim() };
      }
      return api.post<BulkResponse>("/api/v1/hosts/bulk-metadata", {
        host_ids: hosts.map((host) => host.id), reason: draft.reason.trim(), set,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
      queryClient.invalidateQueries({ queryKey: ["fleet-activity"] });
      for (const host of hosts) queryClient.invalidateQueries({ queryKey: ["host", host.id] });
    },
  });

  const touches = splitTags(draft.tagsAdd).length > 0 || splitTags(draft.tagsRemove).length > 0
    || draft.setOwner || draft.setFailureDomain || draft.site.trim() !== "" || draft.environment.trim() !== "";
  const windowReady = draft.maintenance !== "open"
    || (draft.maintenanceUntil !== "" && draft.maintenanceReason.trim() !== "");
  const ready = (touches || draft.maintenance !== "keep") && windowReady && draft.reason.trim().length >= 8;
  const moves = draft.site.trim() !== "" || draft.environment.trim() !== "";
  const result = submit.data;

  return (
    <Card
      title={t("Set metadata on {n} hosts", { n: hosts.length })}
      description={t("What the panel records about these hosts by hand. A field left empty changes nothing; every host is judged in its own scope and answered on its own.")}
      actions={<button type="button" className="secondary" onClick={onClose}>{t("Close")}</button>}
    >
      <FieldGrid>
        {canTag && (
          <>
            <Field label={t("Add tags")} hint={t("key or key=value, separated by commas; added to what each host already carries.")}>
              <input value={draft.tagsAdd} onChange={(e) => change({ tagsAdd: e.target.value })} placeholder="patched=2026-09, role=web" data-testid="bulk-tags-add" />
            </Field>
            <Field label={t("Remove tags")} hint={t("Taken off the hosts that carry them; the others are left as they are.")}>
              <input value={draft.tagsRemove} onChange={(e) => change({ tagsRemove: e.target.value })} placeholder="legacy" />
            </Field>
            <Field label={t("Owner")} hint={t("Tick to set; empty hands the hosts back to nobody.")}>
              <span style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <input type="checkbox" checked={draft.setOwner} onChange={(e) => change({ setOwner: e.target.checked })} aria-label={t("set the owner")} />
                <input value={draft.owner} onChange={(e) => change({ owner: e.target.value, setOwner: true })} placeholder={t("platform team")} data-testid="bulk-owner" />
              </span>
            </Field>
            <Field label={t("Failure domain")} hint={t("Tick to set; empty takes the hosts out from under the domain budgets.")}>
              <span style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <input type="checkbox" checked={draft.setFailureDomain} onChange={(e) => change({ setFailureDomain: e.target.checked })} aria-label={t("set the failure domain")} />
                <input value={draft.failureDomain} onChange={(e) => change({ failureDomain: e.target.value, setFailureDomain: true })} placeholder={t("rack-12, zone-b")} />
              </span>
            </Field>
            <Field label={t("Site")} hint={t("Moves the hosts; empty keeps each host where it stands.")}>
              <input value={draft.site} onChange={(e) => change({ site: e.target.value })} list="bulk-metadata-sites" />
              <FacetList id="bulk-metadata-sites" facets={facets.data?.by_site} />
            </Field>
            <Field label={t("Environment")} hint={t("Moves the hosts; empty keeps each host's environment.")}>
              <input value={draft.environment} onChange={(e) => change({ environment: e.target.value })} list="bulk-metadata-environments" />
              <FacetList id="bulk-metadata-environments" facets={facets.data?.by_environment} />
            </Field>
          </>
        )}
        {canMaintain && (
          <>
            <Field label={t("Maintenance window")}>
              <select value={draft.maintenance} onChange={(e) => change({ maintenance: e.target.value as Draft["maintenance"] })}>
                <option value="keep">{t("leave as it is")}</option>
                <option value="open">{t("open until…")}</option>
                <option value="close">{t("close")}</option>
              </select>
            </Field>
            {draft.maintenance === "open" && (
              <>
                <Field label={t("Until")} hint={t("At most 30 days ahead.")}>
                  <input type="datetime-local" value={draft.maintenanceUntil} onChange={(e) => change({ maintenanceUntil: e.target.value })} />
                </Field>
                <Field label={t("Window reason")} hint={t("What the next person on call will read.")}>
                  <input value={draft.maintenanceReason} onChange={(e) => change({ maintenanceReason: e.target.value })} />
                </Field>
              </>
            )}
          </>
        )}
        <Field label={t("Reason")} wide hint={t("Required, at least 8 characters; kept in the audit trail with every host.")}>
          <input value={draft.reason} onChange={(e) => change({ reason: e.target.value })} placeholder={t("change ticket, handover")} data-testid="bulk-reason" />
        </Field>
      </FieldGrid>
      {moves && (
        <p className="source">
          {t("A move changes who may manage the host, which budgets its changes load and which groups it stands in, from the next order on; nothing already planned is re-evaluated.")}
        </p>
      )}
      <Actions>
        <button type="button" className="primary" onClick={() => submit.mutate()} disabled={!ready || submit.isPending} data-testid="bulk-apply">
          {submit.isPending ? t("applying…") : t("Apply to {n} hosts", { n: hosts.length })}
        </button>
      </Actions>
      {submit.isError && (
        <p className="page-error">{t("Error: {message}", { message: submit.error instanceof Error ? submit.error.message : String(submit.error) })}</p>
      )}
      {result && (
        <>
          <p data-testid="bulk-summary">
            {t("{applied} applied, {failed} refused.", { applied: result.applied, failed: result.failed })}
          </p>
          <table>
            <thead>
              <tr><th>{t("Host")}</th><th>{t("Outcome")}</th><th>{t("Detail")}</th></tr>
            </thead>
            <tbody>
              {result.results.map((outcome) => {
                const host = byID.get(outcome.host_id);
                return (
                  <tr key={outcome.host_id} data-testid={`bulk-outcome-${outcome.host_id}`}>
                    <td>
                      {host ? <Link to={`/hosts/${host.id}/overview`}>{host.hostname}</Link> : <span className="hm-mono">{outcome.host_id}</span>}
                    </td>
                    <td>
                      <span className={outcome.ok ? "badge ok" : "badge error"}>{outcome.ok ? t("applied") : outcome.code}</span>
                    </td>
                    <td>{outcome.detail || ""}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </>
      )}
    </Card>
  );
}
