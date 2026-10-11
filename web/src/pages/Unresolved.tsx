import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import type {
  Unresolved as UnresolvedItem,
  UnresolvedCounts,
  UnresolvedKind,
  UnresolvedOperations,
  UnresolvedRulingKind,
} from "../lib/types";
import { ErrorBox, Empty, Time } from "../components/ui";
import { Card, PageHeader } from "../components/layout";
import { useT } from "../i18n";

/**
 * What the fleet left in a state nobody could confirm.
 *
 * The dashboard counts failed tasks of the last 24 hours, so until now an
 * operation nobody could confirm left the screen because a day had passed.
 * For a product whose first rule is that unknown is not zero, that was the
 * one place the rule did not hold - and the pilot is judged against "no
 * unexplained unknown outcome", which cannot be read off a screen that
 * forgets.
 *
 * Nothing here ages out. An item leaves the list when somebody rules on it,
 * and the ruling is a row of its own: the job keeps the outcome the fleet
 * reported, because an operator's reading is a second fact about the same
 * attempt and not a correction of the first.
 */

/**
 * The two questions, kept apart.
 *
 * Summing them would read the same for "forty changes we cannot confirm
 * happened" and "forty changes we cannot confirm held", and those are
 * different work. Hosts are counted apart from operations for the same
 * reason: one host with forty of them is not forty hosts with one each.
 */
export function describeKind(kind: UnresolvedKind): { title: string; question: string } {
  return kind === "outcome_unknown"
    ? { title: "Outcome unknown", question: "Did it happen?" }
    : { title: "Applied, unverified", question: "Did it hold?" };
}

/** Whether a fleet has anything open at all. */
export function anythingOpen(counts: UnresolvedCounts): boolean {
  return counts.outcome_unknown_operations > 0 || counts.applied_unverified_operations > 0;
}

export default function Unresolved() {
  const t = useT();
  const client = useQueryClient();
  const [kind, setKind] = useState<UnresolvedKind | "">("");
  const [ruling, setRuling] = useState<{ item: UnresolvedItem } | null>(null);

  const { data, error } = useQuery({
    queryKey: ["unresolved", kind],
    queryFn: () =>
      api.get<UnresolvedOperations>(`/api/v1/unresolved${kind ? `?kind=${kind}` : ""}`),
  });

  if (error) return <ErrorBox error={error} />;
  const counts = data?.counts;
  const items = data?.items ?? [];

  return (
    <>
      <PageHeader
        title={t("Needs confirmation")}
        description={t("Operations the fleet could not confirm. Nothing here disappears with time: an item leaves this list when somebody rules on it, and the ruling is recorded beside the task rather than in place of its outcome.")}
      />

      {counts && (
        <div className="fp-cards">
          {(["outcome_unknown", "applied_unverified"] as UnresolvedKind[]).map((one) => {
            const described = describeKind(one);
            const operations =
              one === "outcome_unknown"
                ? counts.outcome_unknown_operations
                : counts.applied_unverified_operations;
            const hosts =
              one === "outcome_unknown"
                ? counts.outcome_unknown_hosts
                : counts.applied_unverified_hosts;
            return (
              <Card key={one} title={t(described.title)}>
                <p className="muted">{t(described.question)}</p>
                {/* Two numbers, never one: a single total reads the same for
                    one host with forty of these and forty hosts with one. */}
                <div className="fp-two-counts" data-testid={`count-${one}`}>
                  <span className={operations > 0 ? "badge warn" : "badge"}>
                    {t("{n} operations", { n: operations })}
                  </span>
                  <span className={hosts > 0 ? "badge warn" : "badge"}>
                    {t("on {n} hosts", { n: hosts })}
                  </span>
                </div>
                <button
                  type="button"
                  className="secondary"
                  onClick={() => setKind(kind === one ? "" : one)}
                  data-testid={`filter-${one}`}
                >
                  {kind === one ? t("Show both") : t("Show only these")}
                </button>
              </Card>
            );
          })}
        </div>
      )}

      {items.length === 0 ? (
        <Empty>
          {counts && anythingOpen(counts)
            ? t("Nothing of this kind is open.")
            : t("Every operation this fleet reported has an outcome somebody could confirm.")}
        </Empty>
      ) : (
        <table className="data">
          <thead>
            <tr>
              <th scope="col">{t("Host")}</th>
              <th scope="col">{t("Operation")}</th>
              <th scope="col">{t("Question")}</th>
              <th scope="col">{t("Reason")}</th>
              <th scope="col">{t("Since")}</th>
              <th scope="col">{t("Last looked at")}</th>
              <th scope="col" />
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.attempt_id}>
                <td>
                  <Link to={`/hosts/${item.host_id}/overview`}>{item.hostname || item.host_id}</Link>
                </td>
                <td>
                  {/* Straight to the task and whatever evidence it holds: the
                      operator's next move is to read it, not to search for it. */}
                  <Link to={`/jobs/${item.job_id}`}>{item.action}</Link>
                </td>
                <td>{t(describeKind(item.kind).question)}</td>
                <td className="muted">{item.reason || "—"}</td>
                <td><Time value={item.first_seen} /></td>
                <td>
                  {item.last_checked_at ? (
                    <Time value={item.last_checked_at} />
                  ) : (
                    /* Not "never": nobody has tried again since, which is a
                       fact about the panel and not about the host. */
                    <span className="badge unknown">{t("not since")}</span>
                  )}
                </td>
                <td>
                  <button type="button" onClick={() => setRuling({ item })}>
                    {t("Rule on this")}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {ruling && (
        <RulingForm
          item={ruling.item}
          onClose={() => setRuling(null)}
          onRuled={() => {
            setRuling(null);
            client.invalidateQueries({ queryKey: ["unresolved"] });
          }}
        />
      )}
    </>
  );
}

/**
 * The form for one ruling.
 *
 * The basis is required, and the form says why: a ruling with none is a
 * screen being cleared. The three rulings are deliberately not "ok / not ok":
 * accepting that the outcome will never be known is a decision too, and one
 * with a name and a date on it, which is the difference between this and an
 * item ageing off a dashboard.
 */
function RulingForm({
  item,
  onClose,
  onRuled,
}: {
  item: UnresolvedItem;
  onClose: () => void;
  onRuled: () => void;
}) {
  const t = useT();
  const [verdict, setVerdict] = useState<UnresolvedRulingKind>("confirmed_applied");
  const [basis, setBasis] = useState("");

  const record = useMutation({
    mutationFn: () =>
      api.post(`/api/v1/unresolved/${item.attempt_id}/ruling`, {
        kind: item.kind,
        ruling: verdict,
        basis,
      }),
    onSuccess: onRuled,
  });

  return (
    <div className="modal" role="dialog" aria-label={t("Rule on this operation")} data-testid="ruling-form">
      <h3>{t("Rule on this operation")}</h3>
      <p className="muted">
        {item.hostname || item.host_id} · {item.action} · {t(describeKind(item.kind).question)}
      </p>
      <p className="muted">
        {t("The task keeps the outcome the fleet reported. What you write here is recorded beside it, with your name and the time.")}
      </p>

      <label>
        {t("What did you find?")}
        <select
          value={verdict}
          onChange={(e) => setVerdict(e.target.value as UnresolvedRulingKind)}
          data-testid="ruling-verdict"
        >
          <option value="confirmed_applied">{t("The change is there")}</option>
          <option value="confirmed_not_applied">{t("The change is not there")}</option>
          <option value="accepted_unknown">{t("It will not be known, and that is accepted")}</option>
        </select>
      </label>

      <label>
        {t("On what basis?")}
        <textarea
          value={basis}
          onChange={(e) => setBasis(e.target.value)}
          placeholder={t("What you read, and where you looked.")}
          data-testid="ruling-basis"
        />
      </label>

      {record.error ? <ErrorBox error={record.error} /> : null}

      <div className="actions">
        <button type="button" className="secondary" onClick={onClose}>
          {t("Cancel")}
        </button>
        <button
          type="button"
          disabled={basis.trim() === "" || record.isPending}
          onClick={() => record.mutate()}
          data-testid="ruling-save"
        >
          {t("Record the ruling")}
        </button>
      </div>
    </div>
  );
}
