import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../../lib/api";
import type { DirectoryChange } from "../../lib/types";
import { Empty } from "../../components/ui";
import { Card, Field } from "../../components/layout";
import { useT } from "../../i18n";

/** The pieces the directory tabs share: a refusal, a list field, the impact card and the change order. */

export function Forbidden() {
  const t = useT();
  return <Card><Empty>{t("You do not have permission to read this resource.")}</Empty></Card>;
}

/**
 * What a change does, in words.
 */
const ACTION_NAMES: Record<string, string> = {
  "identity.user.create": "Create an account",
  "identity.user.enable": "Unlock an account",
  "identity.user.disable": "Lock an account",
  "identity.user.expire": "Set the expiry of an account",
  "identity.user.password.reset": "Reset a password",
  "identity.user.posix": "Change the POSIX data of an account",
  "identity.user.preserve": "Preserve an account",
  "identity.user.delete": "Delete an account",
  "identity.group.members": "Change the members of a group",
  "identity.hostgroup.members": "Change the members of a host group",
  "identity.sshkeys.set": "Set the SSH keys of an account",
  "identity.hbac.rule.ensure": "Set an HBAC rule",
  "identity.hbac.rule.remove": "Remove an HBAC rule",
  "identity.sudo.rule.ensure": "Set a sudo rule",
  "identity.sudo.rule.remove": "Remove a sudo rule",
  "identity.host.enroll": "Join a host to the domain",
  "identity.host.leave": "Take a host out of the domain",
  "identity.host.preflight": "Check a host before joining",
  "identity.keytab.rotate": "Rotate the keytab",
  "identity.keytab.renew": "Renew the keytab",
};

export function actionName(type: string): string {
  return ACTION_NAMES[type] ?? type;
}

/** Splits a comma-separated field into names; blanks fall out. */
export function names(text: string): string[] {
  return text.split(",").map((item) => item.trim()).filter(Boolean);
}

/** Splits a textarea into lines; blanks fall out. */
export function lines(text: string): string[] {
  return text.split("\n").map((item) => item.trim()).filter(Boolean);
}

/** A field holding a list of names, typed as one comma-separated line. */
export function ListField({ label, value, onChange, placeholder, disabled }: {
  label: string; value: string; onChange: (value: string) => void; placeholder?: string; disabled?: boolean;
}) {
  return (
    <Field label={label}>
      <input value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} disabled={disabled} />
    </Field>
  );
}

/**
 * The impact of a planned change, shown as the plan came back: the hosts and
 * users the rule reaches, the diff against the rule of the same name, the
 * warnings and the conflicts.
 */
export function PlanImpact({ change }: { change: DirectoryChange }) {
  const t = useT();
  const plan = change.plan;
  if (!plan) return null;
  const conflicts = plan.conflicts ?? [];
  const warnings = plan.warnings ?? [];
  return (
    <Card
      title={plan.summary}
      tone={conflicts.length ? "error" : warnings.length ? "warn" : undefined}
      description={
        conflicts.length
          ? t("Change {id} is blocked by conflicts and cannot be approved.", { id: change.id.slice(0, 8) })
          : t("Change {id} is {state}; a second person approves it with a reason.", { id: change.id.slice(0, 8), state: change.state.replace("_", " ") })
      }
    >
      {conflicts.map((conflict, index) => (
        <p key={index} className="warning"><span>{conflict}</span></p>
      ))}
      {warnings.map((warning, index) => (
        <p key={index} className="warning"><span>{warning}</span></p>
      ))}
      <ul className="source">
        {(plan.steps ?? []).map((step, index) => <li key={index}>{step}</li>)}
      </ul>
      <p className="source">
        <strong>{t("Hosts reached ({n})", { n: (plan.reachable_hosts ?? []).length })}:</strong>{" "}
        <span className="mono">{(plan.reachable_hosts ?? []).join(", ") || "—"}</span>
      </p>
      <p className="source">
        <strong>{t("Users reached ({n})", { n: (plan.affected_users ?? []).length })}:</strong>{" "}
        <span className="mono">{(plan.affected_users ?? []).join(", ") || "—"}</span>
      </p>
    </Card>
  );
}

/** Orders a directory change and keeps the answer for the impact card. */
export function useDirectoryChange(invalidate: string[]) {
  const t = useT();
  const queryClient = useQueryClient();
  const [change, setChange] = useState<DirectoryChange | null>(null);
  const [message, setMessage] = useState("");
  const mutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post<DirectoryChange>("/api/v1/identity/changes", body),
    onSuccess: (result) => {
      setChange(result);
      setMessage("");
      for (const key of invalidate) queryClient.invalidateQueries({ queryKey: [key] });
      queryClient.invalidateQueries({ queryKey: ["directory-changes"] });
    },
    onError: (error) => {
      setChange(null);
      setMessage(error instanceof ApiError && error.code === "reason_required"
        ? t("A change of access needs a reason of at least 8 characters.")
        : error instanceof Error ? error.message : String(error));
    },
  });
  return { mutation, change, message };
}

/** The reason field every change of access carries. */
export function ReasonField({ value, onChange, placeholder }: {
  value: string; onChange: (value: string) => void; placeholder?: string;
}) {
  const t = useT();
  return (
    <Field label={t("Reason")} wide hint={t("A change of access is recorded with a reason and fresh authentication.")}>
      <input value={value} onChange={(e) => onChange(e.target.value)}
             placeholder={placeholder ?? t("why this changes (min. 8 characters)")} />
    </Field>
  );
}

/**
 * The confirmation of a directory change that cannot be undone from the
 * panel: preserving an account, resetting its password.
 */
export function DirectoryConfirmation({
  target, description, label, onConfirm, onCancel, busy, danger,
}: {
  target: string;
  description: string;
  label: string;
  // danger marks the changes that take something away for good.
  danger?: boolean;
  onConfirm: (reason: string, confirmation: string) => void;
  onCancel: () => void;
  busy: boolean;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const ready = reason.trim().length >= 8 && confirmation === target;

  return (
    <div className={danger ? "form danger" : "form"} data-testid="target-confirmation">
      <h2>{label}</h2>
      <p className="subtitle" style={{ margin: 0 }}>{description}</p>
      <p className="source" style={{ margin: 0 }}>{t("Target: {name}", { name: target })}</p>
      <label>
        {t("Reason (at least 8 characters, kept in the audit trail)")}
        <input value={reason} onChange={(e) => setReason(e.target.value)} />
      </label>
      <label>
        {t("Type the name to confirm:")} <code>{target}</code>
        <input value={confirmation} onChange={(e) => setConfirmation(e.target.value)} />
      </label>
      <div className="operations">
        <button className={danger ? "danger" : undefined} disabled={!ready || busy} onClick={() => onConfirm(reason, confirmation)}>
          {busy ? t("Requesting…") : label}
        </button>
        <button className="secondary" onClick={onCancel} disabled={busy}>{t("Cancel")}</button>
      </div>
    </div>
  );
}

/** A yes / no / unknown badge: the directory not saying is not the same as "no". */
export function TriState({ value, yes, no }: { value: boolean | null | undefined; yes: string; no: string }) {
  const t = useT();
  if (value === true) return <span className="badge ok">{yes}</span>;
  if (value === false) return <span className="badge">{no}</span>;
  return <span className="badge unknown">{t("unknown")}</span>;
}
