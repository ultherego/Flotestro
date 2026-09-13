import { useState } from "react";
import type { Host } from "../../lib/types";
import { useT } from "../../i18n";

/**
 * The confirmation of an irreversible operation.
 *
 * A click is not a sufficient decision for a change that cannot be undone:
 * the host list tends to be long and alike, and a confirmation dialog opened
 * on the wrong row looks the same as on the right one. That is why the
 * operator types the hostname and gives a reason - one protects against a
 * mistaken target, the other stays in the audit log.
 */
export function TargetConfirmation({
  host, description, label, onConfirm, onCancel, busy,
}: {
  host: Host;
  description: string;
  label: string;
  onConfirm: (reason: string, confirmation: string) => void;
  onCancel: () => void;
  busy: boolean;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const ready = reason.trim().length >= 8 && confirmation === host.hostname;

  return (
    <div className="form" style={{ marginTop: 16 }}>
      <h2>{label}</h2>
      <p className="subtitle" style={{ margin: 0 }}>{description}</p>
      {/* The target repeated in the dialog: the operator approves a specific machine. */}
      <p className="source" style={{ margin: 0 }}>
        {t("Target: {host}", { host: host.hostname })}
        {host.management_address ? ` · ${host.management_address}` : ` · ${t("address unknown")}`}
        {` · ${host.site} / ${host.environment}`}
      </p>
      <label>
        {t("Reason (at least 8 characters, kept in the audit trail)")}
        <input value={reason} onChange={(e) => setReason(e.target.value)} />
      </label>
      <label>
        {t("Type the hostname to confirm:")} <code>{host.hostname}</code>
        <input value={confirmation} onChange={(e) => setConfirmation(e.target.value)} />
      </label>
      <div className="operations">
        <button disabled={!ready || busy} onClick={() => onConfirm(reason, confirmation)}>
          {busy ? t("Requesting…") : label}
        </button>
        <button className="secondary" onClick={onCancel} disabled={busy}>{t("Cancel")}</button>
      </div>
    </div>
  );
}
