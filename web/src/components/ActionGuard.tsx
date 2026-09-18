import type { ReactNode } from "react";
import { useAllowed, useModuleAccess } from "../lib/actions";
import { useT } from "../i18n";

/**
 * A control that exists only where the order it places would be taken.
 *
 * The server previews every action of a host for the signed-in operator;
 * the guard draws its children when the action is allowed and nothing
 * otherwise, so a viewer sees no restart button and a host without a
 * package adapter shows no upgrade. A page with one primary action asks
 * for `explain` instead: the control stays on the screen, disabled, with
 * the reason on it, because a page whose only button is missing reads as
 * broken rather than as refused.
 *
 * The guard is a courtesy to the operator, not a gate: the order is judged
 * again by the server, and the refusal it may answer with is still shown
 * by the page.
 */
export function ActionGuard({
  action, host, explain, children,
}: {
  /** The operation type, as the catalogue names it: unit.restart, packages.upgrade. */
  action: string;
  /** The identifier of the host the order would go to. */
  host: string;
  /** Keep the control on the screen, disabled, with the reason as its hint. */
  explain?: boolean;
  children: ReactNode;
}) {
  const t = useT();
  const verdict = useAllowed(host, action);
  if (verdict.allowed) return <>{children}</>;
  if (!explain || verdict.pending) return null;
  // A disabled fieldset disables every control inside it, whatever the
  // children are; the hint says why in the title, and once more in a line
  // under the control for whoever does not hover.
  const reason = verdict.reason || t("This action is not available.");
  return (
    <span className="action-guard action-guard-denied" title={reason} data-reason-code={verdict.reason_code}>
      <fieldset disabled aria-disabled="true" style={{ display: "contents" }}>
        {children}
      </fieldset>
      <span className="source action-guard-hint" style={{ marginLeft: 8 }}>{reason}</span>
    </span>
  );
}

/**
 * The one line a module page shows when every change it offers is
 * refused: the operator can read the module and learns what changing it
 * would take, instead of a page with its buttons quietly gone.
 */
export function ReadOnlyModuleNotice({ host, actions }: { host: string; actions: string[] }) {
  const t = useT();
  const access = useModuleAccess(host, actions);
  if (!access.known || access.anyAllowed) return null;
  const text = access.permissions.length > 0 && access.reasons.length === 0
    ? t("You can read this module; changing it needs the permission {permissions}.", {
      permissions: access.permissions.join(", "),
    })
    : t("You can read this module; changing it is not possible here: {reasons}", {
      reasons: [...access.reasons, ...access.permissions.map((permission) => t("missing permission {permission}", { permission }))].join("; "),
    });
  return (
    <p className="hm-message action-guard-notice" data-testid="module-read-only">{text}</p>
  );
}
