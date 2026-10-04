import { useQuery } from "@tanstack/react-query";
import { api } from "./api";
import { ACTION_RISK, type ActionType } from "../generated/actions";

/**
 * What one host lets the signed-in operator do, action by action.
 */

/** The codes a refused action carries; the server owns the list. */
export type ActionReasonCode =
  | "permission_denied"
  | "capability_missing"
  | "host_quarantined"
  | "host_recovery"
  | "host_retired"
  | "read_only_host"
  | "helper_unavailable"
  | "host_offline"
  | "package_database_broken";

export type HostAction = {
  action: string;
  permission: string;
  mutating: boolean;
  risk: string;
  allowed: boolean;
  reason_code?: ActionReasonCode | string;
  reason?: string;
  /** The permission a permission_denied verdict is about. */
  missing_permission?: string;
  /** A fact about an allowed action: the order waits for an offline host, asks for a reason. */
  note?: string;
};

export type HostActions = { items: HostAction[]; version: number };

export function hostActionsKey(hostID: string) {
  return ["host-actions", hostID] as const;
}

/**
 * The preview of the host's actions.
 */
export function useHostActions(hostID: string) {
  return useQuery({
    queryKey: hostActionsKey(hostID),
    queryFn: () => api.get<HostActions>(`/api/v1/hosts/${hostID}/actions`),
    enabled: hostID !== "",
    staleTime: 30_000,
    refetchInterval: 60_000,
    refetchOnWindowFocus: true,
    // A refusal of the preview itself - a panel from before the endpoint,
    // a token without host.read - is an answer, not a network failure.
    retry: false,
  });
}

/** The verdict on one action, as a screen reads it. */
export type Allowance = {
  /** Whether the control may be drawn: the server allowed it, or gave no answer to refuse it with. */
  allowed: boolean;
  /** Whether the server answered; a refusal is known, a missing answer is not. */
  known: boolean;
  /** Whether the answer is still on its way. */
  pending: boolean;
  reason: string;
  reason_code: string;
  permission: string;
  missing_permission: string;
  note: string;
};

const unknownAllowance: Allowance = {
  allowed: true, known: false, pending: false,
  reason: "", reason_code: "", permission: "", missing_permission: "", note: "",
};

/**
 * Reads the verdict on one action out of the preview.
 */
export function allowanceOf(
  data: HostActions | undefined,
  state: { isPending: boolean; isError: boolean },
  action: string,
): Allowance {
  if (state.isPending) return { ...unknownAllowance, allowed: false, pending: true };
  if (state.isError || !data) return unknownAllowance;
  const item = data.items.find((entry) => entry.action === action);
  if (!item) {
    return {
      ...unknownAllowance, allowed: false, known: true,
      reason_code: "unknown_action", reason: `the panel has no contract for ${action}`,
    };
  }
  return {
    allowed: item.allowed,
    known: true,
    pending: false,
    reason: item.reason ?? "",
    reason_code: item.reason_code ?? "",
    permission: item.permission,
    missing_permission: item.missing_permission ?? "",
    note: item.note ?? "",
  };
}

/** The verdict on one action of a host, for a control built inline. */
export function useAllowed(hostID: string, action: string): Allowance {
  const query = useHostActions(hostID);
  return allowanceOf(query.data, query, action);
}

/**
 * What a page can say when every one of its changes is refused: which
 * permissions are missing when the refusals are about permissions, and the
 * host's reasons otherwise.
 */
export type ModuleAccess = {
  /** Whether at least one of the listed actions may be ordered. */
  anyAllowed: boolean;
  known: boolean;
  pending: boolean;
  /** The permissions the refused actions need, without repeats. */
  permissions: string[];
  /** The reasons other than a missing permission, without repeats. */
  reasons: string[];
};

export function moduleAccessOf(
  data: HostActions | undefined,
  state: { isPending: boolean; isError: boolean },
  actions: string[],
): ModuleAccess {
  const verdicts = actions.map((action) => allowanceOf(data, state, action));
  const known = verdicts.length > 0 && verdicts.every((verdict) => verdict.known);
  const permissions: string[] = [];
  const reasons: string[] = [];
  for (const verdict of verdicts) {
    if (verdict.allowed || !verdict.known) continue;
    if (verdict.reason_code === "permission_denied") {
      if (verdict.missing_permission && !permissions.includes(verdict.missing_permission)) {
        permissions.push(verdict.missing_permission);
      }
    } else if (verdict.reason && !reasons.includes(verdict.reason)) {
      reasons.push(verdict.reason);
    }
  }
  return {
    anyAllowed: verdicts.some((verdict) => verdict.allowed),
    known,
    pending: verdicts.some((verdict) => verdict.pending),
    permissions,
    reasons,
  };
}

/** The verdicts on the changes a page offers, folded into one line's worth. */
export function useModuleAccess(hostID: string, actions: string[]): ModuleAccess {
  const query = useHostActions(hostID);
  return moduleAccessOf(query.data, query, actions);
}

/**
 * Whether the panel will refuse this order without a reason and a second
 * confirmation of who is ordering it.
 *
 * The risk of every action is generated into ACTION_RISK from the one table
 * the panel judges by, and it was used nowhere in the interface: so a form for
 * a critical action sent no reason, the panel answered 4xx, and the operator
 * saw a refusal with nothing to do about it. The rule is the panel's own -
 * critical and destructive need fresh authentication - read from the same
 * table rather than restated per screen.
 */
export function needsReason(action: string): boolean {
  const risk = ACTION_RISK[action as ActionType];
  return risk === "critical" || risk === "destructive";
}
