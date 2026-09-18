import { useQuery } from "@tanstack/react-query";
import { api } from "./api";

/**
 * What one host lets the signed-in operator do, action by action.
 *
 * The server judges every operation of the catalogue the way it judges an
 * order at the door - the permission in the host's scope, the lifecycle
 * state, the adapter registry - and answers ahead of the click, so a
 * screen draws no button the order would refuse. The answer is a preview:
 * the order is judged again when it is placed, and a 403 or a 409 from
 * the order still reaches the screen as the backstop.
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
 * The preview of the host's actions. It is asked again when the tab comes
 * back into focus and once a minute besides: a binding granted or a host
 * reconnected in the meantime shows up without a reload, and a minute of
 * staleness costs at most one refused order.
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
 *
 * Before the answer the control is held back, so a button never appears
 * and vanishes a moment later. When the preview itself failed there is
 * nothing to refuse the control with: it is drawn as before the preview
 * existed, and the refusal of the order, if any, is the backstop. An
 * action the catalogue does not know is refused: a screen that names an
 * operation the server has no contract for would only order a 400.
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
 * permissions are missing when the refusals are about permissions, and
 * the host's reasons otherwise.
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
