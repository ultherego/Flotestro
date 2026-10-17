import { registryOrder, type RegistryOrder } from "./module";

/**
 * The packages of one host: what the agent reports, what a plan binds the
 * operator to, and the orders a change is placed as.
 *
 * None of it draws anything, and both panels read the same answers from the
 * same host - a second copy of "is this plan still good" would be a second
 * answer to it.
 */

export type Repository = {
  id: string;
  name?: string;
  url?: string;
  suites?: string[];
  components?: string[];
  enabled: boolean;
  priority?: number;
  gpg_key_fingerprint?: string;
  signed: boolean;
  username?: string;
  secret_name?: string;
  managed: boolean;
  path?: string;
  unavailable_reason?: string;
};

export type RepositoryView = {
  repositories?: Repository[];
  repositories_known?: boolean;
  repositories_unavailable_reason?: string;
};

export type PackagesState = {
  manager?: string;
  installed?: number;
  upgradable?: number;
  security_upgradable?: number;
  unavailable_reason?: string;
  repositories?: RepositoryView;
  // The digest of the host's own package list: the panel's copy is stale
  // when it carries another one.
  installed_digest?: string;
  // The holds as the host reports them: an unread list is not a host
  // without holds, so the count is unknown until holds_known says so.
  holds?: string[];
  holds_known?: boolean;
  holds_unavailable_reason?: string;
};

export type RemovalPlan = {
  mode?: string;
  removals?: string[];
  protected?: string[];
};

/** One installed package as the panel's copy of the host's list carries it. */
export type InstalledPackage = {
  name: string;
  version: string;
  epoch?: string;
  release?: string;
  architecture?: string;
  source_name?: string;
  repository_id?: string;
  origin?: string;
  origin_class?: string;
  vendor?: string;
};

export type PackageListState = {
  digest?: string;
  package_count: number;
  collected_at?: string;
  job_id?: string;
  unavailable_reason?: string;
};

export type PackageList = {
  items: InstalledPackage[];
  count: number;
  state: PackageListState;
};

/**
 * One change of an upgrade plan: what the host would move a package to, from
 * which repository, in which architecture and in which direction.
 */
export type PlanChange = {
  name: string;
  current_version?: string;
  candidate_version?: string;
  origin?: string;
  security?: boolean;
  architecture?: string;
  action?: string;
};

/**
 * The plan an operator approved, as the panel carries it from the plan job
 * to the change: the digest the host recomputes under its lock, the header
 * it rebuilds the envelope from, and the elements that were approved, so a
 */
export type ApprovedPlan = {
  plan_hash: string;
  planner_version?: string;
  schema_version?: number;
  inventory_revision?: string;
  resource_revision?: string;
  expires_at?: string;
  changes?: PlanChange[];
};

/**
 * The plan of a change out of the result of the plan job, or nothing.
 */
export function planBinding(detail: Record<string, unknown> | undefined): ApprovedPlan | null {
  if (!detail || detail.kind !== "package_plan") return null;
  const hash = typeof detail.plan_hash === "string" ? detail.plan_hash : "";
  if (!hash) return null;
  const text = (key: string) => (typeof detail[key] === "string" ? (detail[key] as string) : undefined);
  return {
    plan_hash: hash,
    planner_version: text("planner_version"),
    schema_version: typeof detail.schema_version === "number" ? detail.schema_version : undefined,
    inventory_revision: text("inventory_revision"),
    resource_revision: text("resource_revision"),
    expires_at: text("expires_at"),
    changes: Array.isArray(detail.changes) ? (detail.changes as PlanChange[]) : undefined,
  };
}

/**
 * The payload of a change bound to its plan: the digest always, and the
 * envelope's header with the approved elements when the host's planner built
 * one.
 */
// The body the operations endpoint takes. The payload alone was posted here
// once, and the panel could not install a package until it was noticed.
export function operationBody(action: string, payload: Record<string, unknown>): Record<string, unknown> {
  return { action, payload };
}

export function changePayload(action: string, packages: string[],
  plan: ApprovedPlan | null): Record<string, unknown> | null {
  if (!plan?.plan_hash || packages.length === 0) return null;
  const bound: Record<string, unknown> = { packages, plan_hash: plan.plan_hash };
  if (plan.planner_version) {
    bound.plan = {
      schema_version: plan.schema_version,
      planner_version: plan.planner_version,
      inventory_revision: plan.inventory_revision,
      resource_revision: plan.resource_revision,
      expires_at: plan.expires_at,
      changes: plan.changes,
    };
  }
  switch (action) {
    case "packages.install":
      return { package_change: bound };
    case "packages.upgrade":
      return { package_upgrade: bound };
    default:
      return null;
  }
}

/** The mode of the plan job that prepares a change of this kind. */
export function planMode(action: string): string {
  return action === "packages.install" ? "install" : "upgrade";
}

/**
 * The header of the last upgrade plan: who made it and until when it
 * holds. A plan of an agent from before the envelope carries none of it.
 */
export type PlanHeader = {
  planner_version?: string;
  expires_at?: string;
  plan_hash?: string;
};

/** A row of the package table: the package with what the host says about it. */
export type PackageRow = InstalledPackage & {
  /** Whether the package is held; unknown when the host did not read the holds. */
  held?: boolean;
  /** The version the last upgrade plan would move it to; absent when nothing waits. */
  candidate?: string;
  security: boolean;
  /** The direction the plan named for the move, and where the candidate comes from. */
  action?: string;
  candidateOrigin?: string;
};

export type PackageFilter = "all" | "upgradable" | "security" | "held";

/**
 * The version of a package as the manager prints it: the epoch in front, the
 * release behind, so the row reads like the tool's own output and a
 * candidate version from the plan compares by eye.
 */
export function packageVersion(pkg: InstalledPackage): string {
  let version = pkg.version;
  if (pkg.epoch && pkg.epoch !== "0") version = `${pkg.epoch}:${version}`;
  if (pkg.release) version = `${version}-${pkg.release}`;
  return version;
}

/**
 * The rows of the table: every installed package joined with the holds the
 * host reported and the changes of the last upgrade plan.
 */
export function packageRows(
  items: InstalledPackage[], holds: string[] | undefined, changes: PlanChange[] | undefined,
): PackageRow[] {
  const held = holds ? new Set(holds) : undefined;
  // apt names a foreign-architecture package as name:arch in the plan; the
  // list keeps the name and the architecture apart, so both spellings match.
  const planned = new Map<string, PlanChange>();
  for (const change of changes ?? []) {
    planned.set(change.name, change);
    const bare = change.name.split(":")[0];
    if (!planned.has(bare)) planned.set(bare, change);
  }
  return items.map((pkg) => {
    const change = planned.get(pkg.architecture ? `${pkg.name}:${pkg.architecture}` : pkg.name) ?? planned.get(pkg.name);
    return {
      ...pkg,
      held: held ? held.has(pkg.name) : undefined,
      candidate: change?.candidate_version || (change ? "?" : undefined),
      security: change?.security === true,
      action: change?.action || undefined,
      candidateOrigin: change?.origin || undefined,
    };
  });
}

/**
 * Whether the plan is past its expiry: its digest may still match, but
 * the host does not start on it, and the caption says so.
 */
export function planExpired(header: PlanHeader | undefined, now = Date.now()): boolean {
  if (!header?.expires_at) return false;
  const expiry = new Date(header.expires_at).getTime();
  return !Number.isNaN(expiry) && expiry < now;
}

/**
 * The rows narrowed by the search box and the filter, in the chosen order.
 */
export function filterRows(
  rows: PackageRow[], query: string, filter: PackageFilter, direction: "asc" | "desc" = "asc",
): PackageRow[] {
  const needle = query.trim().toLowerCase();
  const kept = rows.filter((row) => {
    if (needle && !row.name.toLowerCase().includes(needle) && !(row.source_name ?? "").toLowerCase().includes(needle)) {
      return false;
    }
    switch (filter) {
      case "upgradable": return row.candidate !== undefined;
      case "security": return row.security;
      case "held": return row.held === true;
      default: return true;
    }
  });
  kept.sort((a, b) => a.name.localeCompare(b.name) || (a.architecture ?? "").localeCompare(b.architecture ?? ""));
  if (direction === "desc") kept.reverse();
  return kept;
}

/** The count of held packages from the module: unknown until the host read the holds. */
export function heldCount(packages: PackagesState | undefined): number | undefined {
  if (!packages || packages.holds_known !== true) return undefined;
  return packages.holds?.length ?? 0;
}

/**
 * The host's packages. Installing and removing are separated from upgrading:
 * they are three different decisions about the same host.
 */
/** The changes this page offers; when every one is refused, the page says so once. */
/**
 * Replacing the agent, as an order the operation registry composes: this
 * page and the Bulk workspace then send one payload and refuse one set of
 * versions and checksums.
 */
export function agentUpgradeOrder(version: string, checksum: string, rollback: string): RegistryOrder {
  return registryOrder("agent.upgrade", {
    target_version: version, package_sha256: checksum, rollback_version: rollback,
  });
}
