import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, loadedItems, type Collection, type Page } from "../../lib/api";
import { awaitJob } from "../../lib/jobs";
import { RELEASE_CHANNELS, type Attempt, type Host, type Job, type ReleaseChannel } from "../../lib/types";
import { Empty, ErrorCode, JobState, Time } from "../../components/ui";
import { Breakdown } from "../../components/widgets";
import { VirtualRows } from "../../components/virtual";
import { ColumnChooser, Td, Th, useColumns } from "../../components/SortableTable";
import {
  Check, Fact, Facts, Field, Fields, Foot, Form, FormActions, Message, ModuleFreshness, ModuleHeader,
  ModulePage, RequestOperation, Section, Summary, Table, Unknown, Widgets, countWhere, useHost, useModule,
} from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { useT } from "../../i18n";

type Repository = {
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

type RepositoryView = {
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

type RemovalPlan = {
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

type PackageListState = {
  digest?: string;
  package_count: number;
  collected_at?: string;
  job_id?: string;
  unavailable_reason?: string;
};

type PackageList = {
  items: InstalledPackage[];
  count: number;
  state: PackageListState;
};

/**
 * One change of an upgrade plan: what the host would move a package to,
 * from which repository, in which architecture and in which direction.
 * The direction and the origin enter the plan digest, so the row shows
 * them as the host named them.
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
 * The version of a package as the manager prints it: the epoch in front,
 * the release behind, so the row reads like the tool's own output and a
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
 * host reported and the changes of the last upgrade plan. A held state is
 * unknown when the holds were not read, and a package the plan does not
 * name has no candidate - which says "nothing waits", not "not planned":
 * the caption of the table says how old the plan is.
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
 * The search is over the name and the source package, case-insensitively;
 * the filter "held" keeps the rows known to be held, so an unread hold
 * list filters to nothing rather than to everything.
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
 * The host's packages.
 *
 * Installing and removing are separated from upgrading: they are three
 * different decisions about the same host. A removal goes through a plan,
 * because one package can drag dozens of dependants along.
 */
export function Packages() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const module = useModule<PackagesState>(host.id, "packages");
  const packages = module.data?.payload;

  const [names, setNames] = useState("");
  // The removal plan and the set it was computed for: a removal ordered
  // from the table names one package, a removal from the form names what
  // was typed, and the confirmation removes the set that was reviewed.
  const [plan, setPlan] = useState<{ requested: string[]; plan: RemovalPlan } | null>(null);
  const [toRemove, setToRemove] = useState<{ requested: string[]; removals: string[] } | null>(null);
  const [sourceIntent, setSourceIntent] = useState<SourceIntent | null>(null);
  const [agentVersion, setAgentVersion] = useState("");
  const [repairing, setRepairing] = useState(false);
  const [message, setMessage] = useState("");

  // The release channel is a policy recorded in the panel, not an operation:
  // nothing runs on the host, so it goes straight to the host record.
  const setChannel = useMutation({
    mutationFn: (channel: ReleaseChannel) => api.put<Host>(`/api/v1/hosts/${host.id}/channel`, { channel }),
    onSuccess: (updated) => {
      setMessage(t("The host now follows the {channel} channel.", { channel: updated.release_channel }));
      queryClient.invalidateQueries({ queryKey: ["host", host.id] });
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (job) => {
      setMessage(
        job.requires_approval
          ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
          : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }),
      );
      setToRemove(null);
      setRepairing(false);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const list = () =>
    names.split(/[\s,]+/).map((name) => name.trim()).filter(Boolean);

  // The removal plan is computed on the host, so the screen waits for its result.
  const planRemoval = useMutation({
    mutationFn: async (requested: string[]) => {
      const job = await api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "packages.plan",
        payload: { package_plan: { mode: "remove", only_packages: requested } },
      });
      const last = await awaitJob<RemovalPlan>(api, job.id);
      if (!last) throw new Error(t("The plan did not arrive in time."));
      if (last.status !== "succeeded") {
        throw new Error(last.message || t("The host refused to plan the removal."));
      }
      return { requested, plan: last.detail ?? {} };
    },
    onSuccess: (result) => { setPlan(result); setMessage(""); },
    onError: (error) => {
      setPlan(null);
      setMessage(error instanceof Error ? error.message : String(error));
    },
  });

  // The package list is read by the panel on its own cycle; the operator
  // asks for it here when the copy is missing or older than the host. The
  // rows appear when the job lands, not at the next timed refetch.
  const readList = useMutation({
    mutationFn: () => api.post<Job>(`/api/v1/hosts/${host.id}/operations`, { action: "packages.list", payload: {} }),
    onSuccess: (job) => {
      setMessage(t("Job {id} reads the package list.", { id: job.id.slice(0, 8) }));
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      void awaitJob(api, job.id).then(
        () => queryClient.invalidateQueries({ queryKey: ["host-packages", host.id] }),
        () => undefined,
      );
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const sources = packages?.repositories?.repositories ?? [];
  const pending = host.pending_updates ?? undefined;
  const security = host.pending_security_updates ?? undefined;
  // The sources are a known list only when the host could read them; an
  // unread list is not an empty one.
  const knownSources = packages?.repositories?.repositories_known === false ? undefined : sources;
  const upToDate = packages?.installed !== undefined && pending !== undefined
    ? Math.max(0, packages.installed - pending)
    : undefined;
  // pacman plans with checkupdates and upgrades the whole system at once;
  // the labels say so, because the operator will not find a partial upgrade
  // here and should not look for a security count Arch cannot give.
  const pacman = packages?.manager === "pacman";

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Packages")}
        description={t("Installed software, its sources and the updates waiting for this host. A removal is planned before it runs.")}
      />
      <ModuleFreshness fragment={module.data} />
      <Message text={message} />

      <Widgets>
        {/* The counts decide whether the rest is worth reading; an unknown
            count is a dash, because zero would mean "nothing to do". The
            holds come from the host with the counters, and a hold list the
            host could not read leaves the slot unknown. */}
        <Summary
          title={t("Updates")}
          description={t("The installed packages by what waits for them.")}
          span={8}
          segments={[
            { label: t("up to date"), value: upToDate, tone: "ok" },
            { label: t("upgradable"), value: pending, tone: "warn" },
            { label: t("security"), value: security, tone: "error" },
            { label: t("held"), value: heldCount(packages), tone: "neutral" },
          ]}
        >
          {/* A dash is not a zero: the operator is told why the host has
              no count, and what produces one. */}
          {pending === undefined && (
            <p className="source" style={{ margin: "8px 0 0" }}>
              {packages?.unavailable_reason
                ? t("The update counts could not be read: {reason}", { reason: packages.unavailable_reason })
                : t("The host has not counted its updates yet; plan updates below to count them.")}
            </p>
          )}
        </Summary>
        <Section title={t("Sources")} span={4} flush>
          <Facts>
            <Fact label={t("Installed")}>{packages?.installed ?? <Unknown />}</Fact>
            <Fact label={t("Manager")}>{packages?.manager || "—"}</Fact>
            <Fact label={t("Package database")}>
              {host.package_database_broken
                ? (
                  <>
                    <span className="badge error">{t("needs repair")}</span>
                    {/* Every other package operation is refused while the
                        database is broken, so the repair stands where the
                        verdict is. Critical: it finishes a transaction
                        somebody interrupted, with a reason and an approval. */}
                    {" "}
                    <button type="button" className="link" onClick={() => setRepairing(true)} disabled={repairing}>
                      {t("Repair the package database…")}
                    </button>
                  </>
                )
                : <span className="badge ok">{t("healthy")}</span>}
            </Fact>
            <Fact label={t("Repositories")}>{knownSources ? knownSources.length : <Unknown />}</Fact>
            <Fact label={t("By state")} wide>
              {knownSources ? (
                <Breakdown
                  items={[
                    { label: t("enabled"), value: countWhere(knownSources, (s) => s.enabled) ?? 0, tone: "ok" },
                    { label: t("signatures checked"), value: countWhere(knownSources, (s) => s.signed) ?? 0, tone: "ok" },
                    { label: t("not checked"), value: countWhere(knownSources, (s) => !s.signed) ?? 0, tone: "error" },
                    { label: t("managed by the panel"), value: countWhere(knownSources, (s) => s.managed) ?? 0, tone: "info" },
                  ]}
                />
              ) : "—"}
            </Fact>
          </Facts>
        </Section>

      {/* The three things an operator does here are short forms; in one
          row they make a workbench, in a column a strip. The removal plan,
          when there is one, follows the row; the sources come last. */}
      <RequestOperation
        host={host}
        description={pacman
          ? t("Count available updates without changing host state. On Arch the plan comes from checkupdates, the whole system upgrades at once and the security count is unknown.")
          : t("Count available updates without changing host state.")}
        action="packages.plan"
        payload={{ package_plan: { refresh_metadata: true } }}
        label={t("Plan updates")}
        span={4}
      />

      <Section title={t("Install, remove or hold")} span={4}>
        <Form>
          <Fields>
            <Field label={t("Package names (space or comma separated)")} wide>
              <input value={names} onChange={(e) => { setNames(e.target.value); setPlan(null); }}
                     placeholder="nginx htop" />
            </Field>
          </Fields>
          <FormActions>
            <button
              disabled={request.isPending || list().length === 0}
              onClick={() => request.mutate({
                action: "packages.install",
                payload: { package_change: { packages: list() } },
              })}
            >
              {t("Install")}
            </button>
            <button
              className="secondary"
              disabled={request.isPending || list().length === 0}
              onClick={() => request.mutate({
                action: "packages.hold.set",
                payload: { package_change: { packages: list(), hold: true } },
              })}
            >
              {t("Hold")}
            </button>
            <button
              className="secondary"
              disabled={request.isPending || list().length === 0}
              onClick={() => request.mutate({
                action: "packages.hold.set",
                payload: { package_change: { packages: list(), hold: false } },
              })}
            >
              {t("Unhold")}
            </button>
            {/* A removal does not go straight through: one package can drag
                dozens of dependants along, and the operator is to see them
                first. */}
            <button
              className="hm-danger"
              disabled={planRemoval.isPending || list().length === 0}
              onClick={() => planRemoval.mutate(list())}
            >
              {planRemoval.isPending ? t("Planning…") : t("Plan removal")}
            </button>
          </FormActions>
        </Form>
      </Section>

      <Section
        title={t("Agent")}
        span={4}
        description={t("The agent is left alone by ordinary package upgrades: replacing it in the middle of a transaction it is running would cut the host off from management with nobody to report the result. Replacing it is its own operation, and it counts as done only when the host comes back reporting the version that was asked for.")}
      >
        <Facts>
          <Fact label={t("Agent version")}>{host.agent_version || <Unknown />}</Fact>
          <Fact label={t("Release channel")}>
            <span className={host.release_channel === "beta" ? "badge warn" : "badge ok"}>{host.release_channel}</span>
          </Fact>
        </Facts>
        <Form>
          <Fields>
            {/* The channel decides which releases reach the host first: a
                fleet upgrade in waves names the beta hosts before the
                stable ones. It is assigned here explicitly; there is no
                implicit latest. */}
            <Field label={t("Release channel")} narrow>
              <select
                value={host.release_channel}
                disabled={setChannel.isPending}
                onChange={(e) => setChannel.mutate(e.target.value as ReleaseChannel)}
              >
                {RELEASE_CHANNELS.map((name) => (
                  <option key={name} value={name}>{name === "beta" ? t("beta (sees a release first)") : t("stable")}</option>
                ))}
              </select>
            </Field>
            <Field label={t("Target agent version (currently {version})", { version: host.agent_version || t("unknown") })} narrow>
              <input
                value={agentVersion}
                onChange={(e) => setAgentVersion(e.target.value)}
                placeholder={t("e.g. {version}", { version: host.agent_version || "0.51.0" })}
              />
            </Field>
          </Fields>
          <FormActions>
            <button
              disabled={!agentVersion || agentVersion === host.agent_version}
              onClick={() =>
                request.mutate({
                  action: "agent.upgrade",
                  payload: { agent_upgrade: { target_version: agentVersion } },
                })
              }
            >
              {t("Replace agent")}
            </button>
          </FormActions>
        </Form>
      </Section>

      </Widgets>

      {plan && (
        <Section title={t("Removal plan")} count={plan.plan.removals?.length ?? 0} flush>
          {plan.plan.protected && plan.plan.protected.length > 0 && (
            <p className="warning">
              <span>
                {t("These packages are protected and will not be removed: {packages}. Removing them would leave the host unmanageable or unbootable.", { packages: plan.plan.protected.join(", ") })}
              </span>
            </p>
          )}
          {!plan.plan.removals?.length ? (
            <Empty>{t("Nothing would be removed.")}</Empty>
          ) : (
            <>
              <Table>
                <thead><tr><th>{t("Package")}</th><th>{t("Reason")}</th></tr></thead>
                <tbody>
                  {plan.plan.removals.map((pkg) => (
                    <tr key={pkg}>
                      <td className="hm-mono">{pkg}</td>
                      <td>{plan.requested.includes(pkg) ? t("requested") : t("dependency")}</td>
                    </tr>
                  ))}
                </tbody>
              </Table>
              <Foot>
                <span>
                  {t("{n} package(s) would be removed. The host recomputes this set before removing; a difference cancels the operation.", { n: plan.plan.removals.length })}
                </span>
                {(!plan.plan.protected || plan.plan.protected.length === 0) && (
                  <button className="danger" onClick={() => setToRemove({ requested: plan.requested, removals: plan.plan.removals ?? [] })}>
                    {t("Remove these packages")}
                  </button>
                )}
              </Foot>
            </>
          )}
        </Section>
      )}

      <InstalledPackages
        host={host}
        packages={packages}
        busy={request.isPending || planRemoval.isPending}
        onRead={() => readList.mutate()}
        reading={readList.isPending}
        onHold={(name, hold) => request.mutate({
          action: "packages.hold.set",
          payload: { package_change: { packages: [name], hold } },
        })}
        onRemove={(name) => { setPlan(null); planRemoval.mutate([name]); }}
      />

      <Repositories
        view={packages?.repositories}
        manager={packages?.manager}
        onIntent={setSourceIntent}
      />

      <TransactionHistory hostId={host.id} />

      {sourceIntent && (
        <TargetConfirmation
          host={host}
          label={sourceIntent.label}
          description={sourceIntent.description}
          busy={request.isPending}
          onConfirm={(reason) =>
            request.mutate({
              action: "packages.repository.set",
              reason,
              payload: { repository: sourceIntent.payload },
            })
          }
          onCancel={() => setSourceIntent(null)}
        />
      )}

      {repairing && (
        <TargetConfirmation
          host={host}
          label={t("Repair the package database")}
          description={t("The host finishes the interrupted package transaction on {host} and configures what was left half-way. Package operations are refused until this succeeds.", { host: host.hostname })}
          busy={request.isPending}
          onConfirm={(reason) =>
            request.mutate({
              action: "packages.repair",
              reason,
              payload: { package_repair: {} },
            })
          }
          onCancel={() => setRepairing(false)}
        />
      )}

      {toRemove && (
        <TargetConfirmation
          host={host}
          label={t("Remove packages")}
          description={t("{n} package(s) will be removed: {packages}.", {
            n: toRemove.removals.length,
            packages: `${toRemove.removals.slice(0, 6).join(", ")}${toRemove.removals.length > 6 ? "…" : ""}`,
          })}
          busy={request.isPending}
          onConfirm={(reason, confirmation) =>
            request.mutate({
              action: "packages.remove",
              reason,
              target_confirmation: confirmation,
              payload: {
                package_change: { packages: toRemove.requested, expected_removals: toRemove.removals },
              },
            })
          }
          onCancel={() => setToRemove(null)}
        />
      )}
    </ModulePage>
  );
}

type SourceIntent = { label: string; description: string; payload: Record<string, unknown> };

/** The height of a package row: one line of text, so the window arithmetic holds. */
const PACKAGE_ROW = 34;

/**
 * The installed packages, from the panel's copy of the host's list.
 *
 * The copy is read on request and kept next to the vulnerability
 * assessment; the inventory carries the digest of the host's own list, so
 * the table says when the copy stopped describing the host instead of
 * serving it as current. The holds come from the host with the counters,
 * and the version a package would move to comes from the last upgrade
 * plan - the table joins the three, and the caption says how old each is.
 * A few thousand rows are windowed: the search runs over the whole list,
 * the browser draws a screenful.
 */
function InstalledPackages({
  host, packages, busy, reading, onRead, onHold, onRemove,
}: {
  host: Host;
  packages: PackagesState | undefined;
  /** Whether an order is on its way; the row actions wait for it. */
  busy: boolean;
  reading: boolean;
  onRead: () => void;
  onHold: (name: string, hold: boolean) => void;
  onRemove: (name: string) => void;
}) {
  const t = useT();
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<PackageFilter>("all");
  const [direction, setDirection] = useState<"asc" | "desc">("asc");
  const [selected, setSelected] = useState<string>("");

  const list = useQuery({
    queryKey: ["host-packages", host.id],
    queryFn: () => api.get<PackageList>(`/api/v1/hosts/${host.id}/packages`),
    retry: false,
  });
  const plan = useLastUpgradePlan(host.id);

  const holds = useMemo(() => (packages?.holds_known ? packages.holds ?? [] : undefined), [packages]);
  const rows = useMemo(
    () => packageRows(list.data?.items ?? [], holds, plan.changes),
    [list.data, holds, plan.changes],
  );
  const shown = useMemo(() => filterRows(rows, query, filter, direction), [rows, query, filter, direction]);
  const current = rows.find((row) => `${row.name}/${row.architecture ?? ""}` === selected);
  const state = list.data?.state;
  // The copy is stale when the host's own list has another digest: the
  // rows then describe an earlier moment, and the caption says so.
  const stale = !!state?.digest && !!packages?.installed_digest && state.digest !== packages.installed_digest;
  const pacman = packages?.manager === "pacman";
  const key = (row: PackageRow) => `${row.name}/${row.architecture ?? ""}`;
  // A column with nothing in any row says nothing: the architecture is
  // left out where the manager does not report one, and the two plan
  // columns until a plan exists - the caption says one is missing.
  const showArchitecture = rows.some((row) => !!row.architecture);
  const showPlan = plan.changes !== undefined;
  // The columns the operator may fold, remembered per table; the name of
  // the package stays whatever the preference says. A column the host
  // gives nothing for is not offered at all.
  const columns = useColumns("host-packages", [
    { key: "name", label: t("Package"), fixed: true },
    { key: "version", label: t("Version") },
    ...(showArchitecture ? [{ key: "architecture", label: t("Architecture"), secondary: true }] : []),
    { key: "source", label: t("Source"), secondary: true },
    ...(showPlan ? [{ key: "candidate", label: t("Upgrade to") }, { key: "security", label: t("Security") }] : []),
    { key: "held", label: t("Held") },
  ]);

  return (
    <>
      <Section
        title={t("Installed packages")}
        count={list.data ? shown.length : undefined}
        description={t("The panel's copy of the host's package list, joined with the holds the host reports and the changes of the last upgrade plan. Select a package to act on it.")}
        tools={list.data && list.data.items.length > 0 && (
          <>
            <input
              placeholder={t("Search packages")}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <select value={filter} onChange={(e) => setFilter(e.target.value as PackageFilter)}>
              <option value="all">{t("all packages")}</option>
              <option value="upgradable">{t("upgradable only")}</option>
              <option value="security">{t("security updates only")}</option>
              <option value="held">{t("held only")}</option>
            </select>
            <select value={direction} onChange={(e) => setDirection(e.target.value as "asc" | "desc")}>
              <option value="asc">{t("name A–Z")}</option>
              <option value="desc">{t("name Z–A")}</option>
            </select>
            <ColumnChooser columns={columns} />
          </>
        )}
        flush
      >
        {list.error ? (
          <Empty>{list.error instanceof Error ? list.error.message : String(list.error)}</Empty>
        ) : !list.data ? (
          <Empty>{t("Loading…")}</Empty>
        ) : list.data.items.length === 0 ? (
          <>
            {/* No rows is not a host without packages: the panel has not
                read the list, or could not, and says which. */}
            <Empty>
              {state?.unavailable_reason === "package_list_missing" || !state?.unavailable_reason
                ? t("The panel has not read the package list of this host yet.")
                : t("The package list could not be read: {reason}", { reason: state.unavailable_reason })}
            </Empty>
            <Foot>
              <span>{t("The read goes through a job and needs no root on the host.")}</span>
              <button className="secondary" onClick={onRead} disabled={reading || host.connection_state !== "online"}>
                {reading ? t("Requesting…") : t("Read the package list")}
              </button>
            </Foot>
          </>
        ) : (
          <>
            {stale && (
              <p className="warning">
                <span>{t("The host's own list has changed since the panel read it; the rows describe an earlier moment.")}</span>
                <button className="secondary" onClick={onRead} disabled={reading || host.connection_state !== "online"}>
                  {reading ? t("Requesting…") : t("Read it again")}
                </button>
              </p>
            )}
            {packages && packages.holds_known === false && (
              <p className="warning">
                <span>
                  {t("The holds could not be read, so no package is known to be held")}
                  {packages.holds_unavailable_reason ? `: ${packages.holds_unavailable_reason}` : "."}
                </span>
              </p>
            )}
            {shown.length === 0 ? (
              <Empty>{t("No package matches.")}</Empty>
            ) : (
              <VirtualRows
                items={shown}
                rowHeight={PACKAGE_ROW}
                height={480}
                columns={columns.visible.length}
                rowKey={key}
                head={
                  <tr>
                    {columns.all.map((column) => <Th key={column.key} columns={columns} name={column.key} />)}
                  </tr>
                }
                render={(row) => (
                  <>
                    <Td columns={columns} name="name">
                      <button
                        className="inline"
                        aria-pressed={selected === key(row)}
                        onClick={() => setSelected(selected === key(row) ? "" : key(row))}
                        title={row.source_name && row.source_name !== row.name ? t("source package {name}", { name: row.source_name }) : undefined}
                      >
                        {row.name}
                      </button>
                    </Td>
                    <Td columns={columns} name="version" className="hm-mono">{packageVersion(row)}</Td>
                    <Td columns={columns} name="architecture">{row.architecture || "—"}</Td>
                    <Td columns={columns} name="source" className="source" title={row.origin || undefined}>
                      {row.repository_id || row.origin || originWords(t, row.origin_class)}
                    </Td>
                    {/* The candidate with its origin on hover, and the
                        direction where it is not an upgrade: a plan that
                        takes a package back a version is what the
                        operator must not miss in a column of upgrades. */}
                    <Td columns={columns} name="candidate" className="hm-mono" title={row.candidateOrigin || undefined}>
                      {row.candidate ?? ""}
                      {row.action && row.action !== "upgrade" && <> <span className="badge warn">{t(row.action)}</span></>}
                    </Td>
                    <Td columns={columns} name="security">{row.security && <span className="badge error">{t("security")}</span>}</Td>
                    <Td columns={columns} name="held">
                      {row.held === true
                        ? <span className="badge warn">{t("held")}</span>
                        : row.held === undefined
                          ? <span className="badge unknown" title={t("The holds were not read.")}>?</span>
                          : ""}
                    </Td>
                  </>
                )}
              />
            )}
            <Foot>
              <span>
                {t("{shown} of {total} packages", { shown: shown.length, total: list.data.items.length })}
                {" · "}
                {t("list read")} <Time value={state?.collected_at} />
                {state?.job_id && <> (<Link to={`/jobs/${state.job_id}`} className="mono">{state.job_id.slice(0, 8)}</Link>)</>}
                {" · "}
                {plan.at
                  ? <>
                      {t("upgrade plan from")} <Time value={plan.at} />
                      {plan.header?.planner_version && <> · {t("planner")} <span className="hm-mono">{plan.header.planner_version}</span></>}
                      {plan.header?.expires_at && (planExpired(plan.header)
                        ? <> · <span className="badge error">{t("plan expired")}</span></>
                        : <> · {t("valid until")} <Time value={plan.header.expires_at} /></>)}
                    </>
                  : t("no upgrade plan yet; the upgrade column fills in after one")}
              </span>
              <button className="secondary" onClick={onRead} disabled={reading || host.connection_state !== "online"}>
                {reading ? t("Requesting…") : t("Read again")}
              </button>
            </Foot>
            {/* The actions of the selected package stand under the table,
                with the target named once more: a hold and a release go
                straight to a job, a removal to a plan first, and an upgrade
                to the request form with its reason. */}
            {current && (
              <Foot>
                <span>
                  <span className="hm-mono">{current.name}</span> {packageVersion(current)}
                  {current.candidate && <> → <span className="hm-mono">{current.candidate}</span></>}
                  {current.held === true && <> · {t("held")}</>}
                </span>
                <button className="secondary" disabled={busy} onClick={() => onHold(current.name, current.held !== true)}>
                  {current.held === true ? t("Unhold") : t("Hold")}
                </button>
                <button className="hm-danger" disabled={busy} onClick={() => onRemove(current.name)}>
                  {t("Plan removal")}
                </button>
                <button className="secondary" onClick={() => setSelected("")}>{t("Deselect")}</button>
              </Foot>
            )}
          </>
        )}
      </Section>
      {current && (pacman ? (
        <Section title={t("Upgrade {name}", { name: current.name })}>
          <p className="source" style={{ margin: 0 }}>
            {t("pacman upgrades the whole system at once: a single package cannot be moved on its own without leaving the host partially upgraded. Plan updates above and upgrade the host as a whole.")}
          </p>
        </Section>
      ) : (
        <RequestOperation
          host={host}
          description={current.candidate
            ? t("Upgrades {name} alone, from {from} to {to}, through a package transaction; the rest of the host stays as it is.", {
                name: current.name, from: packageVersion(current), to: current.candidate,
              })
            : t("Upgrades {name} alone through a package transaction; the last plan named no newer version, so the host may find nothing to do.", { name: current.name })}
          action="packages.upgrade"
          payload={{ package_upgrade: { packages: [current.name] } }}
          label={t("Upgrade {name}", { name: current.name })}
        />
      ))}
    </>
  );
}

/** The origin class of a package in the operator's words; empty when the host did not classify it. */
function originWords(t: (key: string) => string, originClass?: string): string {
  switch (originClass) {
    case "vendor_distribution": return t("distribution");
    case "third_party_repository": return t("third-party repository");
    case "local_package": return t("local package");
    case "origin_unknown": return t("origin unknown");
    default: return "—";
  }
}

/**
 * The changes of the last upgrade plan of the host, with when it was made.
 * The plan is the newest succeeded packages.plan job that planned an
 * upgrade - a removal plan or an install plan says nothing about what
 * waits - and its changes are in the result of its last attempt.
 */
function useLastUpgradePlan(hostId: string): { changes?: PlanChange[]; at?: string; header?: PlanHeader } {
  const jobs = useQuery({
    queryKey: ["jobs", hostId, "packages.plan", "succeeded"],
    queryFn: () => api.get<Page<Job>>(`/api/v1/jobs?host_id=${hostId}&action=packages.plan&state=succeeded&limit=10`),
  });
  const upgrade = (jobs.data?.items ?? []).find((job) => {
    const mode = (job.payload as { package_plan?: { mode?: string } } | undefined)?.package_plan?.mode;
    return !mode || mode === "upgrade";
  });
  const attempts = useQuery({
    queryKey: ["job-attempts", upgrade?.id ?? ""],
    queryFn: () => api.get<Collection<Attempt>>(`/api/v1/jobs/${upgrade?.id}/attempts`),
    enabled: !!upgrade,
    staleTime: Infinity,
  });
  if (!upgrade || !attempts.data) return {};
  const last = attempts.data.items[attempts.data.items.length - 1];
  const detail = last?.detail as ({ kind?: string; changes?: PlanChange[] } & PlanHeader) | undefined;
  if (detail?.kind !== "package_plan") return {};
  return {
    changes: detail.changes, at: upgrade.finished_at ?? upgrade.created_at,
    header: { planner_version: detail.planner_version, expires_at: detail.expires_at, plan_hash: detail.plan_hash },
  };
}

/** How many transactions one page of the history carries. */
const HISTORY_PAGE = 20;

/** The package operations that change the host; a plan or a listing applies nothing. */
const APPLYING = ["packages.install", "packages.remove", "packages.upgrade", "packages.hold.set"];

/**
 * The transaction history of the host: every package operation ordered
 * through the panel, newest first, with what it applied. It is the
 * operation list narrowed to the package family, not a second record - a
 * transaction the host ran by hand is not here, and the packages module
 * above says what is installed now.
 */
function TransactionHistory({ hostId }: { hostId: string }) {
  const t = useT();
  const history = useInfiniteQuery({
    queryKey: ["jobs", hostId, "packages"],
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams({ host_id: hostId, action_prefix: "packages.", limit: String(HISTORY_PAGE) });
      if (pageParam) params.set("cursor", pageParam);
      return api.get<Page<Job>>(`/api/v1/jobs?${params}`);
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor || undefined,
  });
  const jobs = loadedItems(history.data);

  return (
    <Section
      title={t("Transaction history")}
      count={jobs.length}
      description={t("The package operations ordered through the panel, newest first; a transaction run by hand on the host is not here.")}
      flush
    >
      {history.error ? (
        <Empty>{t("The history could not be read.")}</Empty>
      ) : jobs.length === 0 ? (
        <Empty>{history.isLoading ? t("Loading…") : t("No package operation has been ordered on this host.")}</Empty>
      ) : (
        <>
          <Table>
            <thead>
              <tr>
                <th>{t("When")}</th>
                <th>{t("Operation")}</th>
                <th>{t("Outcome")}</th>
                <th>{t("Applied")}</th>
                <th>{t("By")}</th>
                <th>{t("Job")}</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((job) => (
                <tr key={job.id}>
                  <td><Time value={job.finished_at ?? job.created_at} /></td>
                  <td className="hm-mono">{job.action_type.replace(/^packages\./, "")}</td>
                  <td>
                    <JobState state={job.state} />
                    {job.result_error_code && <> <ErrorCode code={job.result_error_code} /></>}
                  </td>
                  <td>
                    {APPLYING.includes(job.action_type) && job.state === "succeeded"
                      ? <AppliedCount jobId={job.id} />
                      : "—"}
                  </td>
                  <td>{job.created_by}</td>
                  <td>
                    <Link to={`/jobs/${job.id}`} className="mono" title={job.id}>{job.id.slice(0, 8)}</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
          {history.hasNextPage && (
            <Foot>
              <button className="secondary" onClick={() => history.fetchNextPage()} disabled={history.isFetchingNextPage}>
                {t("Load more")}
              </button>
            </Foot>
          )}
        </>
      )}
    </Section>
  );
}

/**
 * How many packages a transaction applied, from the result of its last
 * attempt. The count is not on the job row, so it is read per transaction
 * once the row is on screen; a page of twenty is twenty small reads, kept
 * by the query cache.
 */
function AppliedCount({ jobId }: { jobId: string }) {
  const t = useT();
  const attempts = useQuery({
    queryKey: ["job-attempts", jobId],
    queryFn: () => api.get<Collection<Attempt>>(`/api/v1/jobs/${jobId}/attempts`),
    staleTime: Infinity,
  });
  if (attempts.error) return <span className="badge unknown">{t("unknown")}</span>;
  if (!attempts.data) return <>…</>;
  const last = attempts.data.items[attempts.data.items.length - 1];
  const applied = (last?.detail as { kind?: string; applied?: unknown[] } | undefined)?.applied;
  if (!Array.isArray(applied)) return <span className="badge unknown">{t("unknown")}</span>;
  return <>{t("{n} package(s)", { n: applied.length })}</>;
}

/**
 * Package sources.
 *
 * Adding a source installs nothing today, but decides whose packages the
 * host accepts tomorrow - together with their scripts, which run as root.
 * That is why a source without signature checking requires explicit
 * consent, and the password to a private source is named by a secret, not
 * given as a value.
 */
function Repositories({
  view, manager, onIntent,
}: {
  view?: RepositoryView;
  manager?: string;
  onIntent: (intent: SourceIntent) => void;
}) {
  const t = useT();
  const [form, setForm] = useState(false);
  const sources = view?.repositories ?? [];

  return (
    <>
      <Section
        title={t("Repositories")}
        count={sources.length}
        description={t("Where this host takes software from. Adding a source installs nothing today; it decides whose packages the host will accept tomorrow, with their scripts running as root.")}
        tools={
          <button className="secondary" onClick={() => setForm((open) => !open)}>
            {form ? t("Cancel") : t("Add or change a source")}
          </button>
        }
        flush
      >
        {view && view.repositories_known === false && (
          <p className="warning">
            <span>
              {t("The list of sources could not be read")}
              {view.repositories_unavailable_reason
                ? `: ${view.repositories_unavailable_reason}`
                : "."}
            </span>
          </p>
        )}

        {!sources.length ? (
          <Empty>{t("This host reports no package source.")}</Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>{t("Source")}</th><th>{t("Address")}</th><th>{t("State")}</th><th>{t("Signatures")}</th>
                <th>{t("Managed by")}</th><th>{t("Actions")}</th>
              </tr>
            </thead>
            <tbody>
              {sources.map((source) => (
                <tr key={`${source.path}-${source.id}`}>
                  <td>
                    <span className="hm-primary">{source.id}</span>
                    {source.path && <div className="source hm-mono">{source.path}</div>}
                  </td>
                  <td className="source">
                    {source.unavailable_reason ? (
                      <span className="badge unknown">{source.unavailable_reason}</span>
                    ) : (
                      <>
                        <span className="hm-mono">{source.url}</span>
                        {source.suites?.length ? (
                          <div>{source.suites.join(" ")} {source.components?.join(" ")}</div>
                        ) : null}
                      </>
                    )}
                  </td>
                  <td>
                    {source.enabled
                      ? <span className="badge ok">{t("enabled")}</span>
                      : <span className="badge">{t("disabled")}</span>}
                  </td>
                  <td>
                    {/* A source without signature checking is a remote root
                        shell, not a setting - and it is to look like one. */}
                    {source.signed
                      ? <span className="badge ok">{t("checked")}</span>
                      : <span className="badge error">{t("not checked")}</span>}
                  </td>
                  <td>
                    {source.managed ? (
                      <>
                        <span className="badge ok">{t("panel")}</span>
                        {source.secret_name && (
                          <div className="source">{t("password from {secret}", { secret: source.secret_name })}</div>
                        )}
                      </>
                    ) : (
                      <span className="badge">{t("distribution")}</span>
                    )}
                  </td>
                  <td>
                    <div className="operations">
                      <button
                        className="secondary"
                        disabled={!source.managed}
                        title={source.managed ? undefined : t("Only a source written by the panel can be changed here; this one belongs to the distribution or the host administrator.")}
                        onClick={() =>
                          onIntent({
                            label: source.enabled ? t("Disable source") : t("Enable source"),
                            description: source.enabled
                              ? t("{id} will be disabled. The files stay on the host.", { id: source.id })
                              : t("{id} will be enabled. The files stay on the host.", { id: source.id }),
                            payload: {
                              id: source.id, url: source.url, name: source.name,
                              suites: source.suites, components: source.components,
                              enabled: !source.enabled, allow_unsigned: !source.signed,
                            },
                          })
                        }
                      >
                        {source.enabled ? t("Disable") : t("Enable")}
                      </button>
                      <button
                        className="hm-danger"
                        disabled={!source.managed}
                        title={source.managed ? undefined : t("Only a source written by the panel can be removed here; this one belongs to the distribution or the host administrator.")}
                        onClick={() =>
                          onIntent({
                            label: t("Remove source"),
                            description: t("{id} will be removed from this host, together with its key and its password file.", { id: source.id }),
                            payload: { id: source.id, remove: true },
                          })
                        }
                      >
                        {t("Remove")}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>
      {form && <SourceForm manager={manager} onIntent={onIntent} />}
    </>
  );
}

/** The source form. The key is pasted in ASCII armour; the password is named by a secret. */
function SourceForm({
  manager, onIntent,
}: {
  manager?: string;
  onIntent: (intent: SourceIntent) => void;
}) {
  const t = useT();
  const [id, setId] = useState("");
  const [url, setUrl] = useState("");
  const [suites, setSuites] = useState("");
  const [components, setComponents] = useState("");
  const [key, setKey] = useState("");
  const [unsigned, setUnsigned] = useState(false);
  const [username, setUsername] = useState("");
  const [secret, setSecret] = useState("");
  const apt = manager === "apt";
  const pacman = manager === "pacman";

  const ready = id !== "" && url !== "" && (unsigned || key.includes("BEGIN PGP")) &&
    (!apt || suites.trim() !== "");

  return (
    <Section
      title={t("Package source")}
      description={pacman
        ? t("The key travels in the job — it is public, and the plan should show what the host will trust. pacman writes the source as a section of /etc/pacman.conf and signs the key in its keyring; a pacman source carries no password.")
        : t("The key travels in the job — it is public, and the plan should show what the host will trust. The password does not: name a secret and the host fetches its value once, while it writes the file.")}
    >
      <Form>
        <Fields>
          <Field label={t("Source")}>
            <input value={id} onChange={(e) => setId(e.target.value)} placeholder="internal" />
          </Field>
          <Field label={t("Address")} wide>
            <input value={url} onChange={(e) => setUrl(e.target.value)}
                   placeholder={pacman ? "https://packages.example.com/arch/$arch" : "https://packages.example.com/debian"} />
          </Field>
          {apt && (
            <>
              <Field label={t("Suites (stable)")}>
                <input value={suites} onChange={(e) => setSuites(e.target.value)} placeholder="stable" />
              </Field>
              <Field label={t("Components (main)")}>
                <input value={components} onChange={(e) => setComponents(e.target.value)} placeholder="main" />
              </Field>
            </>
          )}
          <Field label={t("Username (private source)")}>
            <input value={username} onChange={(e) => setUsername(e.target.value)} />
          </Field>
          <Field label={t("Password secret (name only)")}>
            <input value={secret} onChange={(e) => setSecret(e.target.value)} />
          </Field>
        </Fields>
        <Check checked={unsigned} onChange={setUnsigned}>
          {t("Do not check signatures (the host will install anything from this address)")}
        </Check>
        {!unsigned && (
          <Fields>
            <Field label={t("Signing key (ASCII-armored public key)")} wide>
              <textarea rows={8} value={key} onChange={(e) => setKey(e.target.value)}
                        placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----" />
            </Field>
          </Fields>
        )}
        <FormActions>
          <button
            disabled={!ready}
            onClick={() =>
              onIntent({
                label: t("Write source"),
                description:
                  t("{id} ({url}) becomes a package source on this host", { id, url }) +
                  (unsigned ? `, ${t("with signature checking off — the host will install whatever comes from that address")}` : "") +
                  (secret ? `, ${t("authenticating as {user} with the value of secret {secret}", { user: username, secret })}` : "") +
                  `. ${t("The host fetches its metadata before the change counts as done, and rolls back if it cannot.")}`,
                payload: {
                  id, url, enabled: true, allow_unsigned: unsigned,
                  ...(apt ? {
                    suites: suites.split(/[\s,]+/).filter(Boolean),
                    components: components.split(/[\s,]+/).filter(Boolean),
                  } : {}),
                  ...(unsigned ? {} : { gpg_key: key }),
                  ...(secret ? { username, password_secret: { name: secret } } : {}),
                },
              })
            }
          >
            {t("Write source")}
          </button>
        </FormActions>
      </Form>
    </Section>
  );
}
