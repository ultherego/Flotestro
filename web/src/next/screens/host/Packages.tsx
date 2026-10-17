import { useMemo, useState, type ReactNode } from "react";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, loadedItems, type Collection, type Page } from "../../../lib/api";
import { useAllowed, useModuleAccess } from "../../../lib/actions";
import { awaitJob } from "../../../lib/jobs";
import { absoluteTime, relativeTime } from "../../../lib/format";
import {
  RELEASE_CHANNELS, type Attempt, type Host, type InventoryFragment, type Job, type ReleaseChannel,
} from "../../../lib/types";
import { stateName } from "../../../lib/states";
import {
  agentUpgradeOrder, changePayload, filterRows, heldCount, operationBody, packageRows, packageVersion,
  planBinding, planExpired, planMode,
  type ApprovedPlan, type InstalledPackage, type PackageFilter, type PackageRow, type PackagesState,
  type PlanChange, type PlanHeader,
} from "../../../lib/host/packages";
import { orderReady, refusalOf } from "../../../lib/host/module";
import { useT } from "../../../i18n";
import {
  Actions, Band, Banner, Bars, Button, C, Card, Check, Empty, Fact, Facts, Field, Fields, Find, Form,
  Grid, Modal, Note, PAGE_SIZES, Pager, Pill, Problem, Seg, Table, Tabs, Tag, Toolbar, useTab,
  type Segment, type Tone,
} from "../../kit";

/** The sub-tabs of this screen, in the order a reader wants them. */
const PACKAGE_TABS = ["state", "change", "history"] as const;

/**
 * The software of one host: what is installed, where it comes from, and
 * what waits for it.
 *
 * Three rules shape the screen. A change is never ordered from what the
 * panel believes about the host - it is planned on the host and applied
 * with the digest of that plan. A removal is read before it runs, because
 * one package can drag dozens of dependants with it. And a count nobody
 * took is an em dash: a host that has not counted its updates and a host
 * with nothing waiting are different answers.
 */

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

type RemovalPlan = { mode?: string; removals?: string[]; protected?: string[] };

type PackageListState = {
  digest?: string;
  package_count: number;
  collected_at?: string;
  job_id?: string;
  unavailable_reason?: string;
};

type PackageList = { items: InstalledPackage[]; count: number; state: PackageListState };

type SourceIntent = { label: string; description: string; payload: Record<string, unknown> };

/** The changes this screen offers; when every one is refused, it says so once. */
export const PACKAGE_CHANGES = [
  "packages.install", "packages.remove", "packages.upgrade", "packages.hold.set", "packages.repair",
  "packages.repository.set", "agent.upgrade",
];

/** The package operations that change the host; a plan or a listing applies nothing. */
const APPLYING = ["packages.install", "packages.remove", "packages.upgrade", "packages.hold.set"];

/** How many transactions one page of the history carries. */
const HISTORY_PAGE = 20;

/** How long a reason has to be before the trail will take it. */
export const REASON_MIN_LENGTH = 8;

/** The origin class of a package in the operator's words. */
export function originWords(t: (key: string) => string, originClass?: string): string {
  switch (originClass) {
    case "vendor_distribution": return t("distribution");
    case "third_party_repository": return t("third-party repository");
    case "local_package": return t("local package");
    case "origin_unknown": return t("origin unknown");
    default: return "—";
  }
}

/** The outcome of a job as a state. */
export function jobTone(state: string): Tone {
  if (["succeeded", "completed", "no_change", "active"].includes(state)) return "ok";
  if (["failed", "timed_out", "expired", "partially_applied", "plan_failed"].includes(state)) return "error";
  if (["ineligible", "skipped", "superseded_by_result", "unknown"].includes(state)) return "unknown";
  return "warn";
}

/** A count of what satisfies a test, or nothing at all when the list is unread. */
function countWhere<T>(items: T[] | undefined, test: (item: T) => boolean): number | undefined {
  return items === undefined ? undefined : items.filter(test).length;
}

/** A control that exists only where the order it places would be taken. */
function Guard({ action, host, explain, children }: {
  action: string;
  host: string;
  explain?: boolean;
  children: ReactNode;
}) {
  const t = useT();
  const verdict = useAllowed(host, action);
  if (verdict.allowed) return <>{children}</>;
  if (!explain || verdict.pending) return null;
  return <Note>{verdict.reason || t("This action is not available.")}</Note>;
}

/** The one line a module shows when every change it offers is refused. */
function ReadOnlyNotice({ host, actions }: { host: string; actions: string[] }) {
  const t = useT();
  const access = useModuleAccess(host, actions);
  if (!access.known || access.anyAllowed) return null;
  const text = access.permissions.length > 0 && access.reasons.length === 0
    ? t("You can read this module; changing it needs the permission {permissions}.", {
        permissions: access.permissions.join(", "),
      })
    : t("You can read this module; changing it is not possible here: {reasons}", {
        reasons: [
          ...access.reasons,
          ...access.permissions.map((permission) => t("missing permission {permission}", { permission })),
        ].join("; "),
      });
  return <Banner tone="info">{text}</Banner>;
}

export function Packages({ host }: { host: Host }) {
  const t = useT();
  const [tab, go] = useTab(PACKAGE_TABS);
  const queryClient = useQueryClient();

  const module = useQuery({
    queryKey: ["inventory", host.id, "packages"],
    queryFn: () => api.get<InventoryFragment<PackagesState>>(`/api/v1/hosts/${host.id}/inventory/packages`),
    retry: false,
  });
  const packages = module.data?.payload;

  const [names, setNames] = useState("");
  // The removal plan and the set it was computed for: a removal ordered
  // from the table names one package, a removal from the form names what
  // was typed, and the confirmation removes the set that was reviewed.
  const [plan, setPlan] = useState<{ requested: string[]; plan: RemovalPlan } | null>(null);
  const [toRemove, setToRemove] = useState<{ requested: string[]; removals: string[] } | null>(null);
  const [sourceIntent, setSourceIntent] = useState<SourceIntent | null>(null);
  const [agentVersion, setAgentVersion] = useState("");
  // The digest the panel pins the bytes to, and the version to fall back
  // to. Both are in the operation's contract and in no form the operator
  // ever saw.
  const [agentDigest, setAgentDigest] = useState("");
  const [agentRollback, setAgentRollback] = useState("");
  const [repairing, setRepairing] = useState(false);
  const [notice, setNotice] = useState("");
  const [problem, setProblem] = useState("");
  const [sourceForm, setSourceForm] = useState(false);
  const agentRequest = agentUpgradeOrder(agentVersion, agentDigest, agentRollback);

  const say = (text: string) => { setNotice(text); setProblem(""); };
  const fail = (text: string) => { setProblem(text); setNotice(""); };

  // The release channel is a policy recorded in the panel, not an
  // operation: nothing runs on the host, so it goes to the host record.
  const setChannel = useMutation({
    mutationFn: (channel: ReleaseChannel) => api.put<Host>(`/api/v1/hosts/${host.id}/channel`, { channel }),
    onSuccess: (updated) => {
      say(t("The host now follows the {channel} channel.", { channel: updated.release_channel }));
      void queryClient.invalidateQueries({ queryKey: ["host", host.id] });
      void queryClient.invalidateQueries({ queryKey: ["hosts"] });
    },
    onError: (error) => fail(error instanceof Error ? error.message : String(error)),
  });

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (job) => {
      say(job.requires_approval
        ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
        : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }));
      setToRemove(null);
      setRepairing(false);
      setSourceIntent(null);
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => fail(error instanceof Error ? error.message : String(error)),
  });

  const list = () => names.split(/[\s,]+/).map((name) => name.trim()).filter(Boolean);

  // The removal plan is computed on the host, so the screen waits for it.
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
    onSuccess: (result) => { setPlan(result); say(""); },
    onError: (error) => {
      setPlan(null);
      fail(error instanceof Error ? error.message : String(error));
    },
  });

  // The package list is read by the panel on its own cycle; the operator
  // asks for it here when the copy is missing or older than the host.
  const readList = useMutation({
    mutationFn: () => api.post<Job>(`/api/v1/hosts/${host.id}/operations`, { action: "packages.list", payload: {} }),
    onSuccess: (job) => {
      say(t("Job {id} reads the package list.", { id: job.id.slice(0, 8) }));
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      void awaitJob(api, job.id).then(
        () => queryClient.invalidateQueries({ queryKey: ["host-packages", host.id] }),
        () => undefined,
      );
    },
    onError: (error) => fail(error instanceof Error ? error.message : String(error)),
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
  // the words say so, because the operator will not find a partial upgrade
  // here and should not look for a security count Arch cannot give.
  const pacman = packages?.manager === "pacman";

  const updates: Segment[] = [
    { label: t("up to date"), value: upToDate, tone: "ok" },
    { label: t("upgradable"), value: pending, tone: "warn" },
    { label: t("security"), value: security, tone: "error" },
    { label: t("held"), value: heldCount(packages), tone: "neutral" },
  ];

  const freshness = module.data
    ? t("Source: {source}, revision {revision}, observed {when}", {
        source: module.data.source,
        revision: module.data.revision.slice(0, 12),
        when: relativeTime(module.data.observed_at),
      })
    : undefined;

  return (
    <>
      <ReadOnlyNotice host={host.id} actions={PACKAGE_CHANGES} />
      {module.data?.unavailable_reason && (
        <Banner tone="warn">
          {t("The packages could not be read: {reason}", { reason: module.data.unavailable_reason })}
        </Banner>
      )}
      {notice && <Banner tone="info">{notice}</Banner>}
      {problem && <Problem>{problem}</Problem>}

      {repairing && (
        <Confirm
          host={host}
          label={t("Repair the package database")}
          description={t("The host finishes the interrupted package transaction on {host} and configures what was left half-way. Package operations are refused until this succeeds.", { host: host.hostname })}
          busy={request.isPending}
          onCancel={() => setRepairing(false)}
          onConfirm={(reason) => request.mutate({ action: "packages.repair", reason, payload: { package_repair: {} } })}
        />
      )}
      {toRemove && (
        <Confirm
          host={host}
          label={t("Remove packages")}
          description={t("{n} package(s) will be removed: {packages}.", {
            n: toRemove.removals.length,
            packages: `${toRemove.removals.slice(0, 6).join(", ")}${toRemove.removals.length > 6 ? "…" : ""}`,
          })}
          busy={request.isPending}
          onCancel={() => setToRemove(null)}
          onConfirm={(reason, confirmation) => request.mutate({
            action: "packages.remove",
            reason,
            target_confirmation: confirmation,
            payload: { package_change: { packages: toRemove.requested, expected_removals: toRemove.removals } },
          })}
        />
      )}
      {sourceIntent && (
        <Confirm
          host={host}
          label={sourceIntent.label}
          description={sourceIntent.description}
          busy={request.isPending}
          onCancel={() => setSourceIntent(null)}
          onConfirm={(reason) => request.mutate({
            action: "packages.repository.set",
            reason,
            payload: { repository: sourceIntent.payload },
          })}
        />
      )}

      <Tabs
        value={tab}
        onChange={go}
        tabs={[
          { value: "state", label: t("State") },
          { value: "change", label: t("Change") },
          { value: "history", label: t("History") },
        ]}
      />

      {tab === "state" && (
        <Grid>
          <C span={12}>
            <Card
              title={t("Updates")}
              note={t("The installed packages by what waits for them.")}
              foot={freshness}
            >
              <Band segments={updates} testId="updates" />
              {pending === undefined && (
                <Note>
                  {packages?.unavailable_reason
                    ? t("The update counts could not be read: {reason}", { reason: packages.unavailable_reason })
                    : t("The host has not counted its updates yet; plan updates on the Change tab to count them.")}
                </Note>
              )}
            </Card>
          </C>
          <C span={12}>
            <Card title={t("Sources")} note={t("What manages the software here, and where it comes from.")}>
              <Facts>
                <Fact label={t("Installed")}>
                  {packages?.installed ?? <Pill tone="unknown">{t("unknown")}</Pill>}
                </Fact>
                <Fact label={t("Manager")}>{packages?.manager || "—"}</Fact>
                <Fact label={t("Package database")}>
                  {host.package_database_broken
                    ? (
                      <>
                        <Pill tone="error">{t("needs repair")}</Pill>
                        {/* Every other package operation is refused while the
                            database is broken, so the repair stands where the
                            verdict is. */}
                        <Guard action="packages.repair" host={host.id}>
                          <Button kind="word" onClick={() => setRepairing(true)} disabled={repairing} testId="repair">
                            {t("Repair the package database…")}
                          </Button>
                        </Guard>
                      </>
                    )
                    : <Pill tone="ok">{t("healthy")}</Pill>}
                </Fact>
                <Fact label={t("Repositories")}>
                  {knownSources ? knownSources.length : <Pill tone="unknown">{t("unknown")}</Pill>}
                </Fact>
              </Facts>
              {knownSources
                ? (
                  <Bars items={[
                    { label: t("enabled"), value: countWhere(knownSources, (one) => one.enabled) ?? 0, tone: "ok" },
                    { label: t("signatures checked"), value: countWhere(knownSources, (one) => one.signed) ?? 0, tone: "ok" },
                    { label: t("not checked"), value: countWhere(knownSources, (one) => !one.signed) ?? 0, tone: "error" },
                    { label: t("managed by the panel"), value: countWhere(knownSources, (one) => one.managed) ?? 0, tone: "info" },
                  ]} />
                )
                : <Note>{t("The sources have not been read, so nothing is counted here.")}</Note>}
            </Card>
          </C>
          <C span={12}>
            <InstalledPackages
              host={host}
              packages={packages}
              busy={request.isPending || planRemoval.isPending}
              reading={readList.isPending}
              onRead={() => readList.mutate()}
              onHold={(name, hold) => request.mutate({
                action: "packages.hold.set",
                payload: { package_change: { packages: [name], hold } },
              })}
              onRemove={(name) => { setPlan(null); planRemoval.mutate([name]); }}
              onSay={say}
              onFail={fail}
            />
          </C>
        </Grid>
      )}

      {tab === "change" && (
        <Grid>
          <C span={12}>
            <Guard action="packages.plan" host={host.id}>
              <PlanUpdates
                host={host}
                pacman={pacman}
                busy={request.isPending}
                onSay={say}
                onFail={fail}
              />
            </Guard>
          </C>
          <C span={12}>
            <Form
              title={t("Install, remove or hold")}
              note={t("One list of names, and three different decisions about it.")}
              actions={(
                <>
                  <Guard action="packages.hold.set" host={host.id}>
                    <Button
                      kind="quiet"
                      disabled={request.isPending || list().length === 0}
                      onClick={() => request.mutate({
                        action: "packages.hold.set",
                        payload: { package_change: { packages: list(), hold: true } },
                      })}
                      testId="hold"
                    >
                      {t("Hold")}
                    </Button>
                    <Button
                      kind="quiet"
                      disabled={request.isPending || list().length === 0}
                      onClick={() => request.mutate({
                        action: "packages.hold.set",
                        payload: { package_change: { packages: list(), hold: false } },
                      })}
                      testId="unhold"
                    >
                      {t("Unhold")}
                    </Button>
                  </Guard>
                  {/* A removal does not go straight through: one package can
                      drag dozens of dependants along, and the operator is to
                      see them first. The plan is a read, but it prepares a
                      removal, so it stands behind the right to remove. */}
                  <Guard action="packages.remove" host={host.id}>
                    <Button
                      kind="danger"
                      disabled={planRemoval.isPending || list().length === 0}
                      onClick={() => planRemoval.mutate(list())}
                      testId="plan-removal"
                    >
                      {planRemoval.isPending ? t("Planning…") : t("Plan removal")}
                    </Button>
                  </Guard>
                </>
              )}
            >
              <Fields>
                <Field label={t("Package names (space or comma separated)")} wide>
                  <input
                    value={names}
                    onChange={(event) => { setNames(event.target.value); setPlan(null); }}
                    placeholder="nginx htop"
                    data-testid="package-names"
                  />
                </Field>
              </Fields>
              {/* An installation is planned on the host first: the operator
                  reads what would really be pulled in, and the change carries
                  the digest of that plan. There is no install button before
                  the plan - a change with nothing to bind it to is the false
                  success this screen no longer offers. */}
              <Guard action="packages.install" host={host.id}>
                <PlanThenApply
                  host={host}
                  action="packages.install"
                  packages={list()}
                  planLabel={t("Plan install")}
                  applyLabel={t("Install the planned packages")}
                  busy={request.isPending || planRemoval.isPending}
                  onSay={say}
                  onFail={fail}
                />
              </Guard>
            </Form>
          </C>
          {plan !== null && (
            <C span={12}>
              <Card
                title={t("Removal plan")}
                note={t("What the host would really take away, computed on the host.")}
                foot={plan.plan.removals?.length
                  ? t("{n} package(s) would be removed. The host recomputes this set before removing; a difference cancels the operation.", { n: plan.plan.removals.length })
                  : undefined}
                flush
              >
                {plan.plan.protected && plan.plan.protected.length > 0 && (
                  <Banner tone="error">
                    {t("These packages are protected and will not be removed: {packages}. Removing them would leave the host unmanageable or unbootable.", {
                      packages: plan.plan.protected.join(", "),
                    })}
                  </Banner>
                )}
                {!plan.plan.removals?.length
                  ? <Empty>{t("Nothing would be removed.")}</Empty>
                  : (
                    <>
                      <Table
                        rows={plan.plan.removals}
                        keyOf={(one) => one}
                        testId="removals"
                        columns={[
                          { key: "package", head: t("Package"), tight: true, cell: (one) => one },
                          {
                            key: "why", head: t("Reason"),
                            cell: (one) => (plan.requested.includes(one) ? t("requested") : t("dependency")),
                          },
                        ]}
                      />
                      {(!plan.plan.protected || plan.plan.protected.length === 0) && (
                        <Actions>
                          <Guard action="packages.remove" host={host.id}>
                            <Button
                              kind="danger"
                              onClick={() => setToRemove({ requested: plan.requested, removals: plan.plan.removals ?? [] })}
                              testId="remove-these"
                            >
                              {t("Remove these packages")}
                            </Button>
                          </Guard>
                        </Actions>
                      )}
                    </>
                  )}
              </Card>
            </C>
          )}
          <C span={12}>
            <Form
              title={t("Agent")}
              note={t("The agent is left alone by ordinary package upgrades: replacing it in the middle of a transaction it is running would cut the host off from management with nobody to report the result. Replacing it is its own operation, and it counts as done only when the host comes back reporting the version that was asked for.")}
              actions={(
                <>
                  <Guard action="agent.upgrade" host={host.id}>
                    <Button
                      // The version the host already runs is this screen's own
                      // refusal: the registry sees the form, not the host.
                      disabled={!orderReady(agentRequest) || agentVersion === host.agent_version}
                      title={refusalOf(t, agentRequest)}
                      onClick={() => request.mutate({ action: agentRequest.action, payload: agentRequest.payload })}
                      testId="replace-agent"
                    >
                      {t("Replace agent")}
                    </Button>
                  </Guard>
                  {!orderReady(agentRequest) && agentVersion !== "" && <Note>{refusalOf(t, agentRequest)}</Note>}
                </>
              )}
            >
              <Facts>
                <Fact label={t("Agent version")}>
                  {host.agent_version || <Pill tone="unknown">{t("unknown")}</Pill>}
                </Fact>
                <Fact label={t("Release channel")}>
                  <Pill tone={host.release_channel === "beta" ? "warn" : "ok"}>{host.release_channel}</Pill>
                </Fact>
              </Facts>
              <Fields>
                {/* The channel decides which releases reach the host first: a
                    fleet upgrade in waves names the beta hosts before the
                    stable ones. It is assigned here, never implied. */}
                <Field label={t("Release channel")}>
                  <select
                    value={host.release_channel}
                    disabled={setChannel.isPending}
                    onChange={(event) => setChannel.mutate(event.target.value as ReleaseChannel)}
                    data-testid="release-channel"
                  >
                    {RELEASE_CHANNELS.map((name) => (
                      <option key={name} value={name}>
                        {name === "beta" ? t("beta (sees a release first)") : t("stable")}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field label={t("Target agent version (currently {version})", { version: host.agent_version || t("unknown") })}>
                  <input
                    value={agentVersion}
                    onChange={(event) => setAgentVersion(event.target.value)}
                    placeholder={t("e.g. {version}", { version: host.agent_version || "0.51.0" })}
                    data-testid="agent-version"
                  />
                </Field>
                <Field
                  label={t("Package checksum")}
                  wide
                  hint={t("The SHA-256 from the release. Without it the host installs whatever its repository serves under that version: the repository's own signature is then the only proof, and the panel has none of its own.")}
                >
                  <input
                    value={agentDigest}
                    onChange={(event) => setAgentDigest(event.target.value.trim())}
                    placeholder={t("64 hexadecimal characters, or empty")}
                    data-testid="agent-digest"
                  />
                </Field>
                <Field
                  label={t("Fall back to")}
                  hint={t("The version to return to when the host does not come back with the new one. Empty means no prepared return.")}
                >
                  <input
                    value={agentRollback}
                    onChange={(event) => setAgentRollback(event.target.value.trim())}
                    placeholder={t("e.g. {version}", { version: host.agent_version || "0.51.0" })}
                    data-testid="agent-rollback"
                  />
                </Field>
              </Fields>
            </Form>
          </C>
          <C span={12}>
            <Repositories
              hostID={host.id}
              view={packages?.repositories}
              open={sourceForm}
              onOpen={setSourceForm}
              onIntent={setSourceIntent}
            />
          </C>
          {sourceForm && (
            <C span={12}>
              <Guard action="packages.repository.set" host={host.id}>
                <SourceForm manager={packages?.manager} onIntent={setSourceIntent} />
              </Guard>
            </C>
          )}
        </Grid>
      )}

      {tab === "history" && (
        <Grid>
          <C span={12}>
            <TransactionHistory hostId={host.id} />
          </C>
        </Grid>
      )}
    </>
  );
}

/**
 * Counting what waits for the host without changing anything on it.
 *
 * The target is named right at the button: the operator approves a
 * specific machine, not "the host I think I have open".
 */
function PlanUpdates({ host, pacman, busy, onSay, onFail }: {
  host: Host;
  pacman: boolean;
  busy: boolean;
  onSay: (text: string) => void;
  onFail: (text: string) => void;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const [reason, setReason] = useState("");

  const ask = useMutation({
    mutationFn: () => api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
      action: "packages.plan",
      payload: { package_plan: { refresh_metadata: true } },
      ...(reason.trim() ? { reason: reason.trim() } : {}),
    }),
    onSuccess: (job) => {
      onSay(job.requires_approval
        ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
        : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }));
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => onFail(error instanceof Error ? error.message : String(error)),
  });

  return (
    <Form
      title={t("Plan updates")}
      note={pacman
        ? t("Count available updates without changing host state. On Arch the plan comes from checkupdates, the whole system upgrades at once and the security count is unknown.")
        : t("Count available updates without changing host state.")}
      actions={(
        <>
          <Button onClick={() => ask.mutate()} disabled={ask.isPending || busy} testId="plan-updates">
            {ask.isPending ? t("Requesting…") : t("Plan updates")}
          </Button>
          <Tag to={`/hosts/${host.id}/jobs`}>{t("See all jobs")}</Tag>
        </>
      )}
    >
      <Note>
        {t("Target: {host}", { host: host.hostname })}
        {host.management_address ? ` · ${host.management_address}` : ` · ${t("address unknown")}`}
        {` · ${host.site} / ${host.environment}`}
      </Note>
      <Fields>
        <Field label={t("Reason")} hint={t("Optional; kept in the audit trail.")} wide>
          <input
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder={t("change ticket, handover")}
            data-testid="plan-reason"
          />
        </Field>
      </Fields>
    </Form>
  );
}

/**
 * Plan, then apply - the two halves of every package change on this
 * screen. A change is never ordered from what the panel believes about
 * the host.
 */
function PlanThenApply({ host, action, packages, planLabel, applyLabel, busy, onSay, onFail }: {
  host: Host;
  action: string;
  packages: string[];
  planLabel: string;
  applyLabel: string;
  /** Whether another order of this screen is on its way. */
  busy?: boolean;
  onSay: (text: string) => void;
  onFail: (text: string) => void;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const [planned, setPlanned] = useState<{ for: string; plan: ApprovedPlan } | null>(null);
  const key = packages.join(" ");
  const plan = planned && planned.for === key ? planned.plan : null;

  const planning = useMutation({
    mutationFn: async () => {
      const job = await api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "packages.plan",
        payload: { package_plan: { mode: planMode(action), only_packages: packages, refresh_metadata: true } },
      });
      const last = await awaitJob<Record<string, unknown>>(api, job.id);
      if (!last) throw new Error(t("The plan did not arrive in time."));
      if (last.status !== "succeeded") {
        throw new Error(last.message || t("The host refused to plan the change."));
      }
      const bound = planBinding(last.detail);
      if (!bound) throw new Error(t("The host computed no plan for this change; nothing will be applied."));
      return { for: key, plan: bound };
    },
    onSuccess: (result) => { setPlanned(result); onSay(""); },
    onError: (error) => {
      setPlanned(null);
      onFail(error instanceof Error ? error.message : String(error));
    },
  });

  const apply = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (job) => {
      onSay(job.requires_approval
        ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
        : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }));
      setPlanned(null);
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => onFail(error instanceof Error ? error.message : String(error)),
  });

  const payload = changePayload(action, packages, plan);
  return (
    <>
      <Actions>
        <Button
          kind="quiet"
          disabled={packages.length === 0 || planning.isPending || apply.isPending || busy}
          onClick={() => planning.mutate()}
          testId={`plan-${action}`}
        >
          {planning.isPending ? t("Planning…") : planLabel}
        </Button>
        {payload && (
          <Button
            disabled={apply.isPending || busy}
            onClick={() => apply.mutate(operationBody(action, payload))}
            testId={`apply-${action}`}
          >
            {apply.isPending ? t("Requesting…") : applyLabel}
          </Button>
        )}
      </Actions>
      {plan && (
        <>
          {plan.changes && plan.changes.length > 0
            ? (
              <Table
                rows={plan.changes}
                keyOf={(change) => `${change.name}/${change.architecture ?? ""}`}
                testId={`plan-changes-${action}`}
                columns={[
                  { key: "package", head: t("Package"), tight: true, cell: (change) => change.name },
                  { key: "from", head: t("From"), cell: (change) => change.current_version || "—" },
                  { key: "to", head: t("To"), tight: true, cell: (change) => change.candidate_version || "—" },
                ]}
              />
            )
            : <Empty>{t("The host would change nothing; there is nothing to apply.")}</Empty>}
          <Note>
            {t("The plan {hash} binds this operation; the host computes it again before the transaction and refuses it if anything moved since.", {
              hash: plan.plan_hash.slice(0, 12),
            })}
            {plan.expires_at ? ` · ${t("valid until {when}", { when: absoluteTime(plan.expires_at) })}` : ""}
          </Note>
        </>
      )}
    </>
  );
}

/**
 * The installed packages, from the panel's copy of the host's list,
 * joined with the holds the host reports and the changes of the last
 * upgrade plan.
 */
function InstalledPackages({ host, packages, busy, reading, onRead, onHold, onRemove, onSay, onFail }: {
  host: Host;
  packages: PackagesState | undefined;
  /** Whether an order is on its way; the row actions wait for it. */
  busy: boolean;
  reading: boolean;
  onRead: () => void;
  onHold: (name: string, hold: boolean) => void;
  onRemove: (name: string) => void;
  onSay: (text: string) => void;
  onFail: (text: string) => void;
}) {
  const t = useT();
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<PackageFilter>("all");
  const [direction, setDirection] = useState<"asc" | "desc">("asc");
  const [selected, setSelected] = useState("");
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(50);

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
  const key = (row: PackageRow) => `${row.name}/${row.architecture ?? ""}`;
  const current = rows.find((row) => key(row) === selected);
  const state = list.data?.state;
  // The copy is stale when the host's own list has another digest: the
  // rows then describe an earlier moment, and the caption says so.
  const stale = !!state?.digest && !!packages?.installed_digest && state.digest !== packages.installed_digest;
  const pacman = packages?.manager === "pacman";
  // A column with nothing in any row says nothing: the architecture is
  // left out where the manager reports none, and the two plan columns
  // until a plan exists - the caption then says one is missing.
  const showArchitecture = rows.some((row) => !!row.architecture);
  const showPlan = plan.changes !== undefined;
  const paged = shown.slice((page - 1) * size, page * size);

  const foot = list.data
    ? [
        t("{shown} of {total} packages", { shown: shown.length, total: list.data.items.length }),
        state?.collected_at ? t("list read {when}", { when: relativeTime(state.collected_at) }) : undefined,
        plan.at
          ? [
              t("upgrade plan from {when}", { when: relativeTime(plan.at) }),
              plan.header?.planner_version ? t("planner {version}", { version: plan.header.planner_version }) : undefined,
              plan.header?.expires_at
                ? (planExpired(plan.header)
                    ? t("plan expired")
                    : t("valid until {when}", { when: absoluteTime(plan.header.expires_at) }))
                : undefined,
            ].filter(Boolean).join(" · ")
          : t("no upgrade plan yet; the upgrade column fills in after one"),
      ].filter(Boolean).join(" · ")
    : undefined;

  return (
    <Card
      title={t("Installed packages")}
      note={t("The panel's copy of the host's package list, joined with the holds the host reports and the changes of the last upgrade plan. Select a package to act on it.")}
      tools={
        <Guard action="packages.list" host={host.id} explain>
          <Button
            kind="quiet"
            onClick={onRead}
            disabled={reading || host.connection_state !== "online"}
            testId="read-package-list"
          >
            {reading ? t("Requesting…") : t("Read the package list")}
          </Button>
        </Guard>
      }
      foot={foot}
      flush
    >
      {list.data && list.data.items.length > 0 && (
        <Toolbar
          end={<Pager page={page} size={size} total={shown.length} onPage={setPage} onSize={setSize} sizes={PAGE_SIZES} />}
        >
          <Find
            value={query}
            onChange={(value) => { setQuery(value); setPage(1); }}
            placeholder={t("Search packages")}
            testId="package-search"
          />
          <Seg<PackageFilter>
            value={filter}
            onChange={(value) => { setFilter(value); setPage(1); }}
            label={t("Which packages to show")}
            options={[
              { value: "all", label: t("all packages") },
              { value: "upgradable", label: t("upgradable only") },
              { value: "security", label: t("security updates only") },
              { value: "held", label: t("held only") },
            ]}
          />
          <Seg<"asc" | "desc">
            value={direction}
            onChange={setDirection}
            label={t("Which way round")}
            options={[
              { value: "asc", label: t("name A–Z") },
              { value: "desc", label: t("name Z–A") },
            ]}
          />
        </Toolbar>
      )}

      {list.error
        ? <Problem>{list.error instanceof Error ? list.error.message : String(list.error)}</Problem>
        : !list.data
          ? <Table rows={[] as PackageRow[]} keyOf={key} loading columns={[]} />
          : list.data.items.length === 0
            ? (
              /* No rows is not a host without packages: the panel has not
                 read the list, or could not, and says which. */
              <Empty
                icon="packages"
                action={
                  <Guard action="packages.list" host={host.id} explain>
                    <Button kind="quiet" onClick={onRead} disabled={reading || host.connection_state !== "online"}>
                      {reading ? t("Requesting…") : t("Read the package list")}
                    </Button>
                  </Guard>
                }
              >
                {state?.unavailable_reason === "package_list_missing" || !state?.unavailable_reason
                  ? t("The panel has not read the package list of this host yet. The read goes through a job and needs no root on the host.")
                  : t("The package list could not be read: {reason}", { reason: state.unavailable_reason })}
              </Empty>
            )
            : (
              <>
                {stale && (
                  <Banner
                    tone="warn"
                    actions={
                      <Guard action="packages.list" host={host.id}>
                        <Button kind="quiet" onClick={onRead} disabled={reading || host.connection_state !== "online"}>
                          {reading ? t("Requesting…") : t("Read it again")}
                        </Button>
                      </Guard>
                    }
                  >
                    {t("The host's own list has changed since the panel read it; the rows describe an earlier moment.")}
                  </Banner>
                )}
                {packages && packages.holds_known === false && (
                  <Banner tone="warn">
                    {packages.holds_unavailable_reason
                      ? t("The holds could not be read, so no package is known to be held: {reason}", {
                          reason: packages.holds_unavailable_reason,
                        })
                      : t("The holds could not be read, so no package is known to be held.")}
                  </Banner>
                )}
                <Table
                  rows={paged}
                  keyOf={key}
                  rowTestId={(row) => `package-${row.name}`}
                  /* The chosen row is marked: the card of what can be done
                     to it sits beside the table, and without the mark it
                     belongs to no row the reader can see. */
                  marked={(row) => key(row) === selected}
                  testId="packages"
                  empty={t("No package matches.")}
                  /* The columns an operator folds away are this browser's;
                     the name of the package is the row and always stays. */
                  remember="fl.columns.host-packages"
                  columns={[
                    {
                      key: "name", head: t("Package"), tight: true, cell: (row) => (
                        <Button
                          kind="word"
                          onClick={() => setSelected(selected === key(row) ? "" : key(row))}
                          title={row.source_name && row.source_name !== row.name
                            ? t("source package {name}", { name: row.source_name })
                            : undefined}
                        >
                          {row.name}
                        </Button>
                      ),
                    },
                    {
                      key: "version", head: t("Version"), tight: true, optional: true,
                      cell: (row) => packageVersion(row),
                    },
                    ...(showArchitecture
                      ? [{
                        key: "architecture", head: t("Architecture"), minor: true, optional: true,
                        cell: (row: PackageRow) => row.architecture || "—",
                      }]
                      : []),
                    {
                      key: "source", head: t("Source"), minor: true, optional: true, cell: (row) => (
                        <span title={row.origin || undefined}>
                          {row.repository_id || row.origin || originWords(t, row.origin_class)}
                        </span>
                      ),
                    },
                    /* The candidate with its origin on hover, and the
                       direction where it is not an upgrade: a plan that
                       takes a package back a version is what the operator
                       must not miss in a column of upgrades. */
                    ...(showPlan
                      ? [
                        {
                          key: "candidate", head: t("Upgrade to"), tight: true, optional: true,
                          cell: (row: PackageRow) => (
                            <span title={row.candidateOrigin || undefined}>
                              {row.candidate ?? "—"}
                              {row.action && row.action !== "upgrade" && <Pill tone="warn">{t(row.action)}</Pill>}
                            </span>
                          ),
                        },
                        {
                          key: "security", head: t("Security"), optional: true, cell: (row: PackageRow) => (
                            row.security ? <Pill tone="error">{t("security")}</Pill> : "—"
                          ),
                        },
                      ]
                      : []),
                    {
                      key: "held", head: t("Held"), optional: true, cell: (row) => (
                        row.held === true
                          ? <Pill tone="warn">{t("held")}</Pill>
                          : row.held === undefined
                            ? <Pill tone="unknown" title={t("The holds were not read.")}>?</Pill>
                            : "—"
                      ),
                    },
                  ]}
                />

                {/* What can be done to the one that was chosen, with the
                    target named once more: a hold goes straight to a job,
                    a removal to a plan first, and an upgrade is planned on
                    the host before it is applied. */}
                {current && (
                  <>
                    <Note>
                      {t("{name} {version}", { name: current.name, version: packageVersion(current) })}
                      {current.candidate ? ` → ${current.candidate}` : ""}
                      {current.held === true ? ` · ${t("held")}` : ""}
                    </Note>
                    <Actions>
                      <Guard action="packages.hold.set" host={host.id}>
                        <Button
                          kind="quiet"
                          disabled={busy}
                          onClick={() => onHold(current.name, current.held !== true)}
                          testId="hold-selected"
                        >
                          {current.held === true ? t("Unhold") : t("Hold")}
                        </Button>
                      </Guard>
                      <Guard action="packages.remove" host={host.id}>
                        <Button kind="danger" disabled={busy} onClick={() => onRemove(current.name)} testId="remove-selected">
                          {t("Plan removal")}
                        </Button>
                      </Guard>
                      <Button kind="quiet" onClick={() => setSelected("")}>{t("Deselect")}</Button>
                    </Actions>
                    {pacman ? (
                      <Note>
                        {t("pacman upgrades the whole system at once: a single package cannot be moved on its own without leaving the host partially upgraded. Plan updates above and upgrade the host as a whole.")}
                      </Note>
                    ) : (
                      <Guard action="packages.upgrade" host={host.id}>
                        <Note>
                          {current.candidate
                            ? t("Upgrades {name} alone, from {from} to {to}, through a package transaction; the rest of the host stays as it is. The host plans the move first and the change carries that plan.", {
                                name: current.name, from: packageVersion(current), to: current.candidate,
                              })
                            : t("Upgrades {name} alone through a package transaction; the host plans the move first, and a plan that names no newer version leaves nothing to apply.", {
                                name: current.name,
                              })}
                        </Note>
                        <PlanThenApply
                          host={host}
                          action="packages.upgrade"
                          packages={[current.name]}
                          planLabel={t("Plan the upgrade")}
                          applyLabel={t("Upgrade {name}", { name: current.name })}
                          busy={busy}
                          onSay={onSay}
                          onFail={onFail}
                        />
                      </Guard>
                    )}
                  </>
                )}
              </>
            )}
    </Card>
  );
}

/**
 * The changes of the last upgrade plan of the host, with when it was
 * made. The plan is the newest succeeded packages.plan job.
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
    changes: detail.changes,
    at: upgrade.finished_at ?? upgrade.created_at,
    header: { planner_version: detail.planner_version, expires_at: detail.expires_at, plan_hash: detail.plan_hash },
  };
}

/**
 * The transaction history of the host: every package operation ordered
 * through the panel, newest first, with what it applied.
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
    <Card
      title={t("Transaction history")}
      note={t("The package operations ordered through the panel, newest first; a transaction run by hand on the host is not here.")}
      foot={history.hasNextPage
        ? (
          <Button
            kind="quiet"
            onClick={() => history.fetchNextPage()}
            disabled={history.isFetchingNextPage}
            testId="history-more"
          >
            {t("Load more")}
          </Button>
        )
        : undefined}
      flush
    >
      {history.error
        ? <Problem>{t("The history could not be read.")}</Problem>
        : (
          <Table
            rows={jobs}
            keyOf={(job) => job.id}
            loading={history.isLoading}
            empty={t("No package operation has been ordered on this host.")}
            testId="transactions"
            columns={[
              {
                key: "when", head: t("When"),
                cell: (job) => (
                  <span title={absoluteTime(job.finished_at ?? job.created_at)}>
                    {relativeTime(job.finished_at ?? job.created_at)}
                  </span>
                ),
              },
              {
                key: "what", head: t("Operation"), tight: true,
                cell: (job) => job.action_type.replace(/^packages\./, ""),
              },
              {
                key: "outcome", head: t("Outcome"), cell: (job) => (
                  <>
                    <Pill tone={jobTone(job.state)}>{t(stateName(job.state))}</Pill>
                    {job.result_error_code && <Pill tone="error" title={job.result_error_code}>{job.result_error_code}</Pill>}
                  </>
                ),
              },
              {
                key: "applied", head: t("Applied"), minor: true, cell: (job) => (
                  APPLYING.includes(job.action_type) && job.state === "succeeded"
                    ? <AppliedCount jobId={job.id} />
                    : "—"
                ),
              },
              { key: "by", head: t("By"), minor: true, cell: (job) => job.created_by },
              {
                key: "job", head: t("Job"), tight: true,
                cell: (job) => <Tag to={`/jobs/${job.id}`} title={job.id}>{job.id.slice(0, 8)}</Tag>,
              },
            ]}
          />
        )}
    </Card>
  );
}

/** How many packages a transaction applied, from its last attempt. */
function AppliedCount({ jobId }: { jobId: string }) {
  const t = useT();
  const attempts = useQuery({
    queryKey: ["job-attempts", jobId],
    queryFn: () => api.get<Collection<Attempt>>(`/api/v1/jobs/${jobId}/attempts`),
    staleTime: Infinity,
  });
  if (attempts.error) return <Pill tone="unknown">{t("unknown")}</Pill>;
  if (!attempts.data) return <>…</>;
  const last = attempts.data.items[attempts.data.items.length - 1];
  const applied = (last?.detail as { kind?: string; applied?: unknown[] } | undefined)?.applied;
  if (!Array.isArray(applied)) return <Pill tone="unknown">{t("unknown")}</Pill>;
  return <>{t("{n} package(s)", { n: applied.length })}</>;
}

/**
 * Where this host takes software from.
 *
 * Adding a source installs nothing today; it decides whose packages the
 * host will accept tomorrow, with their scripts running as root. That is
 * why a source without signature checking is drawn as an error and not
 * as a setting.
 */
function Repositories({ hostID, view, open, onOpen, onIntent }: {
  hostID: string;
  view?: RepositoryView;
  open: boolean;
  onOpen: (open: boolean) => void;
  onIntent: (intent: SourceIntent) => void;
}) {
  const t = useT();
  const sources = view?.repositories ?? [];

  return (
    <Card
      title={t("Repositories")}
      note={t("Where this host takes software from. Adding a source installs nothing today; it decides whose packages the host will accept tomorrow, with their scripts running as root.")}
      tools={
        <Guard action="packages.repository.set" host={hostID}>
          <Button kind="quiet" onClick={() => onOpen(!open)} testId="source-form-toggle">
            {open ? t("Cancel") : t("Add or change a source")}
          </Button>
        </Guard>
      }
      flush
    >
      {view && view.repositories_known === false && (
        <Banner tone="warn">
          {view.repositories_unavailable_reason
            ? t("The list of sources could not be read: {reason}", { reason: view.repositories_unavailable_reason })
            : t("The list of sources could not be read.")}
        </Banner>
      )}
      <Table
        rows={sources}
        keyOf={(source) => `${source.path ?? ""}-${source.id}`}
        rowTestId={(source) => `source-${source.id}`}
        testId="sources"
        empty={t("This host reports no package source.")}
        columns={[
          {
            key: "source", head: t("Source"),
            cell: (source) => <span title={source.path}>{source.id}</span>,
          },
          {
            key: "address", head: t("Address"), tight: true, cell: (source) => (
              source.unavailable_reason
                ? <Pill tone="unknown">{source.unavailable_reason}</Pill>
                : (
                  <span title={[source.suites?.join(" "), source.components?.join(" ")].filter(Boolean).join(" ")}>
                    {source.url || "—"}
                  </span>
                )
            ),
          },
          {
            key: "state", head: t("State"), cell: (source) => (
              source.enabled ? <Pill tone="ok">{t("enabled")}</Pill> : <Pill tone="neutral">{t("disabled")}</Pill>
            ),
          },
          {
            key: "signatures", head: t("Signatures"), cell: (source) => (
              /* A source without signature checking is a remote root
                 shell, not a setting - and it is to look like one. */
              source.signed ? <Pill tone="ok">{t("checked")}</Pill> : <Pill tone="error">{t("not checked")}</Pill>
            ),
          },
          {
            key: "managed", head: t("Managed by"), minor: true, cell: (source) => (
              source.managed
                ? (
                  <>
                    <Pill tone="ok">{t("panel")}</Pill>
                    {source.secret_name && t("password from {secret}", { secret: source.secret_name })}
                  </>
                )
                : <Pill tone="neutral">{t("distribution")}</Pill>
            ),
          },
          {
            key: "actions", head: t("Actions"), actions: true, optional: true, cell: (source) => (
              <Guard action="packages.repository.set" host={hostID}>
                <Button
                  kind="quiet"
                  disabled={!source.managed}
                  title={source.managed
                    ? undefined
                    : t("Only a source written by the panel can be changed here; this one belongs to the distribution or the host administrator.")}
                  onClick={() => onIntent({
                    label: source.enabled ? t("Disable source") : t("Enable source"),
                    description: source.enabled
                      ? t("{id} will be disabled. The files stay on the host.", { id: source.id })
                      : t("{id} will be enabled. The files stay on the host.", { id: source.id }),
                    payload: {
                      id: source.id, url: source.url, name: source.name,
                      suites: source.suites, components: source.components,
                      enabled: !source.enabled, allow_unsigned: !source.signed,
                    },
                  })}
                >
                  {source.enabled ? t("Disable") : t("Enable")}
                </Button>
                <Button
                  kind="danger"
                  disabled={!source.managed}
                  title={source.managed
                    ? undefined
                    : t("Only a source written by the panel can be removed here; this one belongs to the distribution or the host administrator.")}
                  onClick={() => onIntent({
                    label: t("Remove source"),
                    description: t("{id} will be removed from this host, together with its key and its password file.", { id: source.id }),
                    payload: { id: source.id, remove: true },
                  })}
                  testId={`remove-source-${source.id}`}
                >
                  {t("Remove")}
                </Button>
              </Guard>
            ),
          },
        ]}
      />
    </Card>
  );
}

/**
 * The source form. The key is pasted in ASCII armour; the password is
 * named by a secret and never typed here.
 */
function SourceForm({ manager, onIntent }: {
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

  const ready = id !== "" && url !== "" && (unsigned || key.includes("BEGIN PGP")) && (!apt || suites.trim() !== "");

  return (
    <Form
      title={t("Package source")}
      note={pacman
        ? t("The key travels in the job — it is public, and the plan should show what the host will trust. pacman writes the source as a section of /etc/pacman.conf and signs the key in its keyring; a pacman source carries no password.")
        : t("The key travels in the job — it is public, and the plan should show what the host will trust. The password does not: name a secret and the host fetches its value once, while it writes the file.")}
      actions={(
        <Button
          disabled={!ready}
          testId="write-source"
          onClick={() => onIntent({
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
          })}
        >
          {t("Write source")}
        </Button>
      )}
    >
      <Fields>
        <Field label={t("Source")}>
          <input value={id} onChange={(event) => setId(event.target.value)} placeholder="internal" data-testid="source-id" />
        </Field>
        <Field label={t("Address")} wide>
          <input
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            placeholder={pacman ? "https://packages.example.com/arch/$arch" : "https://packages.example.com/debian"}
            data-testid="source-url"
          />
        </Field>
        {apt && (
          <>
            <Field label={t("Suites (stable)")}>
              <input value={suites} onChange={(event) => setSuites(event.target.value)} placeholder="stable" data-testid="source-suites" />
            </Field>
            <Field label={t("Components (main)")}>
              <input value={components} onChange={(event) => setComponents(event.target.value)} placeholder="main" />
            </Field>
          </>
        )}
        <Field label={t("Username (private source)")}>
          <input value={username} onChange={(event) => setUsername(event.target.value)} />
        </Field>
        <Field label={t("Password secret (name only)")}>
          <input value={secret} onChange={(event) => setSecret(event.target.value)} />
        </Field>
      </Fields>
      <Check checked={unsigned} onChange={setUnsigned}>
        {t("Do not check signatures (the host will install anything from this address)")}
      </Check>
      {!unsigned && (
        <Fields>
          <Field label={t("Signing key (ASCII-armored public key)")} wide>
            <textarea
              rows={8}
              value={key}
              onChange={(event) => setKey(event.target.value)}
              placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----"
              data-testid="source-key"
            />
          </Field>
        </Fields>
      )}
    </Form>
  );
}

/**
 * What cannot be undone is asked for by name: the reason the trail keeps,
 * and the hostname typed out, so a machine is never approved by habit.
 */
function Confirm({ host, label, description, busy, onConfirm, onCancel }: {
  host: Host;
  label: string;
  description: string;
  busy: boolean;
  onConfirm: (reason: string, confirmation: string) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const ready = reason.trim().length >= REASON_MIN_LENGTH && confirmation === host.hostname;

  return (
    <Modal
      title={label}
      onClose={onCancel}
      actions={
        <>
          <Button kind="quiet" onClick={onCancel} disabled={busy}>{t("Cancel")}</Button>
          <Button
            kind="danger"
            disabled={!ready || busy}
            onClick={() => onConfirm(reason.trim(), confirmation)}
            testId="confirm"
          >
            {busy ? t("Requesting…") : label}
          </Button>
        </>
      }
    >
      <Note>{description}</Note>
      <Note>
        {t("Target: {host}", { host: host.hostname })}
        {host.management_address ? ` · ${host.management_address}` : ` · ${t("address unknown")}`}
        {` · ${host.site} / ${host.environment}`}
      </Note>
      <Fields>
        <Field label={t("Reason (at least 8 characters, kept in the audit trail)")} wide>
          <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="confirm-reason" />
        </Field>
        <Field label={t("Type the hostname to confirm:")} hint={host.hostname} wide>
          <input
            value={confirmation}
            onChange={(event) => setConfirmation(event.target.value)}
            data-testid="confirm-hostname"
          />
        </Field>
      </Fields>
    </Modal>
  );
}
