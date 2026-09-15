import { useState } from "react";
import { Link } from "react-router-dom";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, loadedItems, type Collection, type Page } from "../../lib/api";
import { awaitJob } from "../../lib/jobs";
import { RELEASE_CHANNELS, type Attempt, type Host, type Job, type ReleaseChannel } from "../../lib/types";
import { Empty, ErrorCode, JobState, Time } from "../../components/ui";
import { Breakdown } from "../../components/widgets";
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

type PackagesState = {
  manager?: string;
  installed?: number;
  upgradable?: number;
  security_upgradable?: number;
  unavailable_reason?: string;
  repositories?: RepositoryView;
};

type RemovalPlan = {
  mode?: string;
  removals?: string[];
  protected?: string[];
};

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
  const [plan, setPlan] = useState<RemovalPlan | null>(null);
  const [toRemove, setToRemove] = useState<string[] | null>(null);
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
    mutationFn: async () => {
      const job = await api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: "packages.plan",
        payload: { package_plan: { mode: "remove", only_packages: list() } },
      });
      const last = await awaitJob<RemovalPlan>(api, job.id);
      if (!last) throw new Error(t("The plan did not arrive in time."));
      if (last.status !== "succeeded") {
        throw new Error(last.message || t("The host refused to plan the removal."));
      }
      return last.detail ?? {};
    },
    onSuccess: (result) => { setPlan(result); setMessage(""); },
    onError: (error) => {
      setPlan(null);
      setMessage(error instanceof Error ? error.message : String(error));
    },
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
            count is a dash, because zero would mean "nothing to do". Held
            packages are not in the report yet, so their slot says so. */}
        <Summary
          title={t("Updates")}
          description={t("The installed packages by what waits for them.")}
          span={8}
          segments={[
            { label: t("up to date"), value: upToDate, tone: "ok" },
            { label: t("upgradable"), value: pending, tone: "warn" },
            { label: t("security"), value: security, tone: "error" },
            { label: t("held"), value: undefined, tone: "neutral" },
          ]}
        />
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
              onClick={() => planRemoval.mutate()}
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
                placeholder="0.2.0"
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
        <Section title={t("Removal plan")} count={plan.removals?.length ?? 0} flush>
          {plan.protected && plan.protected.length > 0 && (
            <p className="warning">
              <span>
                {t("These packages are protected and will not be removed: {packages}. Removing them would leave the host unmanageable or unbootable.", { packages: plan.protected.join(", ") })}
              </span>
            </p>
          )}
          {!plan.removals?.length ? (
            <Empty>{t("Nothing would be removed.")}</Empty>
          ) : (
            <>
              <Table>
                <thead><tr><th>{t("Package")}</th><th>{t("Reason")}</th></tr></thead>
                <tbody>
                  {plan.removals.map((pkg) => (
                    <tr key={pkg}>
                      <td className="hm-mono">{pkg}</td>
                      <td>{list().includes(pkg) ? t("requested") : t("dependency")}</td>
                    </tr>
                  ))}
                </tbody>
              </Table>
              <Foot>
                <span>
                  {t("{n} package(s) would be removed. The host recomputes this set before removing; a difference cancels the operation.", { n: plan.removals.length })}
                </span>
                {(!plan.protected || plan.protected.length === 0) && (
                  <button className="danger" onClick={() => setToRemove(plan.removals ?? [])}>
                    {t("Remove these packages")}
                  </button>
                )}
              </Foot>
            </>
          )}
        </Section>
      )}

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
            n: toRemove.length, packages: `${toRemove.slice(0, 6).join(", ")}${toRemove.length > 6 ? "…" : ""}`,
          })}
          busy={request.isPending}
          onConfirm={(reason, confirmation) =>
            request.mutate({
              action: "packages.remove",
              reason,
              target_confirmation: confirmation,
              payload: {
                package_change: { packages: list(), expected_removals: toRemove },
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
                <th></th>
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
                    <Link to={`/hosts/${hostId}/jobs`} className="mono" title={job.id}>{job.id.slice(0, 8)}</Link>
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
