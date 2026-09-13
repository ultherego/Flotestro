import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Empty } from "../../components/ui";
import {
  Check, Field, Fields, Foot, Form, FormActions, Message, ModuleFreshness, ModuleHeader,
  ModulePage, RequestOperation, Section, Stat, Stats, Table, Unknown, useHost, useModule,
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

type Attempt = { status?: string; message?: string; detail?: RemovalPlan };

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
  const [message, setMessage] = useState("");

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
      for (let attempt = 0; attempt < 30; attempt++) {
        await new Promise((done) => setTimeout(done, 1500));
        const attempts = await api.get<{ items: Attempt[] }>(`/api/v1/jobs/${job.id}/attempts`);
        const last = attempts.items[attempts.items.length - 1];
        if (!last?.status) continue;
        if (last.status !== "succeeded") {
          throw new Error(last.message || t("The host refused to plan the removal."));
        }
        return last.detail ?? {};
      }
      throw new Error(t("The plan did not arrive in time."));
    },
    onSuccess: (result) => { setPlan(result); setMessage(""); },
    onError: (error) => {
      setPlan(null);
      setMessage(error instanceof Error ? error.message : String(error));
    },
  });

  const sources = packages?.repositories?.repositories ?? [];
  const pending = host.pending_updates;
  const security = host.pending_security_updates;

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Packages")}
        description={t("Installed software, its sources and the updates waiting for this host. A removal is planned before it runs.")}
      />
      <ModuleFreshness fragment={module.data} />
      <Message text={message} />

      {/* The counts decide whether the rest is worth reading; an unknown
          count is shown as unknown, because zero would mean "nothing to do". */}
      <Stats>
        <Stat label={t("Installed")} value={packages?.installed ?? <Unknown />} hint={packages?.manager ? `${t("Manager")}: ${packages.manager}` : undefined} />
        <Stat
          label={t("Upgradable")}
          value={pending === null || pending === undefined ? <Unknown /> : pending}
          tone={pending ? "warn" : undefined}
        />
        <Stat
          label={t("Security updates")}
          value={security === null || security === undefined ? <Unknown /> : security}
          tone={security ? "error" : undefined}
        />
        <Stat
          label={t("Package database")}
          value={host.package_database_broken ? t("needs repair") : t("healthy")}
          tone={host.package_database_broken ? "error" : "ok"}
        />
        <Stat label={t("Repositories")} value={packages?.repositories?.repositories_known === false ? <Unknown /> : sources.length} />
      </Stats>

      <RequestOperation
        host={host}
        description={t("Count available updates without changing host state.")}
        action="packages.plan"
        payload={{ package_plan: { refresh_metadata: true } }}
        label={t("Plan updates")}
      />

      <Repositories
        view={packages?.repositories}
        manager={packages?.manager}
        onIntent={setSourceIntent}
      />

      <Section title={t("Install, remove or hold")}>
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

      <Section
        title={t("Agent")}
        description={t("The agent is left alone by ordinary package upgrades: replacing it in the middle of a transaction it is running would cut the host off from management with nobody to report the result. Replacing it is its own operation, and it counts as done only when the host comes back reporting the version that was asked for.")}
      >
        <Form>
          <Fields>
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

  const ready = id !== "" && url !== "" && (unsigned || key.includes("BEGIN PGP")) &&
    (!apt || suites.trim() !== "");

  return (
    <Section
      title={t("Package source")}
      description={t("The key travels in the job — it is public, and the plan should show what the host will trust. The password does not: name a secret and the host fetches its value once, while it writes the file.")}
    >
      <Form>
        <Fields>
          <Field label={t("Source")}>
            <input value={id} onChange={(e) => setId(e.target.value)} placeholder="internal" />
          </Field>
          <Field label={t("Address")} wide>
            <input value={url} onChange={(e) => setUrl(e.target.value)}
                   placeholder="https://packages.example.com/debian" />
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
