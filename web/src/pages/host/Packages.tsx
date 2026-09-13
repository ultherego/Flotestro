import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { OptionalNumber, Pair, Pairs, Empty } from "../../components/ui";
import { ModuleFreshness, useHost, useModule, RequestOperation } from "./shared";
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

  return (
    <>
      <Pairs>
        <Pair label={t("Manager")}>{packages?.manager || "—"}</Pair>
        <Pair label={t("Installed")}>
          {packages?.installed ?? <span className="badge unknown">{t("unknown")}</span>}
        </Pair>
        <Pair label={t("Upgradable")}><OptionalNumber value={host.pending_updates} /></Pair>
        <Pair label={t("Security updates")}>
          <OptionalNumber value={host.pending_security_updates} />
        </Pair>
        <Pair label={t("Package database")}>
          {host.package_database_broken
            ? <span className="badge error">{t("needs repair")}</span>
            : t("healthy")}
        </Pair>
      </Pairs>
      <ModuleFreshness fragment={module.data} />

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

      <h2>{t("Agent")}</h2>
      <p className="subtitle">
        {t("The agent is left alone by ordinary package upgrades: replacing it in the middle of a transaction it is running would cut the host off from management with nobody to report the result. Replacing it is its own operation, and it counts as done only when the host comes back reporting the version that was asked for.")}
      </p>
      <div className="form" style={{ marginBottom: 16 }}>
        <label>
          {t("Target agent version (currently {version})", { version: host.agent_version || t("unknown") })}
          <input
            value={agentVersion}
            onChange={(e) => setAgentVersion(e.target.value)}
            placeholder="0.2.0"
          />
        </label>
        <div className="operations">
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
        </div>
      </div>

      <h2>{t("Install, remove or hold")}</h2>
      <div className="form">
        <label>
          {t("Package names (space or comma separated)")}
          <input value={names} onChange={(e) => { setNames(e.target.value); setPlan(null); }}
                 placeholder="nginx htop" />
        </label>
        <div className="operations">
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
            disabled={request.isPending || list().length === 0}
            onClick={() => request.mutate({
              action: "packages.hold.set",
              payload: { package_change: { packages: list(), hold: true } },
            })}
          >
            {t("Hold")}
          </button>
          <button
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
            className="secondary"
            disabled={planRemoval.isPending || list().length === 0}
            onClick={() => planRemoval.mutate()}
          >
            {planRemoval.isPending ? t("Planning…") : t("Plan removal")}
          </button>
        </div>
      </div>

      {message && <p className="source" style={{ marginTop: 12 }}>{message}</p>}

      {plan && (
        <>
          <h2>{t("Removal plan")}</h2>
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
              <table>
                <thead><tr><th>{t("Package")}</th><th>{t("Reason")}</th></tr></thead>
                <tbody>
                  {plan.removals.map((pkg) => (
                    <tr key={pkg}>
                      <td>{pkg}</td>
                      <td>{list().includes(pkg) ? t("requested") : t("dependency")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="source" style={{ marginTop: 8 }}>
                {t("{n} package(s) would be removed. The host recomputes this set before removing; a difference cancels the operation.", { n: plan.removals.length })}
              </p>
              {(!plan.protected || plan.protected.length === 0) && (
                <div className="operations" style={{ marginTop: 12 }}>
                  <button onClick={() => setToRemove(plan.removals ?? [])}>
                    {t("Remove these packages")}
                  </button>
                </div>
              )}
            </>
          )}
        </>
      )}

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
    </>
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
      <h2>{t("Repositories")}</h2>
      <p className="subtitle">
        {t("Where this host takes software from. Adding a source installs nothing today; it decides whose packages the host will accept tomorrow, with their scripts running as root.")}
      </p>
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

      <div className="filters">
        <button className="secondary" onClick={() => setForm((open) => !open)}>
          {form ? t("Cancel") : t("Add or change a source")}
        </button>
      </div>
      {form && <SourceForm manager={manager} onIntent={onIntent} />}

      {!sources.length ? (
        <Empty>{t("This host reports no package source.")}</Empty>
      ) : (
        <table>
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
                  {source.id}
                  {source.path && <div className="source">{source.path}</div>}
                </td>
                <td className="source">
                  {source.unavailable_reason ? (
                    <span className="badge unknown">{source.unavailable_reason}</span>
                  ) : (
                    <>
                      {source.url}
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
                      className="secondary"
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
        </table>
      )}
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
    <div className="form" style={{ marginBottom: 16 }}>
      <h2>{t("Package source")}</h2>
      <p className="subtitle" style={{ margin: 0 }}>
        {t("The key travels in the job — it is public, and the plan should show what the host will trust. The password does not: name a secret and the host fetches its value once, while it writes the file.")}
      </p>
      <div className="filters">
        <input value={id} onChange={(e) => setId(e.target.value)}
               placeholder="internal" style={{ minWidth: 160 }} />
        <input value={url} onChange={(e) => setUrl(e.target.value)}
               placeholder="https://packages.example.com/debian" style={{ minWidth: 320 }} />
      </div>
      {apt && (
        <div className="filters">
          <input value={suites} onChange={(e) => setSuites(e.target.value)}
                 placeholder={t("Suites (stable)")} style={{ minWidth: 200 }} />
          <input value={components} onChange={(e) => setComponents(e.target.value)}
                 placeholder={t("Components (main)")} style={{ minWidth: 200 }} />
        </div>
      )}
      <div className="filters">
        <input value={username} onChange={(e) => setUsername(e.target.value)}
               placeholder={t("Username (private source)")} style={{ minWidth: 200 }} />
        <input value={secret} onChange={(e) => setSecret(e.target.value)}
               placeholder={t("Password secret (name only)")} style={{ minWidth: 220 }} />
      </div>
      <label style={{ flexDirection: "row", alignItems: "center", gap: 8 }}>
        <input type="checkbox" checked={unsigned}
               onChange={(e) => setUnsigned(e.target.checked)} />
        {t("Do not check signatures (the host will install anything from this address)")}
      </label>
      {!unsigned && (
        <label>
          {t("Signing key (ASCII-armored public key)")}
          <textarea rows={8} value={key} onChange={(e) => setKey(e.target.value)}
                    placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----" />
        </label>
      )}
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
    </div>
  );
}
