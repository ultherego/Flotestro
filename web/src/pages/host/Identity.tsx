import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../../lib/api";
import type { Host, HostAccess, Job, LocalSudoRule, OfflineVerdict } from "../../lib/types";
import { Time, OptionalFlag } from "../../components/ui";
import { absoluteTime } from "../../lib/format";
import {
  Fact, Facts, Foot, FormActions, Message, ModuleFreshness, ModuleHeader, ModulePage, Section, Table, Unknown,
  useHost, useModule,
} from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { useT } from "../../i18n";

/**
 * The offline policy as the helper read it from sssd.conf. A missing field is
 * a value that could not be read; a key named in `defaulted` was absent from
 * the file and took the SSSD default, which is shown as such.
 */
type SssdOfflinePolicy = {
  cache_credentials?: boolean;
  offline_credentials_expiration_days?: number;
  entry_cache_timeout_seconds?: number;
  krb5_store_password_if_offline?: boolean;
  defaulted?: string[];
  unavailable_reason?: string;
};

type IdentityState = {
  servers?: string[];
  sssd_running?: boolean;
  cache_age_seconds?: number;
  host_principal?: string;
  keytab_kvno?: number;
  time_synchronized?: boolean;
  unavailable_reason?: string;
  sssd_offline_policy?: SssdOfflinePolicy;
};

export function Identity() {
  const t = useT();
  const host = useHost();
  const module = useModule<IdentityState>(host.id, "identity");
  const identity = module.data?.payload ?? {};

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Identity")}
        description={t("Domain membership and the directory client, as the host last checked them.")}
      />
      <ModuleFreshness fragment={module.data} />

      <Section title={t("Domain")} flush>
        <Facts>
          <Fact label={t("In domain")}>
            {host.identity.enrolled ? <span className="badge ok">{t("yes")}</span> : <span className="badge">{t("no")}</span>}
          </Fact>
          <Fact label={t("Domain")}>{host.identity.domain || "—"}</Fact>
          <Fact label={t("Realm")}>{host.identity.realm || "—"}</Fact>
          <Fact label={t("Servers")}><span className="hm-mono">{(identity.servers ?? []).join(", ") || "—"}</span></Fact>
          <Fact label={t("Host principal")}>
            {identity.host_principal ? <span className="hm-mono">{identity.host_principal}</span> : <Unknown />}
          </Fact>
          <Fact label={t("Keytab KVNO")}>{identity.keytab_kvno ?? <Unknown />}</Fact>
        </Facts>
      </Section>

      <Section title={t("Directory client")} flush>
        <Facts>
          <Fact label={t("SSSD running")}>{identity.sssd_running ? t("yes") : t("no")}</Fact>
          <Fact label={t("SSSD online")}><OptionalFlag value={host.identity.sssd_online} /></Fact>
          <Fact label={t("Cache age")}>
            {identity.cache_age_seconds !== undefined
              ? `${identity.cache_age_seconds} s`
              : <Unknown />}
          </Fact>
          <Fact label={t("Clock synchronized")}>{identity.time_synchronized ? t("yes") : t("no")}</Fact>
          <Fact label={t("Checked")}><Time value={host.identity.checked_at} /></Fact>
        </Facts>
      </Section>

      {host.identity.enrolled && (
        <OfflinePolicy policy={identity.sssd_offline_policy} verdict={host.identity.offline_verdict} />
      )}

      <EffectiveAccess host={host} />

      {host.identity.enrolled && <LeaveDomain host={host} />}
    </ModulePage>
  );
}

/**
 * Taking the host out of its domain. The button exists only for a host that
 * is in one and an operator allowed to order it: a button that leads to a
 * refusal is an interface defect. The order is confirmed by typing the
 * hostname, because every directory account loses this host at once and
 * the way back is a new join with a new credential from the directory.
 */
function LeaveDomain({ host }: { host: Host }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const [message, setMessage] = useState("");
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<{ permissions: string[] }>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const mayLeave = (whoami.data?.permissions ?? []).includes("identity.host.leave");

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (job) => {
      setMessage(
        job.requires_approval
          ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
          : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }),
      );
      setConfirming(false);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  if (!mayLeave) return null;

  return (
    <Section
      title={t("Leave the domain")}
      description={t("The host unenrolls itself with its own keytab and restores the files the join changed. Directory accounts stop signing in here at once; the entry in the directory stays, and a new join needs a new one-time password.")}
    >
      <Message text={message} />
      {confirming ? (
        <TargetConfirmation
          host={host}
          label={t("Leave domain")}
          description={t("{host} will leave {realm}. Every directory account loses this host the moment SSSD is reconfigured.", {
            host: host.hostname, realm: host.identity.realm ?? "",
          })}
          busy={request.isPending}
          onConfirm={(reason, confirmation) =>
            request.mutate({
              action: "identity.host.leave",
              reason,
              target_confirmation: confirmation,
              payload: { domain_leave: { domain: host.identity.domain, realm: host.identity.realm } },
            })
          }
          onCancel={() => setConfirming(false)}
        />
      ) : (
        <FormActions>
          <button className="secondary" onClick={() => setConfirming(true)}>{t("Leave domain")}</button>
        </FormActions>
      )}
    </Section>
  );
}

/**
 * What happens to directory logins when the directory is unreachable. The
 * facts come from sssd.conf on the host; the verdict is the panel's and is
 * drawn as unknown whenever a fact is missing - a host that did not report
 * its policy is not a host without a cache.
 */
function OfflinePolicy({ policy, verdict }: { policy?: SssdOfflinePolicy; verdict?: OfflineVerdict }) {
  const t = useT();
  const defaulted = new Set(policy?.defaulted ?? []);

  const flag = (key: string, value: boolean | undefined) => {
    if (value === undefined) return <Unknown />;
    return (
      <>
        {value ? t("yes") : t("no")}
        {defaulted.has(key) && <> <span className="badge">{t("default")}</span></>}
      </>
    );
  };
  const number = (key: string, value: number | undefined, render: (n: number) => string) => {
    if (value === undefined) return <Unknown />;
    return (
      <>
        {render(value)}
        {defaulted.has(key) && <> <span className="badge">{t("default")}</span></>}
      </>
    );
  };

  return (
    <Section
      title={t("Logins during a directory outage")}
      description={t("What sssd.conf on the host says about cached credentials, and what the panel concludes from it.")}
      flush
    >
      <Facts>
        <Fact label={t("Verdict")} wide><VerdictChip verdict={verdict} /></Fact>
        <Fact label={t("Credentials cached")}>{flag("cache_credentials", policy?.cache_credentials)}</Fact>
        <Fact label={t("Cached credentials expire")}>
          {number("offline_credentials_expiration", policy?.offline_credentials_expiration_days,
            (days) => days === 0 ? t("never") : t("after {days} days", { days }))}
        </Fact>
        <Fact label={t("Entry cache timeout")}>
          {number("entry_cache_timeout", policy?.entry_cache_timeout_seconds, (seconds) => `${seconds} s`)}
        </Fact>
        <Fact label={t("Password kept when offline")}>
          {flag("krb5_store_password_if_offline", policy?.krb5_store_password_if_offline)}
        </Fact>
      </Facts>
      {policy?.unavailable_reason && (
        <Foot><Unknown /> {policy.unavailable_reason}</Foot>
      )}
      {!policy && (
        <Foot>{t("The host has not reported its SSSD offline policy; an agent from before this check sends none.")}</Foot>
      )}
    </Section>
  );
}

/** The verdict as a chip, with the one sentence behind it. */
function VerdictChip({ verdict }: { verdict?: OfflineVerdict }) {
  const t = useT();
  if (!verdict) {
    return <><Unknown /> {t("The panel has no verdict for this host yet.")}</>;
  }
  const labels: Record<OfflineVerdict["verdict"], string> = {
    cached_logins_until: t("cached logins until {when}", { when: verdict.until ? absoluteTime(verdict.until) : "?" }),
    cached_logins_indefinitely: t("cached logins indefinitely"),
    no_cached_logins: t("no cached logins"),
    unknown: t("unknown"),
  };
  const tone: Record<OfflineVerdict["verdict"], string> = {
    cached_logins_until: "ok",
    cached_logins_indefinitely: "ok",
    // No cache during an outage locks everybody out; before the outage it
    // is a warning about what the outage would do.
    no_cached_logins: verdict.in_force ? "error" : "warn",
    unknown: "unknown",
  };
  return (
    <>
      <span className={`badge ${tone[verdict.verdict]}`}>{labels[verdict.verdict]}</span>
      {verdict.in_force && <> <span className="badge warn">{t("outage in progress")}</span></>}
      {" "}
      <span>{verdict.reason}</span>
    </>
  );
}

/**
 * The effective access: the host's groups and the access and sudo rules
 * that reach it, as the directory holds them, and next to them the rules
 * of the host's own sudoers files, as the helper parsed them. Nothing here
 * is decided by the panel - the host's SSSD and sudo apply the rules - so
 * the section shows the projection and says plainly when either half
 * could not be read. An unavailable directory, a host the directory does
 * not know or a policy the helper did not read is "unknown", never "no
 * access".
 */
function EffectiveAccess({ host }: { host: Host }) {
  const t = useT();
  const access = useQuery({
    queryKey: ["host-access", host.id],
    queryFn: () => api.get<HostAccess>(`/api/v1/hosts/${host.id}/access`),
    retry: false,
  });

  if (access.error) {
    const error = access.error;
    const detail = error instanceof ApiError && error.forbidden
      ? t("You do not have permission to read the directory.")
      : t("The access view could not be read: {error}", { error: error instanceof Error ? error.message : String(error) });
    return (
      <Section title={t("Effective access")} description={t("Who may enter this host and with what privileges, as the directory's rules and the local sudoers say.")}>
        <p className="hm-message"><Unknown /> {detail}</p>
      </Section>
    );
  }

  const data = access.data;
  if (!data) {
    return (
      <Section title={t("Effective access")}>
        <p className="hm-message">{t("Reading the directory…")}</p>
      </Section>
    );
  }

  return (
    <>
      {/* A root-equivalent local grant is the first thing on the page: it is
          the answer to "who can become root here" whatever the directory
          says. */}
      {data.root_equivalent_warnings.length > 0 && (
        <p className="warning">
          <span>
            {t("Local sudoers make somebody root on this host:")}{" "}
            {data.root_equivalent_warnings.join("; ")}
          </span>
        </p>
      )}

      {!data.known ? (
        <Section title={t("Effective access")} description={t("Who may enter this host and with what privileges, as the directory's rules say.")}>
          <p className="hm-message"><Unknown /> {data.detail}</p>
        </Section>
      ) : (
        <>
          <Section title={t("Effective access")} description={t("Who may enter this host and with what privileges, as the directory's rules say.")} flush>
            <Facts>
              <Fact label={t("Directory entry")}><span className="hm-mono">{data.fqdn}</span></Fact>
              <Fact label={t("Enrolled in the directory")}>
                {data.enrolled ? <span className="badge ok">{t("yes")}</span> : <span className="badge">{t("no")}</span>}
              </Fact>
              <Fact label={t("Host groups")} wide>{data.host_groups.join(", ") || t("none")}</Fact>
            </Facts>
          </Section>

          <Section title={t("HBAC rules reaching this host")} count={data.hbac_rules.length} flush>
            <Table>
              <thead><tr><th>{t("Rule")}</th><th>{t("Enabled")}</th><th>{t("Via")}</th><th>{t("Who")}</th><th>{t("Services")}</th></tr></thead>
              <tbody>
                {data.hbac_rules.length === 0 ? (
                  <tr><td colSpan={5} className="empty">{t("No HBAC rule reaches this host: nobody from the directory can sign in.")}</td></tr>
                ) : data.hbac_rules.map((rule) => (
                  <tr key={rule.name}>
                    <td>
                      {rule.name}
                      {rule.allows_everything && <> <span className="badge error">{t("covers the whole fleet")}</span></>}
                    </td>
                    <td>{rule.enabled ? t("yes") : <span className="badge">{t("no")}</span>}</td>
                    <td>{rule.via.join(", ")}</td>
                    <td>
                      {rule.all_users
                        ? t("every user")
                        : (rule.reached_users ?? []).join(", ") || [...(rule.users ?? []), ...(rule.user_groups ?? [])].join(", ") || "—"}
                    </td>
                    <td>{rule.all_services ? t("every service") : [...(rule.services ?? []), ...(rule.service_groups ?? [])].join(", ") || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <Foot>{t("A disabled rule is listed because it would apply the moment somebody enables it.")}</Foot>
          </Section>

          <Section title={t("sudo rules reaching this host")} count={data.sudo_rules.length} flush>
            <Table>
              <thead><tr><th>{t("Rule")}</th><th>{t("Enabled")}</th><th>{t("Via")}</th><th>{t("Who")}</th><th>{t("Commands")}</th><th>{t("Run as")}</th><th>{t("Risk")}</th></tr></thead>
              <tbody>
                {data.sudo_rules.length === 0 ? (
                  <tr><td colSpan={7} className="empty">{t("No sudo rule from the directory reaches this host.")}</td></tr>
                ) : data.sudo_rules.map((rule) => (
                  <tr key={rule.name}>
                    <td>{rule.name}</td>
                    <td>{rule.enabled ? t("yes") : <span className="badge">{t("no")}</span>}</td>
                    <td>{rule.via.join(", ")}</td>
                    <td>
                      {rule.all_users
                        ? t("every user")
                        : (rule.reached_users ?? []).join(", ") || [...(rule.users ?? []), ...(rule.user_groups ?? [])].join(", ") || "—"}
                    </td>
                    <td className="hm-mono">{rule.all_commands ? t("every command") : [...(rule.commands ?? []), ...(rule.command_groups ?? [])].join(", ") || "—"}</td>
                    <td>{rule.run_as_any_user ? t("any user") : [...(rule.run_as ?? []), ...(rule.run_as_groups ?? [])].join(", ") || "—"}</td>
                    <td>
                      {rule.critical
                        ? <span className="badge error" title={(rule.critical_reasons ?? []).join("; ")}>{t("critical")}</span>
                        : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </Section>
        </>
      )}

      <LocalSudoRules access={data} />
    </>
  );
}

/**
 * The rules of the host's own sudoers files. They apply next to the
 * directory's rules - or instead of them on a host outside the domain -
 * and they are the ones an administrator writes by hand, so each is shown
 * with the file and line it comes from. A policy the helper did not read
 * is unknown with its reason, never "no local rules".
 */
function LocalSudoRules({ access }: { access: HostAccess }) {
  const t = useT();
  const state = access.local_sudoers;
  const rules = access.local_sudo_rules ?? [];
  const runAs = (rule: LocalSudoRule) => {
    if (rule.run_as_any_user) return t("any user");
    const names = [...(rule.run_as ?? []), ...(rule.run_as_groups ?? [])];
    if (rule.run_as_self) return t("self") + (names.length ? `: ${names.join(", ")}` : "");
    return names.join(", ") || "root";
  };

  return (
    <Section
      title={t("Local sudoers rules")}
      count={state.read ? rules.length : undefined}
      description={t("What /etc/sudoers and its drop-ins grant on this host, as the helper parsed them. A rule that names other hosts is listed but does not reach this one.")}
      flush
    >
      {!state.read ? (
        <p className="hm-message"><Unknown /> {state.reason}</p>
      ) : (
        <>
          {state.passwordless_globally && (
            <p className="warning">
              <span>{t("A global Defaults line turns authentication off: every local rule is passwordless whatever its tags say.")}</span>
            </p>
          )}
          <Table>
            <thead><tr><th>{t("Who")}</th><th>{t("Hosts")}</th><th>{t("Commands")}</th><th>{t("Run as")}</th><th>{t("Password")}</th><th>{t("Risk")}</th><th>{t("Source")}</th></tr></thead>
            <tbody>
              {rules.length === 0 ? (
                <tr><td colSpan={7} className="empty">{t("The local sudoers files grant nothing.")}</td></tr>
              ) : rules.map((rule) => (
                <tr key={`${rule.source}:${rule.line}:${rule.commands.join(",")}:${rule.nopasswd}`} style={rule.reaches_host ? undefined : { opacity: 0.55 }}>
                  <td>
                    {rule.all_users ? t("every user") : rule.users.join(", ")}
                    {(rule.reached_users ?? []).length > 0 && !rule.all_users && rule.users.some((user) => user.startsWith("%") || user.startsWith("#")) && (
                      <div className="source">{t("members: {users}", { users: (rule.reached_users ?? []).join(", ") })}</div>
                    )}
                  </td>
                  <td>
                    {rule.reaches_host
                      ? rule.via.join(", ")
                      : <span className="badge unknown" title={rule.hosts.join(", ")}>{t("not this host")}</span>}
                  </td>
                  <td className="hm-mono">{rule.all_commands ? t("every command") : rule.commands.join(", ")}</td>
                  <td>{runAs(rule)}</td>
                  <td>{rule.nopasswd || state.passwordless_globally ? <span className="badge warn">{t("none")}</span> : t("required")}</td>
                  <td>
                    {rule.root_equivalent
                      ? <span className="badge error" title={(rule.critical_reasons ?? []).join("; ")}>{t("root")}</span>
                      : rule.critical
                        ? <span className="badge warn" title={(rule.critical_reasons ?? []).join("; ")}>{t("critical")}</span>
                        : "—"}
                  </td>
                  <td className="hm-mono">{rule.source}:{rule.line}</td>
                </tr>
              ))}
            </tbody>
          </Table>
          {(state.problems ?? []).length > 0 && (
            <Foot>
              <Unknown />{" "}
              {t("{count} lines were not understood and may grant something the table does not show:", { count: (state.problems ?? []).length })}{" "}
              {(state.problems ?? []).map((problem) => `${problem.source}:${problem.line}`).join(", ")}
            </Foot>
          )}
          {(state.files ?? []).some((file) => file.reason) && (
            <Foot>
              <Unknown />{" "}
              {t("Files not read:")}{" "}
              {(state.files ?? []).filter((file) => file.reason).map((file) => `${file.path} (${file.reason})`).join("; ")}
            </Foot>
          )}
          <Foot>
            {t("Read from {files} files", { files: (state.files ?? []).length })}
            {state.observed_at && <>, <Time value={state.observed_at} /></>}
          </Foot>
        </>
      )}
    </Section>
  );
}
