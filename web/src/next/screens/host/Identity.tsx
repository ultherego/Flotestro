import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../../../lib/api";
import { useAllowed, useModuleAccess } from "../../../lib/actions";
import { absoluteTime, duration, relativeTime } from "../../../lib/format";
import {
  emptyForm, operationForm, type FormProblem, type FormValue,
} from "../../../lib/operations";
import type {
  Host, HostAccess, InventoryFragment, Job, LocalSudoRule, OfflineVerdict, Whoami,
} from "../../../lib/types";
import { useT } from "../../../i18n";
import { Board } from "../../Board";
import type { BoardEntry } from "../../../components/board";
import {
  Actions, Banner, Bones, Button, Card, Fact, Facts, Field, Fields, Modal, Note, Pill,
  Problem, Table, type Tone,
} from "../../kit";

/**
 * Where this machine gets its people from, and who the directory lets in.
 *
 * Two halves that are not the same question: what the host believes about
 * its domain, and what the directory and the local sudoers actually grant
 * on it. A host outside a domain has no principal and no cache - which is
 * "does not apply", not "unknown", and the screen says which.
 *
 * Nothing here carries a password. A join fetches its one-time password
 * from the connector when the task is delivered; it is never typed, never
 * shown, never put in an address and never written to the trail.
 */

/** The offline policy as the helper read it from sssd.conf. */
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

/** One precondition of the join as the helper checked it. */
type PreflightCheck = { name: string; detail?: string; blocking: boolean; passed: boolean | null };

/** The typed detail of a join or a preflight, as the attempt carries it. */
type EnrollDetail = {
  kind?: string;
  enrolled?: boolean;
  host_principal?: string;
  checks?: PreflightCheck[];
  verifications?: PreflightCheck[];
};

/** One attempt of a job as a result view reads it. */
type ReadAttempt<T> = { status?: string; error_code?: string; message?: string; detail?: T };

/** The changes this module offers; when every one is refused, it says so once. */
const IDENTITY_CHANGES = ["identity.host.enroll", "identity.keytab.renew", "identity.host.leave"];

/** The shortest reason the API takes for a critical operation. */
const MIN_REASON = 8;

/** A name that reaches the directory: at least two labels, as the API requires. */
const DOMAIN_PATTERN = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/;

/** A service principal: service/host.fqdn with an optional realm, never host/. */
const SERVICE_PRINCIPAL_PATTERN =
  /^[a-zA-Z0-9_-]{1,64}\/[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+(@[A-Za-z0-9.-]+)?$/;

/* ------------------------------------------------------------- the order */

type RegistryOrder = { action: string; payload: Record<string, unknown>; problems: FormProblem[] };

function registryOrder(action: string, seed: FormValue): RegistryOrder {
  const entry = operationForm(action);
  if (!entry) {
    return { action, payload: {}, problems: [{ message: "The registry has no form for {action} yet.", params: { action } }] };
  }
  const form = { ...emptyForm(entry), ...seed };
  return { action, payload: entry.toPayload(form), problems: entry.validate(form) };
}

function orderReady(order: RegistryOrder): boolean {
  return order.problems.length === 0;
}

function refusalOf(
  t: (text: string, params?: Record<string, string | number>) => string,
  order: RegistryOrder,
): string {
  const problem = order.problems[0];
  return problem ? t(problem.message, problem.params) : "";
}

/**
 * Joining a domain, as the operation registry composes it. The realm is put
 * in capitals here, because that is what a realm is and the registry keeps
 * what it is given.
 */
export function enrollOrder(domain: string, realm: string, server: string, hostname: string): RegistryOrder {
  return registryOrder("identity.host.enroll", { domain, realm: realm.trim().toUpperCase(), server, hostname });
}

/* ------------------------------------------------------------- the gates */

function Guard({ action, host, explain = false, children }: {
  action: string;
  host: string;
  explain?: boolean;
  children: ReactNode;
}) {
  const t = useT();
  const verdict = useAllowed(host, action);
  if (verdict.allowed) return <>{children}</>;
  if (verdict.pending || !explain) return null;
  return <Note>{verdict.reason || t("This action is not available.")}</Note>;
}

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

/** An undetermined fact. Unknown is not a no. */
function Unknown() {
  const t = useT();
  return <Pill tone="unknown">{t("unknown")}</Pill>;
}

/** A yes, a no, or nobody told us. */
function Flag({ value }: { value?: boolean | null }) {
  const t = useT();
  if (value === undefined || value === null) return <Unknown />;
  return <>{value ? t("yes") : t("no")}</>;
}

/* ---------------------------------------------------------- the ordering */

/**
 * A read ordered through a job: the order goes out, the screen polls the
 * attempts until the host answers, and the last attempt is the result.
 */
function useReadOperation<T>(host: Host) {
  const queryClient = useQueryClient();
  const [job, setJob] = useState("");
  const [message, setMessage] = useState("");

  const order = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (created) => {
      setMessage("");
      setJob(created.id);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const attempts = useQuery({
    queryKey: ["job-attempts", job],
    queryFn: () => api.get<{ items: ReadAttempt<T>[] }>(`/api/v1/jobs/${job}/attempts`),
    enabled: job !== "",
    refetchInterval: (query) => {
      const items = (query.state.data as { items?: { status?: string }[] } | undefined)?.items;
      return items?.[items.length - 1]?.status ? false : 2000;
    },
  });

  const items = attempts.data?.items ?? [];
  const last = items.length > 0 ? items[items.length - 1] : undefined;
  return {
    order: order.mutate,
    ordered: job !== "",
    busy: order.isPending || (job !== "" && !last?.status),
    message,
    attempt: last?.status ? last : undefined,
  };
}

/** One order placed from this module, with the job it answered with. */
function useOrder(host: Host) {
  const queryClient = useQueryClient();
  const [job, setJob] = useState<Job | null>(null);
  const [message, setMessage] = useState("");
  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (created) => {
      setJob(created);
      setMessage("");
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => {
      setJob(null);
      setMessage(error instanceof Error ? error.message : String(error));
    },
  });
  return { send: request.mutate, busy: request.isPending, job, message };
}

/**
 * The answer to an order, with the job linked: "waiting for approval" is a
 * sentence the operator acts on, so the job it names is one click away and
 * so is the list of this host's jobs.
 */
function JobNotice({ job, hostID }: { job: Job; hostID: string }) {
  const t = useT();
  const sentence = job.requires_approval
    ? t("Job {id} is waiting for approval.")
    : t("Job {id} has been queued.");
  const [before, after = ""] = sentence.split("{id}");
  return (
    <Note>
      {before}
      <Link to={`/jobs/${job.id}`}>{job.id.slice(0, 8)}</Link>
      {after}{" "}
      <Link to={`/hosts/${hostID}/jobs`}>{t("See all jobs")}</Link>
    </Note>
  );
}

/**
 * The confirmation of an operation that changes who may enter the machine.
 *
 * It asks for the reason the panel refuses the order without, and - where
 * the change cannot be taken back by another order - for the host's name
 * typed out, so that the operator approves a specific machine rather than
 * "the host I think I have open".
 */
function Confirm({ host, title, children, label, busy, typed = true, onConfirm, onClose, testId }: {
  host: Host;
  title: string;
  children: ReactNode;
  label: string;
  busy: boolean;
  /** Whether the hostname has to be typed out as well as the reason given. */
  typed?: boolean;
  onConfirm: (reason: string, confirmation: string) => void;
  onClose: () => void;
  testId: string;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const ready = reason.trim().length >= MIN_REASON && (!typed || confirmation === host.hostname);
  return (
    <Modal
      title={title}
      onClose={onClose}
      actions={
        <>
          <Button kind="quiet" onClick={onClose} disabled={busy}>{t("Cancel")}</Button>
          <Button
            kind="danger"
            disabled={!ready || busy}
            testId={testId}
            onClick={() => onConfirm(reason.trim(), confirmation)}
          >
            {busy ? t("Requesting…") : label}
          </Button>
        </>
      }
    >
      <Note>{children}</Note>
      <Facts>
        <Fact label={t("Target")}>
          {host.hostname} · {host.management_address || t("address unknown")} · {host.site} / {host.environment}
        </Fact>
      </Facts>
      <Fields>
        <Field label={t("Reason (at least 8 characters, kept in the audit trail)")} wide>
          <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid={`${testId}-reason`} />
        </Field>
        {typed && (
          <Field label={t("Type the hostname to confirm: {name}", { name: host.hostname })} wide>
            <input value={confirmation} onChange={(event) => setConfirmation(event.target.value)} data-testid={`${testId}-typed`} />
          </Field>
        )}
      </Fields>
    </Modal>
  );
}

/* ------------------------------------------------------------ the module */

export function Identity({ host }: { host: Host }) {
  const t = useT();
  const [asking, setAsking] = useState<"join" | "keytab" | "leave" | null>(null);

  const module = useQuery({
    queryKey: ["inventory", host.id, "identity"],
    queryFn: () => api.get<InventoryFragment<IdentityState>>(`/api/v1/hosts/${host.id}/inventory/identity`),
    retry: false,
  });
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const access = useQuery({
    queryKey: ["host-access", host.id],
    queryFn: () => api.get<HostAccess>(`/api/v1/hosts/${host.id}/access`),
    retry: false,
  });

  const identity = module.data?.payload ?? {};
  const enrolled = host.identity.enrolled;
  const permissions = whoami.data?.permissions ?? [];
  const mayJoin = permissions.includes("identity.host.enroll");
  const mayPreflight = permissions.includes("identity.read");
  const mayRenew = permissions.includes("identity.keytab.rotate");
  const mayLeave = permissions.includes("identity.host.leave");

  // A host outside any domain has no principal, no keytab and no cache to
  // speak of: those facts do not apply, which is not the same as unknown.
  const notInDomain = <Note>{t("not in a domain")}</Note>;

  const [domain, setDomain] = useState(host.identity.domain ?? "");
  const [realm, setRealm] = useState(host.identity.realm ?? "");
  const [server, setServer] = useState("");
  const [hostname, setHostname] = useState(host.hostname);
  const [principal, setPrincipal] = useState(`HTTP/${host.hostname}`);

  const join = useOrder(host);
  const keytab = useOrder(host);
  const leave = useOrder(host);
  const preflight = useReadOperation<EnrollDetail>(host);

  const order = enrollOrder(domain, realm, server, hostname);
  const payload = order.payload as { domain_enroll: { realm: string; hostname: string } } | Record<string, never>;
  // The registry lets the host keep the name it has; joining from here
  // always names it, and a name that reaches the directory is qualified.
  const joinValid = orderReady(order) && DOMAIN_PATTERN.test(hostname.trim());
  const checks = preflight.attempt?.detail?.checks ?? [];
  const blocked = checks.filter((check) => check.blocking && check.passed === false).length;

  const principalName = principal.trim();
  const principalValid = SERVICE_PRINCIPAL_PATTERN.test(principalName)
    && !principalName.toLowerCase().startsWith("host/");

  const data = access.data;
  const accessRefusal = access.error
    ? access.error instanceof ApiError && access.error.forbidden
      ? t("You do not have permission to read the directory.")
      : t("The access view could not be read: {error}", {
          error: access.error instanceof Error ? access.error.message : String(access.error),
        })
    : "";

  return (
    <>
      <ReadOnlyNotice host={host.id} actions={IDENTITY_CHANGES} />
      {/* A root-equivalent local grant comes before everything else: it is
          the answer to "who can become root here" whatever the directory
          says. */}
      {data && data.root_equivalent_warnings.length > 0 && (
        <Banner tone="error">
          {t("Local sudoers make somebody root on this host: {what}", { what: data.root_equivalent_warnings.join("; ") })}
        </Banner>
      )}
      {data?.local_sudoers.read && data.local_sudoers.passwordless_globally && (
        <Banner tone="warn">
          {t("A global Defaults line turns authentication off: every local rule is passwordless whatever its tags say.")}
        </Banner>
      )}
      {module.data?.unavailable_reason && (
        <Banner tone="warn">
          {t("The identity module could not be read: {reason}", { reason: module.data.unavailable_reason })}
        </Banner>
      )}
      {join.message && <Banner tone="error">{join.message}</Banner>}
      {keytab.message && <Banner tone="error">{keytab.message}</Banner>}
      {leave.message && <Banner tone="error">{leave.message}</Banner>}
      {preflight.message && <Banner tone="error">{preflight.message}</Banner>}

      <Board screen="next_host_identity" catalogue={HOST_IDENTITY} drawn={{
        domain: (
          <Card
            title={t("Domain")}
            note={t("Domain membership and the directory client, as the host last checked them.")}
            foot={module.data
              ? t("Source: {source}, revision {revision}, observed {when}", {
                  source: module.data.source,
                  revision: module.data.revision.slice(0, 12),
                  when: relativeTime(module.data.observed_at),
                })
              : undefined}
          >
            <Facts>
              <Fact label={t("In domain")}>
                {enrolled ? <Pill tone="ok">{t("yes")}</Pill> : <Pill tone="neutral">{t("no")}</Pill>}
              </Fact>
              <Fact label={t("Domain")}>{host.identity.domain || "—"}</Fact>
              <Fact label={t("Realm")}>{host.identity.realm || "—"}</Fact>
              <Fact label={t("Servers")}>{(identity.servers ?? []).join(", ") || "—"}</Fact>
              <Fact label={t("Host principal")}>
                {identity.host_principal ? identity.host_principal : enrolled ? <Unknown /> : notInDomain}
              </Fact>
              <Fact label={t("Keytab KVNO")}>
                {identity.keytab_kvno ?? (enrolled ? <Unknown /> : notInDomain)}
              </Fact>
            </Facts>
          </Card>
        ),
        client: (
          <Card title={t("Directory client")}>
            <Facts>
              <Fact label={t("SSSD running")}>{identity.sssd_running ? t("yes") : t("no")}</Fact>
              <Fact label={t("SSSD online")}>
                {enrolled || (host.identity.sssd_online !== undefined && host.identity.sssd_online !== null)
                  ? <Flag value={host.identity.sssd_online} />
                  : notInDomain}
              </Fact>
              <Fact label={t("Cache age")}>
                {identity.cache_age_seconds !== undefined
                  ? <span title={t("{n} seconds", { n: identity.cache_age_seconds })}>{duration(identity.cache_age_seconds)}</span>
                  : enrolled ? <Unknown /> : notInDomain}
              </Fact>
              <Fact label={t("Clock synchronized")}>
                <Flag value={identity.time_synchronized ?? null} />
              </Fact>
              <Fact label={t("Checked")}>
                {host.identity.checked_at
                  ? <span title={absoluteTime(host.identity.checked_at)}>{relativeTime(host.identity.checked_at)}</span>
                  : <Unknown />}
              </Fact>
            </Facts>
          </Card>
        ),
        offline: enrolled && (
          <OfflinePolicy policy={identity.sssd_offline_policy} verdict={host.identity.offline_verdict} />
        ),
        access: (
          <Card
            title={t("Effective access")}
            note={t("Who may enter this host and with what privileges, as the directory's rules and the local sudoers say.")}
          >
            {accessRefusal ? (
              <Note><Unknown /> {accessRefusal}</Note>
            ) : !data ? (
              <Bones rows={4} />
            ) : !data.known ? (
              <Note><Unknown /> {data.detail}</Note>
            ) : (
              <Facts>
                <Fact label={t("Directory entry")}>{data.fqdn || "—"}</Fact>
                <Fact label={t("Enrolled in the directory")}>
                  {data.enrolled ? <Pill tone="ok">{t("yes")}</Pill> : <Pill tone="neutral">{t("no")}</Pill>}
                </Fact>
                <Fact label={t("Host groups")}>{data.host_groups.join(", ") || t("none")}</Fact>
              </Facts>
            )}
          </Card>
        ),
        hbac: data?.known && (
          <Card
            title={t("HBAC rules reaching this host")}
            note={t("{n} of them", { n: data.hbac_rules.length })}
            foot={t("A disabled rule is listed because it would apply the moment somebody enables it.")}
            flush
          >
            <Table
              rows={data.hbac_rules}
              keyOf={(rule) => rule.name}
              empty={t("No HBAC rule reaches this host: nobody from the directory can sign in.")}
              columns={[
                { key: "name", head: t("Rule"), cell: (rule) => (
                  <>
                    {rule.name}
                    {rule.allows_everything && <> <Pill tone="error">{t("covers the whole fleet")}</Pill></>}
                  </>
                ) },
                { key: "enabled", head: t("Enabled"), cell: (rule) => rule.enabled ? t("yes") : <Pill tone="neutral">{t("no")}</Pill> },
                { key: "via", head: t("Via"), minor: true, cell: (rule) => rule.via.join(", ") },
                { key: "who", head: t("Who"), cell: (rule) => rule.all_users
                  ? t("every user")
                  : (rule.reached_users ?? []).join(", ") || [...(rule.users ?? []), ...(rule.user_groups ?? [])].join(", ") || "—" },
                { key: "services", head: t("Services"), cell: (rule) => rule.all_services
                  ? t("every service")
                  : [...(rule.services ?? []), ...(rule.service_groups ?? [])].join(", ") || "—" },
              ]}
            />
          </Card>
        ),
        sudo: data?.known && (
          <Card
            title={t("sudo rules reaching this host")}
            note={t("{n} of them", { n: data.sudo_rules.length })}
            flush
          >
            <Table
              rows={data.sudo_rules}
              keyOf={(rule) => rule.name}
              empty={t("No sudo rule from the directory reaches this host.")}
              columns={[
                { key: "name", head: t("Rule"), cell: (rule) => rule.name },
                { key: "enabled", head: t("Enabled"), cell: (rule) => rule.enabled ? t("yes") : <Pill tone="neutral">{t("no")}</Pill> },
                { key: "via", head: t("Via"), minor: true, cell: (rule) => rule.via.join(", ") },
                { key: "who", head: t("Who"), cell: (rule) => rule.all_users
                  ? t("every user")
                  : (rule.reached_users ?? []).join(", ") || [...(rule.users ?? []), ...(rule.user_groups ?? [])].join(", ") || "—" },
                { key: "commands", head: t("Commands"), tight: true, cell: (rule) => rule.all_commands
                  ? t("every command")
                  : [...(rule.commands ?? []), ...(rule.command_groups ?? [])].join(", ") || "—" },
                { key: "runas", head: t("Run as"), minor: true, cell: (rule) => rule.run_as_any_user
                  ? t("any user")
                  : [...(rule.run_as ?? []), ...(rule.run_as_groups ?? [])].join(", ") || "—" },
                { key: "risk", head: t("Risk"), cell: (rule) => rule.critical
                  ? <Pill tone="error" title={(rule.critical_reasons ?? []).join("; ")}>{t("critical")}</Pill>
                  : "—" },
              ]}
            />
          </Card>
        ),
        localsudo: data && <LocalSudoRules access={data} />,
        join: !enrolled && (mayJoin || mayPreflight) && (
          <Card
            title={t("Join the domain")}
            note={t("The host joins with a one-time password the panel fetches from the directory connector when the task is delivered; nothing is typed here and the password reaches neither the database nor the audit trail. A panel without a connector lets the order through and the host refuses it as missing_credential.")}
          >
            <Fields>
              <Field label={t("Domain")} hint={t("The DNS domain of the directory, e.g. example.internal.")}>
                <input value={domain} placeholder="example.internal" onChange={(event) => setDomain(event.target.value)} data-testid="domain" />
              </Field>
              <Field label={t("Realm")} hint={t("The Kerberos realm; usually the domain in capitals.")}>
                <input value={realm} placeholder="EXAMPLE.INTERNAL" onChange={(event) => setRealm(event.target.value)} data-testid="realm" />
              </Field>
              <Field label={t("Server")} hint={t("Optional; the directory server to talk to instead of the one DNS names.")}>
                <input value={server} placeholder="ipa.example.internal" onChange={(event) => setServer(event.target.value)} />
              </Field>
              <Field label={t("Host name in the directory")} hint={t("The FQDN the host is entered under; the one-time password is issued for it.")}>
                <input value={hostname} onChange={(event) => setHostname(event.target.value)} data-testid="join-hostname" />
              </Field>
            </Fields>
            {domain.trim() !== "" && !joinValid && (
              <Problem>
                {refusalOf(t, order) || t("The domain and the host name must be fully qualified names, and the realm must not be empty.")}
              </Problem>
            )}
            <Actions>
              {/* The preview of the host's actions decides in the scope of
                  the host; the permission list of the session is the
                  cheaper first gate. */}
              {mayPreflight && (
                <Guard action="identity.host.preflight" host={host.id} explain>
                  <Button
                    kind="quiet"
                    disabled={!joinValid || preflight.busy || host.connection_state !== "online"}
                    title={!joinValid
                      ? t("Fill in the domain, the realm and the fully qualified host name first.")
                      : host.connection_state !== "online"
                        ? t("The host is not online; a preflight needs an answer from it.")
                        : t("The host checks DNS, the clock and the reach of the directory before anything changes; nothing is joined.")}
                    testId="preflight"
                    onClick={() => preflight.order({ action: "identity.host.preflight", payload })}
                  >
                    {preflight.busy ? t("Checking…") : t("Preflight first")}
                  </Button>
                </Guard>
              )}
              {mayJoin && (
                <Guard action="identity.host.enroll" host={host.id}>
                  <Button
                    disabled={!joinValid || join.busy}
                    title={!joinValid ? t("Fill in the domain, the realm and the fully qualified host name first.") : undefined}
                    testId="join"
                    onClick={() => setAsking("join")}
                  >
                    {t("Join the domain…")}
                  </Button>
                </Guard>
              )}
            </Actions>
            {join.job && <JobNotice job={join.job} hostID={host.id} />}
          </Card>
        ),
        preflight: preflight.attempt !== undefined && (
          <PreflightResult attempt={preflight.attempt} blocked={blocked} />
        ),
        keytab: enrolled && mayRenew && (
          <Card
            title={t("Renew a keytab")}
            note={t("The host fetches a new key for a service principal with its own credentials and writes it into /etc/krb5.keytab. The old key stops working the moment the new one lands; restart the service that uses it afterwards.")}
          >
            <Fields>
              <Field
                label={t("Service principal")}
                hint={t("service/host.fqdn, optionally @REALM. The host's own principal (host/) is replaced by a re-join, not renewed.")}
                wide
              >
                <input
                  value={principal}
                  onChange={(event) => setPrincipal(event.target.value)}
                  placeholder={`HTTP/${host.hostname}`}
                  data-testid="principal"
                />
              </Field>
            </Fields>
            {principalName !== "" && !principalValid && (
              <Problem>{t("This is not a service principal: expected service/host.example.test, and not host/.")}</Problem>
            )}
            <Actions>
              <Guard action="identity.keytab.renew" host={host.id}>
                <Button disabled={!principalValid || keytab.busy} testId="renew" onClick={() => setAsking("keytab")}>
                  {t("Renew the keytab…")}
                </Button>
              </Guard>
            </Actions>
            {keytab.job && <JobNotice job={keytab.job} hostID={host.id} />}
          </Card>
        ),
        leave: enrolled && mayLeave && (
          <Card
            title={t("Leave the domain")}
            note={t("The host unenrolls itself with its own keytab and restores the files the join changed. Directory accounts stop signing in here at once; the entry in the directory stays, and a new join needs a new one-time password.")}
          >
            <Actions>
              <Guard action="identity.host.leave" host={host.id}>
                <Button kind="danger" disabled={leave.busy} testId="leave" onClick={() => setAsking("leave")}>
                  {t("Leave domain")}
                </Button>
              </Guard>
            </Actions>
            {leave.job && <JobNotice job={leave.job} hostID={host.id} />}
          </Card>
        ),
      }} />

      {asking === "join" && "domain_enroll" in payload && (
        <Confirm
          host={host}
          title={t("Join the domain")}
          label={t("Join the domain")}
          busy={join.busy}
          testId="confirm-join"
          onClose={() => setAsking(null)}
          onConfirm={(reason, confirmation) => {
            join.send({ action: "identity.host.enroll", reason, target_confirmation: confirmation, payload });
            setAsking(null);
          }}
        >
          {t("{host} joins {realm} as {name}. Authentication for the whole host changes: directory accounts sign in here once SSSD is configured.", {
            host: host.hostname,
            realm: payload.domain_enroll.realm,
            name: payload.domain_enroll.hostname,
          })}
        </Confirm>
      )}
      {asking === "keytab" && (
        <Confirm
          host={host}
          title={t("Renew the keytab")}
          label={t("Renew the keytab")}
          busy={keytab.busy}
          testId="confirm-keytab"
          onClose={() => setAsking(null)}
          onConfirm={(reason, confirmation) => {
            keytab.send({
              action: "identity.keytab.renew",
              reason,
              target_confirmation: confirmation,
              payload: { keytab: { principal: principalName } },
            });
            setAsking(null);
          }}
        >
          {t("The key of {principal} on {host} is replaced. The service cannot authenticate between the fetch and its restart.", {
            principal: principalName, host: host.hostname,
          })}
        </Confirm>
      )}
      {asking === "leave" && (
        <Confirm
          host={host}
          title={t("Leave domain")}
          label={t("Leave domain")}
          busy={leave.busy}
          testId="confirm-leave"
          onClose={() => setAsking(null)}
          onConfirm={(reason, confirmation) => {
            leave.send({
              action: "identity.host.leave",
              reason,
              target_confirmation: confirmation,
              payload: { domain_leave: { domain: host.identity.domain, realm: host.identity.realm } },
            });
            setAsking(null);
          }}
        >
          {t("{host} will leave {realm}. Every directory account loses this host the moment SSSD is reconfigured.", {
            host: host.hostname, realm: host.identity.realm ?? "",
          })}
        </Confirm>
      )}
    </>
  );
}

/* -------------------------------------------------------- the preflight */

/** The checks of a preflight, one row each. */
function PreflightResult({ attempt, blocked }: { attempt: ReadAttempt<EnrollDetail>; blocked: number }) {
  const t = useT();
  const checks = attempt.detail?.checks ?? [];
  return (
    <Card
      title={t("Preflight")}
      note={attempt.message}
      foot={blocked > 0
        ? t("{n} blocking check(s) failed: fix the host before ordering the join.", { n: blocked })
        : undefined}
      flush
    >
      <Note>
        {attempt.status === "succeeded"
          ? <Pill tone="ok">{t("the host meets the conditions")}</Pill>
          : <Pill tone="error">{attempt.error_code || attempt.status}</Pill>}
      </Note>
      <Table
        rows={checks}
        keyOf={(check) => check.name}
        testId="preflight-result"
        empty={t("The host answered with no checks.")}
        columns={[
          { key: "name", head: t("Check"), tight: true, cell: (check) => (
            <>
              {check.name}
              {check.blocking && <> <Pill tone="neutral">{t("blocking")}</Pill></>}
            </>
          ) },
          { key: "result", head: t("Result"), cell: (check) => (
            check.passed === null || check.passed === undefined
              ? <Unknown />
              : check.passed
                ? <Pill tone="ok">{t("passed")}</Pill>
                : <Pill tone={check.blocking ? "error" : "warn"}>{t("failed")}</Pill>
          ) },
          { key: "detail", head: t("Detail"), cell: (check) => check.detail || "—" },
        ]}
      />
    </Card>
  );
}

/* ----------------------------------------------------------- the policy */

/**
 * What happens to directory logins when the directory is unreachable. The
 * facts come from sssd.conf; the verdict is the panel's reading of them.
 */
function OfflinePolicy({ policy, verdict }: { policy?: SssdOfflinePolicy; verdict?: OfflineVerdict }) {
  const t = useT();
  const defaulted = new Set(policy?.defaulted ?? []);

  const flag = (key: string, value: boolean | undefined) => {
    if (value === undefined) return <Unknown />;
    return (
      <>
        {value ? t("yes") : t("no")}
        {defaulted.has(key) && <> <Pill tone="neutral">{t("default")}</Pill></>}
      </>
    );
  };
  const number = (key: string, value: number | undefined, render: (n: number) => string) => {
    if (value === undefined) return <Unknown />;
    return (
      <>
        {render(value)}
        {defaulted.has(key) && <> <Pill tone="neutral">{t("default")}</Pill></>}
      </>
    );
  };

  return (
    <Card
      title={t("Logins during a directory outage")}
      note={t("What sssd.conf on the host says about cached credentials, and what the panel concludes from it.")}
      foot={policy?.unavailable_reason
        ? <><Unknown /> {policy.unavailable_reason}</>
        : !policy
          ? t("The host has not reported its SSSD offline policy; an agent from before this check sends none.")
          : undefined}
    >
      <Facts>
        <Fact label={t("Verdict")}><VerdictChip verdict={verdict} /></Fact>
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
    </Card>
  );
}

/** The verdict as a chip, with the one sentence behind it. */
function VerdictChip({ verdict }: { verdict?: OfflineVerdict }) {
  const t = useT();
  if (!verdict) return <><Unknown /> {t("The panel has no verdict for this host yet.")}</>;
  const labels: Record<OfflineVerdict["verdict"], string> = {
    cached_logins_until: t("cached logins until {when}", { when: verdict.until ? absoluteTime(verdict.until) : "?" }),
    cached_logins_indefinitely: t("cached logins indefinitely"),
    no_cached_logins: t("no cached logins"),
    unknown: t("unknown"),
  };
  // No cache during an outage locks everybody out; before the outage it is
  // a warning about what the outage would do.
  const tones: Record<OfflineVerdict["verdict"], Tone> = {
    cached_logins_until: "ok",
    cached_logins_indefinitely: "ok",
    no_cached_logins: verdict.in_force ? "error" : "warn",
    unknown: "unknown",
  };
  return (
    <>
      <Pill tone={tones[verdict.verdict]}>{labels[verdict.verdict]}</Pill>
      {verdict.in_force && <> <Pill tone="warn">{t("outage in progress")}</Pill></>}
      {" "}
      <span>{verdict.reason}</span>
    </>
  );
}

/* ------------------------------------------------------ the local policy */

/** The rules of the host's own sudoers files, as the helper parsed them. */
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
  const problems = state.problems ?? [];
  const unread = (state.files ?? []).filter((file) => file.reason);

  return (
    <Card
      title={t("Local sudoers rules")}
      note={t("What /etc/sudoers and its drop-ins grant on this host, as the helper parsed them. A rule that names other hosts is listed but does not reach this one.")}
      foot={state.read
        ? (
          <>
            {problems.length > 0 && (
              <Note>
                <Unknown />{" "}
                {t("{count} lines were not understood and may grant something the table does not show: {where}", {
                  count: problems.length,
                  where: problems.map((problem) => `${problem.source}:${problem.line}`).join(", "),
                })}
              </Note>
            )}
            {unread.length > 0 && (
              <Note>
                <Unknown />{" "}
                {t("Files not read: {files}", {
                  files: unread.map((file) => `${file.path} (${file.reason})`).join("; "),
                })}
              </Note>
            )}
            <span title={state.observed_at ? absoluteTime(state.observed_at) : undefined}>
              {t("Read from {files} files", { files: (state.files ?? []).length })}
              {state.observed_at ? ` · ${relativeTime(state.observed_at)}` : ""}
            </span>
          </>
        )
        : undefined}
      flush
    >
      {!state.read ? (
        <Note><Unknown /> {state.reason}</Note>
      ) : (
        <Table
          rows={rules}
          keyOf={(rule) => `${rule.source}:${rule.line}:${rule.commands.join(",")}:${rule.nopasswd}`}
          empty={t("The local sudoers files grant nothing.")}
          columns={[
            { key: "who", head: t("Who"), cell: (rule) => (
              <>
                {rule.all_users ? t("every user") : rule.users.join(", ")}
                {(rule.reached_users ?? []).length > 0 && !rule.all_users
                  && rule.users.some((user) => user.startsWith("%") || user.startsWith("#")) && (
                    <Note>{t("members: {users}", { users: (rule.reached_users ?? []).join(", ") })}</Note>
                  )}
              </>
            ) },
            { key: "hosts", head: t("Hosts"), minor: true, cell: (rule) => rule.reaches_host
              ? rule.via.join(", ")
              : <Pill tone="unknown" title={rule.hosts.join(", ")}>{t("not this host")}</Pill> },
            { key: "commands", head: t("Commands"), tight: true, cell: (rule) => rule.all_commands ? t("every command") : rule.commands.join(", ") },
            { key: "runas", head: t("Run as"), minor: true, cell: (rule) => runAs(rule) },
            { key: "password", head: t("Password"), cell: (rule) => rule.nopasswd || state.passwordless_globally
              ? <Pill tone="warn">{t("none")}</Pill>
              : t("required") },
            { key: "risk", head: t("Risk"), cell: (rule) => rule.root_equivalent
              ? <Pill tone="error" title={(rule.critical_reasons ?? []).join("; ")}>{t("root")}</Pill>
              : rule.critical
                ? <Pill tone="warn" title={(rule.critical_reasons ?? []).join("; ")}>{t("critical")}</Pill>
                : "—" },
            { key: "source", head: t("Source"), tight: true, minor: true, cell: (rule) => `${rule.source}:${rule.line}` },
          ]}
        />
      )}
    </Card>
  );
}

/** The containers this module can draw, and the shape each ships with. */
export const HOST_IDENTITY: BoardEntry[] = [
  { key: "domain", title: "Domain", width: 6, height: 4 },
  { key: "client", title: "Directory client", width: 6, height: 4 },
  { key: "offline", title: "Logins during a directory outage", width: 6, height: 4 },
  { key: "access", title: "Effective access", width: 6, height: 4 },
  { key: "hbac", title: "HBAC rules reaching this host", width: 12, height: 5 },
  { key: "sudo", title: "sudo rules reaching this host", width: 12, height: 5 },
  { key: "localsudo", title: "Local sudoers rules", width: 12, height: 5 },
  { key: "join", title: "Join the domain", width: 12, height: 5 },
  { key: "preflight", title: "Preflight", width: 12, height: 5 },
  { key: "keytab", title: "Renew a keytab", width: 6, height: 4 },
  { key: "leave", title: "Leave the domain", width: 6, height: 4 },
];

/** The name this module's arrangement is stored under. */
export const HOST_IDENTITY_SCREEN = "next_host_identity";
