import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../../lib/api";
import { absoluteTime, relativeTime } from "../../lib/format";
import { copyToClipboard } from "../../lib/clipboard";
import type {
  AccessSimulation, DirectoryChange, DirectoryGroup, DirectoryHost, DirectoryHostGroup,
  DirectoryService, DirectoryUser, HBACRule, Host, IdentityStatus, RevealedSecret, SudoRule,
} from "../../lib/types";
import { useT } from "../../i18n";
import type { Translate } from "../../i18n";
import {
  Actions, Banner, C, Form, Bones, Card, Check, Empty, Fact, Facts, Field, Fields, Fig, Figs, Find, Grid,
  Kpi, Kpis, Modal, Note, Pie, Pill, Problem, Ring, Screen, Stack, Table, Tabs, Tag, Tags, type Tone,
  TwoLine, useTab,
} from "../kit";

/**
 * The identity directory: the objects the panel manages in somebody else's
 * database.
 *
 * The panel does not own a single record on this screen. It reads them, and
 * a change made here is a change *asked* of the directory: planned first,
 * approved by a second person, and only then carried out. That is why every
 * writing card ends in "Plan …" rather than "Save", and why the plan's own
 * answer - the hosts it reaches, the users it reaches, the conflicts - is
 * drawn before anybody can approve anything.
 *
 * A field the directory did not send is an em dash. A directory that has
 * not said whether a keytab is on record has not said "no", and the screen
 * keeps the three answers apart.
 */

export type Tab =
  | "users" | "groups" | "hbac" | "sudo" | "hosts" | "host-groups" | "ssh-keys"
  | "services" | "dns" | "health";

/** The tab key is an identifier in code, not a caption for the operator. */
const TAB_TITLES: Record<Tab, string> = {
  users: "Users",
  groups: "Groups",
  hbac: "HBAC rules",
  sudo: "sudo rules",
  hosts: "Hosts",
  "host-groups": "Host groups",
  "ssh-keys": "SSH keys",
  services: "Services",
  dns: "DNS",
  health: "Integration health",
};

const TABS: Tab[] = [
  "users", "groups", "hbac", "sudo", "hosts", "host-groups", "ssh-keys", "services", "dns", "health",
];

/** The least a reason may be before the server takes it. */
export const REASON_MINIMUM = 8;

/** Splits a comma-separated field into names; blanks fall out. */
export function names(text: string): string[] {
  return text.split(",").map((item) => item.trim()).filter(Boolean);
}

/** Splits a textarea into lines; blanks fall out. */
export function lines(text: string): string[] {
  return text.split("\n").map((item) => item.trim()).filter(Boolean);
}

/** What a change does, in words rather than in its action identifier. */
const ACTION_NAMES: Record<string, string> = {
  "identity.user.create": "Create an account",
  "identity.user.enable": "Unlock an account",
  "identity.user.disable": "Lock an account",
  "identity.user.expire": "Set the expiry of an account",
  "identity.user.password.reset": "Reset a password",
  "identity.user.posix": "Change the POSIX data of an account",
  "identity.user.preserve": "Preserve an account",
  "identity.user.delete": "Delete an account",
  "identity.group.members": "Change the members of a group",
  "identity.hostgroup.members": "Change the members of a host group",
  "identity.sshkeys.set": "Set the SSH keys of an account",
  "identity.hbac.rule.ensure": "Set an HBAC rule",
  "identity.hbac.rule.remove": "Remove an HBAC rule",
  "identity.sudo.rule.ensure": "Set a sudo rule",
  "identity.sudo.rule.remove": "Remove a sudo rule",
  "identity.host.enroll": "Join a host to the domain",
  "identity.host.leave": "Take a host out of the domain",
  "identity.host.preflight": "Check a host before joining",
  "identity.keytab.rotate": "Rotate the keytab",
  "identity.keytab.renew": "Renew the keytab",
};

export function actionName(type: string): string {
  return ACTION_NAMES[type] ?? type;
}

/* ------------------------------------------------------------- the screen */

export function Directory() {
  const t = useT();
  const [tab, setTab] = useTab(TABS);

  const status = useQuery({
    queryKey: ["identity-status"],
    queryFn: () => api.get<IdentityStatus>("/api/v1/identity/status"),
  });

  const lead = status.data?.configured === false
    ? t("No directory connector is configured.")
    : status.data?.reachable
      ? t("{summary} · connector {principal}", {
          summary: status.data.summary ?? "", principal: status.data.principal ?? "—",
        })
      : status.data?.error
        ? t("Directory unavailable: {error}", { error: status.data.error })
        : undefined;

  return (
    <Screen
      icon="directory"
      title={t("Identity directory")}
      lead={lead}
      help={
        <p>
          {t("What the identity directory holds about the fleet, as the panel reads it. The panel owns none of these records: it reads them, and a change made here is a change asked of the directory - planned first, with the hosts and users it would reach named in the plan, approved by a second person with a reason, and only then carried out. A field the directory did not send is drawn as unknown and never as an empty one, because a directory that said nothing about a keytab has not said there is none.")}
        </p>
      }
      banner={status.data?.configured === false
        ? <Banner tone="warn">{t("No directory connector is configured. Nothing on this screen can be read or changed until one is.")}</Banner>
        : status.error
          ? <Banner tone="error">{t("The panel could not read the state of its directory connector: {error}", { error: String(status.error) })}</Banner>
          : undefined}
    >
      <Tabs
        value={tab}
        onChange={setTab}
        tabs={TABS.map((key) => ({ value: key, label: t(TAB_TITLES[key]) }))}
      />

      {tab === "users" && <UsersTab />}
      {tab === "groups" && <GroupsTab />}
      {tab === "hbac" && <HBACTab />}
      {tab === "sudo" && <SudoTab />}
      {tab === "hosts" && <HostsTab />}
      {tab === "host-groups" && <HostGroupsTab />}
      {tab === "ssh-keys" && <SshKeysTab />}
      {tab === "services" && <ServicesTab />}
      {tab === "dns" && <DNSTab />}
      {tab === "health" && <HealthTab />}
    </Screen>
  );
}

/* -------------------------------------------------------- the shared parts */

/** A read the signed-in person may not make. It says so and stops there. */
function Forbidden() {
  const t = useT();
  return (
    <Card>
      <Empty icon="help">{t("You do not have permission to read this resource.")}</Empty>
    </Card>
  );
}

/** The reason every change of access carries, as its own field. */
function Reason({ value, onChange, placeholder, testId }: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  testId?: string;
}) {
  const t = useT();
  return (
    <Field
      label={t("Reason")}
      wide
      hint={t("A change of access is recorded with a reason of at least {n} characters and fresh authentication.", { n: REASON_MINIMUM })}
    >
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder ?? t("why this changes")}
        data-testid={testId ?? "reason"}
      />
    </Field>
  );
}

/** A field holding a list of names, typed as one comma-separated line. */
function ListField({ label, value, onChange, placeholder, disabled, testId }: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  disabled?: boolean;
  testId?: string;
}) {
  return (
    <Field label={label}>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        disabled={disabled}
        data-testid={testId}
      />
    </Field>
  );
}

/** A yes / no / unknown badge: the directory not saying is not the same as "no". */
function TriState({ value, yes, no }: { value: boolean | null | undefined; yes: string; no: string }) {
  const t = useT();
  if (value === true) return <Pill tone="ok">{yes}</Pill>;
  if (value === false) return <Pill tone="neutral">{no}</Pill>;
  return <Pill tone="unknown">{t("unknown")}</Pill>;
}

/** A list of names as the directory holds it, or an em dash where it holds none. */
function Names({ items }: { items?: string[] }) {
  if (!items || items.length === 0) return <>—</>;
  return <Tags>{items.map((one) => <Tag key={one}><code>{one}</code></Tag>)}</Tags>;
}

/**
 * The impact of a planned change, as the plan came back.
 *
 * This is the whole reason a change is planned rather than done: the hosts
 * and users it reaches, the steps it would take, and the conflicts that
 * stop it being approved at all.
 */
function PlanImpact({ change }: { change: DirectoryChange }) {
  const t = useT();
  const plan = change.plan;
  if (!plan) return null;
  const conflicts = plan.conflicts ?? [];
  const warnings = plan.warnings ?? [];
  return (
    <Card
      span={12}
      title={plan.summary}
      note={conflicts.length
        ? t("Change {id} is blocked by conflicts and cannot be approved.", { id: change.id.slice(0, 8) })
        : t("Change {id} is {state}; a second person approves it with a reason.", {
            id: change.id.slice(0, 8), state: change.state.replace("_", " "),
          })}
    >
      <Stack>
        {conflicts.map((conflict, index) => (
          <Banner key={`conflict-${index}`} tone="error">{conflict}</Banner>
        ))}
        {warnings.map((warning, index) => (
          <Banner key={`warning-${index}`} tone="warn">{warning}</Banner>
        ))}
        {(plan.steps ?? []).length > 0 && (
          <Facts>
            {(plan.steps ?? []).map((step, index) => (
              <Fact key={index} label={t("Step {n}", { n: index + 1 })}>{step}</Fact>
            ))}
          </Facts>
        )}
        <Facts>
          <Fact label={t("Hosts reached ({n})", { n: (plan.reachable_hosts ?? []).length })}>
            <Names items={plan.reachable_hosts} />
          </Fact>
          <Fact label={t("Users reached ({n})", { n: (plan.affected_users ?? []).length })}>
            <Names items={plan.affected_users} />
          </Fact>
          {(plan.sudo_rules ?? []).length > 0 && (
            <Fact label={t("sudo rules reached ({n})", { n: (plan.sudo_rules ?? []).length })}>
              <Names items={plan.sudo_rules} />
            </Fact>
          )}
        </Facts>
      </Stack>
    </Card>
  );
}

/** Orders a directory change and keeps the answer for the impact card. */
function useDirectoryChange(invalidate: string[]) {
  const t = useT();
  const queryClient = useQueryClient();
  const [change, setChange] = useState<DirectoryChange | null>(null);
  const [message, setMessage] = useState("");
  const mutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post<DirectoryChange>("/api/v1/identity/changes", body),
    onSuccess: (result) => {
      setChange(result);
      setMessage("");
      for (const key of invalidate) queryClient.invalidateQueries({ queryKey: [key] });
      queryClient.invalidateQueries({ queryKey: ["directory-changes"] });
    },
    onError: (error) => {
      setChange(null);
      setMessage(error instanceof ApiError && error.code === "reason_required"
        ? t("A change of access needs a reason of at least {n} characters.", { n: REASON_MINIMUM })
        : error instanceof Error ? error.message : String(error));
    },
  });
  return { mutation, change, message };
}

/**
 * The confirmation of a change the panel cannot undo: preserving an
 * account, resetting its password, retiring a keytab.
 *
 * It is a modal because it is a decision and not a form, and it asks for
 * the name to be typed because the cost of doing it to the wrong target is
 * somebody locked out of a machine they are standing in front of.
 */
function Confirm({ target, title, description, label, busy, danger, onConfirm, onCancel }: {
  target: string;
  title: string;
  description: string;
  label: string;
  busy: boolean;
  danger?: boolean;
  onConfirm: (reason: string) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [typed, setTyped] = useState("");
  const ready = reason.trim().length >= REASON_MINIMUM && typed === target;
  return (
    <Modal
      title={title}
      onClose={onCancel}
      actions={
        <>
          <button type="button" className="fl-quiet" onClick={onCancel} disabled={busy}>{t("Cancel")}</button>
          <button
            type="button"
            className={danger ? "fl-danger" : undefined}
            disabled={!ready || busy}
            onClick={() => onConfirm(reason)}
            data-testid="confirm"
          >
            {busy ? t("Requesting…") : label}
          </button>
        </>
      }
    >
      <Stack>
        <Note>{description}</Note>
        <Fields>
          <Field label={t("Type the name to confirm")} hint={target}>
            <input value={typed} onChange={(event) => setTyped(event.target.value)} data-testid="confirm-target" />
          </Field>
          <Reason value={reason} onChange={setReason} testId="confirm-reason" />
        </Fields>
      </Stack>
    </Modal>
  );
}

/** What went wrong with a read, in the one shape every tab uses. */
function readProblem(error: unknown): ReactNode {
  if (error instanceof ApiError && error.forbidden) return <Forbidden />;
  if (error) return <Problem>{error instanceof Error ? error.message : String(error)}</Problem>;
  return null;
}

/* ---------------------------------------------------------------- accounts */

const EMPTY_USER = { uid: "", first_name: "", last_name: "", email: "", shell: "", groups: "", ssh_keys: "" };
type UserForm = typeof EMPTY_USER;

type Intent = "disable" | "enable" | "expire" | "posix" | "preserve" | "password";

const DAY = 24 * 60 * 60 * 1000;

/** A datetime-local value for an RFC3339 stamp, in the browser's zone. */
function localInput(value?: string): string {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/** RFC3339 for a datetime-local value; the browser's zone is what the operator meant. */
function rfc3339(local: string): string {
  return local ? new Date(local).toISOString() : "";
}

/** The expiry of an account as a pill: past is red, a fortnight out amber. */
function Expiry({ value, label }: { value?: string; label: string }) {
  const t = useT();
  if (!value) return null;
  const at = new Date(value).getTime();
  // The date in the ISO shape every screen uses, not the browser locale's:
  // two operators reading the same account must read the same day.
  const text = `${label} ${absoluteTime(value).slice(0, 10)}`;
  if (Number.isNaN(at)) return <Pill tone="unknown" title={value}>{label}</Pill>;
  const left = at - Date.now();
  if (left < 0) return <Pill tone="error" title={absoluteTime(value)}>{t("{what} expired", { what: text })}</Pill>;
  if (left < 14 * DAY) return <Pill tone="warn" title={absoluteTime(value)}>{text}</Pill>;
  return <Pill tone="neutral" title={absoluteTime(value)}>{text}</Pill>;
}

function UsersTab() {
  const t = useT();
  const [form, setForm] = useState<UserForm | null>(null);
  const [reason, setReason] = useState("");
  const [picked, setPicked] = useState("");
  const [intent, setIntent] = useState<Intent | null>(null);
  const { mutation, change, message } = useDirectoryChange(["identity-users", "identity-users-preserved"]);

  const { data, error, isLoading } = useQuery({
    queryKey: ["identity-users"],
    queryFn: () => api.get<Collection<DirectoryUser>>("/api/v1/identity/users"),
    retry: false,
  });
  // The preserved accounts are read separately: they are not accounts
  // anybody signs in with, and a list that mixed them in would count them
  // as users.
  const preserved = useQuery({
    queryKey: ["identity-users-preserved"],
    queryFn: () => api.get<Collection<DirectoryUser>>("/api/v1/identity/users?preserved=true"),
    retry: false,
  });

  const problem = readProblem(error);
  if (problem) return problem;

  const users = data?.items ?? [];
  const chosen = users.find((one) => one.uid === picked);
  const locked = data ? users.filter((one) => one.disabled).length : null;

  const set = <K extends keyof UserForm>(key: K, value: UserForm[K]) =>
    setForm((current) => (current ? { ...current, [key]: value } : current));

  const order = (action: string, payload: Record<string, unknown>, why: string) => {
    mutation.mutate({ action, reason: why, payload }, { onSuccess: () => { setIntent(null); setForm(null); } });
  };

  return (
    <>
      <Kpis>
        <Kpi hero icon="accounts" label={t("Accounts")} value={data ? users.length : null}
             note={t("the directory's own, not the panel's")} testId="kpi-accounts" />
        <Kpi icon="security" label={t("Locked")} value={locked} tone={locked ? "warn" : "ok"}
             note={t("no Kerberos login until unlocked")} testId="kpi-locked" />
        <Kpi icon="files" label={t("Preserved")} value={preserved.data ? preserved.data.items.length : null}
             note={t("soft-deleted; the UID and the trail stay")} testId="kpi-preserved" />
      </Kpis>

      <Grid>
        <Card span={12}>
          <Note>
            {t("An account is created, locked, expired, preserved or given a new password as a change: the plan shows the groups, the hosts reachable through HBAC and the sudo rules, a second person approves it, and every phase keeps its own result. The initial password never reaches the logs.")}
          </Note>
        </Card>

        <Card
          span={8}
          title={t("Accounts")}
          flush
          tools={
            <button type="button" className="fl-quiet fl-small" data-testid="new-account"
                    onClick={() => { setForm({ ...EMPTY_USER }); setIntent(null); }}>
              {t("New account")}
            </button>
          }
          foot={data ? t("{n} accounts", { n: users.length }) : undefined}
        >
          <Table
            rows={users}
            keyOf={(one) => one.uid}
            testId="accounts"
            rowTestId={(one) => `account-${one.uid}`}
            empty={isLoading ? t("Reading the directory…") : t("The directory holds no accounts.")}
            columns={[
              {
                key: "uid",
                head: t("Account"),
                tight: true,
                cell: (one) => (
                  <TwoLine sub={[one.first_name, one.last_name].filter(Boolean).join(" ") || undefined}>
                    <button type="button" className="fl-word" data-testid={`pick-${one.uid}`}
                            onClick={() => { setPicked(one.uid); setIntent(null); }}>
                      {one.uid}
                    </button>
                  </TwoLine>
                ),
              },
              { key: "uid_number", head: "UID", num: true, minor: true, cell: (one) => one.uid_number || "—" },
              { key: "groups", head: t("Groups"), minor: true, cell: (one) => <Names items={one.groups} /> },
              {
                key: "keys",
                head: t("SSH keys"),
                num: true,
                // A directory that sent no list of fingerprints has not said
                // the account has none.
                cell: (one) => one.ssh_key_fingerprints?.length ?? "—",
              },
              {
                key: "expiry",
                head: t("Expires"),
                cell: (one) => !one.principal_expires_at && !one.password_expires_at ? "—" : (
                  <Stack>
                    <Expiry value={one.principal_expires_at} label={t("account")} />
                    <Expiry value={one.password_expires_at} label={t("password")} />
                  </Stack>
                ),
              },
              {
                key: "state",
                head: t("State"),
                cell: (one) => one.disabled
                  ? <Pill tone="error">{t("locked")}</Pill>
                  : <Pill tone="ok">{t("active")}</Pill>,
              },
            ]}
          />
        </Card>

        <Card
          span={4}
          title={chosen ? chosen.uid : t("The account")}
          note={chosen
            ? t("Everything the directory holds, and everything the panel may ask of it.")
            : t("Pick an account to read it and to act on it.")}
        >
          {!chosen
            ? <Empty icon="accounts">{t("Pick an account from the list to read what the directory holds about it.")}</Empty>
            : (
              <Stack>
                <Facts>
                  <Fact label={t("Full name")}>{[chosen.first_name, chosen.last_name].filter(Boolean).join(" ") || "—"}</Fact>
                  <Fact label={t("State")}>
                    {chosen.disabled ? <Pill tone="error">{t("locked")}</Pill> : <Pill tone="ok">{t("active")}</Pill>}
                  </Fact>
                  <Fact label="UID">{chosen.uid_number || "—"}</Fact>
                  <Fact label="GID">{chosen.gid_number || "—"}</Fact>
                  <Fact label={t("Shell")}>{chosen.shell ? <code>{chosen.shell}</code> : "—"}</Fact>
                  <Fact label={t("Home directory")}>{chosen.home_directory ? <code>{chosen.home_directory}</code> : "—"}</Fact>
                  <Fact label={t("Groups")}><Names items={chosen.groups} /></Fact>
                  <Fact label={t("SSH fingerprints")}><Names items={chosen.ssh_key_fingerprints} /></Fact>
                  <Fact label={t("Last password change")}>
                    {chosen.last_password_change
                      ? <span title={absoluteTime(chosen.last_password_change)}>{relativeTime(chosen.last_password_change)}</span>
                      : "—"}
                  </Fact>
                </Facts>
                <Actions>
                  <button type="button" className="fl-quiet fl-small" data-testid="act-lock"
                          onClick={() => { setIntent(chosen.disabled ? "enable" : "disable"); setForm(null); setReason(""); }}>
                    {chosen.disabled ? t("Unlock…") : t("Lock…")}
                  </button>
                  <button type="button" className="fl-quiet fl-small" data-testid="act-expire"
                          onClick={() => { setIntent("expire"); setForm(null); }}>
                    {t("Expire…")}
                  </button>
                  <button type="button" className="fl-quiet fl-small" data-testid="act-posix"
                          onClick={() => { setIntent("posix"); setForm(null); }}>
                    {t("POSIX…")}
                  </button>
                  <button type="button" className="fl-quiet fl-small" data-testid="act-password"
                          onClick={() => { setIntent("password"); setForm(null); }}>
                    {t("Reset password…")}
                  </button>
                  <button type="button" className="fl-danger fl-small" data-testid="act-preserve"
                          onClick={() => { setIntent("preserve"); setForm(null); }}>
                    {t("Preserve…")}
                  </button>
                </Actions>
              </Stack>
            )}
        </Card>

        {form && (
          <C span={12}>
            <Form
            title={t("New account")}
            actions={
              <Actions>
                <button
                  type="button"
                  disabled={!form.uid || !form.last_name || reason.trim().length < REASON_MINIMUM || mutation.isPending}
                  data-testid="plan-account"
                  onClick={() => order("identity.user.create", {
                    user: {
                      uid: form.uid.trim(), first_name: form.first_name.trim(), last_name: form.last_name.trim(),
                      email: form.email.trim(), shell: form.shell.trim(),
                      groups: names(form.groups), ssh_keys: lines(form.ssh_keys),
                    },
                  }, reason)}
                >
                  {t("Plan account")}
                </button>
                <button type="button" className="fl-quiet" onClick={() => setForm(null)}>{t("Close")}</button>
              </Actions>
            }
          >
            <Stack>
              {message && <Problem>{message}</Problem>}
              <Fields>
                <Field label={t("Account")}>
                  <input value={form.uid} onChange={(e) => set("uid", e.target.value)} placeholder="jsmith" data-testid="new-uid" />
                </Field>
                <Field label={t("First name")}>
                  <input value={form.first_name} onChange={(e) => set("first_name", e.target.value)} />
                </Field>
                <Field label={t("Surname")}>
                  <input value={form.last_name} onChange={(e) => set("last_name", e.target.value)} data-testid="new-surname" />
                </Field>
                <Field label={t("E-mail")}>
                  <input value={form.email} onChange={(e) => set("email", e.target.value)} placeholder="jsmith@example.test" />
                </Field>
                <Field label={t("Shell")}>
                  <input value={form.shell} onChange={(e) => set("shell", e.target.value)} placeholder="/bin/bash" />
                </Field>
                <ListField label={t("Groups")} value={form.groups} onChange={(v) => set("groups", v)} placeholder="ops, developers" />
                <Field
                  label={t("SSH public keys, one per line")}
                  wide
                  hint={t("A private key never reaches the system; only the public half is accepted.")}
                >
                  <textarea rows={3} value={form.ssh_keys} onChange={(e) => set("ssh_keys", e.target.value)}
                            placeholder="ssh-ed25519 AAAA… user@host" />
                </Field>
                <Reason value={reason} onChange={setReason} />
              </Fields>
            </Stack>
          </Form>
          </C>
        )}

        {intent === "expire" && chosen && (
          <ExpireCard
            user={chosen}
            busy={mutation.isPending}
            message={message}
            onSubmit={(payload, why) => order("identity.user.expire", payload, why)}
            onClose={() => setIntent(null)}
          />
        )}

        {intent === "posix" && chosen && (
          <PosixCard
            user={chosen}
            busy={mutation.isPending}
            message={message}
            onSubmit={(payload, why) => order("identity.user.posix", payload, why)}
            onClose={() => setIntent(null)}
          />
        )}

        {change && <PlanImpact change={change} />}
        {change && change.action_type === "identity.user.password.reset" && (
          <Card span={12}>
            <Note>
              {t("The reset waits for a second person's approval. Once it is carried out, the one-time password appears under recent changes for the person who ordered it.")}
            </Note>
          </Card>
        )}
        {message && !form && !intent && <Card span={12}><Problem>{message}</Problem></Card>}

        <Card
          span={12}
          title={t("Preserved accounts")}
          note={t("Soft-deleted entries: the UID and the trail stay, nobody signs in. They are listed apart so they are not counted as users.")}
          flush
        >
          {preserved.error
            ? <Problem>{String(preserved.error)}</Problem>
            : (
              <Table
                rows={preserved.data?.items ?? []}
                keyOf={(one) => one.uid}
                testId="preserved"
                rowTestId={(one) => `preserved-${one.uid}`}
                empty={preserved.isLoading ? t("Reading the directory…") : t("No preserved accounts.")}
                columns={[
                  { key: "uid", head: t("Account"), tight: true, cell: (one) => <code>{one.uid}</code> },
                  { key: "name", head: t("Full name"), cell: (one) => [one.first_name, one.last_name].filter(Boolean).join(" ") || "—" },
                  { key: "uid_number", head: "UID", num: true, cell: (one) => one.uid_number || "—" },
                  {
                    key: "password",
                    head: t("Last password change"),
                    cell: (one) => one.last_password_change
                      ? <span title={absoluteTime(one.last_password_change)}>{relativeTime(one.last_password_change)}</span>
                      : "—",
                  },
                ]}
              />
            )}
        </Card>

        <RecentChanges />
      </Grid>

      {/* Locking an account is a decision: the denial marker and the panel
          sessions go first, the directory second. */}
      {chosen && (intent === "disable" || intent === "enable") && (
        <Modal
          title={intent === "disable"
            ? t("Lock the account {uid}", { uid: chosen.uid })
            : t("Unlock the account {uid}", { uid: chosen.uid })}
          onClose={() => { setIntent(null); setReason(""); }}
          actions={
            <>
              <button type="button" className="fl-quiet" onClick={() => { setIntent(null); setReason(""); }}>
                {t("Cancel")}
              </button>
              <button
                type="button"
                disabled={reason.trim().length < REASON_MINIMUM || mutation.isPending}
                data-testid="plan-lock"
                onClick={() => order(`identity.user.${intent}`, { reference: { uid: chosen.uid, reason } }, reason)}
              >
                {intent === "disable" ? t("Plan lock") : t("Plan unlock")}
              </button>
            </>
          }
        >
          <Stack>
            <Note>
              {intent === "disable"
                ? t("The local denial marker and the panel sessions go first, the directory second: the reverse order would leave a working session for the time the change takes to propagate.")
                : t("The directory unlocks the account and the panel lifts its denial marker.")}
            </Note>
            {message && <Problem>{message}</Problem>}
            <Fields><Reason value={reason} onChange={setReason} testId="lock-reason" /></Fields>
          </Stack>
        </Modal>
      )}

      {chosen && intent === "preserve" && (
        <Confirm
          target={chosen.uid}
          danger
          title={t("Preserve the account {uid}", { uid: chosen.uid })}
          label={t("Plan preservation")}
          description={t("The account is locked, its panel sessions end, and the entry moves to the preserved accounts: it keeps its UID and its trail but nobody signs in with it. The panel cannot bring it back.")}
          busy={mutation.isPending}
          onConfirm={(why) => order("identity.user.preserve", { reference: { uid: chosen.uid, reason: why } }, why)}
          onCancel={() => setIntent(null)}
        />
      )}

      {chosen && intent === "password" && (
        <Confirm
          target={chosen.uid}
          title={t("Reset the password of {uid}", { uid: chosen.uid })}
          label={t("Plan password reset")}
          description={t("The directory generates a one-time password that expires on first login. After a second person approves the change, the person who ordered it reads the password once from the recent changes below; it is neither stored nor written to the audit trail.")}
          busy={mutation.isPending}
          onConfirm={(why) => order("identity.user.password.reset", { reference: { uid: chosen.uid } }, why)}
          onCancel={() => setIntent(null)}
        />
      )}
    </>
  );
}

/**
 * The expiry of an account: the Kerberos principal (no ticket after the
 * date) and the password (a change forced at the next login).
 */
function ExpireCard({ user, busy, message, onSubmit, onClose }: {
  user: DirectoryUser;
  busy: boolean;
  message: string;
  onSubmit: (payload: Record<string, unknown>, reason: string) => void;
  onClose: () => void;
}) {
  const t = useT();
  const [principal, setPrincipal] = useState(localInput(user.principal_expires_at));
  const [password, setPassword] = useState(localInput(user.password_expires_at));
  const [clearPrincipal, setClearPrincipal] = useState(false);
  const [clearPassword, setClearPassword] = useState(false);
  const [reason, setReason] = useState("");

  const expiry: Record<string, string> = { uid: user.uid };
  if (clearPrincipal) expiry.principal_expires_at = "";
  else if (principal) expiry.principal_expires_at = rfc3339(principal);
  if (clearPassword) expiry.password_expires_at = "";
  else if (password) expiry.password_expires_at = rfc3339(password);
  const touched = "principal_expires_at" in expiry || "password_expires_at" in expiry;

  return (
    <C span={12}>
      <Form
      title={t("Expiry of the account {uid}", { uid: user.uid })}
      note={t("The account expiry ends every Kerberos login after the date; the password expiry forces a change at the next login. A field left empty stays as it is.")}
      actions={
        <Actions>
          <button type="button" disabled={!touched || reason.trim().length < REASON_MINIMUM || busy}
                  data-testid="plan-expiry" onClick={() => onSubmit({ expiry }, reason)}>
            {t("Plan expiry")}
          </button>
          <button type="button" className="fl-quiet" onClick={onClose}>{t("Close")}</button>
        </Actions>
      }
    >
      <Stack>
        {message && <Problem>{message}</Problem>}
        <Fields>
          <Field label={t("Account expires at")}>
            <input type="datetime-local" value={principal} disabled={clearPrincipal}
                   onChange={(e) => setPrincipal(e.target.value)} data-testid="expiry-principal" />
          </Field>
          <Field label={t("Password expires at")}>
            <input type="datetime-local" value={password} disabled={clearPassword}
                   onChange={(e) => setPassword(e.target.value)} />
          </Field>
        </Fields>
        <Check checked={clearPrincipal} onChange={setClearPrincipal}>{t("Clear the account expiry")}</Check>
        <Check checked={clearPassword} onChange={setClearPassword}>{t("Clear the password expiry")}</Check>
        <Fields><Reason value={reason} onChange={setReason} testId="expiry-reason" /></Fields>
      </Stack>
    </Form>
    </C>
  );
}

/** The POSIX data of an account; only a field that differs from the directory is sent. */
function PosixCard({ user, busy, message, onSubmit, onClose }: {
  user: DirectoryUser;
  busy: boolean;
  message: string;
  onSubmit: (payload: Record<string, unknown>, reason: string) => void;
  onClose: () => void;
}) {
  const t = useT();
  const [uidNumber, setUidNumber] = useState(user.uid_number ?? "");
  const [gidNumber, setGidNumber] = useState(user.gid_number ?? "");
  const [shell, setShell] = useState(user.shell ?? "");
  const [home, setHome] = useState(user.home_directory ?? "");
  const [reason, setReason] = useState("");

  const posix: Record<string, string> = { uid: user.uid };
  if (uidNumber.trim() !== (user.uid_number ?? "")) posix.uid_number = uidNumber.trim();
  if (gidNumber.trim() !== (user.gid_number ?? "")) posix.gid_number = gidNumber.trim();
  if (shell.trim() !== (user.shell ?? "")) posix.shell = shell.trim();
  if (home.trim() !== (user.home_directory ?? "")) posix.home_directory = home.trim();
  const changed = Object.keys(posix).length > 1;

  return (
    <C span={12}>
      <Form
      title={t("POSIX data of the account {uid}", { uid: user.uid })}
      note={t("A changed UID or GID leaves the files on every host owned by the old number; the plan says so before anybody approves.")}
      actions={
        <Actions>
          <button type="button" disabled={!changed || reason.trim().length < REASON_MINIMUM || busy}
                  data-testid="plan-posix" onClick={() => onSubmit({ posix }, reason)}>
            {t("Plan POSIX change")}
          </button>
          <button type="button" className="fl-quiet" onClick={onClose}>{t("Close")}</button>
        </Actions>
      }
    >
      <Stack>
        {message && <Problem>{message}</Problem>}
        <Fields>
          <Field label="UID"><input value={uidNumber} onChange={(e) => setUidNumber(e.target.value)} data-testid="posix-uid" /></Field>
          <Field label="GID"><input value={gidNumber} onChange={(e) => setGidNumber(e.target.value)} /></Field>
          <Field label={t("Shell")}><input value={shell} onChange={(e) => setShell(e.target.value)} placeholder="/bin/bash" /></Field>
          <Field label={t("Home directory")}>
            <input value={home} onChange={(e) => setHome(e.target.value)} placeholder={`/home/${user.uid}`} />
          </Field>
          <Reason value={reason} onChange={setReason} testId="posix-reason" />
        </Fields>
      </Stack>
    </Form>
    </C>
  );
}

/**
 * The recent directory changes and, for a finished password reset, the
 * one-time password - handed to the person who ordered it, once.
 */
function RecentChanges() {
  const t = useT();
  const queryClient = useQueryClient();
  const [revealing, setRevealing] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [secret, setSecret] = useState<RevealedSecret | null>(null);
  const [copied, setCopied] = useState(false);

  const changes = useQuery({
    queryKey: ["directory-changes"],
    queryFn: () => api.get<Collection<DirectoryChange>>("/api/v1/identity/changes?limit=20"),
    retry: false,
  });

  const reveal = useMutation({
    mutationFn: (id: string) => api.post<RevealedSecret>(`/api/v1/identity/changes/${id}/reveal`, { reason }),
    onSuccess: (result) => {
      setSecret(result);
      setRevealing(null);
      setReason("");
      queryClient.invalidateQueries({ queryKey: ["directory-changes"] });
    },
  });

  const revealError = reveal.error instanceof ApiError
    ? reveal.error.code === "secret_consumed" ? t("The password was already read once; order a new reset if it is needed again.")
      : reveal.error.code === "no_secret" ? t("There is no password waiting for this change: it may have been read, or the panel restarted since.")
        : reveal.error.code === "not_requester" ? t("Only the person who ordered the reset may read the password.")
          : reveal.error.code === "reason_required" ? t("A change of access needs a reason of at least {n} characters.", { n: REASON_MINIMUM })
            : reveal.error.message
    : reveal.error instanceof Error ? reveal.error.message : "";

  // A trail the reader may not see is not an empty trail, and it is not
  // this card's business to say so: the tab above already did.
  if (changes.error instanceof ApiError && changes.error.forbidden) return null;

  return (
    <>
      <Card
        span={12}
        title={t("Recent changes")}
        note={t("The last directory changes, newest first; a change is approved by a second person before it runs.")}
        flush
      >
        {changes.error
          ? <Problem>{String(changes.error)}</Problem>
          : (
            <Table
              rows={changes.data?.items ?? []}
              keyOf={(one) => one.id}
              testId="changes"
              rowTestId={(one) => `change-${one.id}`}
              empty={changes.isLoading ? t("Reading the directory…") : t("No directory changes yet.")}
              columns={[
                { key: "id", head: t("Change"), tight: true, cell: (one) => <code title={one.id}>{one.id.slice(0, 8)}</code> },
                {
                  key: "type",
                  head: t("Type"),
                  // The plan names what the change touches; without one the
                  // type says at least what kind of change it is.
                  cell: (one) => (
                    <TwoLine sub={one.plan?.summary || <code>{one.action_type}</code>}>
                      {t(actionName(one.action_type))}
                    </TwoLine>
                  ),
                },
                { key: "state", head: t("State"), cell: (one) => <Pill tone={changeTone(one.state)}>{t(one.state.replace("_", " "))}</Pill> },
                { key: "by", head: t("Ordered by"), minor: true, cell: (one) => one.created_by || "—" },
                {
                  key: "when",
                  head: t("When"),
                  // A change is read by when it ended; one still running is
                  // read by when it was ordered.
                  cell: (one) => {
                    const at = one.finished_at || one.created_at;
                    return at ? <span title={absoluteTime(at)}>{relativeTime(at)}</span> : "—";
                  },
                },
                { key: "result", head: t("Result"), minor: true, cell: (one) => one.result_message || "—" },
                {
                  key: "secret",
                  head: "",
                  actions: true,
                  cell: (one) => one.action_type === "identity.user.password.reset" && one.secret_available
                    ? (
                      <button type="button" className="fl-quiet fl-small" data-testid={`reveal-${one.id}`}
                              onClick={() => { setRevealing(one.id); setSecret(null); setReason(""); }}>
                        {t("Reveal one-time password")}
                      </button>
                    )
                    : null,
                },
              ]}
            />
          )}
      </Card>

      {secret && (
        <Card span={12} title={t("The one-time password of {uid}", { uid: secret.uid })}>
          <Stack>
            <Banner tone="warn">
              {t("It expires on first login and will not be shown again.")}
            </Banner>
            <p data-testid="one-time-password"><code>{secret.one_time_password}</code></p>
            <Actions>
              <button type="button" className="fl-quiet" onClick={() => {
                // The clipboard is refused outside a secure context; the
                // password stays on the screen either way, and the button
                // never claims a copy that did not happen.
                void copyToClipboard(secret.one_time_password).then(setCopied);
              }}>
                {copied ? t("Copied") : t("Copy")}
              </button>
              <button type="button" className="fl-quiet" onClick={() => { setSecret(null); setCopied(false); }}>
                {t("Hide")}
              </button>
            </Actions>
          </Stack>
        </Card>
      )}

      {revealing && (
        <Modal
          title={t("Read the one-time password")}
          onClose={() => { setRevealing(null); setReason(""); }}
          actions={
            <>
              <button type="button" className="fl-quiet" onClick={() => { setRevealing(null); setReason(""); }}>
                {t("Cancel")}
              </button>
              <button type="button" disabled={reason.trim().length < REASON_MINIMUM || reveal.isPending}
                      data-testid="reveal-confirm" onClick={() => reveal.mutate(revealing)}>
                {t("Reveal")}
              </button>
            </>
          }
        >
          <Stack>
            <Note>{t("The password is handed out once, to the person who ordered the reset, and the reading itself is recorded.")}</Note>
            {revealError && <Problem>{revealError}</Problem>}
            <Fields>
              <Reason value={reason} onChange={setReason} placeholder={t("why the password is read")} testId="reveal-reason" />
            </Fields>
          </Stack>
        </Modal>
      )}
    </>
  );
}

/** The state of a change as a tone; a change nobody approved yet is waiting, not wrong. */
export function changeTone(state: string): Tone {
  if (state === "succeeded" || state === "applied") return "ok";
  if (state === "failed" || state === "blocked") return "error";
  if (state === "partially_applied") return "warn";
  return "info";
}

/* ------------------------------------------------------------------ groups */

function GroupsTab() {
  const t = useT();
  const [editing, setEditing] = useState<DirectoryGroup | null>(null);
  const [add, setAdd] = useState("");
  const [remove, setRemove] = useState("");
  const [reason, setReason] = useState("");
  const { mutation, change, message } = useDirectoryChange(["identity-groups", "identity-users"]);

  const { data, error, isLoading } = useQuery({
    queryKey: ["identity-groups"],
    queryFn: () => api.get<Collection<DirectoryGroup>>("/api/v1/identity/groups"),
    retry: false,
  });

  const problem = readProblem(error);
  if (problem) return problem;

  return (
    <Grid>
      {editing && (
        <Card
          span={12}
          title={t("Members of the group {name}", { name: editing.name })}
          note={t("The plan shows the resulting membership and the hosts and sudo rules the group leads to; the moved users lose their panel sessions and log in with the new scope.")}
          foot={
            <Actions>
              <button
                type="button"
                data-testid="plan-members"
                disabled={(!names(add).length && !names(remove).length) || reason.trim().length < REASON_MINIMUM || mutation.isPending}
                onClick={() => mutation.mutate({
                  action: "identity.group.members", reason,
                  payload: { group: { group: editing.name, add: names(add), remove: names(remove) } },
                }, { onSuccess: () => setEditing(null) })}
              >
                {t("Plan membership change")}
              </button>
              <button type="button" className="fl-quiet" onClick={() => setEditing(null)}>{t("Close")}</button>
            </Actions>
          }
        >
          <Stack>
            {message && <Problem>{message}</Problem>}
            <Facts>
              <Fact label={t("Current members ({n})", { n: (editing.members ?? []).length })}>
                <Names items={editing.members} />
              </Fact>
            </Facts>
            <Fields>
              <ListField label={t("Add users")} value={add} onChange={setAdd} placeholder="alice, bob" testId="group-add" />
              <ListField label={t("Remove users")} value={remove} onChange={setRemove} placeholder="carol" />
              <Reason value={reason} onChange={setReason} testId="group-reason" />
            </Fields>
          </Stack>
        </Card>
      )}

      {change && <PlanImpact change={change} />}

      <Card
        span={12}
        title={t("Groups")}
        flush
        foot={data ? t("{n} groups", { n: data.items.length }) : undefined}
      >
        <Table
          rows={data?.items ?? []}
          keyOf={(one) => one.name}
          testId="groups"
          rowTestId={(one) => `group-${one.name}`}
          empty={isLoading ? t("Reading the directory…") : t("No groups.")}
          columns={[
            { key: "name", head: t("Group"), tight: true, cell: (one) => <code>{one.name}</code> },
            { key: "gid", head: "GID", num: true, cell: (one) => one.gid_number || "—" },
            { key: "description", head: t("Description"), minor: true, cell: (one) => one.description || "—" },
            { key: "members", head: t("Members"), cell: (one) => <Names items={one.members} /> },
            {
              key: "edit",
              head: "",
              actions: true,
              cell: (one) => (
                <button type="button" className="fl-quiet fl-small" data-testid={`edit-${one.name}`}
                        onClick={() => { setEditing(one); setAdd(""); setRemove(""); }}>
                  {t("Edit members")}
                </button>
              ),
            },
          ]}
        />
      </Card>
    </Grid>
  );
}

/* -------------------------------------------------------------- HBAC rules */

const EMPTY_HBAC = {
  name: "", description: "", enabled: true,
  users: "", user_groups: "", hosts: "", host_groups: "", services: "sshd", service_groups: "",
  all_users: false, all_hosts: false, all_services: false,
};

type HBACForm = typeof EMPTY_HBAC;

function hbacFormOf(rule: HBACRule): HBACForm {
  return {
    name: rule.name, description: rule.description ?? "", enabled: rule.enabled,
    users: (rule.users ?? []).join(", "), user_groups: (rule.user_groups ?? []).join(", "),
    hosts: (rule.hosts ?? []).join(", "), host_groups: (rule.host_groups ?? []).join(", "),
    services: (rule.services ?? []).join(", "), service_groups: (rule.service_groups ?? []).join(", "),
    all_users: rule.all_users, all_hosts: rule.all_hosts, all_services: rule.all_services,
  };
}

function HBACTab() {
  const t = useT();
  const [form, setForm] = useState<HBACForm | null>(null);
  const [editing, setEditing] = useState(false);
  const [reason, setReason] = useState("");
  const { mutation, change, message } = useDirectoryChange(["identity-hbac"]);

  const { data, error, isLoading } = useQuery({
    queryKey: ["identity-hbac"],
    queryFn: () => api.get<Collection<HBACRule>>("/api/v1/identity/hbac-rules"),
    retry: false,
  });

  const problem = readProblem(error);
  if (problem) return problem;

  const set = <K extends keyof HBACForm>(key: K, value: HBACForm[K]) =>
    setForm((current) => (current ? { ...current, [key]: value } : current));

  const payload = (f: HBACForm) => ({
    hbac_rule: {
      name: f.name.trim(), description: f.description.trim(), enabled: f.enabled,
      users: names(f.users), user_groups: names(f.user_groups),
      hosts: names(f.hosts), host_groups: names(f.host_groups),
      services: names(f.services), service_groups: names(f.service_groups),
      all_users: f.all_users, all_hosts: f.all_hosts, all_services: f.all_services,
    },
  });

  const rules = data?.items ?? [];
  const wide = data ? rules.filter((one) => one.allows_everything).length : null;

  return (
    <>
      <Kpis>
        <Kpi icon="access" label={t("HBAC rules")} value={data ? rules.length : null}
             note={t("who may enter which host through which service")} testId="kpi-hbac" />
        <Kpi icon="security" label={t("Covering the whole fleet")} value={wide} tone={wide ? "error" : "ok"}
             note={t("a rule narrowed by nothing reaches every host")} testId="kpi-hbac-wide" />
      </Kpis>

      <Grid>
        <Card span={12}>
          <Note>
            {t("An HBAC rule says who may enter which hosts through which services. A rule is declared as a whole and the directory is brought to it; the plan shows the hosts and users it reaches and the diff against the rule of the same name before a second person approves.")}
          </Note>
        </Card>

        <Card
          span={12}
          title={t("HBAC rules")}
          flush
          tools={
            <button type="button" className="fl-quiet fl-small" data-testid="new-hbac"
                    onClick={() => { setForm({ ...EMPTY_HBAC }); setEditing(false); }}>
              {t("New rule")}
            </button>
          }
          foot={data ? t("{n} rules", { n: rules.length }) : undefined}
        >
          <Table
            rows={rules}
            keyOf={(one) => one.name}
            testId="hbac"
            rowTestId={(one) => `hbac-${one.name}`}
            empty={isLoading ? t("Reading the directory…") : t("No rules.")}
            columns={[
              { key: "name", head: t("Rule"), tight: true, cell: (one) => <code>{one.name}</code> },
              {
                key: "enabled",
                head: t("Enabled"),
                cell: (one) => one.enabled ? <Pill tone="ok">{t("yes")}</Pill> : <Pill tone="neutral">{t("no")}</Pill>,
              },
              {
                key: "who",
                head: t("Who"),
                cell: (one) => one.all_users
                  ? <Pill tone="warn">{t("every user")}</Pill>
                  : <Names items={[...(one.users ?? []), ...(one.user_groups ?? [])]} />,
              },
              {
                key: "hosts",
                head: t("Hosts"),
                cell: (one) => one.all_hosts
                  ? <Pill tone="warn">{t("every host")}</Pill>
                  : <Names items={[...(one.hosts ?? []), ...(one.host_groups ?? [])]} />,
              },
              {
                key: "services",
                head: t("Services"),
                minor: true,
                cell: (one) => one.all_services
                  ? <Pill tone="warn">{t("every service")}</Pill>
                  : <Names items={[...(one.services ?? []), ...(one.service_groups ?? [])]} />,
              },
              {
                key: "risk",
                head: t("Risk"),
                cell: (one) => one.allows_everything
                  ? <Pill tone="error">{t("covers the whole fleet")}</Pill>
                  : <Pill tone="neutral">{t("narrowed")}</Pill>,
              },
              {
                key: "edit",
                head: "",
                actions: true,
                cell: (one) => (
                  <button type="button" className="fl-quiet fl-small" data-testid={`edit-hbac-${one.name}`}
                          onClick={() => { setForm(hbacFormOf(one)); setEditing(true); }}>
                    {t("Edit")}
                  </button>
                ),
              },
            ]}
          />
        </Card>

        {form && (
          <C span={12}>
            <Form
            title={editing ? t("Edit rule {name}", { name: form.name }) : t("New HBAC rule")}
            actions={
              <Actions>
                <button type="button" data-testid="plan-hbac"
                        disabled={!form.name || reason.trim().length < REASON_MINIMUM || mutation.isPending}
                        onClick={() => mutation.mutate({ action: "identity.hbac.rule.ensure", reason, payload: payload(form) })}>
                  {t("Plan rule")}
                </button>
                {editing && (
                  <button type="button" className="fl-danger" data-testid="plan-hbac-removal"
                          disabled={reason.trim().length < REASON_MINIMUM || mutation.isPending}
                          onClick={() => mutation.mutate({ action: "identity.hbac.rule.remove", reason, payload: { hbac_rule: { name: form.name } } })}>
                    {t("Plan removal")}
                  </button>
                )}
                <button type="button" className="fl-quiet" onClick={() => setForm(null)}>{t("Close")}</button>
              </Actions>
            }
          >
            <Stack>
              {message && <Problem>{message}</Problem>}
              <Fields>
                <Field label={t("Name")}>
                  <input value={form.name} onChange={(e) => set("name", e.target.value)} disabled={editing}
                         placeholder="ops-ssh" data-testid="hbac-name" />
                </Field>
                <Field label={t("Description")} wide>
                  <input value={form.description} onChange={(e) => set("description", e.target.value)} />
                </Field>
                <ListField label={t("Users")} value={form.users} onChange={(v) => set("users", v)}
                           placeholder="alice, bob" disabled={form.all_users} />
                <ListField label={t("User groups")} value={form.user_groups} onChange={(v) => set("user_groups", v)}
                           placeholder="ops" disabled={form.all_users} />
                <ListField label={t("Hosts")} value={form.hosts} onChange={(v) => set("hosts", v)}
                           placeholder="web1.example.test" disabled={form.all_hosts} />
                <ListField label={t("Host groups")} value={form.host_groups} onChange={(v) => set("host_groups", v)}
                           placeholder="web" disabled={form.all_hosts} />
                <ListField label={t("Services")} value={form.services} onChange={(v) => set("services", v)}
                           placeholder="sshd, sudo" disabled={form.all_services} />
                <ListField label={t("Service groups")} value={form.service_groups} onChange={(v) => set("service_groups", v)}
                           placeholder="Sudo" disabled={form.all_services} />
              </Fields>
              <Check checked={form.enabled} onChange={(v) => set("enabled", v)}>
                {t("Enabled — a disabled rule is a draft and may be incomplete")}
              </Check>
              <Check checked={form.all_users} onChange={(v) => set("all_users", v)}>
                {t("Every user, instead of the listed users and groups")}
              </Check>
              <Check checked={form.all_hosts} onChange={(v) => set("all_hosts", v)}>
                {t("Every host, instead of the listed hosts and host groups")}
              </Check>
              <Check checked={form.all_services} onChange={(v) => set("all_services", v)}>
                {t("Every service, instead of the listed services")}
              </Check>
              <Fields><Reason value={reason} onChange={setReason} placeholder={t("why this rule changes")} testId="hbac-reason" /></Fields>
            </Stack>
          </Form>
          </C>
        )}

        {change && <PlanImpact change={change} />}

        <SimulateAccess />
      </Grid>
    </>
  );
}

/**
 * The directory's own answer to "may this user use this service on this
 * host" - its verdict, not a guess made in the browser.
 */
function SimulateAccess() {
  const t = useT();
  const [user, setUser] = useState("");
  const [host, setHost] = useState("");
  const [service, setService] = useState("sshd");
  const simulate = useMutation({
    mutationFn: () => api.post<AccessSimulation>("/api/v1/identity/access/simulate", { user, host, service }),
  });
  const result = simulate.data;

  return (
    <C span={12}>
      <Form
      title={t("Simulate access")}
      note={t("Ask the directory whether a user may use a service on a host. The answer is the directory's verdict, not a guess of the panel.")}
      actions={
        <Actions>
          <button type="button" disabled={!user || !host || simulate.isPending}
                  data-testid="simulate" onClick={() => simulate.mutate()}>
            {simulate.isPending ? t("Asking…") : t("Simulate")}
          </button>
        </Actions>
      }
    >
      <Stack>
        {simulate.error && <Problem>{simulate.error instanceof Error ? simulate.error.message : String(simulate.error)}</Problem>}
        <Fields>
          <Field label={t("User")}>
            <input value={user} onChange={(e) => setUser(e.target.value)} placeholder="alice" data-testid="simulate-user" />
          </Field>
          <Field label={t("Host")}>
            <input value={host} onChange={(e) => setHost(e.target.value)} placeholder="web1.example.test" data-testid="simulate-host" />
          </Field>
          <Field label={t("Service")}>
            <input value={service} onChange={(e) => setService(e.target.value)} placeholder="sshd" />
          </Field>
        </Fields>
        {result && (
          <Facts>
            <Fact label={t("Verdict")}>
              {result.allowed ? <Pill tone="ok">{t("allowed")}</Pill> : <Pill tone="error">{t("denied")}</Pill>}
            </Fact>
            <Fact label={t("Matched")}><Names items={result.matched} /></Fact>
            <Fact label={t("Not matched")}><Names items={result.not_matched} /></Fact>
            {(result.errors ?? []).length > 0 && (
              <Fact label={t("Could not evaluate")}><Names items={result.errors} /></Fact>
            )}
            {(result.warnings ?? []).length > 0 && (
              <Fact label={t("Warnings")}>{(result.warnings ?? []).join("; ")}</Fact>
            )}
          </Facts>
        )}
      </Stack>
    </Form>
    </C>
  );
}

/* -------------------------------------------------------------- sudo rules */

const EMPTY_SUDO = {
  name: "", description: "", enabled: true,
  users: "", user_groups: "", hosts: "", host_groups: "",
  commands: "", command_groups: "", run_as_users: "root", run_as_groups: "", options: "",
  all_users: false, all_hosts: false, all_commands: false, run_as_any_user: false,
};

type SudoForm = typeof EMPTY_SUDO;

function sudoFormOf(rule: SudoRule): SudoForm {
  return {
    name: rule.name, description: rule.description ?? "", enabled: rule.enabled,
    users: (rule.users ?? []).join(", "), user_groups: (rule.user_groups ?? []).join(", "),
    hosts: (rule.hosts ?? []).join(", "), host_groups: (rule.host_groups ?? []).join(", "),
    commands: (rule.commands ?? []).join(", "), command_groups: (rule.command_groups ?? []).join(", "),
    run_as_users: (rule.run_as ?? []).join(", "), run_as_groups: (rule.run_as_groups ?? []).join(", "),
    options: (rule.options ?? []).join(", "),
    all_users: rule.all_users, all_hosts: rule.all_hosts, all_commands: rule.all_commands,
    run_as_any_user: rule.run_as_any_user,
  };
}

function SudoTab() {
  const t = useT();
  const [form, setForm] = useState<SudoForm | null>(null);
  const [editing, setEditing] = useState(false);
  const [reason, setReason] = useState("");
  const { mutation, change, message } = useDirectoryChange(["identity-sudo"]);

  const { data, error, isLoading } = useQuery({
    queryKey: ["identity-sudo"],
    queryFn: () => api.get<Collection<SudoRule>>("/api/v1/identity/sudo-rules"),
    retry: false,
  });

  const problem = readProblem(error);
  if (problem) return problem;

  const set = <K extends keyof SudoForm>(key: K, value: SudoForm[K]) =>
    setForm((current) => (current ? { ...current, [key]: value } : current));

  const payload = (f: SudoForm) => ({
    sudo_rule: {
      name: f.name.trim(), description: f.description.trim(), enabled: f.enabled,
      users: names(f.users), user_groups: names(f.user_groups),
      hosts: names(f.hosts), host_groups: names(f.host_groups),
      commands: names(f.commands), command_groups: names(f.command_groups),
      run_as_users: names(f.run_as_users), run_as_groups: names(f.run_as_groups),
      options: names(f.options),
      all_users: f.all_users, all_hosts: f.all_hosts, all_commands: f.all_commands,
      run_as_any_user: f.run_as_any_user,
    },
  });

  const rules = data?.items ?? [];
  const critical = data ? rules.filter((one) => one.critical).length : null;

  return (
    <>
      <Kpis>
        <Kpi icon="security" label={t("sudo rules")} value={data ? rules.length : null}
             note={t("who may run what, as whom, where")} testId="kpi-sudo" />
        <Kpi icon="vulnerabilities" label={t("Critical")} value={critical} tone={critical ? "error" : "ok"}
             note={t("every command, no password, or running as root")} testId="kpi-sudo-critical" />
      </Kpis>

      <Grid>
        <Card span={12}>
          <Note>
            {t("A sudo rule says who may run which commands as whom on which hosts. Every command, no password (!authenticate) and running as root are named in the plan one by one, so the person approving reads what the rule grants rather than a single word.")}
          </Note>
        </Card>

        <Card
          span={12}
          title={t("sudo rules")}
          flush
          tools={
            <button type="button" className="fl-quiet fl-small" data-testid="new-sudo"
                    onClick={() => { setForm({ ...EMPTY_SUDO }); setEditing(false); }}>
              {t("New rule")}
            </button>
          }
          foot={data ? t("{n} rules", { n: rules.length }) : undefined}
        >
          <Table
            rows={rules}
            keyOf={(one) => one.name}
            testId="sudo"
            rowTestId={(one) => `sudo-${one.name}`}
            empty={isLoading ? t("Reading the directory…") : t("No sudo rules.")}
            columns={[
              { key: "name", head: t("Rule"), tight: true, cell: (one) => <code>{one.name}</code> },
              {
                key: "enabled",
                head: t("Enabled"),
                cell: (one) => one.enabled ? <Pill tone="ok">{t("yes")}</Pill> : <Pill tone="neutral">{t("no")}</Pill>,
              },
              {
                key: "who",
                head: t("Applies to"),
                cell: (one) => one.all_users
                  ? <Pill tone="warn">{t("every user")}</Pill>
                  : <Names items={[...(one.users ?? []), ...(one.user_groups ?? [])]} />,
              },
              {
                key: "hosts",
                head: t("Hosts"),
                cell: (one) => one.all_hosts
                  ? <Pill tone="warn">{t("every host")}</Pill>
                  : <Names items={[...(one.hosts ?? []), ...(one.host_groups ?? [])]} />,
              },
              {
                key: "commands",
                head: t("Commands"),
                minor: true,
                cell: (one) => one.all_commands
                  ? <Pill tone="error">{t("every command")}</Pill>
                  : <Names items={[...(one.commands ?? []), ...(one.command_groups ?? [])]} />,
              },
              {
                key: "risk",
                head: t("Risk"),
                cell: (one) => one.critical
                  ? <Pill tone="error" title={(one.critical_reasons ?? []).join("; ")}>{t("critical")}</Pill>
                  : <>—</>,
              },
              {
                key: "edit",
                head: "",
                actions: true,
                cell: (one) => (
                  <button type="button" className="fl-quiet fl-small" data-testid={`edit-sudo-${one.name}`}
                          onClick={() => { setForm(sudoFormOf(one)); setEditing(true); }}>
                    {t("Edit")}
                  </button>
                ),
              },
            ]}
          />
        </Card>

        {form && (
          <C span={12}>
            <Form
            title={editing ? t("Edit rule {name}", { name: form.name }) : t("New sudo rule")}
            actions={
              <Actions>
                <button type="button" data-testid="plan-sudo"
                        disabled={!form.name || reason.trim().length < REASON_MINIMUM || mutation.isPending}
                        onClick={() => mutation.mutate({ action: "identity.sudo.rule.ensure", reason, payload: payload(form) })}>
                  {t("Plan rule")}
                </button>
                {editing && (
                  <button type="button" className="fl-danger" data-testid="plan-sudo-removal"
                          disabled={reason.trim().length < REASON_MINIMUM || mutation.isPending}
                          onClick={() => mutation.mutate({ action: "identity.sudo.rule.remove", reason, payload: { sudo_rule: { name: form.name } } })}>
                    {t("Plan removal")}
                  </button>
                )}
                <button type="button" className="fl-quiet" onClick={() => setForm(null)}>{t("Close")}</button>
              </Actions>
            }
          >
            <Stack>
              {message && <Problem>{message}</Problem>}
              <Fields>
                <Field label={t("Name")}>
                  <input value={form.name} onChange={(e) => set("name", e.target.value)} disabled={editing}
                         placeholder="ops-restart" data-testid="sudo-name" />
                </Field>
                <Field label={t("Description")} wide>
                  <input value={form.description} onChange={(e) => set("description", e.target.value)} />
                </Field>
                <ListField label={t("Users")} value={form.users} onChange={(v) => set("users", v)}
                           placeholder="alice, bob" disabled={form.all_users} />
                <ListField label={t("User groups")} value={form.user_groups} onChange={(v) => set("user_groups", v)}
                           placeholder="ops" disabled={form.all_users} />
                <ListField label={t("Hosts")} value={form.hosts} onChange={(v) => set("hosts", v)}
                           placeholder="web1.example.test" disabled={form.all_hosts} />
                <ListField label={t("Host groups")} value={form.host_groups} onChange={(v) => set("host_groups", v)}
                           placeholder="web" disabled={form.all_hosts} />
                <ListField label={t("Commands")} value={form.commands} onChange={(v) => set("commands", v)}
                           placeholder="/usr/bin/systemctl, /usr/bin/journalctl" disabled={form.all_commands} />
                <ListField label={t("Command groups")} value={form.command_groups} onChange={(v) => set("command_groups", v)}
                           placeholder="services" disabled={form.all_commands} />
                <ListField label={t("Run as users")} value={form.run_as_users} onChange={(v) => set("run_as_users", v)}
                           placeholder="root" disabled={form.run_as_any_user} />
                <ListField label={t("Run as groups")} value={form.run_as_groups} onChange={(v) => set("run_as_groups", v)}
                           placeholder="wheel" />
                <ListField label={t("Options")} value={form.options} onChange={(v) => set("options", v)}
                           placeholder="!authenticate, !requiretty" />
              </Fields>
              <Check checked={form.enabled} onChange={(v) => set("enabled", v)}>
                {t("Enabled — a disabled rule is a draft and may be incomplete")}
              </Check>
              <Check checked={form.all_users} onChange={(v) => set("all_users", v)}>
                {t("Every user, instead of the listed users and groups")}
              </Check>
              <Check checked={form.all_hosts} onChange={(v) => set("all_hosts", v)}>
                {t("Every host, instead of the listed hosts and host groups")}
              </Check>
              <Check checked={form.all_commands} onChange={(v) => set("all_commands", v)}>
                {t("Every command — together with root this is full root access")}
              </Check>
              <Check checked={form.run_as_any_user} onChange={(v) => set("run_as_any_user", v)}>
                {t("Run as any user, instead of the listed run-as users")}
              </Check>
              <Fields><Reason value={reason} onChange={setReason} placeholder={t("why this rule changes")} testId="sudo-reason" /></Fields>
            </Stack>
          </Form>
          </C>
        )}

        {change && <PlanImpact change={change} />}
      </Grid>
    </>
  );
}

/* ------------------------------------------------------------ host entries */

function HostsTab() {
  const t = useT();
  const [filter, setFilter] = useState("");

  const { data, error, isLoading } = useQuery({
    queryKey: ["identity-hosts"],
    queryFn: () => api.get<Collection<DirectoryHost>>("/api/v1/identity/hosts"),
    retry: false,
  });
  // The fleet is read once for the whole table; a lookup per row would be a
  // query per host, and the fleet list is paged by the same limit the host
  // list uses.
  const fleet = useQuery({
    queryKey: ["hosts", "directory-link"],
    queryFn: () => api.get<Collection<Host>>("/api/v1/hosts?limit=500"),
    retry: false,
  });

  const problem = readProblem(error);
  if (problem) return problem;

  const byName = new Map<string, Host>();
  for (const host of fleet.data?.items ?? []) {
    byName.set(host.hostname.toLowerCase(), host);
    if (host.identity?.domain) byName.set(`${host.hostname}.${host.identity.domain}`.toLowerCase(), host);
  }
  const linked = (fqdn: string) => byName.get(fqdn.toLowerCase());

  const needle = filter.trim().toLowerCase();
  const items = (data?.items ?? []).filter((host) => !needle || host.fqdn.toLowerCase().includes(needle));
  const enrolled = data ? (data.items ?? []).filter((one) => one.enrolled).length : null;

  return (
    <>
      <Kpis>
        <Kpi icon="hosts" label={t("Host entries")} value={data ? data.items.length : null}
             note={t("as the directory holds them")} testId="kpi-entries" />
        <Kpi icon="identity" label={t("Enrolled")} value={enrolled}
             note={t("an entry that holds a host key")} testId="kpi-enrolled" />
      </Kpis>

      <Grid>
        <Card span={12}>
          <Note>
            {t("The host entries of the directory. An enrolled entry holds a host key; the fleet host of the same name, when there is one, is linked - the two records have separate lifecycles and the name is the only bridge.")}
          </Note>
        </Card>

        <Card
          span={12}
          title={t("Hosts")}
          flush
          tools={<Find value={filter} onChange={setFilter} placeholder={t("Filter by name")} testId="host-filter" />}
          foot={data ? t("{n} hosts", { n: items.length }) : undefined}
        >
          <Table
            rows={items}
            keyOf={(one) => one.fqdn}
            testId="directory-hosts"
            rowTestId={(one) => `entry-${one.fqdn}`}
            empty={isLoading
              ? t("Reading the directory…")
              : data?.items.length
                ? t("No host matches the filter.")
                : t("The directory has no host entries.")}
            columns={[
              {
                key: "fqdn",
                head: t("Host"),
                tight: true,
                cell: (one) => <TwoLine sub={one.description || undefined}><code>{one.fqdn}</code></TwoLine>,
              },
              {
                key: "enrolled",
                head: t("Enrolled"),
                cell: (one) => (
                  <TwoLine sub={one.enrolled_at ? <code>{one.enrolled_at}</code> : undefined}>
                    {one.enrolled
                      ? <Pill tone="ok" title={one.enrolled_at}>{t("enrolled")}</Pill>
                      : <Pill tone="neutral">{t("entry only")}</Pill>}
                  </TwoLine>
                ),
              },
              { key: "member_of", head: t("Host groups"), cell: (one) => <Names items={one.member_of} /> },
              { key: "managed_by", head: t("Managed by"), minor: true, cell: (one) => <Names items={one.managed_by} /> },
              {
                key: "fleet",
                head: t("Fleet host"),
                cell: (one) => {
                  const panelHost = linked(one.fqdn);
                  if (panelHost) return <Link to={`/hosts/${panelHost.id}`}>{panelHost.hostname}</Link>;
                  // A fleet still being read has not answered "no".
                  return fleet.isPending ? <Pill tone="unknown">{t("still reading the fleet")}</Pill> : <>{t("not in the fleet")}</>;
                },
              },
              {
                key: "join",
                head: "",
                actions: true,
                cell: (one) => {
                  const panelHost = linked(one.fqdn);
                  return panelHost
                    ? <Link className="fl-quiet fl-small" to={`/hosts/${panelHost.id}/identity`}>{t("Join")}</Link>
                    : null;
                },
              },
            ]}
          />
        </Card>
      </Grid>
    </>
  );
}

/* ------------------------------------------------------------- host groups */

function HostGroupsTab() {
  const t = useT();
  const [editing, setEditing] = useState<DirectoryHostGroup | null>(null);
  const [add, setAdd] = useState("");
  const [remove, setRemove] = useState("");
  const [reason, setReason] = useState("");
  const { mutation, change, message } = useDirectoryChange(["identity-host-groups", "identity-hosts"]);

  const { data, error, isLoading } = useQuery({
    queryKey: ["identity-host-groups"],
    queryFn: () => api.get<Collection<DirectoryHostGroup>>("/api/v1/identity/host-groups"),
    retry: false,
  });

  const problem = readProblem(error);
  if (problem) return problem;

  return (
    <Grid>
      <Card span={12}>
        <Note>
          {t("Host groups are what the access and sudo rules point at, so a host moved into one gains every rule that names the group. The plan lists those rules before a second person approves. Directory host groups and panel groups have separate lifecycles: one is read by SSSD on the hosts, the other by the panel alone.")}
        </Note>
      </Card>

      {editing && (
        <Card
          span={12}
          title={t("Members of the host group {name}", { name: editing.name })}
          note={t("Hosts by their FQDN, as the directory knows them. A host the directory has no entry for is a conflict of the plan.")}
          foot={
            <Actions>
              <button
                type="button"
                data-testid="plan-host-members"
                disabled={(!names(add).length && !names(remove).length) || reason.trim().length < REASON_MINIMUM || mutation.isPending}
                onClick={() => mutation.mutate({
                  action: "identity.hostgroup.members", reason,
                  payload: { host_group: { group: editing.name, add: names(add), remove: names(remove) } },
                }, { onSuccess: () => setEditing(null) })}
              >
                {t("Plan membership change")}
              </button>
              <button type="button" className="fl-quiet" onClick={() => setEditing(null)}>{t("Close")}</button>
            </Actions>
          }
        >
          <Stack>
            {message && <Problem>{message}</Problem>}
            <Facts>
              <Fact label={t("Current members ({n})", { n: (editing.hosts ?? []).length })}>
                <Names items={editing.hosts} />
              </Fact>
            </Facts>
            <Fields>
              <ListField label={t("Add hosts")} value={add} onChange={setAdd}
                         placeholder="web1.example.test, web2.example.test" testId="hostgroup-add" />
              <ListField label={t("Remove hosts")} value={remove} onChange={setRemove} placeholder="old.example.test" />
              <Reason value={reason} onChange={setReason} testId="hostgroup-reason" />
            </Fields>
          </Stack>
        </Card>
      )}

      {change && <PlanImpact change={change} />}

      <Card
        span={12}
        title={t("Host groups")}
        flush
        foot={data ? t("{n} host groups", { n: data.items.length }) : undefined}
      >
        <Table
          rows={data?.items ?? []}
          keyOf={(one) => one.name}
          testId="host-groups"
          rowTestId={(one) => `hostgroup-${one.name}`}
          empty={isLoading ? t("Reading the directory…") : t("The directory has no host groups.")}
          columns={[
            { key: "name", head: t("Host group"), tight: true, cell: (one) => <code>{one.name}</code> },
            { key: "description", head: t("Description"), minor: true, cell: (one) => one.description || "—" },
            { key: "hosts", head: t("Hosts"), cell: (one) => <Names items={one.hosts} /> },
            { key: "nested", head: t("Nested groups"), minor: true, cell: (one) => <Names items={one.host_groups} /> },
            {
              key: "edit",
              head: "",
              actions: true,
              cell: (one) => (
                <button type="button" className="fl-quiet fl-small" data-testid={`edit-hostgroup-${one.name}`}
                        onClick={() => { setEditing(one); setAdd(""); setRemove(""); }}>
                  {t("Edit members")}
                </button>
              ),
            },
          ]}
        />
      </Card>
    </Grid>
  );
}

/* ---------------------------------------------------------------- ssh keys */

function SshKeysTab() {
  const t = useT();
  const [editing, setEditing] = useState<DirectoryUser | null>(null);
  const [keys, setKeys] = useState("");
  const [reason, setReason] = useState("");
  const { mutation, change, message } = useDirectoryChange(["identity-users"]);

  const { data, error, isLoading } = useQuery({
    queryKey: ["identity-users"],
    queryFn: () => api.get<Collection<DirectoryUser>>("/api/v1/identity/users"),
    retry: false,
  });

  const problem = readProblem(error);
  if (problem) return problem;

  const users = data?.items ?? [];
  const withKeys = users.filter((user) => (user.ssh_key_fingerprints ?? []).length > 0);
  const withoutKeys = users.filter((user) => !(user.ssh_key_fingerprints ?? []).length);
  const total = withKeys.reduce((sum, user) => sum + (user.ssh_key_fingerprints ?? []).length, 0);
  const typed = lines(keys);
  const share = data && users.length > 0 ? withKeys.length / users.length : undefined;

  const stateOf = (user: DirectoryUser) =>
    user.disabled ? <Pill tone="error">{t("locked")}</Pill> : <Pill tone="ok">{t("active")}</Pill>;

  return (
    <Grid>
      <Card span={12}>
        <Note>
          {t("The public keys the directory hands to every host. The directory records a key and its fingerprint but not the day it was added, so no key age is shown: unknown is not zero. A private key never reaches the system.")}
        </Note>
      </Card>

      {editing && (
        <Card
          span={12}
          title={t("SSH keys of the account {uid}", { uid: editing.uid })}
          note={t("The complete set of keys, one per line; the directory replaces what it holds with this list.")}
          foot={
            <Actions>
              <button
                type="button"
                data-testid="plan-keys"
                disabled={reason.trim().length < REASON_MINIMUM || mutation.isPending}
                onClick={() => mutation.mutate({
                  action: "identity.sshkeys.set", reason,
                  payload: { ssh_keys: { uid: editing.uid, keys: typed } },
                }, { onSuccess: () => setEditing(null) })}
              >
                {typed.length === 0 ? t("Plan removal of every key") : t("Plan keys")}
              </button>
              <button type="button" className="fl-quiet" onClick={() => setEditing(null)}>{t("Close")}</button>
            </Actions>
          }
        >
          <Stack>
            {typed.length === 0 && (
              <Banner tone="warn">
                {t("An empty list removes every key of the account and can cut off its SSH login.")}
              </Banner>
            )}
            {message && <Problem>{message}</Problem>}
            <Facts>
              <Fact label={t("Fingerprints now ({n})", { n: (editing.ssh_key_fingerprints ?? []).length })}>
                <Names items={editing.ssh_key_fingerprints} />
              </Fact>
            </Facts>
            <Fields>
              <Field label={t("SSH public keys, one per line")} wide>
                <textarea rows={4} value={keys} onChange={(e) => setKeys(e.target.value)}
                          placeholder="ssh-ed25519 AAAA… user@host" data-testid="keys-text" />
              </Field>
              <Reason value={reason} onChange={setReason} testId="keys-reason" />
            </Fields>
          </Stack>
        </Card>
      )}

      {change && <PlanImpact change={change} />}

      <Card
        span={4}
        title={t("Coverage")}
        note={t("How much of the directory signs in with a key rather than a password.")}
      >
        <Ring
          share={share}
          label={t("have a key")}
          tone={share === undefined ? "unknown" : share > 0.8 ? "ok" : "warn"}
          legend={[
            { label: t("Accounts with keys"), value: data ? withKeys.length : "—", tone: "ok" },
            { label: t("Accounts without"), value: data ? withoutKeys.length : "—", tone: "warn" },
            { label: t("Keys on record"), value: data ? total : "—" },
          ]}
        />
      </Card>

      <Card span={8} title={t("Accounts with keys")} flush>
        <Table
          rows={withKeys}
          keyOf={(one) => one.uid}
          testId="with-keys"
          rowTestId={(one) => `withkeys-${one.uid}`}
          empty={isLoading ? t("Reading the directory…") : t("No account has an SSH key in the directory.")}
          columns={[
            { key: "uid", head: t("Account"), tight: true, cell: (one) => <code>{one.uid}</code> },
            { key: "n", head: t("Keys"), num: true, cell: (one) => (one.ssh_key_fingerprints ?? []).length },
            { key: "fingerprints", head: t("Fingerprints"), cell: (one) => <Names items={one.ssh_key_fingerprints} /> },
            { key: "state", head: t("State"), cell: stateOf },
            {
              key: "set",
              head: "",
              actions: true,
              cell: (one) => (
                <button type="button" className="fl-quiet fl-small" data-testid={`setkeys-${one.uid}`}
                        onClick={() => { setEditing(one); setKeys(""); }}>
                  {t("Set keys")}
                </button>
              ),
            },
          ]}
        />
      </Card>

      <Card
        span={12}
        title={t("Accounts without keys")}
        note={t("These accounts sign in with a password or not at all over SSH.")}
        flush
      >
        <Table
          rows={withoutKeys}
          keyOf={(one) => one.uid}
          testId="without-keys"
          rowTestId={(one) => `withoutkeys-${one.uid}`}
          empty={isLoading ? t("Reading the directory…") : t("Every account has at least one key.")}
          columns={[
            { key: "uid", head: t("Account"), tight: true, cell: (one) => <code>{one.uid}</code> },
            { key: "state", head: t("State"), cell: stateOf },
            {
              key: "set",
              head: "",
              actions: true,
              cell: (one) => (
                <button type="button" className="fl-quiet fl-small" data-testid={`setkeys-${one.uid}`}
                        onClick={() => { setEditing(one); setKeys(""); }}>
                  {t("Set keys")}
                </button>
              ),
            },
          ]}
        />
      </Card>
    </Grid>
  );
}

/* ---------------------------------------------------------------- services */

function ServicesTab() {
  const t = useT();
  const [filter, setFilter] = useState("");
  const [rotating, setRotating] = useState<DirectoryService | null>(null);
  const { mutation, change, message } = useDirectoryChange(["identity-services"]);

  const { data, error, isLoading } = useQuery({
    queryKey: ["identity-services"],
    queryFn: () => api.get<Collection<DirectoryService>>("/api/v1/identity/services"),
    retry: false,
  });
  // The rotation column is drawn for holders of the permission alone: a
  // button the server would refuse is a promise the page cannot keep.
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<{ permissions: string[] }>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const canRotate = (whoami.data?.permissions ?? []).includes("identity.keytab.rotate");

  const problem = readProblem(error);
  if (problem) return problem;

  const needle = filter.trim().toLowerCase();
  const items = (data?.items ?? []).filter((service) =>
    !needle || service.principal.toLowerCase().includes(needle) || service.host.toLowerCase().includes(needle));
  // The host's own principal is not rotated here: its keytab is replaced by
  // a re-join, and retiring it would cut the host off from the directory it
  // fetches from.
  const rotatable = (service: DirectoryService) => service.service.toLowerCase() !== "host" && service.host !== "";

  return (
    <Grid>
      <Card span={12}>
        <Note>
          {t("The service principals of the directory, one per service and host. A keytab is never exported to the browser: this view says whether one is on record, and a rotation retires it in the directory while the host fetches its own new one.")}
        </Note>
      </Card>

      {message && <Card span={12}><Problem>{message}</Problem></Card>}
      {change && <PlanImpact change={change} />}

      <Card
        span={12}
        title={t("Service principals")}
        flush
        tools={<Find value={filter} onChange={setFilter} placeholder={t("Filter by principal or host")} testId="service-filter" />}
        foot={data ? t("{n} services", { n: items.length }) : undefined}
      >
        <Table
          rows={items}
          keyOf={(one) => one.principal}
          testId="services"
          rowTestId={(one) => `service-${one.principal}`}
          empty={isLoading
            ? t("Reading the directory…")
            : data?.items.length
              ? t("No service matches the filter.")
              : t("The directory has no service principals the panel can read.")}
          columns={[
            {
              key: "principal",
              head: t("Principal"),
              tight: true,
              cell: (one) => (
                <TwoLine sub={(one.aliases ?? []).length > 0
                  ? t("aliases: {names}", { names: (one.aliases ?? []).join(", ") })
                  : undefined}>
                  <code>{one.principal}</code>
                </TwoLine>
              ),
            },
            { key: "service", head: t("Service"), cell: (one) => <code>{one.service}</code> },
            { key: "host", head: t("Host"), cell: (one) => one.host ? <code>{one.host}</code> : "—" },
            {
              key: "keytab",
              head: t("Keytab"),
              cell: (one) => <TriState value={one.has_keytab} yes={t("on record")} no={t("none")} />,
            },
            { key: "managed_by", head: t("Managed by"), minor: true, cell: (one) => <Names items={one.managed_by} /> },
            ...(canRotate
              ? [{
                  key: "rotate",
                  head: "",
                  actions: true,
                  cell: (one: DirectoryService) => rotatable(one)
                    ? (
                      <button type="button" className="fl-quiet fl-small" disabled={mutation.isPending}
                              data-testid={`rotate-${one.principal}`} onClick={() => setRotating(one)}>
                        {t("Rotate keytab")}
                      </button>
                    )
                    : <span title={t("The host's own keytab is replaced by a re-join, not a rotation.")}>—</span>,
                }]
              : []),
          ]}
        />
      </Card>

      {rotating && (
        <Confirm
          target={rotating.principal}
          danger
          title={t("Rotate the keytab of {principal}", { principal: rotating.principal })}
          label={t("Plan keytab rotation")}
          description={t("The directory retires the current keytab of the principal - the keytab and the certificates issued to the service are revoked, the entry stays - and the fleet host of that name is ordered to fetch a new one with a ticket it takes from its own host key. Between the two the service cannot authenticate, and the retired key cannot be put back from here. A second person approves the change; it stays partially applied until the task on the host reports the old and the new key version.")}
          busy={mutation.isPending}
          onConfirm={(why) => mutation.mutate(
            { action: "identity.keytab.rotate", reason: why, payload: { keytab: { principal: rotating.principal } } },
            { onSuccess: () => setRotating(null) },
          )}
          onCancel={() => setRotating(null)}
        />
      )}
    </Grid>
  );
}

/* --------------------------------------------------------------------- DNS */

type Zone = { name: string; reverse: boolean };
type DNSRecord = { zone: string; name: string; type: string; values: string[]; ttl?: number };

const RECORD_TYPES = ["A", "AAAA", "CNAME", "TXT", "SRV", "PTR"];

function DNSTab() {
  const t = useT();
  const queryClient = useQueryClient();
  const [zone, setZone] = useState("");
  const [name, setName] = useState("");
  const [type, setType] = useState("A");
  const [value, setValue] = useState("");
  const [ttl, setTtl] = useState("");
  const [reverse, setReverse] = useState(true);
  const [message, setMessage] = useState("");

  const zones = useQuery({
    queryKey: ["dns-zones"],
    queryFn: () => api.get<Collection<Zone>>("/api/v1/identity/dns/zones"),
    retry: false,
  });
  const selected = zone || zones.data?.items?.[0]?.name || "";

  const records = useQuery({
    queryKey: ["dns-records", selected],
    queryFn: () => api.get<Collection<DNSRecord>>(`/api/v1/identity/dns/records?zone=${encodeURIComponent(selected)}`),
    enabled: selected !== "",
    retry: false,
  });

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post<DirectoryChange>("/api/v1/identity/changes", body),
    onSuccess: (change) => {
      const conflicts = change.plan?.conflicts ?? [];
      setMessage(
        conflicts.length
          ? t("Change {id} planned with conflicts: {conflicts}", { id: change.id.slice(0, 8), conflicts: conflicts.join("; ") })
          : t("Change {id} is {state}.", { id: change.id.slice(0, 8), state: change.state.replace("_", " ") }),
      );
      queryClient.invalidateQueries({ queryKey: ["dns-records", selected] });
      queryClient.invalidateQueries({ queryKey: ["directory-changes"] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const problem = readProblem(zones.error);
  if (problem) return problem;

  const record = (ensure: boolean) => ({
    action: ensure ? "dns.record.ensure" : "dns.record.remove",
    payload: {
      dns: {
        zone: selected, name, type, value,
        ttl: Number(ttl) || 0,
        reverse: reverse && (type === "A" || type === "AAAA"),
      },
    },
  });

  return (
    <Grid>
      <Card span={12}>
        <Note>
          {t("Zones and records live in the directory, not in anyone's /etc/hosts. A record here answers for the whole network, so it goes the same way as a directory account: plan first, then approval, then execution — and the reverse record is a separate, visible step of that plan.")}
        </Note>
      </Card>

      <C span={12}>
        <Form
        title={t("A record")}
        note={t("The zone chosen here is the zone of the form and of the list below it.")}
        actions={
          <Actions>
            <button type="button" disabled={!selected || !name || !value} data-testid="plan-record"
                    onClick={() => request.mutate(record(true))}>
              {t("Plan record")}
            </button>
            <button type="button" className="fl-danger" disabled={!selected || !name || !value}
                    data-testid="plan-record-removal" onClick={() => request.mutate(record(false))}>
              {t("Plan removal")}
            </button>
          </Actions>
        }
      >
        <Stack>
          {message && <Note>{message}</Note>}
          <Fields>
            <Field label={t("Zone")}>
              <select value={selected} onChange={(e) => setZone(e.target.value)} data-testid="zone">
                {(zones.data?.items ?? []).map((item) => (
                  <option key={item.name} value={item.name}>
                    {item.reverse ? `${item.name} (${t("reverse")})` : item.name}
                  </option>
                ))}
              </select>
            </Field>
            <Field label={t("Name")}>
              <input value={name} onChange={(e) => setName(e.target.value)}
                     placeholder={t("name (web, @, _ldap._tcp)")} data-testid="record-name" />
            </Field>
            <Field label={t("Type")}>
              <select value={type} onChange={(e) => setType(e.target.value)} data-testid="record-type">
                {RECORD_TYPES.map((item) => <option key={item} value={item}>{item}</option>)}
              </select>
            </Field>
            <Field label={t("Value")}>
              <input value={value} onChange={(e) => setValue(e.target.value)}
                     placeholder={t("value (10.0.0.5)")} data-testid="record-value" />
            </Field>
            <Field label="TTL">
              <input value={ttl} onChange={(e) => setTtl(e.target.value)} placeholder="TTL" />
            </Field>
          </Fields>
          {(type === "A" || type === "AAAA") && (
            <Check checked={reverse} onChange={setReverse}>
              {t("Also write the reverse (PTR) record — forgetting it is the usual mistake")}
            </Check>
          )}
        </Stack>
      </Form>
      </C>

      <Card
        span={12}
        title={selected ? t("Records of {zone}", { zone: selected }) : t("Records")}
        flush
        foot={records.data ? t("{n} records", { n: records.data.items.length }) : undefined}
      >
        {records.error
          ? <Problem>{String(records.error)}</Problem>
          : (
            <Table
              rows={records.data?.items ?? []}
              keyOf={(one, index) => `${one.name}-${one.type}-${index}`}
              testId="dns-records"
              rowTestId={(one) => `record-${one.name}-${one.type}`}
              empty={!selected
                ? t("The directory has no zone the panel can read.")
                : records.isLoading
                  ? t("Reading the directory…")
                  : t("This zone has no records the panel can read.")}
              columns={[
                { key: "name", head: t("Name"), tight: true, cell: (one) => <code>{one.name}</code> },
                { key: "type", head: t("Type"), cell: (one) => one.type },
                { key: "values", head: t("Value"), cell: (one) => <Names items={one.values} /> },
                // A record whose TTL the directory did not give has no TTL
                // of nought; it has none the panel was told about.
                { key: "ttl", head: "TTL", num: true, cell: (one) => one.ttl ?? "—" },
              ]}
            />
          )}
      </Card>
    </Grid>
  );
}

/* ----------------------------------------------------------------- health */

function HealthTab() {
  const t = useT();
  const status = useQuery({
    queryKey: ["identity-status"],
    queryFn: () => api.get<IdentityStatus>("/api/v1/identity/status"),
    retry: false,
  });

  if (status.error) return <Problem>{String(status.error)}</Problem>;
  const data = status.data;
  if (!data) return <Bones rows={5} />;

  const connector = data.connector;
  const fleet = data.hosts;
  const verdicts = fleet?.by_verdict ?? {};
  return (
    <Grid>
      <Card span={12}>
        <Note>
          {t("Two independent halves: what the panel can say about its own connection to the directory, and what the hosts reported about theirs. One being red does not colour the other.")}
        </Note>
      </Card>

      <Card
        span={6}
        title={t("Connector")}
        note={!data.configured
          ? t("No directory connector is configured.")
          : data.reachable
            ? data.summary
            : t("Directory unavailable: {error}", { error: data.error ?? "" })}
        tools={
          <Pill tone={!data.configured ? "unknown" : data.reachable ? "ok" : "error"}>
            {!data.configured ? t("not configured") : data.reachable ? t("reachable") : t("unreachable")}
          </Pill>
        }
      >
        {!data.configured
          ? <Empty icon="directory">{t("No directory connector is configured.")}</Empty>
          : (
            <Facts>
              <Fact label={t("Principal")}>
                <code>{data.principal ?? connector?.principal ?? "—"}</code>
              </Fact>
              <Fact label={t("Reachable")}>
                {data.reachable ? <Pill tone="ok">{t("yes")}</Pill> : <Pill tone="error">{t("no")}</Pill>}
              </Fact>
              <Fact label={t("Last successful call")}>
                {connector?.last_success_at
                  ? <span title={absoluteTime(connector.last_success_at)}>{relativeTime(connector.last_success_at)}</span>
                  : "—"}
              </Fact>
              <Fact label={t("Last error")}>
                {connector?.last_error
                  ? (
                    <TwoLine sub={connector.last_error_at
                      ? <span title={absoluteTime(connector.last_error_at)}>{relativeTime(connector.last_error_at)}</span>
                      : undefined}>
                      {connector.last_error}
                    </TwoLine>
                  )
                  : "—"}
              </Fact>
              <Fact label={t("Cache")}>
                {connector
                  ? (
                    <Figs>
                      <Fig label={t("Entries")} value={connector.cache_entries} />
                      <Fig
                        label={t("Oldest")}
                        value={connector.cache_oldest_at ? relativeTime(connector.cache_oldest_at) : undefined}
                      />
                      <Fig label={t("TTL, seconds")} value={connector.cache_ttl_seconds} />
                    </Figs>
                  )
                  : "—"}
              </Fact>
            </Facts>
          )}
      </Card>

      <Card
        span={6}
        title={t("Keytab")}
        note={t("The connector's own keytab as the panel reads it. A keytab file carries no expiry date - only the key version and the stamp of its last write - so none is shown.")}
        tools={connector
          ? <Pill tone={connector.keytab_readable ? "ok" : "warn"}>{connector.keytab_readable ? t("read") : t("unreadable")}</Pill>
          : undefined}
        flush
      >
        {!connector
          ? <Empty icon="directory">{t("No directory connector is configured.")}</Empty>
          : !connector.keytab_readable
            ? <Banner tone="warn">{connector.keytab_detail || t("The keytab could not be read.")}</Banner>
            : (
              <Table
                rows={connector.keytab_entries}
                keyOf={(_, index) => String(index)}
                testId="keytab"
                empty={t("The keytab holds no entries.")}
                columns={[
                  { key: "principal", head: t("Principal"), tight: true, cell: (one) => <code>{one.principal}</code> },
                  { key: "kvno", head: "KVNO", num: true, cell: (one) => one.kvno },
                  {
                    key: "written",
                    head: t("Written"),
                    cell: (one) => one.timestamp
                      ? <span title={absoluteTime(one.timestamp)}>{relativeTime(one.timestamp)}</span>
                      : "—",
                  },
                ]}
              />
            )}
      </Card>

      <Card
        span={4}
        title={t("What the hosts said")}
        note={t("The panel's verdict on the logins of every host that last reported itself cut off, from the facts the host itself reported.")}
      >
        {Object.keys(verdicts).length === 0
          ? <Empty icon="check">{t("No host reported itself cut off from the directory.")}</Empty>
          : (
            <Pie
              testId="verdicts"
              label={t("hosts")}
              slices={Object.keys(verdicts).sort().map((verdict) => ({
                label: verdictLabel(verdict, t),
                value: verdicts[verdict],
                tone: verdictTone(verdict),
              }))}
            />
          )}
      </Card>

      <Card
        span={8}
        title={t("Hosts offline from the directory")}
        note={t("Enrolled hosts whose SSSD last reported itself cut off from the directory.")}
        tools={
          <Pill tone={fleet?.offline_count ? "warn" : "ok"}>
            {fleet
              ? t("{n} offline", { n: fleet.offline_count })
              : t("not counted")}
          </Pill>
        }
        flush
      >
        <Table
          rows={fleet?.offline_from_directory ?? []}
          keyOf={(one) => one.id}
          testId="offline-hosts"
          rowTestId={(one) => `offline-${one.hostname}`}
          empty={t("Every enrolled host last reported the directory reachable.")}
          columns={[
            {
              key: "host",
              head: t("Host"),
              cell: (one) => <Link to={`/hosts/${one.id}/identity`}>{one.hostname}</Link>,
            },
            {
              key: "where",
              head: t("Site / environment"),
              minor: true,
              cell: (one) => [one.site, one.environment].filter(Boolean).join(" / ") || "—",
            },
            {
              key: "checked",
              head: t("Checked"),
              cell: (one) => one.checked_at
                ? <span title={absoluteTime(one.checked_at)}>{relativeTime(one.checked_at)}</span>
                : "—",
            },
            {
              key: "verdict",
              head: t("Verdict"),
              cell: (one) => (
                <TwoLine sub={one.offline_verdict.reason || undefined}>
                  <Pill tone={verdictTone(one.offline_verdict.verdict)}>
                    {verdictLabel(one.offline_verdict.verdict, t)}
                  </Pill>
                </TwoLine>
              ),
            },
          ]}
        />
      </Card>
    </Grid>
  );
}

/** Every verdict has its label; one the panel adds later is shown by its code. */
export function verdictLabel(verdict: string, t: Translate): string {
  switch (verdict) {
    case "cached_logins_until": return t("cached logins until a date");
    case "cached_logins_indefinitely": return t("cached logins indefinitely");
    case "no_cached_logins": return t("no cached logins");
    case "unknown": return t("unknown");
    default: return verdict;
  }
}

/** A host that cannot log in at all is the fault; one nobody judged is unknown. */
export function verdictTone(verdict: string): Tone {
  if (verdict === "no_cached_logins") return "error";
  if (verdict === "unknown") return "unknown";
  return "warn";
}
