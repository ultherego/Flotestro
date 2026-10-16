import { useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../../../lib/api";
import { useAllowed, useModuleAccess } from "../../../lib/actions";
import { absoluteTime, relativeTime } from "../../../lib/format";
import {
  emptyForm, operationForm, type FormProblem, type FormValue,
} from "../../../lib/operations";
import type { Host, Job, LocalAccount } from "../../../lib/types";
import { useT } from "../../../i18n";
import { Board } from "../../Board";
import type { BoardEntry } from "../../../components/board";
import {
  Actions, Band, Banner, Bars, Bones, Button, Card, Check, Empty, Fact, Facts, Field, Fields,
  Modal, Note, Pill, Problem, Table, Tabs, Toolbar, TwoLine, type Segment, type Tone,
} from "../../kit";

/**
 * Who can get into this machine, and how.
 *
 * Every row here is a way in: a key, a password, a group that is root by
 * another name. The module therefore says three things rather than two -
 * a way in, no way in, and *nobody has told us*, which is the answer an
 * account the host could not read gives and is never drawn as a nought.
 *
 * Nothing on this screen reads a secret back. The panel sets no password,
 * carries none in an order, and a private key pasted into the key field is
 * refused by the registry before anything is sent.
 */

/**
 * The groups whose membership is root by another name: sudo and wheel give
 * root directly, docker and lxd through the engine socket.
 */
const PRIVILEGED_GROUPS = ["sudo", "wheel", "docker", "lxd"];

/** The changes this module offers; when every one is refused, it says so once. */
const ACCOUNT_CHANGES = [
  "localuser.create", "localuser.delete", "localuser.lock", "localuser.unlock",
  "localuser.groups.set", "localuser.expiry.set",
  "localuser.sshkeys.add", "localuser.sshkeys.remove", "localuser.sshkeys.replace_all",
];

/** The shortest reason the API takes for a change of access. */
const MIN_REASON = 8;

/** One key of an account, as the inventory reports it. */
type AccountKey = LocalAccount["ssh_keys"][number];

/**
 * The file a key lives in: the user's own `~/.ssh/authorized_keys`, or the
 * file the panel manages under `/etc/ssh/authorized_keys.d`.
 */
type KeyFile = "authorized_keys" | "managed";

function fileOf(key: AccountKey): KeyFile {
  return key.source === "managed" ? "managed" : "authorized_keys";
}

function fileName(t: (text: string) => string, file: KeyFile): string {
  return file === "managed" ? t("the panel's managed file") : t("the user's authorized_keys");
}

/** The fingerprint as a row shows it: short, with the whole of it on hover. */
export function shortFingerprint(fingerprint: string): string {
  return `${fingerprint.replace(/^SHA256:/, "").slice(0, 12)}…`;
}

/** A count over a list, or undefined while the list itself is unknown. */
function countWhere<T>(items: T[] | undefined, test: (item: T) => boolean): number | undefined {
  return items === undefined ? undefined : items.filter(test).length;
}

/* ------------------------------------------------------------- the order */

/** One order as the registry composes it: what would be sent, and what is wrong with it. */
export type RegistryOrder = { action: string; payload: Record<string, unknown>; problems: FormProblem[] };

/**
 * Puts an order through the registry entry of its action, so this module and
 * the Bulk workspace send one payload and refuse one set of values.
 */
export function registryOrder(action: string, seed: FormValue): RegistryOrder {
  const entry = operationForm(action);
  if (!entry) {
    return { action, payload: {}, problems: [{ message: "The registry has no form for {action} yet.", params: { action } }] };
  }
  const form = { ...emptyForm(entry), ...seed };
  return { action, payload: entry.toPayload(form), problems: entry.validate(form) };
}

export type Order = {
  action: string;
  name: string;
  gecos?: string;
  groups?: string[];
  /** The complete key list of a create or a replace; an empty one is a decision. */
  ssh_keys?: string[];
  /** The keys an add appends, each with the comment it is to carry. */
  keys?: { public_key: string; comment?: string }[];
  /** The keys a removal names, by fingerprint. */
  fingerprints?: string[];
  /** The keys the operator saw; a replace is bound to them. */
  expected_fingerprints?: string[];
  /** Consent to leaving the account with no way in. */
  allow_lockout?: boolean;
  /** Edit the panel's own key file instead of the user's authorized_keys. */
  managed_file?: boolean;
  /** Consent to creating an account nobody can log in as. */
  inactive?: boolean;
  create_home?: boolean;
  /** The expiry date as YYYY-MM-DD; an empty string on an expiry order clears it. */
  expires_at?: string;
  remove_home?: boolean;
  /** The reason and the typed target of a destructive order. */
  reason?: string;
  target_confirmation?: string;
};

/**
 * One account order as the operation registry composes it. A comment of the
 * key's own is the one thing the registry's key list does not carry, and this
 * is the only place in the panel where one is typed.
 */
export function accountOrder(order: Order): RegistryOrder {
  const keys = order.keys ?? [];
  const composed = registryOrder(order.action, {
    name: order.name,
    gecos: order.gecos ?? "",
    groups: (order.groups ?? []).join("\n"),
    ssh_keys: (order.ssh_keys ?? []).join("\n"),
    public_keys: keys.map((key) => key.public_key).join("\n"),
    fingerprints: (order.fingerprints ?? []).join("\n"),
    expected_fingerprints: (order.expected_fingerprints ?? []).join("\n"),
    allow_lockout: order.allow_lockout === true,
    managed_file: order.managed_file === true,
    inactive: order.inactive === true,
    create_home: order.create_home === true,
    expires_at: order.expires_at ?? "",
    remove_home: order.remove_home === true,
  });
  if (!keys.some((key) => key.comment)) return composed;
  const section = { ...(composed.payload.local_user as Record<string, unknown>) };
  section.keys = keys.map((key) => (key.comment ? { ...key } : { public_key: key.public_key }));
  return { ...composed, payload: { local_user: section } };
}

/** Whether the registry would take this order as it stands. */
export function orderReady(order: RegistryOrder): boolean {
  return order.problems.length === 0;
}

/** The first refusal of an order as a sentence, or an empty string. */
export function refusalOf(
  t: (text: string, params?: Record<string, string | number>) => string,
  order: RegistryOrder,
): string {
  const problem = order.problems[0];
  return problem ? t(problem.message, problem.params) : "";
}

export type Request = { mutate: (order: Order) => void; message: string; error: boolean; busy: boolean };

/**
 * Requesting an operation creates a plan, not an immediate change: a
 * mutating operation waits for approval by default.
 */
function useRequest(host: Host): Request {
  const t = useT();
  const queryClient = useQueryClient();
  const [message, setMessage] = useState("");
  const [error, setError] = useState(false);

  const mutation = useMutation({
    mutationFn: (order: Order) => {
      const composed = accountOrder(order);
      // The registry's refusal is the same one the Bulk workspace shows;
      // nothing goes out until the order is one the panel would compose.
      const refusal = composed.problems[0];
      if (refusal) return Promise.reject(new Error(t(refusal.message, refusal.params)));
      return api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action: order.action,
        reason: order.reason,
        target_confirmation: order.target_confirmation,
        payload: composed.payload,
      });
    },
    onSuccess: (job) => {
      setError(false);
      setMessage(
        job.requires_approval
          ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
          : t("Job {id} has been queued. The list refreshes after the agent's next report.", { id: job.id.slice(0, 8) }),
      );
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      queryClient.invalidateQueries({ queryKey: ["local-accounts", host.id] });
    },
    onError: (failure) => {
      setError(true);
      setMessage(failure instanceof Error ? failure.message : String(failure));
    },
  });

  return { mutate: mutation.mutate, message, error, busy: mutation.isPending };
}

/* ------------------------------------------------------------- the gates */

/**
 * A control that exists only where the order it places would be taken.
 *
 * `explain` keeps the refusal on the screen as a sentence rather than
 * taking the control away without a word.
 */
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

/** The one line the module shows when every change it offers is refused. */
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

/* ------------------------------------------------------------ the module */

/** What is waiting for a decision before it is sent. */
type Ask =
  | { kind: "unlock"; account: LocalAccount }
  | { kind: "delete"; account: LocalAccount }
  | { kind: "removeKey"; account: LocalAccount; key: AccountKey; cutsOff: boolean }
  | { kind: "replaceKeys"; account: LocalAccount; file: KeyFile; lines: string[]; expected: string[]; cutsOff: boolean };

export function Accounts({ host }: { host: Host }) {
  const t = useT();
  const [showSystem, setShowSystem] = useState(false);
  const [creating, setCreating] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const [ask, setAsk] = useState<Ask | null>(null);
  const request = useRequest(host);

  const query = useQuery({
    queryKey: ["local-accounts", host.id, showSystem],
    queryFn: () =>
      api.get<{ accounts: LocalAccount[] }>(
        `/api/v1/hosts/${host.id}/local-accounts${showSystem ? "?source=system" : ""}`,
      ),
    retry: false,
  });

  if (query.error instanceof ApiError && query.error.forbidden) {
    return (
      <Card title={t("Accounts")}>
        <Empty icon="accounts">{t("You do not have permission to read this host's accounts.")}</Empty>
      </Card>
    );
  }
  if (query.error) return <Problem>{String(query.error)}</Problem>;

  const accounts = query.data?.accounts ?? [];
  // The list is unknown until it lands: dashes, not a host without accounts.
  const known = query.data ? accounts : undefined;
  const selected = accounts.find((one) => one.name === open);
  const sources: LocalAccount["source"][] = ["local", "directory", "system", "unknown"];

  const access: Segment[] = [
    { label: t("SSH key"), value: countWhere(known, (a) => a.locked === false && a.ssh_keys.length > 0), tone: "ok" },
    { label: t("password"), value: countWhere(known, (a) => a.locked === false && a.ssh_keys.length === 0 && a.password_set === true), tone: "warn" },
    { label: t("locked"), value: countWhere(known, (a) => a.locked === true), tone: "neutral" },
    { label: t("no access"), value: countWhere(known, (a) => a.locked === false && a.ssh_keys.length === 0 && a.password_set === false), tone: "error" },
    { label: t("unknown"), value: countWhere(known, (a) => a.locked === null || (a.locked === false && a.ssh_keys.length === 0 && a.password_set === null)), tone: "unknown" },
  ];

  return (
    <>
      <ReadOnlyNotice host={host.id} actions={ACCOUNT_CHANGES} />
      {request.message && (
        <Banner tone={request.error ? "error" : "info"}>{request.message}</Banner>
      )}

      <Board screen="next_host_accounts" catalogue={HOST_ACCOUNTS} drawn={{
        access: (
          <Card
            title={t("Access")}
            note={t("How each account can be entered, as the host reports it.")}
            tools={
              <Guard action="localuser.create" host={host.id}>
                <Button kind="quiet" onClick={() => setCreating(true)} disabled={creating} testId="new-account">
                  {t("Create local account")}
                </Button>
              </Guard>
            }
          >
            {known === undefined
              ? <Bones rows={2} height={18} />
              : <Band segments={access} testId="account-access" />}
          </Card>
        ),
        sources: (
          <Card title={t("By source")} note={t("Where each account is defined.")}>
            {known === undefined ? <Bones rows={4} /> : (
              <Bars items={sources.map((source) => ({
                label: sourceName(t, source),
                value: countWhere(known, (a) => a.source === source) ?? 0,
                tone: (source === "unknown" ? "unknown" : "accent") as Tone,
              }))} />
            )}
          </Card>
        ),
        create: creating && (
          <NewAccount host={host} request={request} onClose={() => setCreating(false)} />
        ),
        accounts: (
          <Card
            title={t("Accounts")}
            note={known === undefined ? undefined : t("{n} on this host", { n: accounts.length })}
            foot={accounts.length > 0
              ? <span title={absoluteTime(accounts[0].observed_at)}>
                  {t("Source: the agent's report, observed {when}", { when: relativeTime(accounts[0].observed_at) })}
                </span>
              : undefined}
            flush
          >
            <Toolbar>
              <Check checked={showSystem} onChange={setShowSystem}>{t("Show system accounts")}</Check>
            </Toolbar>
            <Table
              rows={accounts}
              keyOf={(one) => one.name}
              loading={query.isLoading}
              rowTestId={(one) => `account-${one.name}`}
              empty={showSystem
                ? t("The host reported no system accounts.")
                : t("The host has not reported user accounts yet.")}
              columns={[
                {
                  key: "name",
                  head: t("Account"),
                  cell: (one) => <TwoLine sub={one.gecos || undefined}>{one.name}</TwoLine>,
                },
                { key: "uid", head: "UID", num: true, cell: (one) => one.uid },
                { key: "source", head: t("Source"), minor: true, cell: (one) => sourceName(t, one.source) },
                { key: "access", head: t("Access"), cell: (one) => <AccessPill account={one} /> },
                {
                  key: "keys",
                  head: t("SSH keys"),
                  cell: (one) => one.ssh_keys.length === 0
                    ? <Note>{t("none")}</Note>
                    : <>{one.ssh_keys.map((key) => (
                        <TwoLine key={`${fileOf(key)}:${key.fingerprint}`} sub={key.comment || undefined}>
                          <span title={`${t("fingerprint")} ${key.fingerprint}`}>
                            {key.type || "?"} · {shortFingerprint(key.fingerprint)}
                          </span>
                        </TwoLine>
                      ))}</>,
                },
                { key: "groups", head: t("Groups"), minor: true, cell: (one) => <AccountGroups groups={one.groups} /> },
                { key: "expires", head: t("Expires"), cell: (one) => <Expiry account={one} /> },
                {
                  key: "do",
                  head: t("Actions"),
                  actions: true,
                  cell: (one) => one.source === "directory"
                    // Changing a directory account belongs to the directory.
                    ? <Note>{t("managed by directory")}</Note>
                    : (
                      <Actions>
                        {one.locked === true ? (
                          <Guard action="localuser.unlock" host={host.id}>
                            <Button
                              kind="quiet"
                              title={t("Lets the account log in again; the reason is kept in the audit trail.")}
                              onClick={() => setAsk({ kind: "unlock", account: one })}
                            >
                              {t("Unlock")}
                            </Button>
                          </Guard>
                        ) : (
                          <Guard action="localuser.lock" host={host.id}>
                            <Button
                              kind="quiet"
                              title={t("Locks the account so nobody can log in as it; the order goes out at once and can be undone with Unlock.")}
                              onClick={() => request.mutate({ action: "localuser.lock", name: one.name })}
                              testId={`lock-${one.name}`}
                            >
                              {t("Lock")}
                            </Button>
                          </Guard>
                        )}
                        <Button
                          kind="quiet"
                          onClick={() => setOpen(open === one.name ? null : one.name)}
                          testId={`manage-${one.name}`}
                        >
                          {t("Manage")}
                        </Button>
                        <Guard action="localuser.delete" host={host.id}>
                          <Button kind="danger" onClick={() => setAsk({ kind: "delete", account: one })} testId={`delete-${one.name}`}>
                            {t("Delete")}
                          </Button>
                        </Guard>
                      </Actions>
                    ),
                },
              ]}
            />
          </Card>
        ),
        account: selected && (
          <AccountPanel
            host={host}
            account={selected}
            request={request}
            onAsk={setAsk}
            onClose={() => setOpen(null)}
          />
        ),
      }} />

      {ask?.kind === "unlock" && (
        <UnlockAsk host={host} account={ask.account} request={request} onClose={() => setAsk(null)} />
      )}
      {ask?.kind === "delete" && (
        <DeleteAsk host={host} account={ask.account} request={request} onClose={() => setAsk(null)} />
      )}
      {ask?.kind === "removeKey" && (
        <RemoveKeyAsk ask={ask} request={request} onClose={() => setAsk(null)} />
      )}
      {ask?.kind === "replaceKeys" && (
        <ReplaceKeysAsk ask={ask} request={request} onClose={() => setAsk(null)} />
      )}
    </>
  );
}

/* --------------------------------------------------------------- the row */

/**
 * Access combines three independent facts: the lock, the password and the
 * keys. None of them alone answers whether somebody can enter the host.
 */
export function AccessPill({ account }: { account: LocalAccount }) {
  const t = useT();
  if (account.locked === null) return <Pill tone="unknown">{t("unknown")}</Pill>;
  if (account.locked) return <Pill tone="neutral">{t("locked")}</Pill>;
  if (account.ssh_keys.length > 0) return <Pill tone="ok">{t("SSH key")}</Pill>;
  if (account.password_set === true) return <Pill tone="warn">{t("password")}</Pill>;
  // An account without a password and without a key is reachable by nobody.
  if (account.password_set === false) return <Pill tone="error">{t("no access")}</Pill>;
  return <Pill tone="unknown">{t("unknown")}</Pill>;
}

/** The groups of an account, with a badge on the ones that are root by another name. */
export function AccountGroups({ groups }: { groups: string[] }) {
  const t = useT();
  if (groups.length === 0) return <>—</>;
  return (
    <>
      {groups.map((group, index) => (
        <span key={group}>
          {index > 0 && ", "}
          {PRIVILEGED_GROUPS.includes(group)
            ? (
              <Pill
                tone="warn"
                title={t("Membership of this group is root by another name: changing it needs the permission accounts.privileged_groups on top of the operation's own, and an approval.")}
              >
                {group}
              </Pill>
            )
            : group}
        </span>
      ))}
    </>
  );
}

/** The expiry of an account: a date, never, or unknown where the record was not read. */
function Expiry({ account }: { account: LocalAccount }) {
  const t = useT();
  if (account.expires_at) {
    const expired = account.expires_at < new Date().toISOString().slice(0, 10);
    return (
      <Pill
        tone={expired ? "error" : "warn"}
        title={expired
          ? t("The account stopped accepting logins on that day.")
          : t("The account stops accepting logins on that day.")}
      >
        {account.expires_at}
      </Pill>
    );
  }
  if (account.unavailable_reason) return <Pill tone="unknown">{t("unknown")}</Pill>;
  return <Note>{t("never")}</Note>;
}

/* ------------------------------------------------------- the one account */

/** The three things that can be changed about one account, behind tabs. */
function AccountPanel({ host, account, request, onAsk, onClose }: {
  host: Host;
  account: LocalAccount;
  request: Request;
  onAsk: (ask: Ask) => void;
  onClose: () => void;
}) {
  const t = useT();
  const [tab, setTab] = useState<"keys" | "groups" | "expiry">("keys");
  return (
    <Card
      title={t("{name} on this host", { name: account.name })}
      tools={<Button kind="word" onClick={onClose}>{t("Close")}</Button>}
      bar={
        <Tabs
          value={tab}
          onChange={setTab}
          tabs={[
            { value: "keys", label: t("SSH keys"), count: account.ssh_keys.length },
            { value: "groups", label: t("Groups") },
            { value: "expiry", label: t("Expiry") },
          ]}
        />
      }
    >
      {tab === "keys" && <KeysTab host={host} account={account} request={request} onAsk={onAsk} />}
      {tab === "groups" && <GroupsTab host={host} account={account} request={request} />}
      {tab === "expiry" && <ExpiryTab host={host} account={account} request={request} />}
    </Card>
  );
}

/** The keys of one account: what it has, what is being added, what replaces the lot. */
function KeysTab({ host, account, request, onAsk }: {
  host: Host;
  account: LocalAccount;
  request: Request;
  onAsk: (ask: Ask) => void;
}) {
  const t = useT();
  const keys = account.ssh_keys;
  const [publicKey, setPublicKey] = useState("");
  const [comment, setComment] = useState("");
  const [keyReason, setKeyReason] = useState("");
  const [target, setTarget] = useState<KeyFile>("authorized_keys");
  const [replaceFile, setReplaceFile] = useState<KeyFile>("authorized_keys");
  const [replaceText, setReplaceText] = useState("");
  const privileged = account.groups.filter((group) => PRIVILEGED_GROUPS.includes(group));

  // Taking this key away leaves the account with no key at all, and the
  // account cannot log in with a password - an unread password state is not
  // "a password is set" either.
  const cutsOff = (fingerprint: string) =>
    account.password_set !== true && keys.every((key) => key.fingerprint === fingerprint);

  const addOrder = accountOrder({
    action: "localuser.sshkeys.add",
    name: account.name,
    keys: publicKey.trim() ? [{ public_key: publicKey.trim(), comment: comment.trim() || undefined }] : [],
    managed_file: target === "managed" || undefined,
  });

  // One order writes one file, so the list the order is bound to is the list
  // of that file - not the union the table above shows.
  const current = keys.filter((key) => fileOf(key) === replaceFile);
  const lines = replaceText.split("\n").map((line) => line.trim()).filter(Boolean);
  const replaceCutsOff = lines.length === 0 && account.password_set !== true
    && keys.every((key) => fileOf(key) === replaceFile);

  return (
    <>
      {privileged.length > 0 && (
        <Problem>
          {t("{name} is in {groups}: a key here opens an account that is root by another name. Changing that membership needs the permission accounts.privileged_groups on top of the operation's own, and an approval.", {
            name: account.name, groups: privileged.join(", "),
          })}
        </Problem>
      )}

      {keys.length === 0 ? (
        <Note>{t("The host reports no key for {name}. A key added here is the first way in.", { name: account.name })}</Note>
      ) : (
        <Table
          rows={keys}
          keyOf={(key) => `${fileOf(key)}:${key.fingerprint}`}
          rowTestId={() => "account-key"}
          columns={[
            { key: "type", head: t("Type"), cell: (key) => key.type || "?" },
            { key: "fingerprint", head: t("Fingerprint"), tight: true, cell: (key) => (
              <span title={key.fingerprint}>{shortFingerprint(key.fingerprint)}</span>
            ) },
            { key: "comment", head: t("Comment"), minor: true, cell: (key) => key.comment || "—" },
            { key: "file", head: t("Key file"), minor: true, cell: (key) => fileName(t, fileOf(key)) },
            { key: "do", head: t("Actions"), actions: true, cell: (key) => (
              <Guard action="localuser.sshkeys.remove" host={host.id}>
                <Button
                  kind="danger"
                  disabled={request.busy}
                  onClick={() => onAsk({ kind: "removeKey", account, key, cutsOff: cutsOff(key.fingerprint) })}
                  testId={`remove-key-${key.fingerprint}`}
                >
                  {t("Remove")}
                </Button>
              </Guard>
            ) },
          ]}
        />
      )}

      <Fields>
        <Field
          label={t("New key")}
          hint={t("One public key as it goes into the file: the type, the material and an optional comment. It is appended; the keys above stay as they are.")}
          wide
        >
          <input
            value={publicKey}
            placeholder="ssh-ed25519 AAAA… jane@laptop"
            onChange={(event) => setPublicKey(event.target.value)}
            data-testid="new-key"
          />
        </Field>
        <Field label={t("Comment")} hint={t("Appended only when the key carries none of its own.")}>
          <input value={comment} placeholder="jane@laptop" onChange={(event) => setComment(event.target.value)} />
        </Field>
        <Field
          label={t("Reason for adding the key (at least 8 characters)")}
          hint={t("A key added to an account is a way into it, so the trail says why it was added and not only who added it.")}
          wide
        >
          <input
            value={keyReason}
            placeholder={t("why this key is being added")}
            onChange={(event) => setKeyReason(event.target.value)}
            data-testid="key-reason"
          />
        </Field>
        <Field
          label={t("Key file")}
          hint={t("The panel's file keeps its keys apart from the ones the user wrote; sshd has to list it in AuthorizedKeysFile, or the host refuses the write.")}
        >
          <select value={target} onChange={(event) => setTarget(event.target.value as KeyFile)} data-testid="key-file">
            <option value="authorized_keys">{t("the user's authorized_keys")}</option>
            <option value="managed">{t("the panel's managed file")}</option>
          </select>
        </Field>
      </Fields>
      {publicKey.trim() !== "" && !orderReady(addOrder) && (
        <Problem>{refusalOf(t, addOrder)}</Problem>
      )}
      <Actions>
        <Guard action="localuser.sshkeys.add" host={host.id}>
          <Button
            disabled={!orderReady(addOrder) || keyReason.trim().length < MIN_REASON || request.busy}
            title={keyReason.trim().length < MIN_REASON
              ? t("The reason is kept in the audit trail and is at least 8 characters.")
              : refusalOf(t, addOrder)}
            testId="add-key"
            onClick={() => {
              request.mutate({
                action: "localuser.sshkeys.add",
                name: account.name,
                keys: [{ public_key: publicKey.trim(), comment: comment.trim() || undefined }],
                managed_file: target === "managed" || undefined,
                reason: keyReason.trim(),
              });
              setPublicKey("");
              setComment("");
              setKeyReason("");
            }}
          >
            {t("Add key")}
          </Button>
        </Guard>
      </Actions>

      <Fields>
        <Field label={t("Replace every key in a file")} hint={t("The file that is written anew; the other file of the account is not touched.")}>
          <select value={replaceFile} onChange={(event) => setReplaceFile(event.target.value as KeyFile)} data-testid="replace-file">
            <option value="authorized_keys">{t("the user's authorized_keys")}</option>
            <option value="managed">{t("the panel's managed file")}</option>
          </select>
        </Field>
        <Field
          label={t("The complete list")}
          hint={t("One public key per line. What is not on the list is gone from the file; an empty list revokes key access to it.")}
          wide
        >
          <textarea
            rows={4}
            value={replaceText}
            placeholder={"ssh-ed25519 AAAA… jane@laptop\nssh-ed25519 AAAA… deploy@ci"}
            onChange={(event) => setReplaceText(event.target.value)}
            data-testid="replace-keys"
          />
        </Field>
      </Fields>
      {current.length === 0 ? (
        <Note>{t("{file} of {name} carries no key today, so this order takes nothing away.", { file: fileName(t, replaceFile), name: account.name })}</Note>
      ) : (
        <Note>
          {t("The order carries these fingerprints as the state it was composed on; a key added to the account in the meantime makes it stale and the host refuses it.")}
        </Note>
      )}
      <Actions>
        <Guard action="localuser.sshkeys.replace_all" host={host.id}>
          <Button
            kind="danger"
            disabled={request.busy}
            testId="replace-all"
            onClick={() => onAsk({
              kind: "replaceKeys",
              account,
              file: replaceFile,
              lines,
              expected: current.map((key) => key.fingerprint),
              cutsOff: replaceCutsOff,
            })}
          >
            {t("Replace all…")}
          </Button>
        </Guard>
      </Actions>
    </>
  );
}

/**
 * The supplementary groups of an account, as a complete list: what is not on
 * it is taken away.
 */
function GroupsTab({ host, account, request }: { host: Host; account: LocalAccount; request: Request }) {
  const t = useT();
  const [groups, setGroups] = useState(account.groups.join(", "));
  const [reason, setReason] = useState("");
  const list = groups.split(/[\s,]+/).map((group) => group.trim()).filter(Boolean);
  const privileged = list.filter((group) => PRIVILEGED_GROUPS.includes(group));
  const ready = privileged.length === 0 || reason.trim().length >= MIN_REASON;
  return (
    <>
      <Fields>
        <Field
          label={t("Groups")}
          hint={t("The complete list of supplementary groups for {name}, separated by commas or spaces. An empty list takes every supplementary group away.", { name: account.name })}
          wide
        >
          <input value={groups} placeholder="developers, adm" onChange={(event) => setGroups(event.target.value)} data-testid="groups" />
        </Field>
        {privileged.length > 0 && (
          <Field
            label={t("Reason")}
            hint={t("A change of access that grants root by another name: at least 8 characters, recorded with the order.")}
            wide
          >
            <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="groups-reason" />
          </Field>
        )}
      </Fields>
      {privileged.length > 0 && (
        <Problem>
          {t("Privileged: {groups}. Membership there is root by another name; the order needs the permission accounts.privileged_groups beside localuser.groups.write, ranks critical and asks for fresh authentication and an approval.", { groups: privileged.join(", ") })}
        </Problem>
      )}
      <Actions>
        <Guard action="localuser.groups.set" host={host.id}>
          <Button
            disabled={!ready || request.busy}
            testId="set-groups"
            onClick={() => request.mutate({
              action: "localuser.groups.set",
              name: account.name,
              groups: list,
              reason: privileged.length > 0 ? reason.trim() : undefined,
            })}
          >
            {t("Set groups")}
          </Button>
        </Guard>
      </Actions>
    </>
  );
}

/**
 * The expiry date of an account: access with a date attached. Clearing it
 * restores access - a deliberate change, sent as an empty date.
 */
function ExpiryTab({ host, account, request }: { host: Host; account: LocalAccount; request: Request }) {
  const t = useT();
  const [date, setDate] = useState(account.expires_at ?? "");
  return (
    <>
      <Fields>
        <Field
          label={t("Expires on")}
          hint={t("The account stops accepting logins from that day. A date in the past cuts access off now, with a record of when.")}
        >
          <input type="date" value={date} onChange={(event) => setDate(event.target.value)} data-testid="expiry-date" />
        </Field>
      </Fields>
      <Actions>
        <Guard action="localuser.expiry.set" host={host.id}>
          <Button
            disabled={date === "" || request.busy}
            testId="set-expiry"
            onClick={() => request.mutate({ action: "localuser.expiry.set", name: account.name, expires_at: date })}
          >
            {t("Set expiry")}
          </Button>
        </Guard>
        <Guard action="localuser.expiry.set" host={host.id}>
          <Button
            kind="quiet"
            disabled={!account.expires_at || request.busy}
            testId="clear-expiry"
            onClick={() => request.mutate({ action: "localuser.expiry.set", name: account.name, expires_at: "" })}
          >
            {t("Clear expiry")}
          </Button>
        </Guard>
      </Actions>
    </>
  );
}

/* ---------------------------------------------------------- the new one */

function NewAccount({ host, request, onClose }: { host: Host; request: Request; onClose: () => void }) {
  const t = useT();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [groups, setGroups] = useState("");
  const [keys, setKeys] = useState("");
  const [inactive, setInactive] = useState(false);
  const [reason, setReason] = useState("");

  const groupList = groups.split(",").map((group) => group.trim()).filter(Boolean);
  const keyList = keys.split("\n").map((key) => key.trim()).filter(Boolean);
  const privileged = groupList.filter((group) => PRIVILEGED_GROUPS.includes(group));
  const createOrder = accountOrder({
    action: "localuser.create",
    name: name.trim(),
    gecos: description.trim(),
    groups: groupList,
    ssh_keys: keyList,
    create_home: true,
    inactive: inactive || undefined,
  });
  // The reason for a privileged group is this module's own: the registry sees
  // the form, not the permission the order will be weighed against.
  const ready = orderReady(createOrder) && (privileged.length === 0 || reason.trim().length >= MIN_REASON);

  return (
    <Card
      title={t("New local account")}
      note={t("The account is created without a password; access is by SSH key only. The panel never stores or transmits passwords.")}
    >
      <Fields>
        <Field label={t("Name")}>
          <input value={name} onChange={(event) => setName(event.target.value)} placeholder="jsmith" data-testid="create-name" />
        </Field>
        <Field label={t("Description")}>
          <input value={description} onChange={(event) => setDescription(event.target.value)} placeholder="Jane Smith" />
        </Field>
        <Field label={t("Additional groups")}>
          <input value={groups} onChange={(event) => setGroups(event.target.value)} placeholder="developers, adm" data-testid="create-groups" />
        </Field>
        <Field label={t("SSH public keys, one per line")} wide>
          <textarea rows={3} value={keys} onChange={(event) => setKeys(event.target.value)} data-testid="create-keys" />
        </Field>
        {privileged.length > 0 && (
          <Field
            label={t("Reason")}
            hint={t("A change of access that grants root by another name: at least 8 characters, recorded with the order.")}
            wide
          >
            <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="create-reason" />
          </Field>
        )}
      </Fields>
      {keyList.length === 0 && (
        <Check checked={inactive} onChange={setInactive}>
          {t("Create the account with no way in: no key, and the panel sets no password. Somebody will have to add a key before anybody can log in.")}
        </Check>
      )}
      {privileged.length > 0 && (
        <Problem>
          {t("Privileged: {groups}. An account created straight into such a group is root by another name; the order needs the permission accounts.privileged_groups beside localuser.create, ranks critical and asks for fresh authentication and an approval.", { groups: privileged.join(", ") })}
        </Problem>
      )}
      {name.trim() !== "" && !orderReady(createOrder) && <Problem>{refusalOf(t, createOrder)}</Problem>}
      <Actions>
        <Guard action="localuser.create" host={host.id}>
          <Button
            disabled={!ready || request.busy}
            title={refusalOf(t, createOrder)}
            testId="create-account"
            onClick={() => request.mutate({
              action: "localuser.create",
              name: name.trim(),
              gecos: description.trim(),
              groups: groupList,
              ssh_keys: keyList,
              create_home: true,
              inactive: inactive || undefined,
              reason: privileged.length > 0 ? reason.trim() : undefined,
            })}
          >
            {t("Request account creation")}
          </Button>
        </Guard>
        <Button kind="quiet" onClick={onClose}>{t("Cancel")}</Button>
      </Actions>
    </Card>
  );
}

/* ------------------------------------------------------- the decisions */

/** The target of the order, repeated at the decision: a specific machine. */
function Target({ host }: { host: Host }) {
  const t = useT();
  return (
    <Facts>
      <Fact label={t("Target")}>
        {host.hostname} · {host.management_address || t("address unknown")} · {host.site} / {host.environment}
      </Fact>
    </Facts>
  );
}

/** The reason every one of these orders carries into the trail. */
function Reason({ value, onChange, testId }: { value: string; onChange: (value: string) => void; testId: string }) {
  const t = useT();
  return (
    <Fields>
      <Field label={t("Reason (at least 8 characters, kept in the audit trail)")} wide>
        <input value={value} onChange={(event) => onChange(event.target.value)} data-testid={testId} />
      </Field>
    </Fields>
  );
}

/**
 * Letting an account log in again hands somebody access, and the panel keeps
 * the reason: the trail would otherwise say who unlocked and not why, over
 * the one operation whose whole effect is "this account can be used again".
 */
function UnlockAsk({ host, account, request, onClose }: {
  host: Host; account: LocalAccount; request: Request; onClose: () => void;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  return (
    <Modal
      title={t("Unlock {name}", { name: account.name })}
      onClose={onClose}
      actions={
        <>
          <Button kind="quiet" onClick={onClose} disabled={request.busy}>{t("Cancel")}</Button>
          <Button
            disabled={reason.trim().length < MIN_REASON || request.busy}
            testId="confirm-unlock"
            onClick={() => {
              request.mutate({ action: "localuser.unlock", name: account.name, reason: reason.trim() });
              onClose();
            }}
          >
            {t("Unlock {name}", { name: account.name })}
          </Button>
        </>
      }
    >
      <Note>
        {t("The account {name} will be able to log in to {host} again.", { name: account.name, host: host.hostname })}
      </Note>
      <Target host={host} />
      <Reason value={reason} onChange={setReason} testId="unlock-reason" />
    </Modal>
  );
}

/**
 * Deleting an account is destructive: a removed home directory does not come
 * back, and neither does the UID's ownership of what it left behind.
 */
function DeleteAsk({ host, account, request, onClose }: {
  host: Host; account: LocalAccount; request: Request; onClose: () => void;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [typed, setTyped] = useState("");
  const [removeHome, setRemoveHome] = useState(false);
  const ready = reason.trim().length >= MIN_REASON && typed === account.name;
  return (
    <Modal
      title={t("Delete account")}
      onClose={onClose}
      actions={
        <>
          <Button kind="quiet" onClick={onClose} disabled={request.busy}>{t("Cancel")}</Button>
          <Button
            kind="danger"
            disabled={!ready || request.busy}
            testId="confirm-delete"
            onClick={() => {
              request.mutate({
                action: "localuser.delete",
                name: account.name,
                remove_home: removeHome,
                reason: reason.trim(),
                target_confirmation: typed,
              });
              onClose();
            }}
          >
            {t("Delete account")}
          </Button>
        </>
      }
    >
      <Note>
        {removeHome
          ? t("The account {name} and its home directory will be deleted from {host}. This cannot be undone and needs two approvals.", { name: account.name, host: host.hostname })
          : t("The account {name} will be deleted from {host}; its home directory stays. This cannot be undone and needs two approvals.", { name: account.name, host: host.hostname })}
      </Note>
      <Target host={host} />
      <Check checked={removeHome} onChange={setRemoveHome}>
        {t("Remove the home directory {home} as well. Its contents are lost.", { home: account.home || "" })}
      </Check>
      <Note>{t("Files owned by UID {uid} elsewhere on the host stay behind without an owner.", { uid: account.uid })}</Note>
      <Reason value={reason} onChange={setReason} testId="delete-reason" />
      <Fields>
        <Field label={t("Type the name to confirm: {name}", { name: account.name })} wide>
          <input value={typed} onChange={(event) => setTyped(event.target.value)} data-testid="delete-confirm" />
        </Field>
      </Fields>
    </Modal>
  );
}

/** Taking one key away, and the consent where it is the account's last. */
function RemoveKeyAsk({ ask, request, onClose }: {
  ask: Extract<Ask, { kind: "removeKey" }>;
  request: Request;
  onClose: () => void;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [allowLockout, setAllowLockout] = useState(false);
  const ready = reason.trim().length >= MIN_REASON && (!ask.cutsOff || allowLockout);
  return (
    <Modal
      title={t("Remove a key from {name}", { name: ask.account.name })}
      onClose={onClose}
      actions={
        <>
          <Button kind="quiet" onClick={onClose} disabled={request.busy}>{t("Cancel")}</Button>
          <Button
            kind="danger"
            disabled={!ready || request.busy}
            testId="confirm-remove-key"
            onClick={() => {
              request.mutate({
                action: "localuser.sshkeys.remove",
                name: ask.account.name,
                fingerprints: [ask.key.fingerprint],
                managed_file: fileOf(ask.key) === "managed" || undefined,
                allow_lockout: allowLockout || undefined,
                reason: reason.trim(),
              });
              onClose();
            }}
          >
            {ask.cutsOff ? t("Remove and cut the account off") : t("Remove the key")}
          </Button>
        </>
      }
    >
      <Note>
        {t("{type} · {fingerprint}, from {file}.", {
          type: ask.key.type || "?",
          fingerprint: ask.key.fingerprint,
          file: fileName(t, fileOf(ask.key)),
        })}
      </Note>
      {ask.cutsOff && (
        <>
          <Problem>
            {t("This is the last key of {name}, and the account has no password login: after the removal nobody can log in as it. Add the new key first, or say that cutting the account off is the intent.", { name: ask.account.name })}
          </Problem>
          <Check checked={allowLockout} onChange={setAllowLockout}>
            {t("Nobody will be able to log in as {name} after this order. That is the intent.", { name: ask.account.name })}
          </Check>
        </>
      )}
      <Reason value={reason} onChange={setReason} testId="remove-key-reason" />
    </Modal>
  );
}

/** Writing the key file of an account anew: everything not on the list goes. */
function ReplaceKeysAsk({ ask, request, onClose }: {
  ask: Extract<Ask, { kind: "replaceKeys" }>;
  request: Request;
  onClose: () => void;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [allowLockout, setAllowLockout] = useState(false);
  const order = accountOrder({
    action: "localuser.sshkeys.replace_all",
    name: ask.account.name,
    ssh_keys: ask.lines,
    expected_fingerprints: ask.expected,
    managed_file: ask.file === "managed" || undefined,
    allow_lockout: allowLockout || undefined,
  });
  const ready = reason.trim().length >= MIN_REASON && orderReady(order) && !request.busy;
  const going = ask.account.ssh_keys.filter((key) => fileOf(key) === ask.file);
  return (
    <Modal
      title={t("Replace all keys")}
      onClose={onClose}
      actions={
        <>
          <Button kind="quiet" onClick={onClose} disabled={request.busy}>{t("Cancel")}</Button>
          <Button
            kind="danger"
            disabled={!ready}
            title={refusalOf(t, order)}
            testId="confirm-replace"
            onClick={() => {
              request.mutate({
                action: "localuser.sshkeys.replace_all",
                name: ask.account.name,
                ssh_keys: ask.lines,
                expected_fingerprints: ask.expected,
                managed_file: ask.file === "managed" || undefined,
                allow_lockout: allowLockout || undefined,
                reason: reason.trim(),
              });
              onClose();
            }}
          >
            {t("Replace all keys")}
          </Button>
        </>
      }
    >
      {going.length === 0 ? (
        <Note>{t("{file} of {name} carries no key today, so this order takes nothing away.", { file: fileName(t, ask.file), name: ask.account.name })}</Note>
      ) : (
        <>
          <Note>
            {t("These keys are in {file} of {name} now. Every one of them goes away unless it is on the list above:", { file: fileName(t, ask.file), name: ask.account.name })}
          </Note>
          <Facts>
            {going.map((key) => (
              <Fact key={key.fingerprint} label={key.type || "?"}>
                <span title={key.fingerprint}>
                  {shortFingerprint(key.fingerprint)}{key.comment ? ` · ${key.comment}` : ""}
                </span>
              </Fact>
            ))}
          </Facts>
        </>
      )}
      <Note>{t("The order carries {n} key(s) as the whole of what {file} is to hold afterwards.", { n: ask.lines.length, file: fileName(t, ask.file) })}</Note>
      {ask.lines.length === 0 && (
        <Check checked={allowLockout} onChange={setAllowLockout}>
          {ask.cutsOff
            ? t("The account keeps no key and has no password login: after this order nobody can log in as {name}. That is the intent.", { name: ask.account.name })
            : t("{file} of {name} will carry no key at all after this order. That is the intent.", { file: fileName(t, ask.file), name: ask.account.name })}
        </Check>
      )}
      {!orderReady(order) && <Problem>{refusalOf(t, order)}</Problem>}
      <Reason value={reason} onChange={setReason} testId="replace-reason" />
    </Modal>
  );
}

function sourceName(t: (text: string) => string, source: LocalAccount["source"]): string {
  switch (source) {
    case "local": return t("local");
    case "directory": return t("directory");
    case "system": return t("system");
    default: return t("unknown");
  }
}

/** The containers this module can draw, and the shape each ships with. */
export const HOST_ACCOUNTS: BoardEntry[] = [
  { key: "access", title: "Access", width: 8, height: 2 },
  { key: "sources", title: "By source", width: 4, height: 2 },
  { key: "create", title: "New local account", width: 12, height: 3 },
  { key: "accounts", title: "Accounts", width: 12, height: 4 },
  { key: "account", title: "One account", width: 12, height: 4 },
];

/** The name this module's arrangement is stored under. */
export const HOST_ACCOUNTS_SCREEN = "next_host_accounts";
