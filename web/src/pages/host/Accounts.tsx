import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../../lib/api";
import type { Host, Job, LocalAccount } from "../../lib/types";
import { ErrorBox, Time, Empty } from "../../components/ui";
import { Breakdown } from "../../components/widgets";
import { ActionGuard } from "../../components/ActionGuard";
import {
  Check, Field, Fields, Form, FormActions, FormNote, Message, ModuleHeader, ModulePage, Section, Summary, Table, Widgets,
  countWhere, useHost,
} from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { useT } from "../../i18n";

/**
 * The groups whose membership is root by another name: sudo and wheel give
 * root directly, docker and lxd through the engine socket.
 */
const PRIVILEGED_GROUPS = ["sudo", "wheel", "docker", "lxd"];

/** The panel opened under an account row. */
type Panel = "keys" | "groups" | "expiry" | "delete";

/** One key of an account, as the inventory reports it. */
type AccountKey = LocalAccount["ssh_keys"][number];

/**
 * The file a key lives in: the user's own `~/. ssh/authorized_keys`, or the
 * file the panel manages under `/etc/ssh/authorized_keys.
 */
type KeyFile = "authorized_keys" | "managed";

function fileOf(key: AccountKey): KeyFile {
  return key.source === "managed" ? "managed" : "authorized_keys";
}

function fileName(t: (text: string) => string, file: KeyFile): string {
  return file === "managed" ? t("the panel's managed file") : t("the user's authorized_keys");
}

/** The fingerprint as a row shows it: short, with the full one in the title. */
function shortFingerprint(fingerprint: string): string {
  return `${fingerprint.replace(/^SHA256:/, "").slice(0, 12)}…`;
}

/**
 * The host's local accounts. The module is meant for installations without
 * an identity directory.
 */
export function HostAccounts() {
  const t = useT();
  const host = useHost();
  const [showSystem, setShowSystem] = useState(false);
  const [creating, setCreating] = useState(false);
  const query = useQuery({
    queryKey: ["local-accounts", host.id, showSystem],
    queryFn: () =>
      api.get<{ accounts: LocalAccount[] }>(
        `/api/v1/hosts/${host.id}/local-accounts${showSystem ? "?source=system" : ""}`,
      ),
    retry: false,
  });

  if (query.error instanceof ApiError && query.error.forbidden) {
    return <Empty>{t("You do not have permission to read this host's accounts.")}</Empty>;
  }
  if (query.error) return <ErrorBox error={query.error} />;

  const accounts = query.data?.accounts ?? [];
  const locked = accounts.filter((account) => account.locked === true).length;
  const noAccess = accounts.filter((account) =>
    account.locked === false && account.ssh_keys.length === 0 && account.password_set === false).length;
  // The list is unknown until it loads: dashes, not an empty host.
  const known = query.data ? accounts : undefined;
  const sources: LocalAccount["source"][] = ["local", "directory", "system", "unknown"];

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Accounts")}
        description={t("Accounts seen on the host at the agent's last report.")}
        actions={
          <ActionGuard action="localuser.create" host={host.id}>
            <NewAccountButton onOpen={() => setCreating(true)} open={creating} />
          </ActionGuard>
        }
      />
      {accounts.length > 0 && (
        <p className="hm-freshness">
          <span>{t("Source: the agent's report, observed")} <Time value={accounts[0].observed_at} /></span>
        </p>
      )}

      <Widgets>
      {/* The accounts by how they can be entered: a key, a password, not at
          all - and the ones nobody can say anything about. */}
      <Summary
        title={t("Access")}
        description={t("How each account can be entered, as the host reports it.")}
        span={8}
        segments={[
          { label: t("SSH key"), value: countWhere(known, (a) => a.locked === false && a.ssh_keys.length > 0), tone: "ok" },
          { label: t("password"), value: countWhere(known, (a) => a.locked === false && a.ssh_keys.length === 0 && a.password_set === true), tone: "warn" },
          { label: t("locked"), value: known ? locked : undefined, tone: "neutral" },
          { label: t("no access"), value: known ? noAccess : undefined, tone: "error" },
          { label: t("unknown"), value: countWhere(known, (a) => a.locked === null || (a.locked === false && a.ssh_keys.length === 0 && a.password_set === null)), tone: "unknown" },
        ]}
      />
      <Section title={t("By source")} span={4} description={t("Where each account is defined.")}>
        {!known ? (
          <p className="source" style={{ margin: 0 }}>{t("Loading…")}</p>
        ) : (
          <Breakdown
            items={sources.map((source) => ({
              label: sourceName(t, source), value: countWhere(known, (a) => a.source === source) ?? 0,
              tone: source === "unknown" ? "unknown" as const : "info" as const,
            }))}
          />
        )}
      </Section>

      {creating && <NewAccount host={host} onClose={() => setCreating(false)} />}

      <Section
        title={t("Accounts")}
        count={accounts.length}
        span={12}
        tools={
          <label className="toggle">
            <input
              type="checkbox"
              checked={showSystem}
              onChange={(event) => setShowSystem(event.target.checked)}
            />
            {t("Show system accounts")}
          </label>
        }
        flush
      >
        {accounts.length === 0 ? (
          <Empty>
            {showSystem
              ? t("The host reported no system accounts.")
              : t("The host has not reported user accounts yet.")}
          </Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>{t("Account")}</th><th className="hm-num">UID</th><th>{t("Source")}</th><th>{t("Access")}</th>
                <th>{t("SSH keys")}</th><th>{t("Groups")}</th><th>{t("Expires")}</th><th>{t("Actions")}</th>
              </tr>
            </thead>
            <tbody>
              {accounts.map((account) => (
                <Row key={account.name} host={host} account={account} />
              ))}
            </tbody>
          </Table>
        )}
      </Section>
      </Widgets>
    </ModulePage>
  );
}

/** The header action that opens the creation form. */
function NewAccountButton({ onOpen, open }: { onOpen: () => void; open: boolean }) {
  const t = useT();
  return (
    <button onClick={onOpen} disabled={open}>{t("Create local account")}</button>
  );
}

function Row({ host, account }: { host: Host; account: LocalAccount }) {
  const t = useT();
  const [panel, setPanel] = useState<Panel | null>(null);
  const request = useRequest(host);
  const fromDirectory = account.source === "directory";
  const toggle = (next: Panel) => setPanel(panel === next ? null : next);

  return (
    <>
      <tr>
        <td>
          <span className="hm-mono hm-primary">{account.name}</span>
          {account.gecos && <div className="source">{account.gecos}</div>}
        </td>
        <td className="hm-num">{account.uid}</td>
        <td>{sourceName(t, account.source)}</td>
        <td><Access account={account} /></td>
        <td>
          {account.ssh_keys.length === 0 ? (
            <span className="source">{t("none")}</span>
          ) : (
            account.ssh_keys.map((key) => (
              <div key={key.fingerprint} title={`${t("fingerprint")} ${key.fingerprint}`} className="hm-mono">
                {key.type || "?"} · {shortFingerprint(key.fingerprint)}
                {key.comment && <span className="source"> {key.comment}</span>}
              </div>
            ))
          )}
        </td>
        <td className="source"><AccountGroups groups={account.groups} /></td>
        <td><Expiry account={account} /></td>
        <td>
          {fromDirectory ? (
            // Changing a directory account belongs to the directory.
            <span className="source">{t("managed by directory")}</span>
          ) : (
            <div className="operations">
              {account.locked === true ? (
                <ActionGuard action="localuser.unlock" host={host.id}>
                  <button
                    title={t("Lets the account log in again; the order goes out at once.")}
                    onClick={() => request.mutate({ action: "localuser.unlock", name: account.name })}
                  >
                    {t("Unlock")}
                  </button>
                </ActionGuard>
              ) : (
                <ActionGuard action="localuser.lock" host={host.id}>
                  <button
                    title={t("Locks the account so nobody can log in as it; the order goes out at once and can be undone with Unlock.")}
                    onClick={() => request.mutate({ action: "localuser.lock", name: account.name })}
                  >
                    {t("Lock")}
                  </button>
                </ActionGuard>
              )}
              <button className="secondary" onClick={() => toggle("keys")}>{t("SSH keys")}</button>
              <button className="secondary" onClick={() => toggle("groups")}>{t("Groups")}</button>
              <button className="secondary" onClick={() => toggle("expiry")}>{t("Expiry")}</button>
              {/* Deletion is irreversible, so it does not go straight from
                  the click - it opens the target confirmation. */}
              <ActionGuard action="localuser.delete" host={host.id}>
                <button className="hm-danger" onClick={() => toggle("delete")}>{t("Delete")}</button>
              </ActionGuard>
            </div>
          )}
        </td>
      </tr>

      {panel === "keys" && (
        <tr>
          <td colSpan={8}>
            <KeysPanel hostID={host.id} account={account} request={request} onClose={() => setPanel(null)} />
          </td>
        </tr>
      )}
      {panel === "groups" && (
        <tr>
          <td colSpan={8}>
            <GroupsPanel hostID={host.id} account={account} request={request} onClose={() => setPanel(null)} />
          </td>
        </tr>
      )}
      {panel === "expiry" && (
        <tr>
          <td colSpan={8}>
            <ExpiryPanel hostID={host.id} account={account} request={request} onClose={() => setPanel(null)} />
          </td>
        </tr>
      )}
      {panel === "delete" && (
        <tr>
          <td colSpan={8}>
            <DeletePanel host={host} account={account} request={request} onClose={() => setPanel(null)} />
          </td>
        </tr>
      )}

      {request.message && (
        <tr>
          <td colSpan={8}><Message text={request.message} /></td>
        </tr>
      )}
    </>
  );
}

/**
 * The groups of an account, with a badge on the ones that are root by
 * another name.
 */
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
              <span
                className="badge warn"
                data-testid="privileged-group"
                title={t("Membership of this group is root by another name: changing it needs the permission accounts.privileged_groups on top of the operation's own, and an approval.")}
              >
                {group}
              </span>
            )
            : group}
        </span>
      ))}
    </>
  );
}

/** The expiry date of an account: a date, none, or unknown when the record was not read. */
function Expiry({ account }: { account: LocalAccount }) {
  const t = useT();
  if (account.expires_at) {
    const expired = account.expires_at < new Date().toISOString().slice(0, 10);
    return (
      <span className={expired ? "badge error" : "badge warn"} title={expired ? t("The account stopped accepting logins on that day.") : t("The account stops accepting logins on that day.")}>
        {account.expires_at}
      </span>
    );
  }
  if (account.unavailable_reason) return <span className="badge unknown">{t("unknown")}</span>;
  return <span className="source">{t("never")}</span>;
}

/**
 * The keys of one account, edited one key at a time.
 */
export function KeysPanel({
  hostID, account, request, onClose,
}: { hostID: string; account: LocalAccount; request: Request; onClose: () => void }) {
  const t = useT();
  const keys = account.ssh_keys;
  const [publicKey, setPublicKey] = useState("");
  const [comment, setComment] = useState("");
  const [target, setTarget] = useState<KeyFile>("authorized_keys");
  // The fingerprint whose removal is waiting for the lockout consent.
  const [lockoutFor, setLockoutFor] = useState<string | null>(null);
  const [replacing, setReplacing] = useState(false);
  const privileged = account.groups.filter((group) => PRIVILEGED_GROUPS.includes(group));

  // Taking this key away leaves the account with no key at all, and the
  // account cannot log in with a password - an unread password state is not
  // "a password is set" either.
  const cutsOff = (fingerprint: string) =>
    account.password_set !== true && keys.every((key) => key.fingerprint === fingerprint);

  const remove = (key: AccountKey, allowLockout: boolean) => {
    setLockoutFor(null);
    request.mutate({
      action: "localuser.sshkeys.remove",
      name: account.name,
      fingerprints: [key.fingerprint],
      managed_file: fileOf(key) === "managed" || undefined,
      allow_lockout: allowLockout || undefined,
    });
  };

  const add = () => {
    request.mutate({
      action: "localuser.sshkeys.add",
      name: account.name,
      keys: [{ public_key: publicKey.trim(), comment: comment.trim() || undefined }],
      managed_file: target === "managed" || undefined,
    });
    setPublicKey("");
    setComment("");
  };

  return (
    <Form>
      {privileged.length > 0 && (
        <Message
          error
          text={t("{name} is in {groups}: a key here opens an account that is root by another name. Changing that membership needs the permission accounts.privileged_groups on top of the operation's own, and an approval.", {
            name: account.name, groups: privileged.join(", "),
          })}
        />
      )}

      {keys.length === 0 ? (
        <FormNote>{t("The host reports no key for {name}. A key added here is the first way in.", { name: account.name })}</FormNote>
      ) : (
        <Table>
          <thead>
            <tr>
              <th>{t("Type")}</th><th>{t("Fingerprint")}</th><th>{t("Comment")}</th><th>{t("Key file")}</th><th>{t("Actions")}</th>
            </tr>
          </thead>
          <tbody>
            {keys.map((key) => (
              <tr key={`${fileOf(key)}:${key.fingerprint}`} data-testid="account-key">
                <td>{key.type || "?"}</td>
                <td className="hm-mono" title={key.fingerprint}>{shortFingerprint(key.fingerprint)}</td>
                <td className="source">{key.comment || "—"}</td>
                <td className="source">{fileName(t, fileOf(key))}</td>
                <td>
                  <ActionGuard action="localuser.sshkeys.remove" host={hostID}>
                    <button
                      className="hm-danger"
                      disabled={request.busy}
                      onClick={() => (cutsOff(key.fingerprint) ? setLockoutFor(key.fingerprint) : remove(key, false))}
                    >
                      {t("Remove")}
                    </button>
                  </ActionGuard>
                  {lockoutFor === key.fingerprint && (
                    <div className="hm-form">
                      <Message
                        error
                        text={t("This is the last key of {name}, and the account has no password login: after the removal nobody can log in as it. Add the new key first, or say that cutting the account off is the intent.", { name: account.name })}
                      />
                      <FormActions>
                        <button className="hm-danger" onClick={() => remove(key, true)}>
                          {t("Remove and cut the account off")}
                        </button>
                        <button className="secondary" onClick={() => setLockoutFor(null)}>{t("Cancel")}</button>
                      </FormActions>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      <Fields>
        <Field
          label={t("New key")}
          help={t("One public key as it goes into the file: the type, the material and an optional comment. It is appended; the keys above stay as they are.")}
          wide
        >
          <input
            value={publicKey}
            placeholder="ssh-ed25519 AAAA… jane@laptop"
            onChange={(event) => setPublicKey(event.target.value)}
          />
        </Field>
        <Field label={t("Comment")} help={t("Appended only when the key carries none of its own.")}>
          <input value={comment} placeholder="jane@laptop" onChange={(event) => setComment(event.target.value)} />
        </Field>
        <Field label={t("Key file")} help={t("The panel's file keeps its keys apart from the ones the user wrote; sshd has to list it in AuthorizedKeysFile, or the host refuses the write.")}>
          <select value={target} onChange={(event) => setTarget(event.target.value as KeyFile)}>
            <option value="authorized_keys">{t("the user's authorized_keys")}</option>
            <option value="managed">{t("the panel's managed file")}</option>
          </select>
        </Field>
      </Fields>

      <FormActions>
        <ActionGuard action="localuser.sshkeys.add" host={hostID}>
          <button disabled={!publicKey.trim() || request.busy} onClick={add}>{t("Add key")}</button>
        </ActionGuard>
        <ActionGuard action="localuser.sshkeys.replace_all" host={hostID}>
          <button className="hm-danger" disabled={replacing} onClick={() => setReplacing(true)}>
            {t("Replace all…")}
          </button>
        </ActionGuard>
        <button className="secondary" onClick={onClose}>{t("Cancel")}</button>
      </FormActions>

      {replacing && (
        <ReplaceAllKeys account={account} request={request} onClose={() => setReplacing(false)} />
      )}
    </Form>
  );
}

/**
 * Writing the key file of an account anew.
 */
function ReplaceAllKeys({
  account, request, onClose,
}: { account: LocalAccount; request: Request; onClose: () => void }) {
  const t = useT();
  const [file, setFile] = useState<KeyFile>("authorized_keys");
  const [text, setText] = useState("");
  const [reason, setReason] = useState("");
  const [allowLockout, setAllowLockout] = useState(false);

  // One order writes one file, so the list the order is bound to is the
  // list of that file - not the union the table above shows.
  const current = account.ssh_keys.filter((key) => fileOf(key) === file);
  const expected = current.map((key) => key.fingerprint);
  const lines = text.split("\n").map((line) => line.trim()).filter(Boolean);
  const cutsOff = lines.length === 0 && account.password_set !== true
    && account.ssh_keys.every((key) => fileOf(key) === file);
  const ready = reason.trim().length >= 8 && (!cutsOff || allowLockout) && !request.busy;

  return (
    <div className="hm-form">
      <Fields>
        <Field label={t("Key file")} help={t("The file that is written anew; the other file of the account is not touched.")}>
          <select value={file} onChange={(event) => setFile(event.target.value as KeyFile)}>
            <option value="authorized_keys">{t("the user's authorized_keys")}</option>
            <option value="managed">{t("the panel's managed file")}</option>
          </select>
        </Field>
        <Field
          label={t("The complete list")}
          help={t("One public key per line. What is not on the list is gone from the file; an empty list revokes key access to it.")}
          wide
        >
          <textarea rows={4} value={text} placeholder="ssh-ed25519 AAAA… jane@laptop&#10;ssh-ed25519 AAAA… deploy@ci" onChange={(event) => setText(event.target.value)} />
        </Field>
        <Field label={t("Reason")} help={t("Writing the whole list anew is a critical change of access: at least 8 characters, recorded with the order.")} wide>
          <input value={reason} onChange={(event) => setReason(event.target.value)} />
        </Field>
      </Fields>

      {current.length === 0 ? (
        <FormNote>{t("{file} of {name} carries no key today, so this order takes nothing away.", { file: fileName(t, file), name: account.name })}</FormNote>
      ) : (
        <>
          <FormNote>
            {t("These keys are in {file} of {name} now. Every one of them goes away unless it is on the list above:", { file: fileName(t, file), name: account.name })}
          </FormNote>
          <ul className="source" data-testid="keys-going-away">
            {current.map((key) => (
              <li key={key.fingerprint} className="hm-mono" title={key.fingerprint}>
                {key.type || "?"} · {shortFingerprint(key.fingerprint)}{key.comment ? ` · ${key.comment}` : ""}
              </li>
            ))}
          </ul>
          <FormNote>
            {t("The order carries these fingerprints as the state it was composed on; a key added to the account in the meantime makes it stale and the host refuses it.")}
          </FormNote>
        </>
      )}

      {cutsOff && (
        <Check checked={allowLockout} onChange={setAllowLockout}>
          {t("The account keeps no key and has no password login: after this order nobody can log in as {name}. That is the intent.", { name: account.name })}
        </Check>
      )}

      <FormActions>
        <button
          className="hm-danger"
          disabled={!ready}
          onClick={() => {
            request.mutate({
              action: "localuser.sshkeys.replace_all",
              name: account.name,
              ssh_keys: lines,
              expected_fingerprints: expected,
              managed_file: file === "managed" || undefined,
              allow_lockout: allowLockout || undefined,
              reason: reason.trim(),
            });
            onClose();
          }}
        >
          {t("Replace all keys")}
        </button>
        <button className="secondary" onClick={onClose}>{t("Cancel")}</button>
      </FormActions>
    </div>
  );
}

/**
 * The supplementary groups of an account, as a complete list: what is not on
 * it is taken away.
 */
function GroupsPanel({
  hostID, account, request, onClose,
}: { hostID: string; account: LocalAccount; request: Request; onClose: () => void }) {
  const t = useT();
  const [groups, setGroups] = useState(account.groups.join(", "));
  const [reason, setReason] = useState("");
  const list = groups.split(/[\s,]+/).map((group) => group.trim()).filter(Boolean);
  const privileged = list.filter((group) => PRIVILEGED_GROUPS.includes(group));
  const ready = privileged.length === 0 || reason.trim().length >= 8;
  return (
    <Form>
      <Fields>
        <Field label={t("Groups")} help={t("The complete list of supplementary groups for {name}, separated by commas or spaces. An empty list takes every supplementary group away.", { name: account.name })} wide>
          <input value={groups} placeholder="developers, adm" onChange={(event) => setGroups(event.target.value)} />
        </Field>
        {privileged.length > 0 && (
          <Field label={t("Reason")} help={t("A change of access that grants root by another name: at least 8 characters, recorded with the order.")} wide>
            <input value={reason} onChange={(event) => setReason(event.target.value)} />
          </Field>
        )}
      </Fields>
      {privileged.length > 0 && (
        <Message text={t("Privileged: {groups}. Membership there is root by another name; the order needs the permission accounts.privileged_groups beside localuser.groups.write, ranks critical and asks for fresh authentication and an approval.", { groups: privileged.join(", ") })} error />
      )}
      <FormActions>
        <ActionGuard action="localuser.groups.set" host={hostID}>
          <button
            disabled={!ready}
            onClick={() => request.mutate({
              action: "localuser.groups.set", name: account.name, groups: list,
              reason: privileged.length > 0 ? reason.trim() : undefined,
            })}
          >
            {t("Set groups")}
          </button>
        </ActionGuard>
        <button className="secondary" onClick={onClose}>{t("Cancel")}</button>
      </FormActions>
    </Form>
  );
}

/**
 * The expiry date of an account: access with a date attached. Clearing it
 * restores access - a deliberate change, sent as an empty date.
 */
function ExpiryPanel({
  hostID, account, request, onClose,
}: { hostID: string; account: LocalAccount; request: Request; onClose: () => void }) {
  const t = useT();
  const [date, setDate] = useState(account.expires_at ?? "");
  return (
    <Form>
      <Fields>
        <Field label={t("Expires on")} help={t("The account stops accepting logins from that day. A date in the past cuts access off now, with a record of when.")}>
          <input type="date" value={date} onChange={(event) => setDate(event.target.value)} />
        </Field>
      </Fields>
      <FormActions>
        <ActionGuard action="localuser.expiry.set" host={hostID}>
          <button
            disabled={date === ""}
            onClick={() => request.mutate({ action: "localuser.expiry.set", name: account.name, expires_at: date })}
          >
            {t("Set expiry")}
          </button>
        </ActionGuard>
        <ActionGuard action="localuser.expiry.set" host={hostID}>
          <button
            className="secondary"
            disabled={!account.expires_at}
            onClick={() => request.mutate({ action: "localuser.expiry.set", name: account.name, expires_at: "" })}
          >
            {t("Clear expiry")}
          </button>
        </ActionGuard>
        <button className="secondary" onClick={onClose}>{t("Cancel")}</button>
      </FormActions>
    </Form>
  );
}

/**
 * Deleting an account is destructive: a removed home directory does not come
 * back, and neither does the UID's ownership of what it left behind.
 */
function DeletePanel({ host, account, request, onClose }: { host: Host; account: LocalAccount; request: Request; onClose: () => void }) {
  const t = useT();
  const [removeHome, setRemoveHome] = useState(false);
  return (
    <div className="hm-form">
      <Check checked={removeHome} onChange={setRemoveHome}>
        {t("Remove the home directory {home} as well. Its contents are lost.", { home: account.home || "" })}
      </Check>
      <FormNote>{t("Files owned by UID {uid} elsewhere on the host stay behind without an owner.", { uid: account.uid })}</FormNote>
      <TargetConfirmation
        host={host}
        target={account.name}
        danger
        label={t("Delete account")}
        description={
          removeHome
            ? t("The account {name} and its home directory will be deleted from {host}. This cannot be undone and needs two approvals.", { name: account.name, host: host.hostname })
            : t("The account {name} will be deleted from {host}; its home directory stays. This cannot be undone and needs two approvals.", { name: account.name, host: host.hostname })
        }
        busy={request.busy}
        onConfirm={(reason, confirmation) =>
          request.mutate({
            action: "localuser.delete",
            name: account.name,
            remove_home: removeHome,
            reason,
            target_confirmation: confirmation,
          })
        }
        onCancel={onClose}
      />
    </div>
  );
}

/**
 * Access combines three independent facts: the lock, the password and the
 * keys. None of them alone answers whether somebody can enter the host.
 */
function Access({ account }: { account: LocalAccount }) {
  const t = useT();
  if (account.locked === null) {
    return <span className="badge unknown">{t("unknown")}</span>;
  }
  // The tones are the ones of the bar above the table: a key is the
  // desired way in, a password is worth a look, a lock is deliberate.
  if (account.locked) return <span className="badge">{t("locked")}</span>;
  if (account.ssh_keys.length > 0) {
    return <span className="badge ok">{t("SSH key")}</span>;
  }
  if (account.password_set === true) return <span className="badge warn">{t("password")}</span>;
  if (account.password_set === false) {
    // An account without a password and without a key is reachable by
    // nobody.
    return <span className="badge error">{t("no access")}</span>;
  }
  return <span className="badge unknown">{t("unknown")}</span>;
}

function NewAccount({ host, onClose }: { host: Host; onClose: () => void }) {
  const t = useT();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [groups, setGroups] = useState("");
  const [keys, setKeys] = useState("");
  const [inactive, setInactive] = useState(false);
  const [reason, setReason] = useState("");
  const request = useRequest(host);

  const groupList = groups.split(",").map((group) => group.trim()).filter(Boolean);
  const keyList = keys.split("\n").map((key) => key.trim()).filter(Boolean);
  const privileged = groupList.filter((group) => PRIVILEGED_GROUPS.includes(group));
  // An account with neither a key nor a password is an account nobody can
  // enter.
  const ready = name.trim() !== "" && (keyList.length > 0 ? !inactive : inactive)
    && (privileged.length === 0 || reason.trim().length >= 8);

  return (
    <Section
      title={t("New local account")}
      description={t("The account is created without a password; access is by SSH key only. The panel never stores or transmits passwords.")}
      span={12}
    >
      <Form>
        <Fields>
          <Field label={t("Name")}>
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="jsmith" />
          </Field>
          <Field label={t("Description")}>
            <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Jane Smith" />
          </Field>
          <Field label={t("Additional groups")}>
            <input value={groups} onChange={(e) => setGroups(e.target.value)} placeholder="developers, adm" />
          </Field>
          <Field label={t("SSH public keys, one per line")} wide>
            <textarea rows={3} value={keys} onChange={(e) => setKeys(e.target.value)} />
          </Field>
          {privileged.length > 0 && (
            <Field label={t("Reason")} help={t("A change of access that grants root by another name: at least 8 characters, recorded with the order.")} wide>
              <input value={reason} onChange={(e) => setReason(e.target.value)} />
            </Field>
          )}
        </Fields>
        {keyList.length === 0 && (
          <Check checked={inactive} onChange={setInactive}>
            {t("Create the account with no way in: no key, and the panel sets no password. Somebody will have to add a key before anybody can log in.")}
          </Check>
        )}
        {privileged.length > 0 && (
          <Message
            error
            text={t("Privileged: {groups}. An account created straight into such a group is root by another name; the order needs the permission accounts.privileged_groups beside localuser.create, ranks critical and asks for fresh authentication and an approval.", { groups: privileged.join(", ") })}
          />
        )}
        <FormActions>
          <ActionGuard action="localuser.create" host={host.id}>
            <button
              disabled={!ready}
              onClick={() =>
                request.mutate({
                  action: "localuser.create",
                  name: name.trim(),
                  gecos: description.trim(),
                  groups: groupList,
                  ssh_keys: keyList,
                  create_home: true,
                  inactive: inactive || undefined,
                  reason: privileged.length > 0 ? reason.trim() : undefined,
                })
              }
            >
              {t("Request account creation")}
            </button>
          </ActionGuard>
          <button className="secondary" onClick={onClose}>{t("Cancel")}</button>
        </FormActions>
        <Message text={request.message} />
      </Form>
    </Section>
  );
}

type Order = {
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

export type Request = { mutate: (order: Order) => void; message: string; busy: boolean };

/**
 * Requesting an operation creates a plan, not an immediate change: a
 * mutating operation waits for approval by default.
 */
function useRequest(host: Host): Request {
  const t = useT();
  const queryClient = useQueryClient();
  const [message, setMessage] = useState("");

  const mutation = useMutation({
    mutationFn: ({ action, reason, target_confirmation, ...rest }: Order) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action,
        reason,
        target_confirmation,
        payload: {
          local_user: {
            name: rest.name,
            gecos: rest.gecos || undefined,
            groups: rest.groups,
            ssh_keys: rest.ssh_keys,
            keys: rest.keys,
            fingerprints: rest.fingerprints,
            expected_fingerprints: rest.expected_fingerprints,
            allow_lockout: rest.allow_lockout,
            managed_file: rest.managed_file,
            inactive: rest.inactive,
            create_home: rest.create_home,
            expires_at: rest.expires_at,
            remove_home: rest.remove_home,
          },
        },
      }),
    onSuccess: (job) => {
      setMessage(
        job.requires_approval
          ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
          : t("Job {id} has been queued. The list refreshes after the agent's next report.", { id: job.id.slice(0, 8) }),
      );
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
      queryClient.invalidateQueries({ queryKey: ["local-accounts", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  return { mutate: mutation.mutate, message, busy: mutation.isPending };
}

function sourceName(t: (text: string) => string, source: LocalAccount["source"]) {
  switch (source) {
    case "local": return t("local");
    case "directory": return t("directory");
    case "system": return t("system");
    default: return t("unknown");
  }
}
