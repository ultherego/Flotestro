import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../../lib/api";
import type { Host, Job, LocalAccount } from "../../lib/types";
import { ErrorBox, Time, Empty } from "../../components/ui";
import { Breakdown } from "../../components/widgets";
import {
  Check, Field, Fields, Form, FormActions, FormNote, Message, ModuleHeader, ModulePage, Section, Summary, Table, Widgets,
  countWhere, useHost,
} from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { useT } from "../../i18n";

/**
 * The groups whose membership is root by another name: sudo and wheel give
 * root directly, docker through the engine socket, adm reads every log,
 * root and admin are what they say. The same list the control plane uses
 * to raise such an order to critical.
 */
const PRIVILEGED_GROUPS = ["sudo", "wheel", "docker", "adm", "root", "admin"];

/** The panel opened under an account row. */
type Panel = "keys" | "groups" | "expiry" | "delete";

/**
 * The host's local accounts.
 *
 * The module is meant for installations without an identity directory.
 * Where FreeIPA or another directory runs, people's accounts come from the
 * directory and the panel does not duplicate them - the view then shows
 * that the account is from the directory and offers no changes that belong
 * in the directory.
 *
 * The data comes from the agent's last report, not from querying the host
 * on request; hence the observation marker by the table.
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
        actions={<NewAccountButton onOpen={() => setCreating(true)} open={creating} />}
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
                {key.type || "?"} · {key.fingerprint.replace(/^SHA256:/, "").slice(0, 12)}…
                {key.comment && <span className="source"> {key.comment}</span>}
              </div>
            ))
          )}
        </td>
        <td className="source">
          {account.groups.map((group, index) => (
            <span key={group}>
              {index > 0 && ", "}
              {PRIVILEGED_GROUPS.includes(group)
                ? <span className="badge warn" title={t("Membership of this group gives root-level rights.")}>{group}</span>
                : group}
            </span>
          ))}
          {account.groups.length === 0 && "—"}
        </td>
        <td><Expiry account={account} /></td>
        <td>
          {fromDirectory ? (
            // Changing a directory account belongs to the directory. A
            // local change would drift the state between hosts at the next
            // synchronisation.
            <span className="source">{t("managed by directory")}</span>
          ) : (
            <div className="operations">
              {account.locked === true ? (
                <button
                  title={t("Lets the account log in again; the order goes out at once.")}
                  onClick={() => request.mutate({ action: "localuser.unlock", name: account.name })}
                >
                  {t("Unlock")}
                </button>
              ) : (
                <button
                  title={t("Locks the account so nobody can log in as it; the order goes out at once and can be undone with Unlock.")}
                  onClick={() => request.mutate({ action: "localuser.lock", name: account.name })}
                >
                  {t("Lock")}
                </button>
              )}
              <button className="secondary" onClick={() => toggle("keys")}>{t("SSH keys")}</button>
              <button className="secondary" onClick={() => toggle("groups")}>{t("Groups")}</button>
              <button className="secondary" onClick={() => toggle("expiry")}>{t("Expiry")}</button>
              {/* Deletion is irreversible, so it does not go straight from
                  the click - it opens the target confirmation. */}
              <button className="hm-danger" onClick={() => toggle("delete")}>{t("Delete")}</button>
            </div>
          )}
        </td>
      </tr>

      {panel === "keys" && (
        <tr>
          <td colSpan={8}>
            <KeysPanel account={account} request={request} onClose={() => setPanel(null)} />
          </td>
        </tr>
      )}
      {panel === "groups" && (
        <tr>
          <td colSpan={8}>
            <GroupsPanel account={account} request={request} onClose={() => setPanel(null)} />
          </td>
        </tr>
      )}
      {panel === "expiry" && (
        <tr>
          <td colSpan={8}>
            <ExpiryPanel account={account} request={request} onClose={() => setPanel(null)} />
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

function KeysPanel({ account, request, onClose }: { account: LocalAccount; request: Request; onClose: () => void }) {
  const t = useT();
  const [keys, setKeys] = useState("");
  return (
    <Form>
      <Fields>
        <Field label={t("SSH keys")} help={t("The complete set of keys for {name}, one per line. Saving an empty list revokes SSH key access.", { name: account.name })} wide>
          <textarea
            rows={4}
            value={keys}
            placeholder="ssh-ed25519 AAAA… jane@laptop"
            onChange={(event) => setKeys(event.target.value)}
          />
        </Field>
      </Fields>
      <FormActions>
        <button
          onClick={() =>
            request.mutate({
              action: "localuser.sshkeys.set",
              name: account.name,
              ssh_keys: keys.split("\n").map((line) => line.trim()).filter(Boolean),
            })
          }
        >
          {t("Save keys")}
        </button>
        <button className="secondary" onClick={onClose}>{t("Cancel")}</button>
      </FormActions>
    </Form>
  );
}

/**
 * The supplementary groups of an account, as a complete list: what is not
 * on it is taken away. A privileged group on the list is root by another
 * name; the panel says so before the order goes out, and the control plane
 * treats such an order as critical.
 */
function GroupsPanel({ account, request, onClose }: { account: LocalAccount; request: Request; onClose: () => void }) {
  const t = useT();
  const [groups, setGroups] = useState(account.groups.join(", "));
  const list = groups.split(/[\s,]+/).map((group) => group.trim()).filter(Boolean);
  const privileged = list.filter((group) => PRIVILEGED_GROUPS.includes(group));
  return (
    <Form>
      <Fields>
        <Field label={t("Groups")} help={t("The complete list of supplementary groups for {name}, separated by commas or spaces. An empty list takes every supplementary group away.", { name: account.name })} wide>
          <input value={groups} placeholder="developers, adm" onChange={(event) => setGroups(event.target.value)} />
        </Field>
      </Fields>
      {privileged.length > 0 && (
        <Message text={t("Privileged: {groups}. Membership there is root by another name; the order is critical and asks for fresh authentication.", { groups: privileged.join(", ") })} error />
      )}
      <FormActions>
        <button
          onClick={() => request.mutate({ action: "localuser.groups.set", name: account.name, groups: list })}
        >
          {t("Set groups")}
        </button>
        <button className="secondary" onClick={onClose}>{t("Cancel")}</button>
      </FormActions>
    </Form>
  );
}

/**
 * The expiry date of an account: access with a date attached. Clearing it
 * restores access - a deliberate change, sent as an empty date.
 */
function ExpiryPanel({ account, request, onClose }: { account: LocalAccount; request: Request; onClose: () => void }) {
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
        <button
          disabled={date === ""}
          onClick={() => request.mutate({ action: "localuser.expiry.set", name: account.name, expires_at: date })}
        >
          {t("Set expiry")}
        </button>
        <button
          className="secondary"
          disabled={!account.expires_at}
          onClick={() => request.mutate({ action: "localuser.expiry.set", name: account.name, expires_at: "" })}
        >
          {t("Clear expiry")}
        </button>
        <button className="secondary" onClick={onClose}>{t("Cancel")}</button>
      </FormActions>
    </Form>
  );
}

/**
 * Deleting an account is destructive: a removed home directory does not
 * come back, and neither does the UID's ownership of what it left behind.
 * The operator types the account name - the thing that goes away - and
 * two people approve.
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
    // nobody. It is usually a trace of access half taken away, and worth
    // seeing.
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
  const request = useRequest(host);

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
            <input value={groups} onChange={(e) => setGroups(e.target.value)} placeholder="sudo, adm" />
          </Field>
          <Field label={t("SSH public keys, one per line")} wide>
            <textarea rows={3} value={keys} onChange={(e) => setKeys(e.target.value)} />
          </Field>
        </Fields>
        <FormActions>
          <button
            disabled={!name.trim()}
            onClick={() =>
              request.mutate({
                action: "localuser.create",
                name: name.trim(),
                gecos: description.trim(),
                groups: groups.split(",").map((g) => g.trim()).filter(Boolean),
                ssh_keys: keys.split("\n").map((k) => k.trim()).filter(Boolean),
                create_home: true,
              })
            }
          >
            {t("Request account creation")}
          </button>
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
  ssh_keys?: string[];
  create_home?: boolean;
  /** The expiry date as YYYY-MM-DD; an empty string on an expiry order clears it. */
  expires_at?: string;
  remove_home?: boolean;
  /** The reason and the typed target of a destructive order. */
  reason?: string;
  target_confirmation?: string;
};

type Request = { mutate: (order: Order) => void; message: string; busy: boolean };

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
