import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../../lib/api";
import type { DirectoryChange, DirectoryUser, RevealedSecret } from "../../lib/types";
import { ErrorBox, Empty, Time } from "../../components/ui";
import { Actions, Card, Field, FieldGrid, Toolbar } from "../../components/layout";
import { useT } from "../../i18n";
import {
  DirectoryConfirmation, Forbidden, ListField, PlanImpact, ReasonField, lines, names, useDirectoryChange,
} from "./shared";

/**
 * The accounts of the directory and their lifecycle: creation, lock and
 * unlock, expiry, the POSIX data, preservation and the password reset.
 * Every one of them is a change: planned here, approved by a second
 * person, carried out phase by phase - the panel never writes the
 * directory from a click.
 */

type Intent =
  | { kind: "disable" | "enable"; user: DirectoryUser }
  | { kind: "expire"; user: DirectoryUser }
  | { kind: "posix"; user: DirectoryUser }
  | { kind: "preserve"; user: DirectoryUser }
  | { kind: "password"; user: DirectoryUser };

const EMPTY_USER = { uid: "", first_name: "", last_name: "", email: "", shell: "", groups: "", ssh_keys: "" };
type UserForm = typeof EMPTY_USER;

const DAY = 24 * 60 * 60 * 1000;

/** The expiry as a badge: past is red, within two weeks amber, otherwise the date. */
function Expiry({ value, label }: { value?: string; label: string }) {
  const t = useT();
  if (!value) return null;
  const at = new Date(value).getTime();
  const left = at - Date.now();
  const text = `${label} ${new Date(value).toLocaleDateString()}`;
  if (Number.isNaN(at)) return <span className="badge unknown" title={value}>{label}</span>;
  if (left < 0) return <span className="badge error" title={value}>{t("{what} expired", { what: text })}</span>;
  if (left < 14 * DAY) return <span className="badge warn" title={value}>{text}</span>;
  return <span className="badge" title={value}>{text}</span>;
}

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

export function Users() {
  const t = useT();
  const [form, setForm] = useState<UserForm | null>(null);
  const [reason, setReason] = useState("");
  const [intent, setIntent] = useState<Intent | null>(null);
  const { mutation, change, message } = useDirectoryChange(["identity-users", "identity-users-preserved"]);

  const { data, error } = useQuery({
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
  if (error instanceof ApiError && error.forbidden) return <Forbidden />;
  if (error) return <ErrorBox error={error} />;

  const set = <K extends keyof UserForm>(key: K, value: UserForm[K]) =>
    setForm((current) => (current ? { ...current, [key]: value } : current));

  const order = (action: string, payload: Record<string, unknown>, why: string) => {
    mutation.mutate({ action, reason: why, payload }, { onSuccess: () => { setIntent(null); setForm(null); } });
  };

  return (
    <>
      <p className="subtitle">
        {t("An account is created, locked, expired, preserved or given a new password as a change: the plan shows the groups, the hosts reachable through HBAC and the sudo rules, a second person approves it, and every phase keeps its own result. The initial password never reaches the logs.")}
      </p>

      <Toolbar end={<span>{t("{n} accounts", { n: (data?.items ?? []).length })}</span>}>
        <button onClick={() => { setForm({ ...EMPTY_USER }); setIntent(null); }}>{t("New account")}</button>
      </Toolbar>

      {form && (
        <Card
          title={t("New account")}
          footer={
            <Actions>
              <button disabled={!form.uid || !form.last_name || reason.trim().length < 8 || mutation.isPending}
                      onClick={() => order("identity.user.create", {
                        user: {
                          uid: form.uid.trim(), first_name: form.first_name.trim(), last_name: form.last_name.trim(),
                          email: form.email.trim(), shell: form.shell.trim(),
                          groups: names(form.groups), ssh_keys: lines(form.ssh_keys),
                        },
                      }, reason)}>
                {t("Plan account")}
              </button>
              <button className="secondary" onClick={() => setForm(null)}>{t("Close")}</button>
              {message && <p className="page-error">{message}</p>}
            </Actions>
          }
        >
          <FieldGrid>
            <Field label={t("Account")}>
              <input value={form.uid} onChange={(e) => set("uid", e.target.value)} placeholder="jsmith" />
            </Field>
            <Field label={t("First name")}>
              <input value={form.first_name} onChange={(e) => set("first_name", e.target.value)} />
            </Field>
            <Field label={t("Surname")}>
              <input value={form.last_name} onChange={(e) => set("last_name", e.target.value)} />
            </Field>
            <Field label={t("E-mail")}>
              <input value={form.email} onChange={(e) => set("email", e.target.value)} placeholder="jsmith@example.test" />
            </Field>
            <Field label={t("Shell")}>
              <input value={form.shell} onChange={(e) => set("shell", e.target.value)} placeholder="/bin/bash" />
            </Field>
            <ListField label={t("Groups")} value={form.groups} onChange={(v) => set("groups", v)} placeholder="ops, developers" />
            <Field label={t("SSH public keys, one per line")} wide hint={t("A private key never reaches the system; only the public half is accepted.")}>
              <textarea rows={3} value={form.ssh_keys} onChange={(e) => set("ssh_keys", e.target.value)} placeholder="ssh-ed25519 AAAA… user@host" />
            </Field>
            <ReasonField value={reason} onChange={setReason} />
          </FieldGrid>
        </Card>
      )}

      {intent && (intent.kind === "disable" || intent.kind === "enable") && (
        <Card
          title={intent.kind === "disable" ? t("Lock the account {uid}", { uid: intent.user.uid }) : t("Unlock the account {uid}", { uid: intent.user.uid })}
          description={intent.kind === "disable"
            ? t("The local denial marker and the panel sessions go first, the directory second: the reverse order would leave a working session for the time the change takes to propagate.")
            : t("The directory unlocks the account and the panel lifts its denial marker.")}
          footer={
            <Actions>
              <button disabled={reason.trim().length < 8 || mutation.isPending}
                      onClick={() => order(`identity.user.${intent.kind}`, { reference: { uid: intent.user.uid, reason } }, reason)}>
                {intent.kind === "disable" ? t("Plan lock") : t("Plan unlock")}
              </button>
              <button className="secondary" onClick={() => setIntent(null)}>{t("Close")}</button>
              {message && <p className="page-error">{message}</p>}
            </Actions>
          }
        >
          <FieldGrid><ReasonField value={reason} onChange={setReason} /></FieldGrid>
        </Card>
      )}

      {intent && intent.kind === "expire" && (
        <ExpireForm user={intent.user} busy={mutation.isPending} message={message}
                    onSubmit={(payload, why) => order("identity.user.expire", payload, why)}
                    onClose={() => setIntent(null)} />
      )}

      {intent && intent.kind === "posix" && (
        <PosixForm user={intent.user} busy={mutation.isPending} message={message}
                   onSubmit={(payload, why) => order("identity.user.posix", payload, why)}
                   onClose={() => setIntent(null)} />
      )}

      {intent && intent.kind === "preserve" && (
        <DirectoryConfirmation
          target={intent.user.uid}
          danger
          label={t("Plan preservation")}
          description={t("The account is locked, its panel sessions end, and the entry moves to the preserved accounts: it keeps its UID and its trail but nobody signs in with it. The panel cannot bring it back.")}
          busy={mutation.isPending}
          onConfirm={(why) => order("identity.user.preserve", { reference: { uid: intent.user.uid, reason: why } }, why)}
          onCancel={() => setIntent(null)}
        />
      )}

      {intent && intent.kind === "password" && (
        <DirectoryConfirmation
          target={intent.user.uid}
          label={t("Plan password reset")}
          description={t("The directory generates a one-time password that expires on first login. After a second person approves the change, the person who ordered it reads the password once from the recent changes below; it is neither stored nor written to the audit trail.")}
          busy={mutation.isPending}
          onConfirm={(why) => order("identity.user.password.reset", { reference: { uid: intent.user.uid } }, why)}
          onCancel={() => setIntent(null)}
        />
      )}
      {message && !form && !intent && <p className="page-error">{message}</p>}

      {change && <PlanImpact change={change} />}
      {change && change.action_type === "identity.user.password.reset" && (
        <p className="source">
          {t("The reset waits for a second person's approval. Once it is carried out, the one-time password appears under recent changes for the person who ordered it.")}
        </p>
      )}

      <Card flush>
        {!data?.items.length ? (
          <Empty>{t("No accounts.")}</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>{t("Account")}</th><th>{t("Full name")}</th><th className="num">UID</th><th>{t("Groups")}</th>
                <th className="num">{t("SSH keys")}</th><th>{t("Expires")}</th><th>{t("State")}</th><th></th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((user) => (
                <tr key={user.uid}>
                  <td className="mono">{user.uid}</td>
                  <td>{[user.first_name, user.last_name].filter(Boolean).join(" ")}</td>
                  <td className="num">{user.uid_number || "—"}</td>
                  <td>{(user.groups ?? []).join(", ") || "—"}</td>
                  <td className="num">{user.ssh_key_fingerprints?.length ?? 0}</td>
                  <td>
                    {!user.principal_expires_at && !user.password_expires_at ? "—" : (
                      <>
                        <Expiry value={user.principal_expires_at} label={t("account")} />{" "}
                        <Expiry value={user.password_expires_at} label={t("password")} />
                      </>
                    )}
                  </td>
                  <td>{user.disabled ? <span className="badge error">{t("locked")}</span> : <span className="badge ok">{t("active")}</span>}</td>
                  <td className="num">
                    <div className="actions">
                      {user.disabled
                        ? <button className="secondary" onClick={() => { setIntent({ kind: "enable", user }); setForm(null); }}>{t("Unlock")}</button>
                        : <button className="secondary" onClick={() => { setIntent({ kind: "disable", user }); setForm(null); }}>{t("Lock")}</button>}
                      <button className="secondary" onClick={() => { setIntent({ kind: "expire", user }); setForm(null); }}>{t("Expire")}</button>
                      <button className="secondary" onClick={() => { setIntent({ kind: "posix", user }); setForm(null); }}>{t("POSIX")}</button>
                      <button className="secondary" onClick={() => { setIntent({ kind: "password", user }); setForm(null); }}>{t("Reset password")}</button>
                      <button className="secondary" onClick={() => { setIntent({ kind: "preserve", user }); setForm(null); }}>{t("Preserve")}</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <Card
        title={t("Preserved accounts")}
        description={t("Soft-deleted entries: the UID and the trail stay, nobody signs in. They are listed apart so they are not counted as users.")}
        flush
      >
        {preserved.error ? (
          <ErrorBox error={preserved.error} />
        ) : !(preserved.data?.items ?? []).length ? (
          <Empty>{t("No preserved accounts.")}</Empty>
        ) : (
          <table>
            <thead><tr><th>{t("Account")}</th><th>{t("Full name")}</th><th className="num">UID</th><th>{t("Last password change")}</th></tr></thead>
            <tbody>
              {(preserved.data?.items ?? []).map((user) => (
                <tr key={user.uid}>
                  <td className="mono">{user.uid}</td>
                  <td>{[user.first_name, user.last_name].filter(Boolean).join(" ")}</td>
                  <td className="num">{user.uid_number || "—"}</td>
                  <td><Time value={user.last_password_change} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <RecentChanges />
    </>
  );
}

/**
 * The expiry of an account: the Kerberos principal (no ticket after the
 * date) and the password (a change forced at the next login). Each may be
 * set, left alone or cleared; clearing is a value of its own, because
 * "no date" typed in a field would otherwise mean "do not touch".
 */
function ExpireForm({ user, busy, message, onSubmit, onClose }: {
  user: DirectoryUser; busy: boolean; message: string;
  onSubmit: (payload: Record<string, unknown>, reason: string) => void; onClose: () => void;
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
    <Card
      title={t("Expiry of the account {uid}", { uid: user.uid })}
      description={t("The account expiry ends every Kerberos login after the date; the password expiry forces a change at the next login. A field left empty stays as it is.")}
      footer={
        <Actions>
          <button disabled={!touched || reason.trim().length < 8 || busy} onClick={() => onSubmit({ expiry }, reason)}>
            {t("Plan expiry")}
          </button>
          <button className="secondary" onClick={onClose}>{t("Close")}</button>
          {message && <p className="page-error">{message}</p>}
        </Actions>
      }
    >
      <FieldGrid>
        <Field label={t("Account expires at")}>
          <input type="datetime-local" value={principal} disabled={clearPrincipal} onChange={(e) => setPrincipal(e.target.value)} />
        </Field>
        <Field label={t("Password expires at")}>
          <input type="datetime-local" value={password} disabled={clearPassword} onChange={(e) => setPassword(e.target.value)} />
        </Field>
      </FieldGrid>
      <label className="toggle">
        <input type="checkbox" checked={clearPrincipal} onChange={(e) => setClearPrincipal(e.target.checked)} />
        {t("Clear the account expiry")}
      </label>
      <label className="toggle">
        <input type="checkbox" checked={clearPassword} onChange={(e) => setClearPassword(e.target.checked)} />
        {t("Clear the password expiry")}
      </label>
      <FieldGrid><ReasonField value={reason} onChange={setReason} /></FieldGrid>
    </Card>
  );
}

/** The POSIX data of an account; only a field that differs from the directory is sent. */
function PosixForm({ user, busy, message, onSubmit, onClose }: {
  user: DirectoryUser; busy: boolean; message: string;
  onSubmit: (payload: Record<string, unknown>, reason: string) => void; onClose: () => void;
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
    <Card
      title={t("POSIX data of the account {uid}", { uid: user.uid })}
      description={t("A changed UID or GID leaves the files on every host owned by the old number; the plan says so before anybody approves.")}
      footer={
        <Actions>
          <button disabled={!changed || reason.trim().length < 8 || busy} onClick={() => onSubmit({ posix }, reason)}>
            {t("Plan POSIX change")}
          </button>
          <button className="secondary" onClick={onClose}>{t("Close")}</button>
          {message && <p className="page-error">{message}</p>}
        </Actions>
      }
    >
      <FieldGrid>
        <Field label="UID"><input value={uidNumber} onChange={(e) => setUidNumber(e.target.value)} /></Field>
        <Field label="GID"><input value={gidNumber} onChange={(e) => setGidNumber(e.target.value)} /></Field>
        <Field label={t("Shell")}><input value={shell} onChange={(e) => setShell(e.target.value)} placeholder="/bin/bash" /></Field>
        <Field label={t("Home directory")}><input value={home} onChange={(e) => setHome(e.target.value)} placeholder={`/home/${user.uid}`} /></Field>
        <ReasonField value={reason} onChange={setReason} />
      </FieldGrid>
    </Card>
  );
}

/**
 * The recent directory changes and, for a finished password reset, the
 * one-time password. The password is read once from the panel's memory
 * with a reason and fresh authentication, shown in this card and nowhere
 * else: not in the address, not in the browser's storage, not in a toast
 * that outlives the page.
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
          : reveal.error.code === "reason_required" ? t("A change of access needs a reason of at least 8 characters.")
            : reveal.error.message
    : reveal.error instanceof Error ? reveal.error.message : "";

  if (changes.error instanceof ApiError && changes.error.forbidden) return null;

  return (
    <Card title={t("Recent changes")} description={t("The last directory changes, newest first; a change is approved by a second person before it runs.")} flush>
      {secret && (
        <div className="card-body">
          <p className="warning">
            <span>{t("The one-time password of {uid}. It expires on first login and will not be shown again.", { uid: secret.uid })}</span>
          </p>
          <p className="mono" data-testid="one-time-password">{secret.one_time_password}</p>
          <Actions>
            <button className="secondary" onClick={() => {
              // The clipboard may be refused outside a secure context; the
              // password stays on the screen either way.
              navigator.clipboard?.writeText(secret.one_time_password).then(() => setCopied(true)).catch(() => setCopied(false));
            }}>
              {copied ? t("Copied") : t("Copy")}
            </button>
            <button className="secondary" onClick={() => { setSecret(null); setCopied(false); }}>{t("Hide")}</button>
          </Actions>
        </div>
      )}
      {changes.error ? (
        <ErrorBox error={changes.error} />
      ) : !(changes.data?.items ?? []).length ? (
        <Empty>{t("No directory changes yet.")}</Empty>
      ) : (
        <table>
          <thead><tr><th>{t("Change")}</th><th>{t("Type")}</th><th>{t("State")}</th><th>{t("Ordered by")}</th><th>{t("Result")}</th><th></th></tr></thead>
          <tbody>
            {(changes.data?.items ?? []).map((item) => (
              <tr key={item.id}>
                <td className="mono">{item.id.slice(0, 8)}</td>
                <td className="mono">{item.action_type}</td>
                <td><span className={item.state === "succeeded" ? "badge ok" : item.state === "failed" || item.state === "partially_applied" ? "badge error" : "badge"}>{item.state.replace("_", " ")}</span></td>
                <td>{item.created_by || "—"}</td>
                <td className="source">{item.result_message || "—"}</td>
                <td className="num">
                  {item.action_type === "identity.user.password.reset" && item.secret_available && (
                    revealing === item.id ? (
                      <div className="actions">
                        <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder={t("why the password is read (min. 8 characters)")} />
                        <button disabled={reason.trim().length < 8 || reveal.isPending} onClick={() => reveal.mutate(item.id)}>{t("Reveal")}</button>
                        <button className="secondary" onClick={() => { setRevealing(null); setReason(""); }}>{t("Cancel")}</button>
                      </div>
                    ) : (
                      <button className="secondary" onClick={() => { setRevealing(item.id); setSecret(null); }}>{t("Reveal one-time password")}</button>
                    )
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {revealError && <div className="card-body"><p className="page-error">{revealError}</p></div>}
    </Card>
  );
}
