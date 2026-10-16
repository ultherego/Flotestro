import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../../lib/api";
import type { DirectoryUser } from "../../lib/types";
import { ErrorBox } from "../../components/ui";
import { Actions, Cols, Empty, Field, Fields, Panel, Toolbar } from "../../ui/kit";
import { useT } from "../../i18n";
import { Forbidden, PlanImpact, ReasonField, lines, useDirectoryChange } from "./shared";

/**
 * The SSH public keys of the fleet, seen from the directory: who has keys,
 * which fingerprints, and who has none.
 */
export function SshKeys() {
  const t = useT();
  const [editing, setEditing] = useState<DirectoryUser | null>(null);
  const [keys, setKeys] = useState("");
  const [reason, setReason] = useState("");
  const { mutation, change, message } = useDirectoryChange(["identity-users"]);

  const { data, error } = useQuery({
    queryKey: ["identity-users"],
    queryFn: () => api.get<Collection<DirectoryUser>>("/api/v1/identity/users"),
    retry: false,
  });
  if (error instanceof ApiError && error.forbidden) return <Forbidden />;
  if (error) return <ErrorBox error={error} />;

  const users = data?.items ?? [];
  const withKeys = users.filter((user) => (user.ssh_key_fingerprints ?? []).length > 0);
  const withoutKeys = users.filter((user) => !(user.ssh_key_fingerprints ?? []).length);
  const total = withKeys.reduce((sum, user) => sum + (user.ssh_key_fingerprints ?? []).length, 0);
  const typed = lines(keys);

  return (
    <>
      <p className="ui-note">
        {t("The public keys the directory hands to every host. The directory records a key and its fingerprint but not the day it was added, so no key age is shown: unknown is not zero. A private key never reaches the system.")}
      </p>

      <Toolbar end={<span>{t("{keys} keys on {users} accounts", { keys: total, users: withKeys.length })}</span>} />

      {editing && (
        <Panel
          title={t("SSH keys of the account {uid}", { uid: editing.uid })}
          description={t("The complete set of keys, one per line; the directory replaces what it holds with this list.")}
          tone={typed.length === 0 ? "warn" : undefined}
          footer={
            <Actions>
              <button disabled={reason.trim().length < 8 || mutation.isPending}
                      onClick={() => mutation.mutate({
                        action: "identity.sshkeys.set", reason,
                        payload: { ssh_keys: { uid: editing.uid, keys: typed } },
                      }, { onSuccess: () => setEditing(null) })}>
                {typed.length === 0 ? t("Plan removal of every key") : t("Plan keys")}
              </button>
              <button className="ui-btn-secondary" onClick={() => setEditing(null)}>{t("Close")}</button>
              {message && <p className="ui-errorbox">{message}</p>}
            </Actions>
          }
        >
          {typed.length === 0 && (
            <p className="ui-banner"><span>{t("An empty list removes every key of the account and can cut off its SSH login.")}</span></p>
          )}
          <p className="ui-note">
            <strong>{t("Fingerprints now ({n})", { n: (editing.ssh_key_fingerprints ?? []).length })}:</strong>{" "}
            <span className="ui-mono">{(editing.ssh_key_fingerprints ?? []).join("; ") || "—"}</span>
          </p>
          <Fields>
            <Field label={t("SSH public keys, one per line")} wide>
              <textarea rows={4} value={keys} onChange={(e) => setKeys(e.target.value)} placeholder="ssh-ed25519 AAAA… user@host" />
            </Field>
            <ReasonField value={reason} onChange={setReason} />
          </Fields>
        </Panel>
      )}

      {change && <PlanImpact change={change} />}

      <Cols wide>
        <Panel title={t("Accounts with keys")} flush>
          {!withKeys.length ? (
            <Empty>{t("No account has an SSH key in the directory.")}</Empty>
          ) : (
            <table>
              <thead><tr><th scope="col">{t("Account")}</th><th scope="col" className="ui-numeric">{t("Keys")}</th><th scope="col">{t("Fingerprints")}</th><th scope="col">{t("State")}</th><th scope="col"></th></tr></thead>
              <tbody>
                {withKeys.map((user) => (
                  <tr key={user.uid}>
                    <td className="ui-mono">{user.uid}</td>
                    <td className="ui-numeric">{(user.ssh_key_fingerprints ?? []).length}</td>
                    <td className="ui-mono ui-note">
                      {(user.ssh_key_fingerprints ?? []).map((fingerprint, index) => <div key={index}>{fingerprint}</div>)}
                    </td>
                    <td>{user.disabled ? <span className="ui-pill ui-error">{t("locked")}</span> : <span className="ui-pill ui-ok">{t("active")}</span>}</td>
                    <td className="ui-numeric">
                      <button className="ui-btn-secondary" onClick={() => { setEditing(user); setKeys(""); }}>{t("Set keys")}</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>

        <Panel title={t("Accounts without keys")} description={t("These accounts sign in with a password or not at all over SSH.")} flush>
          {!withoutKeys.length ? (
            <Empty>{t("Every account has at least one key.")}</Empty>
          ) : (
            <table>
              <thead><tr><th scope="col">{t("Account")}</th><th scope="col">{t("State")}</th><th scope="col"></th></tr></thead>
              <tbody>
                {withoutKeys.map((user) => (
                  <tr key={user.uid}>
                    <td className="ui-mono">{user.uid}</td>
                    <td>{user.disabled ? <span className="ui-pill ui-error">{t("locked")}</span> : <span className="ui-pill ui-ok">{t("active")}</span>}</td>
                    <td className="ui-numeric">
                      <button className="ui-btn-secondary" onClick={() => { setEditing(user); setKeys(""); }}>{t("Set keys")}</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      </Cols>
    </>
  );
}
