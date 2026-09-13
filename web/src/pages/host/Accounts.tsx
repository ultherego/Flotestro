import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../../lib/api";
import type { Host, Job, LocalAccount } from "../../lib/types";
import { ErrorBox, Time, Empty } from "../../components/ui";
import { useHost } from "./shared";
import { useT } from "../../i18n";

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

  return (
    <>
      <p className="subtitle">
        {t("Accounts seen on the host at the agent's last report.")}{" "}
        {accounts.length > 0 && <>{t("Observed")}: <Time value={accounts[0].observed_at} />.</>}
      </p>

      <label className="toggle">
        <input
          type="checkbox"
          checked={showSystem}
          onChange={(event) => setShowSystem(event.target.checked)}
        />
        {t("Show system accounts")}
      </label>

      {accounts.length === 0 ? (
        <Empty>
          {showSystem
            ? t("The host reported no system accounts.")
            : t("The host has not reported user accounts yet.")}
        </Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th>{t("Account")}</th><th>UID</th><th>{t("Source")}</th><th>{t("Access")}</th>
              <th>{t("SSH keys")}</th><th>{t("Groups")}</th><th>{t("Actions")}</th>
            </tr>
          </thead>
          <tbody>
            {accounts.map((account) => (
              <Row key={account.name} host={host} account={account} />
            ))}
          </tbody>
        </table>
      )}

      <NewAccount host={host} />
    </>
  );
}

function Row({ host, account }: { host: Host; account: LocalAccount }) {
  const t = useT();
  const [keys, setKeys] = useState<string | null>(null);
  const request = useRequest(host);
  const fromDirectory = account.source === "directory";

  return (
    <>
      <tr>
        <td>
          {account.name}
          {account.gecos && <div className="source">{account.gecos}</div>}
        </td>
        <td>{account.uid}</td>
        <td>{sourceName(t, account.source)}</td>
        <td><Access account={account} /></td>
        <td>
          {account.ssh_keys.length === 0 ? (
            <span className="source">{t("none")}</span>
          ) : (
            account.ssh_keys.map((key) => (
              <div key={key.fingerprint} title={key.fingerprint}>
                {key.type || "?"} · {key.fingerprint.replace(/^SHA256:/, "").slice(0, 12)}…
                {key.comment && <span className="source"> {key.comment}</span>}
              </div>
            ))
          )}
        </td>
        <td className="source">{account.groups.join(", ") || "—"}</td>
        <td>
          {fromDirectory ? (
            // Changing a directory account belongs to the directory. A
            // local change would drift the state between hosts at the next
            // synchronisation.
            <span className="source">{t("managed by directory")}</span>
          ) : (
            <div className="operations">
              {account.locked === true ? (
                <button onClick={() => request.mutate({ action: "localuser.unlock", name: account.name })}>
                  {t("Unlock")}
                </button>
              ) : (
                <button onClick={() => request.mutate({ action: "localuser.lock", name: account.name })}>
                  {t("Lock")}
                </button>
              )}
              <button onClick={() => setKeys(keys === null ? "" : null)}>{t("SSH keys")}</button>
            </div>
          )}
        </td>
      </tr>

      {keys !== null && (
        <tr>
          <td colSpan={7}>
            <div className="form">
              <p className="subtitle">
                {t("The complete set of keys for {name}, one per line. Saving an empty list revokes SSH key access.", { name: account.name })}
              </p>
              <textarea
                rows={4}
                value={keys}
                placeholder="ssh-ed25519 AAAA… jane@laptop"
                onChange={(event) => setKeys(event.target.value)}
              />
              <div className="operations">
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
                <button onClick={() => setKeys(null)}>{t("Cancel")}</button>
              </div>
            </div>
          </td>
        </tr>
      )}

      {request.message && (
        <tr>
          <td colSpan={7} className="source">{request.message}</td>
        </tr>
      )}
    </>
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
  if (account.locked) return <span className="badge error">{t("locked")}</span>;
  if (account.ssh_keys.length > 0) {
    return <span className="badge">{t("SSH key")}</span>;
  }
  if (account.password_set === true) return <span className="badge">{t("password")}</span>;
  if (account.password_set === false) {
    // An account without a password and without a key is reachable by
    // nobody. It is usually a trace of access half taken away, and worth
    // seeing.
    return <span className="badge error">{t("no access")}</span>;
  }
  return <span className="badge unknown">{t("unknown")}</span>;
}

function NewAccount({ host }: { host: Host }) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [groups, setGroups] = useState("");
  const [keys, setKeys] = useState("");
  const request = useRequest(host);

  if (!open) {
    return (
      <div style={{ marginTop: 24 }}>
        <button onClick={() => setOpen(true)}>{t("Create local account")}</button>
        {request.message && <p className="source" style={{ marginTop: 10 }}>{request.message}</p>}
      </div>
    );
  }

  return (
    <div className="form" style={{ marginTop: 24 }}>
      <h2>{t("New local account")}</h2>
      <p className="subtitle">
        {t("The account is created without a password; access is by SSH key only. The panel never stores or transmits passwords.")}
      </p>
      <label>{t("Name")}
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="jsmith" />
      </label>
      <label>{t("Description")}
        <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Jane Smith" />
      </label>
      <label>{t("Additional groups")}
        <input value={groups} onChange={(e) => setGroups(e.target.value)} placeholder="sudo, adm" />
      </label>
      <label>{t("SSH public keys, one per line")}
        <textarea rows={3} value={keys} onChange={(e) => setKeys(e.target.value)} />
      </label>
      <div className="operations">
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
        <button onClick={() => setOpen(false)}>{t("Cancel")}</button>
      </div>
      {request.message && <p className="source">{request.message}</p>}
    </div>
  );
}

type Request = {
  action: string;
  name: string;
  gecos?: string;
  groups?: string[];
  ssh_keys?: string[];
  create_home?: boolean;
};

/**
 * Requesting an operation creates a plan, not an immediate change: a
 * mutating operation waits for approval by default.
 */
function useRequest(host: Host) {
  const t = useT();
  const queryClient = useQueryClient();
  const [message, setMessage] = useState("");

  const mutation = useMutation({
    mutationFn: ({ action, ...rest }: Request) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, {
        action,
        payload: {
          local_user: {
            name: rest.name,
            gecos: rest.gecos || undefined,
            groups: rest.groups,
            ssh_keys: rest.ssh_keys,
            create_home: rest.create_home,
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

  return { mutate: mutation.mutate, message };
}

function sourceName(t: (text: string) => string, source: LocalAccount["source"]) {
  switch (source) {
    case "local": return t("local");
    case "directory": return t("directory");
    case "system": return t("system");
    default: return t("unknown");
  }
}
