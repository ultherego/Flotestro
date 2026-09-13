import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { ErrorBox, Time, Empty } from "../components/ui";
import { useT } from "../i18n";

type SecretVersion = {
  version: number;
  size_bytes: number;
  created_by: string;
  created_at: string;
  destroyed_at?: string;
};

type Secret = {
  id: string;
  name: string;
  description?: string;
  current_version: number;
  created_by: string;
  created_at: string;
  updated_at: string;
  retired_at?: string;
  versions?: SecretVersion[];
};

/**
 * The secret store.
 *
 * A value goes in and does not come out: the API cannot read it back, and
 * the only way out leads through a short lease issued to a host for the
 * duration of one job. This screen shows the metadata - what exists, who
 * created it, when it was rotated - and never the content.
 */
export function Secrets() {
  const t = useT();
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [value, setValue] = useState("");
  const [expanded, setExpanded] = useState("");
  const [rotation, setRotation] = useState("");
  const [message, setMessage] = useState("");

  const list = useQuery({
    queryKey: ["secrets"],
    queryFn: () => api.get<{ items: Secret[] }>("/api/v1/secrets"),
  });

  function afterChange(text: string) {
    setMessage(text);
    setValue("");
    setRotation("");
    queryClient.invalidateQueries({ queryKey: ["secrets"] });
  }

  const create = useMutation({
    mutationFn: () =>
      api.post<Secret>("/api/v1/secrets", { name, description, value }),
    onSuccess: (secret) => {
      setName("");
      setDescription("");
      afterChange(t("Secret {name} created at version {version}.", { name: secret.name, version: secret.current_version }));
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const rotate = useMutation({
    mutationFn: (target: string) => api.post<Secret>(`/api/v1/secrets/${target}/rotate`, { value: rotation }),
    onSuccess: (secret) => afterChange(t("Secret {name} rotated to version {version}.", { name: secret.name, version: secret.current_version })),
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const retire = useMutation({
    mutationFn: (target: string) => api.post<Secret>(`/api/v1/secrets/${target}/retire`, {}),
    onSuccess: (secret) => afterChange(t("Secret {name} retired; no host can be issued its value now.", { name: secret.name })),
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  if (list.error) return <ErrorBox error={list.error} />;

  const secrets = list.data?.items ?? [];

  return (
    <>
      <h1>{t("Secrets")}</h1>
      <p className="subtitle">
        {t("Values go in and do not come out. Nothing here can read a secret back: the only way out is a short lease issued to one host for one job, and the value never appears in a job payload, in the audit trail or in inventory. The store is encrypted with a key kept outside the database.")}
      </p>

      <div className="form" style={{ marginBottom: 16 }}>
        <h2>{t("New secret")}</h2>
        <label>
          {t("Name (lowercase, digits, dot, dash, underscore)")}
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="repo.token" />
        </label>
        <label>
          {t("What it is for")}
          <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder={t("package repository token")} />
        </label>
        <label>
          {t("Value")}
          <textarea
            value={value}
            onChange={(e) => setValue(e.target.value)}
            rows={4}
            placeholder={t("secret value")}
          />
        </label>
        <div className="operations">
          <button onClick={() => create.mutate()} disabled={!name || !value || create.isPending}>
            {t("Create")}
          </button>
        </div>
      </div>
      {message && <p className="source" style={{ marginBottom: 12 }}>{message}</p>}

      {!secrets.length ? (
        <Empty>{t("No secrets are stored in this installation.")}</Empty>
      ) : (
        <table>
          <thead>
            <tr><th>{t("Name")}</th><th>{t("Version")}</th><th>{t("What for")}</th><th>{t("Created")}</th><th>{t("State")}</th><th></th></tr>
          </thead>
          <tbody>
            {secrets.map((secret) => (
              <tr key={secret.id}>
                <td>
                  <button
                    className="secondary"
                    onClick={() => setExpanded((current) => (current === secret.name ? "" : secret.name))}
                  >
                    {expanded === secret.name ? "▾" : "▸"}
                  </button>{" "}
                  {secret.name}
                  {expanded === secret.name && (
                    <div className="source">
                      {(secret.versions ?? []).map((version) => (
                        <div key={version.version}>
                          v{version.version} · {version.size_bytes} B · {version.created_by} ·{" "}
                          <Time value={version.created_at} />
                          {version.destroyed_at && ` · ${t("destroyed")}`}
                        </div>
                      ))}
                    </div>
                  )}
                </td>
                <td>{secret.current_version}</td>
                <td>{secret.description || "—"}</td>
                <td>
                  {secret.created_by} · <Time value={secret.created_at} />
                </td>
                <td>
                  {secret.retired_at ? (
                    <span className="badge error">{t("retired")}</span>
                  ) : (
                    <span className="badge ok">{t("issuable")}</span>
                  )}
                </td>
                <td>
                  {!secret.retired_at && (
                    <div className="filters">
                      <input
                        value={rotation}
                        onChange={(e) => setRotation(e.target.value)}
                        placeholder={t("new value")}
                        style={{ width: 160 }}
                      />
                      <button onClick={() => rotate.mutate(secret.name)} disabled={!rotation || rotate.isPending}>
                        {t("Rotate")}
                      </button>
                      {/* Retiring does not erase the history: the trace of
                          the secret having existed is part of the audit. */}
                      <button
                        className="secondary"
                        onClick={() => retire.mutate(secret.name)}
                        disabled={retire.isPending}
                      >
                        {t("Retire")}
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
