import { useState } from "react";
import { useMutation, useQuery, useQueryClient, type UseMutationResult } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { copyToClipboard } from "../lib/clipboard";
import type { Whoami } from "../lib/types";
import { Board } from "../components/board";
import { ErrorBox, Time } from "../components/ui";
import { absoluteTime } from "../lib/format";
import { Actions, Empty, Field, Fields, PageHead, Panel, Toolbar } from "../ui/kit";
import { Breakdown, StatusBar } from "../components/widgets";
import { useT } from "../i18n";

export type SecretVersion = {
  version: number;
  size_bytes: number;
  created_by: string;
  created_at: string;
  destroyed_at?: string;
};

export type Secret = {
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

/* ---------------------------------------------------------------------- */
/* What the pages agree on: the reason, the reference, the counts.        */
/* ---------------------------------------------------------------------- */

/**
 * The shortest reason the server accepts. The buttons stay disabled
 * below it, so the refusal is not the way the operator learns the rule.
 */
export const REASON_MIN_LENGTH = 8;

export function reasonGiven(reason: string): boolean {
  return reason.trim().length >= REASON_MIN_LENGTH;
}

/**
 * The reference a job payload takes for a secret, as JSON.
 */
export function secretReference(name: string, version?: number): string {
  return version ? JSON.stringify({ name, version }) : JSON.stringify({ name });
}

/** The list narrowed by name or description, case aside. */
export function filterSecrets<T extends Pick<Secret, "name" | "description">>(secrets: T[], query: string): T[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return secrets;
  return secrets.filter((secret) =>
    secret.name.toLowerCase().includes(needle) || (secret.description ?? "").toLowerCase().includes(needle));
}

/**
 * The store at a glance: what can still be issued, what is retired, and what
 * has never been rotated - a secret at its first version since the day it
 * was created is the one to ask about.
 */
export function storeCounts(secrets: Pick<Secret, "current_version" | "retired_at">[]) {
  return {
    issuable: secrets.filter((secret) => !secret.retired_at).length,
    retired: secrets.filter((secret) => !!secret.retired_at).length,
    neverRotated: secrets.filter((secret) => !secret.retired_at && secret.current_version <= 1).length,
  };
}

/**
 * Whether a version's content may be destroyed from the panel.
 */
export function destroyable(secret: Pick<Secret, "current_version" | "retired_at">, version: Pick<SecretVersion, "version" | "destroyed_at">): boolean {
  if (version.destroyed_at) return false;
  return !!secret.retired_at || version.version !== secret.current_version;
}

export function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function usePermissions(): Set<string> {
  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  return new Set(whoami.data?.permissions ?? []);
}

/**
 * The clipboard with a short acknowledgement: the button that copied says so
 * until another one does.
 */
export function useCopy() {
  const [copied, setCopied] = useState("");
  const [failed, setFailed] = useState("");
  const copy = (label: string, text: string) => {
    void copyToClipboard(text).then((done) => {
      setCopied(done ? label : "");
      setFailed(done ? "" : label);
    });
  };
  return { copied, failed, copy };
}

/* ---------------------------------------------------------------------- */
/* The fields the forms share.                                            */
/* ---------------------------------------------------------------------- */

/**
 * The reason field with the rule under it.
 */
export function ReasonField({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  const t = useT();
  return (
    <Field label={t("Reason (kept in the audit trail)")} hint={t("At least {n} characters; the button opens when they are there.", { n: REASON_MIN_LENGTH })} wide>
      <input value={value} onChange={(e) => onChange(e.target.value)} />
    </Field>
  );
}

/**
 * The value on its way in, hidden by default.
 */
function ValueField({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  const t = useT();
  const [shown, setShown] = useState(false);
  return (
    <>
      <Field label={label} hint={t("Hidden while typed. A value of several lines, such as a private key, needs the field shown first.")} wide>
        {shown ? (
          <textarea value={value} onChange={(e) => onChange(e.target.value)} rows={4} autoComplete="off" spellCheck={false} />
        ) : (
          <input type="password" value={value} onChange={(e) => onChange(e.target.value)} autoComplete="new-password" />
        )}
      </Field>
      <label className="ui-check">
        <input type="checkbox" checked={shown} onChange={(e) => setShown(e.target.checked)} />
        {t("Show the value")}
      </label>
    </>
  );
}

/* ---------------------------------------------------------------------- */
/* The page.                                                              */
/* ---------------------------------------------------------------------- */

type RowAction = "rotate" | "retire";

/**
 * The secret store.
 */
export function Secrets() {
  const t = useT();
  const queryClient = useQueryClient();
  const permissions = usePermissions();
  const canWrite = permissions.has("secret.write");
  const canDestroy = permissions.has("secret.destroy");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [value, setValue] = useState("");
  // Every change of the store is taken with fresh authentication and a
  // reason: the values land as root-readable files on hosts.
  const [reason, setReason] = useState("");
  const [search, setSearch] = useState("");
  // The one row whose form is open. Its value and reason live in the form,
  // so they belong to that row alone and vanish when it closes.
  const [pending, setPending] = useState<{ name: string; action: RowAction } | null>(null);
  const [notice, setNotice] = useState("");
  const { copied, failed, copy } = useCopy();

  const list = useQuery({
    queryKey: ["secrets"],
    queryFn: () => api.get<{ items: Secret[] }>("/api/v1/secrets"),
  });

  function afterChange(text: string) {
    setNotice(text);
    setPending(null);
    queryClient.invalidateQueries({ queryKey: ["secrets"] });
  }

  const create = useMutation({
    mutationFn: () =>
      api.post<Secret>("/api/v1/secrets", { name, description, value, reason }),
    onSuccess: (secret) => {
      setName("");
      setDescription("");
      setValue("");
      setReason("");
      afterChange(t("Secret {name} created at version {version}.", { name: secret.name, version: secret.current_version }));
    },
  });

  const rotate = useMutation({
    mutationFn: (input: { name: string; value: string; reason: string }) =>
      api.post<Secret>(`/api/v1/secrets/${input.name}/rotate`, { value: input.value, reason: input.reason }),
    onSuccess: (secret) => afterChange(t("Secret {name} rotated to version {version}.", { name: secret.name, version: secret.current_version })),
  });

  const retire = useMutation({
    mutationFn: (input: { name: string; reason: string }) =>
      api.post<Secret>(`/api/v1/secrets/${input.name}/retire`, { reason: input.reason }),
    onSuccess: (secret) => afterChange(t("Secret {name} retired; no host can be issued its value now.", { name: secret.name })),
  });

  if (list.error) return <ErrorBox error={list.error} />;

  const secrets = list.data?.items ?? [];
  const shown = filterSecrets(secrets, search);
  // Nothing is known before the list arrives, and the bar shows dashes.
  const loaded = list.data !== undefined;
  const counts = loaded ? storeCounts(secrets) : undefined;
  const byCreator = Object.entries(
    secrets.reduce<Record<string, number>>((acc, secret) => { acc[secret.created_by] = (acc[secret.created_by] ?? 0) + 1; return acc; }, {}),
  ).sort((x, y) => y[1] - x[1]).slice(0, 8);
  const createReady = name.trim() !== "" && value !== "" && reasonGiven(reason);

  return (
    <>
      <PageHead
        title={t("Secrets")}
        description={t("Values go in and do not come out.")}
        help={<p>{t("Values go in and do not come out. Nothing here can read a secret back: the only way out is a short lease issued to one host for one job, and the value never appears in a job payload, in the audit trail or in inventory. The store is encrypted with a key kept outside the database.")}</p>}
      />

      <Board
        screen="secrets"
        catalogue={[
          { key: "store", title: "Store", width: 8 },
          { key: "by_creator", title: "By creator", width: 4 },
          { key: "new_secret", title: "New secret", width: 12 },
          { key: "list", title: "Secrets", width: 12 },
        ]}
        drawn={{
          store: (
            <>
              <Panel className="ui-col-8" title={t("Store")} description={t("{n} secrets; the never-rotated ones are counted among the issuable, still on their first version.", { n: secrets.length })}>
          <StatusBar segments={[
            { label: t("Issuable"), value: counts?.issuable, tone: "ok" },
            { label: t("Never rotated"), value: counts?.neverRotated, tone: "warn" },
            { label: t("Retired"), value: counts?.retired, tone: "unknown" },
          ]} />
        </Panel>
            </>
          ),
          by_creator: (
            <>
              <Panel className="ui-col-4" title={t("By creator")} description={t("Who put the secrets in.")}>
          {!loaded ? (
            <Empty>{t("Loading…")}</Empty>
          ) : byCreator.length === 0 ? (
            <p className="ui-empty">{t("Nobody has put a secret in yet.")}</p>
          ) : (
            <Breakdown tone="neutral" items={byCreator.map(([creator, n]) => ({ label: <span className="ui-mono">{creator}</span>, value: n }))} />
          )}
        </Panel>

        {/* The outcome of the last request stands by the button that made it. */}
            </>
          ),
          new_secret: (
            <>
              {canWrite && (
          <Panel
            className="ui-col-12"
            title={t("New secret")}
            footer={
              <Actions>
                <button onClick={() => create.mutate()} disabled={!createReady || create.isPending}>
                  {t("Create")}
                </button>
                {create.error ? <span className="ui-errorbox">{errorText(create.error)}</span> : null}
              </Actions>
            }
          >
            <Fields>
              <Field label={t("Name (lowercase, digits, dot, dash, underscore)")}>
                <input value={name} onChange={(e) => setName(e.target.value)} placeholder="repo.token" autoComplete="off" />
              </Field>
              <Field label={t("What it is for")}>
                <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder={t("package repository token")} />
              </Field>
              <ValueField label={t("Value")} value={value} onChange={setValue} />
              <ReasonField value={reason} onChange={setReason} />
            </Fields>
          </Panel>
        )}
            </>
          ),
          list: (
            <>
              <Panel className="ui-col-12" flush>
          <Toolbar end={loaded && <span>{t("{shown} of {n} secrets", { shown: shown.length, n: secrets.length })}</span>}>
            <input placeholder={t("Search by name or description")} value={search} onChange={(e) => setSearch(e.target.value)} style={{ width: 260 }} />
            {notice && <span className="ui-note">{notice}</span>}
          </Toolbar>
          {!loaded ? (
            <Empty>{t("Loading…")}</Empty>
          ) : !secrets.length ? (
            <Empty>{t("No secrets are stored in this installation.")}</Empty>
          ) : !shown.length ? (
            <Empty>{t("No secret matches the search.")}</Empty>
          ) : (
            <table>
              <thead>
                <tr><th scope="col">{t("Name")}</th><th scope="col" className="ui-numeric">{t("Version")}</th><th scope="col">{t("What for")}</th><th scope="col">{t("Created")}</th><th scope="col">{t("State")}</th><th scope="col"></th></tr>
              </thead>
              <tbody>
                {shown.map((secret) => {
                  const open = pending?.name === secret.name ? pending.action : null;
                  const toggle = (action: RowAction) => setPending(open === action ? null : { name: secret.name, action });
                  return (
                    <SecretRow
                      key={secret.id}
                      secret={secret}
                      open={open}
                      onToggle={toggle}
                      onClose={() => setPending(null)}
                      canRotate={canWrite}
                      canRetire={canDestroy}
                      copied={copied === secret.name}
                      failed={failed === secret.name}
                      onCopy={() => copy(secret.name, secretReference(secret.name, secret.current_version))}
                      rotate={rotate}
                      retire={retire}
                    />
                  );
                })}
              </tbody>
            </table>
          )}
        </Panel>
            </>
          )
        }}
      />
    </>
  );
}

type RotateMutation = UseMutationResult<Secret, Error, { name: string; value: string; reason: string }>;
type RetireMutation = UseMutationResult<Secret, Error, { name: string; reason: string }>;

/**
 * One secret of the list with its actions.
 */
function SecretRow({
  secret, open, onToggle, onClose, canRotate, canRetire, copied, failed, onCopy, rotate, retire,
}: {
  secret: Secret;
  open: RowAction | null;
  onToggle: (action: RowAction) => void;
  onClose: () => void;
  canRotate: boolean;
  canRetire: boolean;
  copied: boolean;
  failed: boolean;
  onCopy: () => void;
  rotate: RotateMutation;
  retire: RetireMutation;
}) {
  const t = useT();
  const busy = (rotate.isPending && rotate.variables?.name === secret.name)
    || (retire.isPending && retire.variables?.name === secret.name);
  return (
    <>
      <tr>
        <td>
          <Link to={`/secrets/${encodeURIComponent(secret.name)}`} className="ui-mono">{secret.name}</Link>
        </td>
        <td className="ui-numeric">{secret.current_version}</td>
        <td>{secret.description || "—"}</td>
        <td>
          {secret.created_by} · <Time value={secret.created_at} />
        </td>
        <td>
          {secret.retired_at ? (
            <span className="ui-pill ui-error" title={absoluteTime(secret.retired_at)}>{t("retired")}</span>
          ) : (
            <span className="ui-pill ui-ok">{t("issuable")}</span>
          )}
        </td>
        <td className="ui-actioncell">
          <div className="ui-rowactions">
            {/* A reference to a retired secret is a job that fails at
                delivery, so the button goes with the lease. */}
            {!secret.retired_at && (
              <button className="ui-btn-secondary" onClick={onCopy} title={secretReference(secret.name, secret.current_version)}>
                {copied ? t("Copied") : failed ? t("Copy by hand") : t("Copy reference")}
              </button>
            )}
            {!secret.retired_at && canRotate && (
              <button className="ui-btn-secondary" aria-expanded={open === "rotate"} aria-label={open === "rotate" ? undefined : t("Rotate {name}", { name: secret.name })} onClick={() => onToggle("rotate")} disabled={busy}>
                {open === "rotate" ? t("Close") : t("Rotate")}
              </button>
            )}
            {!secret.retired_at && canRetire && (
              <button className="ui-btn-secondary" aria-expanded={open === "retire"} aria-label={open === "retire" ? undefined : t("Retire {name}", { name: secret.name })} onClick={() => onToggle("retire")} disabled={busy}>
                {open === "retire" ? t("Close") : t("Retire")}
              </button>
            )}
          </div>
        </td>
      </tr>
      {open === "rotate" && (
        <tr className="ui-detailrow" data-testid="secret-rotate" data-name={secret.name}>
          <td colSpan={6}>
            <RotateForm key={secret.name} secret={secret} rotate={rotate} onClose={onClose} />
          </td>
        </tr>
      )}
      {open === "retire" && (
        <tr className="ui-detailrow" data-testid="secret-retire" data-name={secret.name}>
          <td colSpan={6}>
            <RetireForm key={secret.name} secret={secret} retire={retire} onClose={onClose} />
          </td>
        </tr>
      )}
    </>
  );
}

/**
 * A rotation adds a version and makes it current.
 */
function RotateForm({ secret, rotate, onClose }: { secret: Secret; rotate: RotateMutation; onClose: () => void }) {
  const t = useT();
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("");
  const mine = rotate.variables?.name === secret.name;
  const busy = rotate.isPending && mine;
  return (
    <div className="ui-stack">
      <p className="ui-note">
        {t("A new value for {name} becomes version {version}; the jobs already delivered keep the version they were given.", { name: secret.name, version: secret.current_version + 1 })}
      </p>
      <Fields>
        <ValueField label={t("New value")} value={value} onChange={setValue} />
        <ReasonField value={reason} onChange={setReason} />
      </Fields>
      <Actions>
        <button onClick={() => rotate.mutate({ name: secret.name, value, reason })} disabled={!value || !reasonGiven(reason) || busy}>
          {busy ? t("Rotating…") : t("Rotate")}
        </button>
        <button className="ui-btn-secondary" onClick={onClose} disabled={busy}>{t("Cancel")}</button>
        {mine && rotate.error ? <span className="ui-errorbox">{errorText(rotate.error)}</span> : null}
      </Actions>
    </div>
  );
}

/**
 * Retiring does not erase the history: the trace of the secret having
 * existed is part of the audit.
 */
function RetireForm({ secret, retire, onClose }: { secret: Secret; retire: RetireMutation; onClose: () => void }) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const mine = retire.variables?.name === secret.name;
  const busy = retire.isPending && mine;
  return (
    <div className="ui-stack">
      <p className="ui-note">
        {t("No host will be issued {name} again, at any version. A job that names it will fail at the lease. The metadata and the version history stay; a retirement cannot be undone.", { name: secret.name })}
      </p>
      <Fields>
        <ReasonField value={reason} onChange={setReason} />
        <label className="ui-check">
          <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
          {t("I understand that {name} stops being issued for good.", { name: secret.name })}
        </label>
      </Fields>
      <Actions>
        <button className="ui-btn-danger" onClick={() => retire.mutate({ name: secret.name, reason })} disabled={!confirmed || !reasonGiven(reason) || busy}>
          {busy ? t("Retiring…") : t("Retire {name}", { name: secret.name })}
        </button>
        <button className="ui-btn-secondary" onClick={onClose} disabled={busy}>{t("Cancel")}</button>
        {mine && retire.error ? <span className="ui-errorbox">{errorText(retire.error)}</span> : null}
      </Actions>
    </div>
  );
}
