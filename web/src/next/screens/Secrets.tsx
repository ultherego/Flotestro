import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../../lib/api";
import { copyToClipboard } from "../../lib/clipboard";
import { absoluteTime, relativeTime } from "../../lib/format";
import type { Whoami } from "../../lib/types";
import { useT } from "../../i18n";
import {
  Actions, Banner, Bars, Bones, Band, Button, C, Card, Check, Empty, Fact, Facts, Field, Fields,
  Grid, Kpi, Kpis, Modal, Note, Pill, Problem, Readout, Screen, Stack, Table, Toolbar, Find,
  TwoLine, type Segment,
} from "../kit";

/**
 * The secret store: values go in and do not come out.
 *
 * Nothing on this screen can read a secret back, and that is the whole
 * point of it. A value is written once into a request body and is never
 * drawn, never put in an address, never written to a notice and never
 * carried in the audit trail. What the screen shows is the shape of the
 * store - what may still be issued, what has been retired, and which
 * secrets are still on the version they were created with.
 */

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

/** The permission that writes the store: a new secret and a rotation. */
export const SECRET_WRITE_PERMISSION = "secret.write";

/** The permission that takes a secret out of circulation for good. */
export const SECRET_DESTROY_PERMISSION = "secret.destroy";

/**
 * The shortest reason the server accepts. The buttons stay shut below it,
 * so a refusal is not the way the operator learns the rule.
 */
export const REASON_MIN_LENGTH = 8;

export function reasonGiven(reason: string): boolean {
  return reason.trim().length >= REASON_MIN_LENGTH;
}

/** The reference a job payload takes for a secret, as JSON. Never the value. */
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
 * The store at a glance: what can still be issued, what is retired, and
 * what has never been rotated - a secret still on its first version since
 * the day it was created is the one to ask about.
 */
export function storeCounts(secrets: Pick<Secret, "current_version" | "retired_at">[]) {
  return {
    issuable: secrets.filter((secret) => !secret.retired_at).length,
    retired: secrets.filter((secret) => !!secret.retired_at).length,
    neverRotated: secrets.filter((secret) => !secret.retired_at && secret.current_version <= 1).length,
  };
}

/** Whether a version's content may be destroyed from the panel. */
export function destroyable(
  secret: Pick<Secret, "current_version" | "retired_at">,
  version: Pick<SecretVersion, "version" | "destroyed_at">,
): boolean {
  if (version.destroyed_at) return false;
  return !!secret.retired_at || version.version !== secret.current_version;
}

export function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Where a secret's own record is read, inside the new panel. */
export function secretAddress(name: string): string {
  return `/next/secrets/${encodeURIComponent(name)}`;
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
 * The clipboard with a short acknowledgement: the button that copied says
 * so until another one does. A refusal is an answer as well - on a panel
 * reached over plain HTTP there is no clipboard, and the operator is told
 * to take the reference by hand rather than told it was copied.
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

/* ---------------------------------------------------------------- forms */

/**
 * The reason field with the rule under it. Every write of the store takes
 * one, because the values land as root-readable files on hosts.
 */
function ReasonField({ value, onChange, testId }: {
  value: string;
  onChange: (value: string) => void;
  testId: string;
}) {
  const t = useT();
  return (
    <Field
      label={t("Reason (kept in the audit trail)")}
      hint={t("At least {n} characters; the button opens when they are there.", { n: REASON_MIN_LENGTH })}
      wide
    >
      <input value={value} onChange={(event) => onChange(event.target.value)} data-testid={testId} />
    </Field>
  );
}

/**
 * The value on its way in, hidden by default.
 *
 * It is a password field until somebody asks for it to be shown, and it is
 * never read back out of anywhere: what is typed here goes into one request
 * body and is forgotten when the form closes.
 */
function ValueField({ label, value, onChange, testId }: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  testId: string;
}) {
  const t = useT();
  const [shown, setShown] = useState(false);
  return (
    <>
      <Field
        label={label}
        hint={t("Hidden while typed. A value of several lines, such as a private key, needs the field shown first.")}
        wide
      >
        {shown ? (
          <textarea
            value={value}
            onChange={(event) => onChange(event.target.value)}
            rows={4}
            autoComplete="off"
            spellCheck={false}
            data-testid={testId}
          />
        ) : (
          <input
            type="password"
            value={value}
            onChange={(event) => onChange(event.target.value)}
            autoComplete="new-password"
            data-testid={testId}
          />
        )}
      </Field>
      <Check checked={shown} onChange={setShown}>{t("Show the value")}</Check>
    </>
  );
}

/* ---------------------------------------------------------------- screen */

/** What the store is doing beside the list; one thing at a time. */
type Aside =
  | { kind: "create" }
  | { kind: "rotate"; name: string }
  | { kind: "retire"; name: string };

/**
 * The store, or one secret in it.
 *
 * `/next/secrets` is the store and `/next/secrets/<name>` is one record,
 * because the name is the identifier everywhere else - in a job payload,
 * in the trail, in a lease. The value is the identifier of nothing and
 * never appears in an address.
 */
export function Secrets() {
  const { name } = useParams();
  return name ? <OneSecret name={name} /> : <SecretStore />;
}

function SecretStore() {
  const t = useT();
  const queryClient = useQueryClient();
  const permissions = usePermissions();
  const canWrite = permissions.has(SECRET_WRITE_PERMISSION);
  const canDestroy = permissions.has(SECRET_DESTROY_PERMISSION);

  const [search, setSearch] = useState("");
  const [aside, setAside] = useState<Aside | null>(null);
  const [notice, setNotice] = useState("");
  const { copied, failed, copy } = useCopy();

  const list = useQuery({
    queryKey: ["secrets"],
    queryFn: () => api.get<{ items: Secret[] }>("/api/v1/secrets"),
    retry: false,
  });

  const settled = (text: string) => {
    setNotice(text);
    setAside(null);
    void queryClient.invalidateQueries({ queryKey: ["secrets"] });
  };

  if (list.error instanceof ApiError && list.error.forbidden) {
    return (
      <Screen
        title={t("Secrets")}
        lead={t("Values go in and do not come out.")}
        icon="secrets"
        help={<HelpText />}
      >
        <Card title={t("Secrets")}>
          <Empty>{t("You do not have permission to read the secret store.")}</Empty>
        </Card>
      </Screen>
    );
  }
  if (list.error) return <Problem>{errorText(list.error)}</Problem>;

  const secrets = list.data?.items ?? [];
  const shown = filterSecrets(secrets, search);
  // Nothing is known before the list arrives, and the band says so rather
  // than drawing a store with nothing in it.
  const loaded = list.data !== undefined;
  const counts = loaded ? storeCounts(secrets) : undefined;
  const byCreator = Object.entries(
    secrets.reduce<Record<string, number>>((into, secret) => {
      into[secret.created_by] = (into[secret.created_by] ?? 0) + 1;
      return into;
    }, {}),
  ).sort((x, y) => y[1] - x[1]).slice(0, 8);

  const band: Segment[] = [
    { label: t("Issuable"), value: counts?.issuable, tone: "ok" },
    { label: t("Never rotated"), value: counts?.neverRotated, tone: "warn" },
    { label: t("Retired"), value: counts?.retired, tone: "unknown" },
  ];

  const denied = t("This needs the permission {permission}, which the platform administrator holds.", {
    permission: SECRET_WRITE_PERMISSION,
  });
  const rotating = aside?.kind === "rotate" ? secrets.find((one) => one.name === aside.name) : undefined;
  const retiring = aside?.kind === "retire" ? secrets.find((one) => one.name === aside.name) : undefined;

  return (
    <Screen
      title={t("Secrets")}
      lead={t("Values go in and do not come out.")}
      icon="secrets"
      help={<HelpText />}
      actions={
        <button
          type="button"
          onClick={() => setAside({ kind: "create" })}
          disabled={!canWrite || aside !== null}
          title={canWrite ? undefined : denied}
          data-testid="new-secret"
        >
          {t("New secret")}
        </button>
      }
      banner={notice ? (
        <Banner
          tone="ok"
          actions={<button type="button" className="fl-quiet" onClick={() => setNotice("")}>{t("Close")}</button>}
        >
          <span data-testid="secrets-notice">{notice}</span>
        </Banner>
      ) : undefined}
    >
      {retiring && (
        <RetireSecret
          key={retiring.name}
          secret={retiring}
          onDone={settled}
          onClose={() => setAside(null)}
        />
      )}

      <Grid>
        <Card
          span={8}
          title={t("Store")}
          note={loaded
            ? t("{n} secrets; the never-rotated ones are counted among the issuable, still on their first version.", { n: secrets.length })
            : undefined}
        >
          {loaded ? <Band segments={band} testId="secrets-band" /> : <Bones rows={2} />}
        </Card>

        <Card span={4} title={t("By creator")} note={t("Who put the secrets in.")}>
          {!loaded ? (
            <Bones rows={3} />
          ) : byCreator.length === 0 ? (
            <Empty icon="secrets">{t("Nobody has put a secret in yet.")}</Empty>
          ) : (
            <Bars items={byCreator.map(([creator, n]) => ({ label: creator, value: n, tone: "accent" }))} />
          )}
        </Card>

        {aside?.kind === "create" && canWrite && (
          <C span={12}>
            <NewSecret onDone={settled} onCancel={() => setAside(null)} />
          </C>
        )}

        {rotating && canWrite && (
          <C span={12}>
            <RotateSecret key={rotating.name} secret={rotating} onDone={settled} onCancel={() => setAside(null)} />
          </C>
        )}

        <Card
          span={12}
          title={t("Secrets")}
          foot={canWrite ? undefined : <Note>{denied}</Note>}
          flush
        >
          <Toolbar end={loaded
            ? <span>{t("{shown} of {n} secrets", { shown: shown.length, n: secrets.length })}</span>
            : undefined}
          >
            <Find
              value={search}
              onChange={setSearch}
              placeholder={t("Search by name or description")}
              testId="secrets-search"
            />
          </Toolbar>
          {!loaded ? (
            <Bones rows={5} />
          ) : (
            <Table
              rows={shown}
              keyOf={(one) => one.id}
              rowTestId={(one) => `secret-${one.name}`}
              testId="secrets-table"
              empty={secrets.length === 0
                ? t("No secrets are stored in this installation. A secret is a value a job may be handed on one host for one run; nothing here can read it back afterwards.")
                : t("No secret matches the search.")}
              columns={[
                {
                  key: "name",
                  head: t("Name"),
                  cell: (one) => (
                    <TwoLine sub={one.description || t("nobody wrote what it is for")}>
                      <Link to={secretAddress(one.name)}>{one.name}</Link>
                    </TwoLine>
                  ),
                },
                { key: "version", head: t("Version"), num: true, cell: (one) => one.current_version },
                {
                  key: "created",
                  head: t("Created"),
                  minor: true,
                  cell: (one) => (
                    <TwoLine sub={<span title={absoluteTime(one.created_at)}>{relativeTime(one.created_at)}</span>}>
                      {one.created_by}
                    </TwoLine>
                  ),
                },
                {
                  key: "state",
                  head: t("State"),
                  cell: (one) => one.retired_at
                    ? <Pill tone="error" title={absoluteTime(one.retired_at)}>{t("retired")}</Pill>
                    : <Pill tone="ok">{t("issuable")}</Pill>,
                },
                {
                  key: "actions",
                  head: "",
                  actions: true,
                  cell: (one) => (
                    <>
                      {/* A reference to a retired secret is a job that fails
                          at the lease, so the button goes with the lease. */}
                      {!one.retired_at && (
                        <button
                          type="button"
                          className="fl-quiet fl-small"
                          onClick={() => copy(one.name, secretReference(one.name, one.current_version))}
                          title={secretReference(one.name, one.current_version)}
                          data-testid={`copy-${one.name}`}
                        >
                          {copied === one.name ? t("Copied") : failed === one.name ? t("Copy by hand") : t("Copy reference")}
                        </button>
                      )}
                      {!one.retired_at && canWrite && (
                        <button
                          type="button"
                          className="fl-quiet fl-small"
                          onClick={() => setAside({ kind: "rotate", name: one.name })}
                          disabled={aside !== null}
                          aria-label={t("Rotate {name}", { name: one.name })}
                          data-testid={`rotate-${one.name}`}
                        >
                          {t("Rotate")}
                        </button>
                      )}
                      {!one.retired_at && canDestroy && (
                        <button
                          type="button"
                          className="fl-danger fl-small"
                          onClick={() => setAside({ kind: "retire", name: one.name })}
                          disabled={aside !== null}
                          aria-label={t("Retire {name}", { name: one.name })}
                          data-testid={`retire-${one.name}`}
                        >
                          {t("Retire")}
                        </button>
                      )}
                    </>
                  ),
                },
              ]}
            />
          )}
        </Card>
      </Grid>
    </Screen>
  );
}

/** What this screen is for, at length, behind the mark beside the title. */
function HelpText() {
  const t = useT();
  return (
    <>
      <p>{t("Values go in and do not come out. Nothing here can read a secret back: the only way out is a short lease issued to one host for one job, and the value never appears in a job payload, in the audit trail or in inventory. The store is encrypted with a key kept outside the database.")}</p>
      <p>{t("A rotation adds a version and makes it current; the jobs already delivered keep the version they were given. A retirement cannot be undone - the metadata and the version history stay, but no host is issued the value again at any version.")}</p>
      <p>{t("Every write of the store is recorded with a reason, because the values land as root-readable files on the hosts that are issued them.")}</p>
    </>
  );
}

/* ----------------------------------------------------------- the writes */

/**
 * A new secret: the name a job payload will reference, what it is for, the
 * value, and the reason the store gained it.
 */
function NewSecret({ onDone, onCancel }: { onDone: (notice: string) => void; onCancel: () => void }) {
  const t = useT();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("");

  const create = useMutation({
    mutationFn: () => api.post<Secret>("/api/v1/secrets", { name, description, value, reason }),
    onSuccess: (secret) => onDone(
      t("Secret {name} created at version {version}.", { name: secret.name, version: secret.current_version }),
    ),
  });

  const ready = name.trim() !== "" && value !== "" && reasonGiven(reason) && !create.isPending;

  return (
    <Card
      title={t("New secret")}
      note={t("The name is what a job payload references; the value is written once and is never read back out of the panel.")}
      foot={
        <Actions>
          <button type="button" disabled={!ready} onClick={() => create.mutate()} data-testid="secret-create">
            {create.isPending ? t("Creating…") : t("Create")}
          </button>
          <button type="button" className="fl-quiet" onClick={onCancel} disabled={create.isPending}>
            {t("Cancel")}
          </button>
        </Actions>
      }
    >
      <Fields>
        <Field label={t("Name (lowercase, digits, dot, dash, underscore)")}>
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="repo.token"
            autoComplete="off"
            data-testid="secret-name"
          />
        </Field>
        <Field label={t("What it is for")}>
          <input
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            placeholder={t("package repository token")}
            data-testid="secret-description"
          />
        </Field>
        <ValueField label={t("Value")} value={value} onChange={setValue} testId="secret-value" />
        <ReasonField value={reason} onChange={setReason} testId="secret-reason" />
      </Fields>
      {create.error && <Problem>{errorText(create.error)}</Problem>}
    </Card>
  );
}

/**
 * A rotation adds a version and makes it current.
 *
 * It stands on the page rather than in a dialog: it is a form, and the
 * store behind it is what says whether this secret is the one meant.
 */
function RotateSecret({ secret, onDone, onCancel }: {
  secret: Secret;
  onDone: (notice: string) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("");

  const rotate = useMutation({
    mutationFn: () => api.post<Secret>(`/api/v1/secrets/${secret.name}/rotate`, { value, reason }),
    onSuccess: (one) => onDone(
      t("Secret {name} rotated to version {version}.", { name: one.name, version: one.current_version }),
    ),
  });

  const ready = value !== "" && reasonGiven(reason) && !rotate.isPending;

  return (
    <Card
      title={t("Rotate {name}", { name: secret.name })}
      note={t("A new value for {name} becomes version {version}; the jobs already delivered keep the version they were given.", {
        name: secret.name,
        version: secret.current_version + 1,
      })}
      foot={
        <Actions>
          <button type="button" disabled={!ready} onClick={() => rotate.mutate()} data-testid="secret-rotate">
            {rotate.isPending ? t("Rotating…") : t("Rotate")}
          </button>
          <button type="button" className="fl-quiet" onClick={onCancel} disabled={rotate.isPending}>
            {t("Cancel")}
          </button>
        </Actions>
      }
    >
      <Fields>
        <ValueField label={t("New value")} value={value} onChange={setValue} testId="rotate-value" />
        <ReasonField value={reason} onChange={setReason} testId="rotate-reason" />
      </Fields>
      {rotate.error && <Problem>{errorText(rotate.error)}</Problem>}
    </Card>
  );
}

/**
 * Retiring does not erase the history: the trace of the secret having
 * existed is part of the audit. It is a decision that cannot be undone, so
 * it is asked for in a dialog with its reason and its acknowledgement.
 */
function RetireSecret({ secret, onDone, onClose }: {
  secret: Secret;
  onDone: (notice: string) => void;
  onClose: () => void;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [confirmed, setConfirmed] = useState(false);

  const retire = useMutation({
    mutationFn: () => api.post<Secret>(`/api/v1/secrets/${secret.name}/retire`, { reason }),
    onSuccess: (one) => onDone(
      t("Secret {name} retired; no host can be issued its value now.", { name: one.name }),
    ),
  });

  return (
    <Modal
      title={t("Retire {name}", { name: secret.name })}
      onClose={onClose}
      actions={
        <>
          <button type="button" className="fl-quiet" onClick={onClose} disabled={retire.isPending}>
            {t("Cancel")}
          </button>
          <button
            type="button"
            className="fl-danger"
            disabled={!confirmed || !reasonGiven(reason) || retire.isPending}
            onClick={() => retire.mutate()}
            data-testid="secret-retire"
          >
            {retire.isPending ? t("Retiring…") : t("Retire {name}", { name: secret.name })}
          </button>
        </>
      }
    >
      <Note>
        {t("No host will be issued {name} again, at any version. A job that names it will fail at the lease. The metadata and the version history stay; a retirement cannot be undone.", { name: secret.name })}
      </Note>
      <Fields>
        <ReasonField value={reason} onChange={setReason} testId="retire-reason" />
      </Fields>
      <Check checked={confirmed} onChange={setConfirmed}>
        {t("I understand that {name} stops being issued for good.", { name: secret.name })}
      </Check>
      {retire.error && <Problem>{errorText(retire.error)}</Problem>}
    </Modal>
  );
}

/* ---------------------------------------------------------- one secret */

/**
 * One secret: its metadata and every version it has ever had.
 *
 * The value is not here, and there is no control on this screen that
 * could fetch it. What a reader takes away is the reference a job
 * payload names - the name, and the version where one is pinned - which
 * is the only thing about a secret that is safe to copy.
 */
function OneSecret({ name }: { name: string }) {
  const t = useT();
  const queryClient = useQueryClient();
  const permissions = usePermissions();
  const canDestroy = permissions.has(SECRET_DESTROY_PERMISSION);
  // The version whose destruction is being decided. The reason lives in
  // the dialog and goes away with it.
  const [destroying, setDestroying] = useState<number | null>(null);
  const [notice, setNotice] = useState("");
  const { copied, failed, copy } = useCopy();

  const secret = useQuery({
    queryKey: ["secret", name],
    queryFn: () => api.get<Secret>(`/api/v1/secrets/${encodeURIComponent(name)}`),
    retry: false,
  });

  const destroy = useMutation({
    mutationFn: (input: { version: number; reason: string }) =>
      api.del<Secret>(
        `/api/v1/secrets/${encodeURIComponent(name)}/versions/${input.version}`,
        { reason: input.reason },
      ),
    onSuccess: (updated, input) => {
      setNotice(t("Version {version} of {name} destroyed; its content cannot be issued or recovered.", {
        version: input.version, name: updated.name,
      }));
      setDestroying(null);
      queryClient.setQueryData(["secret", name], updated);
      void queryClient.invalidateQueries({ queryKey: ["secrets"] });
    },
  });

  if (secret.error) {
    const missing = secret.error instanceof ApiError && secret.error.status === 404;
    const forbidden = secret.error instanceof ApiError && secret.error.forbidden;
    return (
      <Screen title={name} lead={t("Values go in and do not come out.")} icon="secrets" help={<HelpText />}>
        <Card>
          {missing ? (
            <Empty icon="secrets" action={<Link to="/next/secrets">{t("All secrets")}</Link>}>
              {t("No secret named {name} exists in this installation.", { name })}
            </Empty>
          ) : forbidden ? (
            <Empty icon="secrets">{t("You do not have permission to read the secret store.")}</Empty>
          ) : (
            <Problem>{errorText(secret.error)}</Problem>
          )}
        </Card>
      </Screen>
    );
  }
  if (!secret.data) {
    return (
      <Screen title={name} lead={t("Values go in and do not come out.")} icon="secrets" help={<HelpText />}>
        <Card><Bones rows={4} /></Card>
      </Screen>
    );
  }

  const data = secret.data;
  // A record that carries no history is a record whose history nobody
  // read, not a secret that never had a version.
  const versions = data.versions ? [...data.versions].sort((x, y) => y.version - x.version) : undefined;
  const kept = versions ? versions.filter((one) => !one.destroyed_at).length : null;
  const pending = destroying === null ? undefined : versions?.find((one) => one.version === destroying);

  return (
    <Screen
      title={data.name}
      lead={data.description || t("Nobody wrote what it is for.")}
      icon="secrets"
      help={<HelpText />}
      banner={notice ? (
        <Banner
          tone="ok"
          actions={<Button kind="quiet" onClick={() => setNotice("")}>{t("Close")}</Button>}
        >
          <span data-testid="secret-notice">{notice}</span>
        </Banner>
      ) : undefined}
      actions={
        data.retired_at
          ? <Pill tone="error" title={absoluteTime(data.retired_at)}>{t("retired")}</Pill>
          : <Pill tone="ok">{t("issuable")}</Pill>
      }
    >
      <Kpis>
        <Kpi
          hero
          icon="secrets"
          label={t("Current version")}
          value={data.current_version}
          note={t("what a reference without a version is given")}
          testId="kpi-secret-version"
        />
        <Kpi
          label={t("Versions with content")}
          value={kept}
          note={versions ? t("of {n} that ever existed", { n: versions.length }) : undefined}
          testId="kpi-secret-kept"
        />
        <Kpi
          label={t("Last change")}
          value={relativeTime(data.updated_at)}
          note={t("created {when}", { when: relativeTime(data.created_at) })}
          testId="kpi-secret-changed"
        />
      </Kpis>

      <Grid>
        <Card
          span={6}
          title={t("Secret")}
          note={t("The metadata. The value is not here and cannot be read back from anywhere in the panel.")}
        >
          <Facts>
            <Fact label={t("Name")} mono>{data.name}</Fact>
            <Fact label={t("Current version")}>{data.current_version}</Fact>
            <Fact label={t("Created by")} mono>{data.created_by}</Fact>
            <Fact label={t("Created")}>
              <span title={absoluteTime(data.created_at)}>{relativeTime(data.created_at)}</span>
            </Fact>
            <Fact label={t("Last change")}>
              <span title={absoluteTime(data.updated_at)}>{relativeTime(data.updated_at)}</span>
            </Fact>
            <Fact label={t("Retired")}>
              {data.retired_at
                ? <span title={absoluteTime(data.retired_at)}>{relativeTime(data.retired_at)}</span>
                : t("no")}
            </Fact>
          </Facts>
        </Card>

        <Card
          span={6}
          title={t("Reference")}
          note={t("What a job payload names. Without a version the host is given the one current at delivery; with a version it is given that one and no other, also after a rotation.")}
        >
          <Stack>
            <Readout
              label={t("Current at delivery")}
              value={secretReference(data.name)}
              testId="reference-current"
            />
            <Readout
              label={t("Pinned to version {version}", { version: data.current_version })}
              value={secretReference(data.name, data.current_version)}
              testId="reference-pinned"
            />
          </Stack>
        </Card>

        <Card
          span={12}
          title={t("Versions")}
          note={t("Every version that ever existed, newest first. Destroying one erases its content, never the row: the record that the version existed is part of the audit.")}
          flush
        >
          <Table
            rows={versions ?? []}
            keyOf={(one) => String(one.version)}
            rowTestId={(one) => `version-${one.version}`}
            testId="secret-versions"
            loading={versions === undefined}
            empty={t("The history of this secret is empty.")}
            columns={[
              { key: "version", head: t("Version"), num: true, cell: (one) => (
                one.version === data.current_version
                  ? <TwoLine sub={<Pill tone="ok">{t("current")}</Pill>}>{one.version}</TwoLine>
                  : one.version
              ) },
              { key: "size", head: t("Size"), num: true, cell: (one) => t("{n} B", { n: one.size_bytes }) },
              { key: "by", head: t("Created by"), minor: true, cell: (one) => (
                <TwoLine sub={<span title={absoluteTime(one.created_at)}>{relativeTime(one.created_at)}</span>}>
                  {one.created_by}
                </TwoLine>
              ) },
              { key: "state", head: t("State"), cell: (one) => (
                one.destroyed_at
                  ? <Pill tone="error" title={absoluteTime(one.destroyed_at)}>{t("destroyed")}</Pill>
                  : <Pill tone="ok">{t("kept")}</Pill>
              ) },
              { key: "actions", head: "", actions: true, cell: (one) => (
                <>
                  <Button
                    kind="quiet"
                    onClick={() => copy(`v${one.version}`, secretReference(data.name, one.version))}
                    title={secretReference(data.name, one.version)}
                    testId={`copy-version-${one.version}`}
                  >
                    {copied === `v${one.version}`
                      ? t("Copied")
                      : failed === `v${one.version}` ? t("Copy by hand") : t("Copy reference")}
                  </Button>
                  {canDestroy && destroyable(data, one) && (
                    <Button
                      kind="danger"
                      onClick={() => setDestroying(one.version)}
                      disabled={destroying !== null}
                      testId={`destroy-${one.version}`}
                    >
                      {t("Destroy…")}
                    </Button>
                  )}
                </>
              ) },
            ]}
          />
        </Card>
      </Grid>

      {pending && (
        <DestroyVersion
          key={pending.version}
          secret={data}
          version={pending}
          busy={destroy.isPending}
          error={destroy.error ? errorText(destroy.error) : ""}
          onClose={() => { destroy.reset(); setDestroying(null); }}
          onDestroy={(reason) => destroy.mutate({ version: pending.version, reason })}
        />
      )}
    </Screen>
  );
}

/**
 * The destruction of one version's content.
 *
 * It says twice what it does, because it cannot be undone: the content
 * goes from the store and from every backup of the database, and a host
 * holding a lease on it is refused instead of served.
 */
function DestroyVersion({ secret, version, busy, error, onClose, onDestroy }: {
  secret: Secret;
  version: SecretVersion;
  busy: boolean;
  error: string;
  onClose: () => void;
  onDestroy: (reason: string) => void;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  return (
    <Modal
      title={t("Destroy version {version} of {name}", { version: version.version, name: secret.name })}
      onClose={onClose}
      actions={
        <>
          <Button kind="quiet" onClick={onClose} disabled={busy}>{t("Cancel")}</Button>
          <Button
            kind="danger"
            disabled={!confirmed || !reasonGiven(reason) || busy}
            onClick={() => onDestroy(reason)}
            testId="destroy-confirm"
          >
            {busy ? t("Destroying…") : t("Destroy version {version}", { version: version.version })}
          </Button>
        </>
      }
    >
      <Note>
        {t("The content of version {version} of {name} is erased now, from the store and from every backup of the database; a job holding a lease on it is refused instead of served. The row stays as the record that the version existed.", {
          version: version.version, name: secret.name,
        })}
      </Note>
      <Fields>
        <ReasonField value={reason} onChange={setReason} testId="destroy-reason" />
      </Fields>
      <Check checked={confirmed} onChange={setConfirmed}>
        {t("I understand that version {version} cannot be recovered afterwards.", { version: version.version })}
      </Check>
      {error && <Problem>{error}</Problem>}
    </Modal>
  );
}
