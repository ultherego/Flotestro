import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, ApiError } from "../lib/api";
import { Empty, ErrorBox, Pair, Pairs, Time } from "../components/ui";
import { Actions, Card, EmptyState, FieldGrid, PageHeader } from "../components/layout";
import { useT } from "../i18n";
import {
  ReasonField, destroyable, errorText, reasonGiven, secretReference, useCopy, usePermissions,
  type Secret, type SecretVersion,
} from "./Secrets";

/**
 * One secret: its metadata and the history of its versions. The content is
 * nowhere on this page.
 */
export function SecretPage() {
  const t = useT();
  const { name = "" } = useParams();
  const queryClient = useQueryClient();
  const permissions = usePermissions();
  const canDestroy = permissions.has("secret.destroy");
  // The version whose destruction is being confirmed. Its reason lives in
  // the form and goes away with it.
  const [pending, setPending] = useState<number | null>(null);
  const [notice, setNotice] = useState("");
  const { copied, copy } = useCopy();

  const secret = useQuery({
    queryKey: ["secret", name],
    queryFn: () => api.get<Secret>(`/api/v1/secrets/${encodeURIComponent(name)}`),
  });

  const destroy = useMutation({
    mutationFn: (input: { version: number; reason: string }) =>
      api.del<Secret>(`/api/v1/secrets/${encodeURIComponent(name)}/versions/${input.version}`, { reason: input.reason }),
    onSuccess: (updated, input) => {
      setNotice(t("Version {version} of {name} destroyed; its content cannot be issued or recovered.", { version: input.version, name: updated.name }));
      setPending(null);
      queryClient.setQueryData(["secret", name], updated);
      queryClient.invalidateQueries({ queryKey: ["secrets"] });
    },
  });

  if (secret.error) {
    if (secret.error instanceof ApiError && secret.error.status === 404) {
      return (
        <>
          <PageHeader title={name} breadcrumb={[{ label: t("Secrets"), to: "/secrets" }]} />
          <EmptyState action={<Link to="/secrets">{t("Back to the secrets")}</Link>}>
            {t("No secret named {name} exists in this installation.", { name })}
          </EmptyState>
        </>
      );
    }
    return <ErrorBox error={secret.error} />;
  }
  if (!secret.data) {
    return (
      <>
        <PageHeader title={name} breadcrumb={[{ label: t("Secrets"), to: "/secrets" }]} />
        <Empty>{t("Loading…")}</Empty>
      </>
    );
  }

  const data = secret.data;
  const versions = [...(data.versions ?? [])].sort((x, y) => y.version - x.version);
  const live = versions.filter((version) => !version.destroyed_at).length;
  const reference = secretReference(data.name);
  const pinned = secretReference(data.name, data.current_version);

  return (
    <>
      <PageHeader
        title={data.name}
        description={data.description || t("No description was given.")}
        breadcrumb={[{ label: t("Secrets"), to: "/secrets" }]}
        actions={
          data.retired_at
            ? <span className="badge error">{t("retired")}</span>
            : <span className="badge ok">{t("issuable")}</span>
        }
      />

      <div className="widgets">
        <Card className="span-7" title={t("Secret")} description={t("The metadata; the value is not here and cannot be read back.")}>
          <Pairs>
            <Pair label={t("Name")}><span className="mono">{data.name}</span></Pair>
            <Pair label={t("Current version")}>{data.current_version}</Pair>
            <Pair label={t("Created by")}><span className="mono">{data.created_by}</span></Pair>
            <Pair label={t("Created")}><Time value={data.created_at} /></Pair>
            <Pair label={t("Last change")}><Time value={data.updated_at} /></Pair>
            <Pair label={t("Retired")}>
              {data.retired_at ? <Time value={data.retired_at} /> : <span className="source">{t("no")}</span>}
            </Pair>
            <Pair label={t("Versions")}>{t("{live} with content of {n}", { live, n: versions.length })}</Pair>
          </Pairs>
        </Card>

        <Card
          className="span-5"
          title={t("Reference")}
          description={t("What a job payload names. Without a version the host gets the one current at delivery; with a version it gets that one and no other, also after a rotation.")}
        >
          <div className="stack" style={{ gap: 8 }}>
            <code className="mono">{reference}</code>
            <Actions>
              <button className="secondary" onClick={() => copy("current", reference)}>
                {copied === "current" ? t("Copied") : t("Copy the reference")}
              </button>
              <button className="secondary" onClick={() => copy("pinned", pinned)} title={pinned}>
                {copied === "pinned" ? t("Copied") : t("Copy pinned to version {version}", { version: data.current_version })}
              </button>
            </Actions>
          </div>
        </Card>

        <Card
          className="span-12"
          title={t("Versions")}
          description={t("Every version that ever existed, newest first. Destroying one erases its content, not the row.")}
          actions={notice ? <span className="source">{notice}</span> : undefined}
          flush
        >
          {versions.length === 0 ? (
            <Empty>{t("The history of this secret is empty.")}</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th className="num">{t("Version")}</th>
                  <th className="num">{t("Size")}</th>
                  <th>{t("Created by")}</th>
                  <th>{t("Created")}</th>
                  <th>{t("State")}</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {versions.map((version) => (
                  <VersionRow
                    key={version.version}
                    secret={data}
                    version={version}
                    open={pending === version.version}
                    onToggle={() => setPending(pending === version.version ? null : version.version)}
                    onClose={() => setPending(null)}
                    canDestroy={canDestroy}
                    copied={copied === `v${version.version}`}
                    onCopy={() => copy(`v${version.version}`, secretReference(data.name, version.version))}
                    destroying={destroy.isPending && destroy.variables?.version === version.version}
                    error={destroy.variables?.version === version.version && destroy.error ? errorText(destroy.error) : ""}
                    onDestroy={(reason) => destroy.mutate({ version: version.version, reason })}
                  />
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>
    </>
  );
}

/**
 * One version with its state and, when opened, the form that destroys its
 * content.
 */
function VersionRow({
  secret, version, open, onToggle, onClose, canDestroy, copied, onCopy, destroying, error, onDestroy,
}: {
  secret: Secret;
  version: SecretVersion;
  open: boolean;
  onToggle: () => void;
  onClose: () => void;
  canDestroy: boolean;
  copied: boolean;
  onCopy: () => void;
  destroying: boolean;
  error: string;
  onDestroy: (reason: string) => void;
}) {
  const t = useT();
  const current = version.version === secret.current_version;
  return (
    <>
      <tr>
        <td className="num">
          {version.version}
          {current && <> <span className="badge">{t("current")}</span></>}
        </td>
        <td className="num">{t("{n} B", { n: version.size_bytes })}</td>
        <td><span className="mono">{version.created_by}</span></td>
        <td><Time value={version.created_at} /></td>
        <td>
          {version.destroyed_at ? (
            <><span className="badge error">{t("destroyed")}</span> <Time value={version.destroyed_at} /></>
          ) : (
            <span className="badge ok">{t("kept")}</span>
          )}
        </td>
        <td className="actions-cell">
          <div className="row-actions">
            <button className="secondary" onClick={onCopy} title={secretReference(secret.name, version.version)}>
              {copied ? t("Copied") : t("Copy reference")}
            </button>
            {canDestroy && destroyable(secret, version) && (
              <button className="secondary" aria-expanded={open} onClick={onToggle} disabled={destroying}>
                {open ? t("Close") : t("Destroy")}
              </button>
            )}
          </div>
        </td>
      </tr>
      {open && (
        <tr className="detail-row" data-testid="secret-destroy" data-version={version.version}>
          <td colSpan={6}>
            <DestroyForm key={version.version} secret={secret} version={version} busy={destroying} error={error} onDestroy={onDestroy} onClose={onClose} />
          </td>
        </tr>
      )}
    </>
  );
}

/**
 * The destruction says twice what it does: the content of the version is
 * gone from the store and from every backup of the database, and a host with
 * a lease on it gets a refusal instead.
 */
function DestroyForm({
  secret, version, busy, error, onDestroy, onClose,
}: {
  secret: Secret;
  version: SecretVersion;
  busy: boolean;
  error: string;
  onDestroy: (reason: string) => void;
  onClose: () => void;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  return (
    <div className="stack">
      <p className="source">
        {t("The content of version {version} of {name} is erased now, from the store and from every backup of the database; a job with a lease on it is refused instead of served. The row stays as the record that the version existed.", { version: version.version, name: secret.name })}
      </p>
      <FieldGrid>
        <ReasonField value={reason} onChange={setReason} />
        <label className="toggle">
          <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
          {t("I understand that version {version} cannot be recovered afterwards.", { version: version.version })}
        </label>
      </FieldGrid>
      <Actions>
        <button className="danger" onClick={() => onDestroy(reason)} disabled={!confirmed || !reasonGiven(reason) || busy}>
          {busy ? t("Destroying…") : t("Destroy version {version}", { version: version.version })}
        </button>
        <button className="secondary" onClick={onClose} disabled={busy}>{t("Cancel")}</button>
        {error && <span className="page-error">{error}</span>}
      </Actions>
    </div>
  );
}
