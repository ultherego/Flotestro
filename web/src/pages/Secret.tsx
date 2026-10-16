import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, ApiError } from "../lib/api";
import { ErrorBox, Pair, Pairs, Time } from "../components/ui";
import { Actions, Empty, Fields, PageHead, Panel } from "../ui/kit";
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
          <PageHead title={name} breadcrumb={[{ label: t("Secrets"), to: "/secrets" }]}
        help={<p>{t("Every version of this secret, newest first. The panel holds the ciphertext and the key it was sealed with; the value itself is shown only on request and is never written into a task.")}</p>}
      />
          <Empty action={<Link to="/secrets">{t("Back to the secrets")}</Link>}>
            {t("No secret named {name} exists in this installation.", { name })}
          </Empty>
        </>
      );
    }
    return <ErrorBox error={secret.error} />;
  }
  if (!secret.data) {
    return (
      <>
        <PageHead title={name} breadcrumb={[{ label: t("Secrets"), to: "/secrets" }]} />
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
      <PageHead
        title={data.name}
        description={data.description || t("No description was given.")}
        breadcrumb={[{ label: t("Secrets"), to: "/secrets" }]}
        actions={
          data.retired_at
            ? <span className="ui-pill ui-error">{t("retired")}</span>
            : <span className="ui-pill ui-ok">{t("issuable")}</span>
        }
      />

      <div className="ui-grid">
        <Panel className="ui-col-7" title={t("Secret")} description={t("The metadata; the value is not here and cannot be read back.")}>
          <Pairs>
            <Pair label={t("Name")}><span className="ui-mono">{data.name}</span></Pair>
            <Pair label={t("Current version")}>{data.current_version}</Pair>
            <Pair label={t("Created by")}><span className="ui-mono">{data.created_by}</span></Pair>
            <Pair label={t("Created")}><Time value={data.created_at} /></Pair>
            <Pair label={t("Last change")}><Time value={data.updated_at} /></Pair>
            <Pair label={t("Retired")}>
              {data.retired_at ? <Time value={data.retired_at} /> : <span className="ui-note">{t("no")}</span>}
            </Pair>
            <Pair label={t("Versions")}>{t("{live} with content of {n}", { live, n: versions.length })}</Pair>
          </Pairs>
        </Panel>

        <Panel
          className="ui-col-5"
          title={t("Reference")}
          description={t("What a job payload names. Without a version the host gets the one current at delivery; with a version it gets that one and no other, also after a rotation.")}
        >
          <div className="ui-stack" style={{ gap: 8 }}>
            <code className="ui-mono">{reference}</code>
            <Actions>
              <button className="ui-btn-secondary" onClick={() => copy("current", reference)}>
                {copied === "current" ? t("Copied") : t("Copy the reference")}
              </button>
              <button className="ui-btn-secondary" onClick={() => copy("pinned", pinned)} title={pinned}>
                {copied === "pinned" ? t("Copied") : t("Copy pinned to version {version}", { version: data.current_version })}
              </button>
            </Actions>
          </div>
        </Panel>

        <Panel
          className="ui-col-12"
          title={t("Versions")}
          description={t("Every version that ever existed, newest first. Destroying one erases its content, not the row.")}
          actions={notice ? <span className="ui-note">{notice}</span> : undefined}
          flush
        >
          {versions.length === 0 ? (
            <Empty>{t("The history of this secret is empty.")}</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th scope="col" className="ui-numeric">{t("Version")}</th>
                  <th scope="col" className="ui-numeric">{t("Size")}</th>
                  <th scope="col">{t("Created by")}</th>
                  <th scope="col">{t("Created")}</th>
                  <th scope="col">{t("State")}</th>
                  <th scope="col"></th>
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
        </Panel>
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
        <td className="ui-numeric">
          {version.version}
          {current && <> <span className="ui-pill">{t("current")}</span></>}
        </td>
        <td className="ui-numeric">{t("{n} B", { n: version.size_bytes })}</td>
        <td><span className="ui-mono">{version.created_by}</span></td>
        <td><Time value={version.created_at} /></td>
        <td>
          {version.destroyed_at ? (
            <><span className="ui-pill ui-error">{t("destroyed")}</span> <Time value={version.destroyed_at} /></>
          ) : (
            <span className="ui-pill ui-ok">{t("kept")}</span>
          )}
        </td>
        <td className="ui-actioncell">
          <div className="ui-rowactions">
            <button className="ui-btn-secondary" onClick={onCopy} title={secretReference(secret.name, version.version)}>
              {copied ? t("Copied") : t("Copy reference")}
            </button>
            {canDestroy && destroyable(secret, version) && (
              <button className="ui-btn-secondary" aria-expanded={open} onClick={onToggle} disabled={destroying}>
                {open ? t("Close") : t("Destroy")}
              </button>
            )}
          </div>
        </td>
      </tr>
      {open && (
        <tr className="ui-detailrow" data-testid="secret-destroy" data-version={version.version}>
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
    <div className="ui-stack">
      <p className="ui-note">
        {t("The content of version {version} of {name} is erased now, from the store and from every backup of the database; a job with a lease on it is refused instead of served. The row stays as the record that the version existed.", { version: version.version, name: secret.name })}
      </p>
      <Fields>
        <ReasonField value={reason} onChange={setReason} />
        <label className="ui-check">
          <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
          {t("I understand that version {version} cannot be recovered afterwards.", { version: version.version })}
        </label>
      </Fields>
      <Actions>
        <button className="ui-btn-danger" onClick={() => onDestroy(reason)} disabled={!confirmed || !reasonGiven(reason) || busy}>
          {busy ? t("Destroying…") : t("Destroy version {version}", { version: version.version })}
        </button>
        <button className="ui-btn-secondary" onClick={onClose} disabled={busy}>{t("Cancel")}</button>
        {error && <span className="ui-errorbox">{error}</span>}
      </Actions>
    </div>
  );
}
