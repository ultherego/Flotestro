import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { ErrorBox, Empty, Time } from "../components/ui";
import { Actions, Card, FieldGrid, PageHeader, Toolbar } from "../components/layout";
import { ReasonField, errorText, reasonGiven, usePermissions } from "./Secrets";
import { useT } from "../i18n";

/**
 * The support bundle of the panel: a set of readings of this installation an
 * operator hands to whoever is helping them. It is asked for with fresh
 * authentication and a reason, fetched through a link that expires, and
 * removed when its retention runs out.
 */

export type SupportBundle = {
  id: string;
  state: "pending" | "ready" | "failed";
  reason: string;
  requested_by: string;
  requested_at: string;
  ready_at?: string;
  error_code?: string;
  size_bytes: number;
  archive_sha256?: string;
  files: number;
  redaction_policy?: string;
  scanned: boolean;
  key_id?: string;
  downloaded_at?: string;
  downloads: number;
  downloadable: boolean;
};

type BundleList = {
  items: SupportBundle[];
  count: number;
  retention: { bundles: string; never_fetched: string };
  token_ttl: string;
};

/** A link the panel issued, good for one fetch within its window. */
type DownloadLink = { url: string; expires_at: string };

/** A size in the unit that reads at a glance. */
export function bundleSize(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(0)} KiB`;
  return `${bytes} B`;
}

/** The first characters of a digest: enough to compare two by eye. */
export function shortDigest(digest?: string): string {
  return digest ? digest.slice(0, 12) : "—";
}

/** A bundle still being assembled is watched; a settled list is left alone. */
export function watching(bundles: SupportBundle[]): boolean {
  return bundles.some((bundle) => bundle.state === "pending");
}

export function Support() {
  const t = useT();
  const queryClient = useQueryClient();
  const permissions = usePermissions();
  const canCreate = permissions.has("support.bundle.create");
  const canRead = permissions.has("support.bundle.read");
  // One reason serves whichever action is pressed: both asking for a bundle
  // and fetching one are recorded with it.
  const [reason, setReason] = useState("");
  const [notice, setNotice] = useState("");

  const list = useQuery({
    queryKey: ["support-bundles"],
    queryFn: () => api.get<BundleList>("/api/v1/support/bundles"),
    // While one is being assembled the row is what the operator watches.
    refetchInterval: (query) => (watching(query.state.data?.items ?? []) ? 2000 : false),
  });

  const ask = useMutation({
    mutationFn: () => api.post<SupportBundle>("/api/v1/support/bundles", { reason }),
    onSuccess: () => {
      setNotice(t("The bundle is being assembled; it can be fetched once it is ready."));
      queryClient.invalidateQueries({ queryKey: ["support-bundles"] });
    },
  });

  const fetchBundle = useMutation({
    mutationFn: async (bundle: SupportBundle) => {
      const link = await api.post<DownloadLink>(`/api/v1/support/bundles/${bundle.id}/download`, { reason });
      const response = await fetch(link.url, { credentials: "same-origin" });
      if (!response.ok) {
        let detail = response.statusText;
        try {
          detail = ((await response.json()) as { detail?: string }).detail ?? detail;
        } catch {
          /* a proxy's page, not the API's answer */
        }
        throw new Error(detail);
      }
      const blob = await response.blob();
      const href = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = href;
      anchor.download = `flotestro-support-${bundle.id}.tar.gz`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(href);
    },
    onSuccess: () => {
      setNotice(t("The bundle was handed over; the link it came through is spent."));
      queryClient.invalidateQueries({ queryKey: ["support-bundles"] });
    },
  });

  if (list.error) return <ErrorBox error={list.error} />;

  const bundles = list.data?.items ?? [];
  const loaded = list.data !== undefined;
  const askReady = canCreate && reasonGiven(reason) && !ask.isPending && !watching(bundles);

  return (
    <>
      <PageHeader
        icon="logs"
        title={t("Support bundle")}
        description={t("A set of readings of this panel - its build, its status, its settings and the counts of the fleet - for whoever is helping you. No credential, key or token is read, and an assembled bundle that carries one is refused rather than written. The archive is encrypted where it rests and removed when its retention runs out.")}
      />

      <div className="widgets">
        {canCreate && (
          <Card
            className="span-12"
            title={t("Ask for a bundle")}
            description={t("The request needs fresh authentication and a reason, and both the request and every download are on the audit trail. What is in the bundle is not.")}
            footer={
              <Actions>
                <button onClick={() => ask.mutate()} disabled={!askReady}>
                  {ask.isPending ? t("Asking…") : t("Ask for a bundle")}
                </button>
                {watching(bundles) && <span className="source">{t("A bundle is being assembled; wait for it before asking for another.")}</span>}
                {ask.error ? <span className="page-error">{errorText(ask.error)}</span> : null}
              </Actions>
            }
          >
            <FieldGrid>
              <ReasonField value={reason} onChange={setReason} />
            </FieldGrid>
          </Card>
        )}

        <Card className="span-12" flush>
          <Toolbar
            end={
              list.data && (
                <span>
                  {t("Kept {age}; never fetched, {unfetched}. A link lasts {ttl}.", {
                    age: list.data.retention.bundles,
                    unfetched: list.data.retention.never_fetched,
                    ttl: list.data.token_ttl,
                  })}
                </span>
              )
            }
          >
            {notice && <span className="source">{notice}</span>}
            {fetchBundle.error ? <span className="page-error">{errorText(fetchBundle.error)}</span> : null}
          </Toolbar>
          {!loaded ? (
            <Empty>{t("Loading…")}</Empty>
          ) : !bundles.length ? (
            <Empty>{t("This panel holds no support bundle.")}</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>{t("Asked for")}</th>
                  <th>{t("By")}</th>
                  <th>{t("Reason")}</th>
                  <th>{t("State")}</th>
                  <th className="num">{t("Files")}</th>
                  <th className="num">{t("Size")}</th>
                  <th>{t("Digest")}</th>
                  <th>{t("Fetched")}</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {bundles.map((bundle) => (
                  <tr key={bundle.id}>
                    <td><Time value={bundle.requested_at} /></td>
                    <td className="mono">{bundle.requested_by}</td>
                    <td>{bundle.reason}</td>
                    <td>
                      <BundleState bundle={bundle} />
                    </td>
                    <td className="num">{bundle.state === "ready" ? bundle.files : "—"}</td>
                    <td className="num">{bundle.state === "ready" ? bundleSize(bundle.size_bytes) : "—"}</td>
                    <td className="mono" title={bundle.archive_sha256}>{shortDigest(bundle.archive_sha256)}</td>
                    <td>{bundle.downloaded_at ? <Time value={bundle.downloaded_at} /> : t("never")}</td>
                    <td>
                      {canRead && bundle.downloadable && (
                        <button
                          className="secondary"
                          onClick={() => fetchBundle.mutate(bundle)}
                          disabled={!reasonGiven(reason) || fetchBundle.isPending}
                          title={reasonGiven(reason) ? undefined : t("A reason is needed; the download is on the audit trail too.")}
                        >
                          {t("Download")}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>
    </>
  );
}

/** What became of one bundle, in the words the trail uses. */
function BundleState({ bundle }: { bundle: SupportBundle }) {
  const t = useT();
  if (bundle.state === "pending") return <span className="badge warn">{t("being assembled")}</span>;
  if (bundle.state === "failed") {
    return <span className="badge error" title={bundle.error_code}>{bundle.error_code || t("refused")}</span>;
  }
  return <span className="badge ok">{t("ready")}</span>;
}
