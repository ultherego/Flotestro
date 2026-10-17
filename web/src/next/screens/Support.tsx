import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, fetchWithCredentials } from "../../lib/api";
import { absoluteTime, relativeTime } from "../../lib/format";
import type { Whoami } from "../../lib/types";
import { useT, type Translate } from "../../i18n";
import {
  Actions, Banner, Bones, Card, Fact, Facts, Field, Fields, Form, Kpi, Kpis, Note,
  Pill, Problem, Screen, Table, Tabs, useTab, type Tone,
} from "../kit";

/**
 * The support bundle of the panel: a set of readings of this installation
 * an operator hands to whoever is helping them.
 *
 * It is asked for with fresh authentication and a reason, fetched through
 * a link that expires, and removed when its retention runs out. The link
 * is never drawn and never logged: it is a bearer of the archive for the
 * length of its window, so it goes from the answer that minted it
 * straight into the fetch and nowhere else.
 */

/** The sub-tabs: what is held, and asking for more. */
const SUPPORT_TABS = ["bundles", "request"] as const;

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

/** How short a reason the audit trail will take. */
export const SUPPORT_REASON_MIN_LENGTH = 8;

export function reasonGiven(reason: string): boolean {
  return reason.trim().length >= SUPPORT_REASON_MIN_LENGTH;
}

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

/** What became of one bundle, in the words the trail uses. */
export function bundleState(bundle: SupportBundle, t: Translate): { tone: Tone; word: string } {
  if (bundle.state === "pending") return { tone: "warn", word: t("being assembled") };
  if (bundle.state === "failed") return { tone: "error", word: bundle.error_code || t("refused") };
  return { tone: "ok", word: t("ready") };
}

export function Support() {
  const t = useT();
  const [tab, goTab] = useTab(SUPPORT_TABS);
  const queryClient = useQueryClient();

  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const permissions = new Set(whoami.data?.permissions ?? []);
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
      void queryClient.invalidateQueries({ queryKey: ["support-bundles"] });
    },
  });

  const fetchBundle = useMutation({
    mutationFn: async (bundle: SupportBundle) => {
      // The address the panel mints is a bearer of the archive for the
      // length of its window: it is used here and never shown, never put in
      // the history of this browser and never written to the console.
      const link = await api.post<DownloadLink>(`/api/v1/support/bundles/${bundle.id}/download`, { reason });
      const response = await fetchWithCredentials(link.url);
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
      void queryClient.invalidateQueries({ queryKey: ["support-bundles"] });
    },
  });

  const bundles = list.data?.items ?? [];
  const loaded = list.data !== undefined;
  const assembling = watching(bundles);
  const askReady = canCreate && reasonGiven(reason) && !ask.isPending && !assembling;
  const ready = bundles.filter((bundle) => bundle.state === "ready").length;
  const neverFetched = bundles.filter((bundle) => bundle.state === "ready" && !bundle.downloaded_at).length;

  if (list.error) return <Problem>{String(list.error)}</Problem>;

  return (
    <Screen
      icon="logs"
      title={t("Support bundle")}
      lead={t("Readings of this panel for whoever is helping you.")}
      help={
        <p>
          {t("A set of readings of this panel — its build, its status, its settings and the counts of the fleet — for whoever is helping you. No credential, key or token is read, and an assembled bundle that carries one is refused rather than written. The archive is encrypted where it rests and removed when its retention runs out. Asking for one and fetching one are both on the audit trail, with the reason given here; what is inside the bundle is not.")}
        </p>
      }
      banner={notice && (
        <Banner
          tone="info"
          actions={<button type="button" onClick={() => setNotice("")} data-testid="dismiss-notice">{t("Close")}</button>}
        >
          {notice}
        </Banner>
      )}
    >
      <Kpis>
        <Kpi
          hero
          icon="logs"
          label={t("Bundles held")}
          value={loaded ? bundles.length : null}
          note={list.data ? t("kept {age}", { age: list.data.retention.bundles }) : undefined}
        />
        <Kpi
          icon="check"
          label={t("Ready to fetch")}
          value={loaded ? ready : null}
          tone={ready > 0 ? "ok" : undefined}
        />
        <Kpi
          icon="backups"
          label={t("Never fetched")}
          value={loaded ? neverFetched : null}
          tone={neverFetched > 0 ? "warn" : undefined}
          note={list.data ? t("removed after {age}", { age: list.data.retention.never_fetched }) : undefined}
        />
      </Kpis>

      <Tabs
        value={tab}
        onChange={goTab}
        tabs={[
          { value: "bundles", label: t("Bundles") },
          { value: "request", label: t("Request") },
        ]}
      />

      {tab === "request" && (
        <>
      {/* Asking for a bundle is a decision, so it stands on a form of its
          own above the table it adds a row to - not in a container, which
          is where the panel read as a wall of identical rectangles. */}
      {canCreate && (
        <Form
          title={t("Ask for a bundle")}
          note={t("The request needs fresh authentication and a reason, and both the request and every download are on the audit trail. What is in the bundle is not.")}
          testId="ask-for-a-bundle"
          actions={
            <Actions>
              <button type="button" onClick={() => ask.mutate()} disabled={!askReady} data-testid="ask">
                {ask.isPending ? t("Asking…") : t("Ask for a bundle")}
              </button>
              {assembling && (
                <Note>{t("A bundle is being assembled; wait for it before asking for another.")}</Note>
              )}
            </Actions>
          }
        >
          <Fields>
            <Field
              label={t("Reason (kept in the audit trail)")}
              wide
              hint={t("At least {n} characters; the button opens when they are there.", { n: SUPPORT_REASON_MIN_LENGTH })}
            >
              <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="reason" />
            </Field>
          </Fields>
          {ask.error ? <Problem>{String(ask.error instanceof Error ? ask.error.message : ask.error)}</Problem> : null}
        </Form>
      )}

      {/* A sentence saying the reader may not do this is a notice, not a
          container of its own with a title that promises a form. */}
      {!canCreate && (
        <Note>{t("Asking for a bundle requires the support.bundle.create permission.")}</Note>
      )}
        </>
      )}

      {tab === "bundles" && (
      <Card
        title={t("The bundles of this panel")}
        note={t("Newest first, as the panel assembled them.")}
        foot={list.data && (
          <Facts>
            <Fact label={t("Kept")}>{list.data.retention.bundles}</Fact>
            <Fact label={t("Never fetched, removed after")}>{list.data.retention.never_fetched}</Fact>
            <Fact label={t("A link lasts")}>{list.data.token_ttl}</Fact>
          </Facts>
        )}
        flush
      >
        {fetchBundle.error
          ? <Problem>{String(fetchBundle.error instanceof Error ? fetchBundle.error.message : fetchBundle.error)}</Problem>
          : null}
        {!loaded ? <Bones rows={4} /> : (
          <Table
            rows={bundles}
            keyOf={(bundle) => bundle.id}
            rowTestId={(bundle) => `bundle-${bundle.id}`}
            testId="bundles"
            empty={t("This panel holds no support bundle.")}
            columns={[
              {
                key: "asked",
                head: t("Asked for"),
                cell: (bundle) => (
                  <span title={absoluteTime(bundle.requested_at)}>{relativeTime(bundle.requested_at)}</span>
                ),
              },
              { key: "by", head: t("By"), tight: true, cell: (bundle) => bundle.requested_by },
              { key: "reason", head: t("Reason"), minor: true, cell: (bundle) => bundle.reason },
              {
                key: "state",
                head: t("State"),
                cell: (bundle) => {
                  const shown = bundleState(bundle, t);
                  return <Pill tone={shown.tone} title={bundle.error_code}>{shown.word}</Pill>;
                },
              },
              {
                key: "files",
                head: t("Files"),
                num: true,
                // A bundle still being assembled has no file count yet, and a
                // refused one never will: neither of them has none.
                cell: (bundle) => bundle.state === "ready" ? bundle.files : "—",
              },
              {
                key: "size",
                head: t("Size"),
                num: true,
                cell: (bundle) => bundle.state === "ready" ? bundleSize(bundle.size_bytes) : "—",
              },
              {
                key: "digest",
                head: t("Digest"),
                tight: true,
                minor: true,
                cell: (bundle) => <span title={bundle.archive_sha256}>{shortDigest(bundle.archive_sha256)}</span>,
              },
              {
                key: "fetched",
                head: t("Fetched"),
                minor: true,
                cell: (bundle) => bundle.downloaded_at
                  ? <span title={absoluteTime(bundle.downloaded_at)}>{relativeTime(bundle.downloaded_at)}</span>
                  : t("never"),
              },
              {
                key: "do",
                head: "",
                actions: true,
                cell: (bundle) => canRead && bundle.downloadable
                  ? (
                    <button
                      type="button"
                      onClick={() => fetchBundle.mutate(bundle)}
                      disabled={!reasonGiven(reason) || fetchBundle.isPending}
                      title={reasonGiven(reason)
                        ? undefined
                        : t("A reason is needed; the download is on the audit trail too.")}
                      data-testid={`download-${bundle.id}`}
                    >
                      {t("Download")}
                    </button>
                  )
                  : null,
              },
            ]}
          />
        )}
      </Card>
      )}
    </Screen>
  );
}
