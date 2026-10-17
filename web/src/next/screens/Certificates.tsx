import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { absoluteTime, relativeTime } from "../../lib/format";
import { useT, type Translate } from "../../i18n";
import {
  Band, Bars, C, Card, Empty, Form, Grid, Kpi, Kpis, Note, Pill, Problem, Seg, Table, Tabs,
  TwoLine, useTab, type Segment, type Tone,
} from "../kit";

/**
 * Every certificate the fleet reports, read as a set of deadlines.
 *
 * A certificate expires quietly and always at the worst moment, so the
 * screen is ordered by how close the deadline is and nothing else: the
 * server hands the nearest one first and the page keeps that order.
 *
 * The counts above the list are the server's, taken over every
 * certificate of every host in scope; the rows are one page of the same
 * answer. Where a block can only count what is loaded it says so in its
 * own words, because "three manual renewals" and "three manual renewals
 * among the hundred nearest deadlines" are different sentences.
 */

type Item = {
  host_id: string;
  hostname: string;
  path: string;
  subject?: string;
  issuer?: string;
  not_after?: string;
  days_to_expiry?: number;
  status: string;
  renewal: string;
  owner_service?: string;
  unavailable_reason?: string;
};

/** The coverage head every fleet view carries: who was judged, and who was not. */
type Coverage = {
  total_hosts: number;
  evaluated_hosts: number;
  unknown_hosts: number;
  partial?: boolean;
  partial_reason?: string;
};

type Page = Coverage & {
  items: Item[];
  count: number;
  total: number;
  next_cursor?: string;
  counts: Record<string, number>;
  hosts_total: number;
  hosts_without_certificates: number;
  timeline?: { reason: string; count: number }[];
  thresholds: { critical_days: number; warning_days: number };
};

type Anchor = {
  fingerprint_sha256?: string;
  subject?: string;
  anchor_id?: string;
  not_after?: string;
  hosts: number;
  sample?: string[];
  unavailable_reason?: string;
};

type TrustView = Coverage & {
  items: Anchor[];
  hosts_total: number;
  hosts_unknown: number;
  hosts_without_trust_store?: { reason: string; count: number }[];
};

/**
 * The colour of a deadline. Expired and urgent are the same colour on
 * purpose - both mean today - while a certificate nobody could read is
 * neither: it is a missing answer, and an unreadable certificate must
 * never wear the colour of a valid one.
 */
export function expiryTone(status: string): Tone {
  if (status === "valid") return "ok";
  if (status === "expired" || status === "critical") return "error";
  if (status === "warning") return "warn";
  return "unknown";
}

/** The windows the server groups the deadlines into, each in its own colour. */
const WINDOW_TONES: Record<string, Tone> = {
  expired: "error",
  "7 days": "error",
  "30 days": "warn",
  "90 days": "info",
  later: "ok",
  "no expiry": "unknown",
};

/** How many authorities the trust table names before it folds the rest. */
const AUTHORITIES_SHOWN = 8;

/** How many rows one request asks the server for. */
const PAGE = 100;

export function Certificates() {
  const t = useT();
  const [size, setSize] = useState(PAGE);
  const [allAuthorities, setAllAuthorities] = useState(false);

  const list = useInfiniteQuery({
    queryKey: ["next-certificates", size],
    queryFn: ({ pageParam }) => api.get<Page>(
      `/api/v1/certificates?limit=${size}${pageParam ? `&cursor=${encodeURIComponent(pageParam)}` : ""}`),
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor || undefined,
  });

  const trust = useQuery({
    queryKey: ["next-certificates", "trust"],
    queryFn: () => api.get<TrustView>("/api/v1/certificates/trust"),
  });

  if (list.error) return <Problem>{String(list.error)}</Problem>;

  // The first page carries the counts over the whole fleet; the rows are
  // every page fetched so far, in the order the server handed them back.
  const head = list.data?.pages[0];
  const rows = (list.data?.pages ?? []).flatMap((page) => page.items);
  // An answer that has not arrived is not an answer of none, so every
  // count is undefined until the first page is in.
  const count = (key: string) => (head ? head.counts?.[key] ?? 0 : undefined);
  const expired = count("expired");
  const critical = count("critical");
  const warning = count("warning");
  const unreadable = count("unknown");
  const soon = critical === undefined || warning === undefined ? undefined : critical + warning;

  const states: Segment[] = [
    { label: t("Expired"), value: expired, tone: "error" },
    { label: t("Urgent"), value: critical, tone: "error" },
    { label: t("Expiring"), value: warning, tone: "warn" },
    { label: t("Unreadable"), value: unreadable, tone: "unknown" },
    { label: t("Valid"), value: count("valid"), tone: "ok" },
  ];

  const timeline = (head?.timeline ?? []).filter((window) => window.count > 0);

  // What renews the certificates that are loaded. "Manual" is a finding and
  // "unknown" a missing answer: they are two colours, never one.
  const renewal = (kind: string) => rows.filter((one) => one.renewal === kind).length;

  const thresholds = head?.thresholds;

  return (
    <Readings panels={{
      expired: (
        <Kpi
          icon="certificates"
          label={t("Past due")}
          value={expired ?? null}
          tone={expired ? "error" : "ok"}
          note={t("already refused by whatever reads them")}
        />
      ),
      soon: (
        <Kpi
          icon="schedules"
          label={t("Due soon")}
          value={soon ?? null}
          tone={soon ? "warn" : "ok"}
          note={thresholds ? t("within {n} days", { n: thresholds.warning_days }) : undefined}
        />
      ),
      unreadable: (
        <Kpi
          icon="overview"
          label={t("Unreadable")}
          value={unreadable ?? null}
          tone={unreadable ? "unknown" : "ok"}
          note={t("the panel could not tell when these end")}
        />
      ),
      silent: (
        <Kpi
          icon="hosts"
          label={t("Hosts reporting none")}
          value={head?.hosts_without_certificates ?? null}
          tone={head?.hosts_without_certificates ? "warn" : "ok"}
          note={head ? t("of {n} hosts in scope", { n: head.total_hosts }) : undefined}
        />
      ),
      expiry: (
        <Card
          title={t("Expiry")}
          note={thresholds
            ? t("Every certificate the fleet reports. Warning at {warning} days, urgent at {critical}.", {
                warning: thresholds.warning_days, critical: thresholds.critical_days,
              })
            : undefined}
          foot={head?.partial && head.partial_reason ? t(head.partial_reason) : undefined}
        >
          <Band segments={states} testId="certificate-states" />
        </Card>
      ),
      hosts: (
        <Card
          title={t("Hosts")}
          note={t("A host that reports no certificate is not a host without them: it is a host nobody has pointed at a path yet.")}
        >
          {head ? (
            <Bars items={[
              {
                label: t("Reporting certificates"),
                value: Math.max(0, head.evaluated_hosts - head.hosts_without_certificates),
                tone: "ok",
              },
              { label: t("Reporting none"), value: head.hosts_without_certificates, tone: "warn" },
              { label: t("Nothing known"), value: head.unknown_hosts, tone: "unknown" },
            ]} />
          ) : (
            <Empty>{t("Reading certificates…")}</Empty>
          )}
        </Card>
      ),
      timeline: (
        <Card title={t("When the deadlines come")} note={t("Over the whole fleet, not over the loaded page.")}>
          {!head ? <Empty>{t("Reading certificates…")}</Empty>
            : timeline.length === 0 ? <Empty>{t("No deadline in the windows watched.")}</Empty>
            : (
              <Bars items={timeline.map((window) => ({
                label: t(window.reason),
                value: window.count,
                tone: WINDOW_TONES[window.reason] ?? "info",
              }))} />
            )}
        </Card>
      ),
      renewal: (
        <Card
          title={t("Renewal")}
          note={t("Among the {n} certificates loaded here, not the whole fleet.", { n: rows.length })}
        >
          {rows.length === 0 ? <Empty>{t("Nothing loaded to count.")}</Empty> : (
            <Bars items={[
              { label: "certmonger", value: renewal("tracked"), tone: "ok" },
              { label: t("by hand"), value: renewal("manual"), tone: "warn" },
              { label: t("unknown"), value: renewal("unknown"), tone: "unknown" },
            ]} />
          )}
        </Card>
      ),
      list: (
        <Card
          title={t("Certificates")}
          flush
          tools={
            <Seg
              value={String(size)}
              onChange={(value) => setSize(Number(value))}
              options={[
                { value: "50", label: "50" },
                { value: "100", label: "100" },
                { value: "200", label: "200" },
              ]}
            />
          }
          foot={
            list.hasNextPage ? (
              <button
                type="button"
                className="fl-quiet fl-small"
                onClick={() => list.fetchNextPage()}
                disabled={list.isFetchingNextPage}
                data-testid="more-certificates"
              >
                {list.isFetchingNextPage
                  ? t("loading…")
                  : t("Load more ({n} left)", { n: (head?.total ?? 0) - rows.length })}
              </button>
            ) : head ? t("{shown} of {total}, nearest deadline first", { shown: rows.length, total: head.total })
              : undefined
          }
        >
          <Table
            rows={rows}
            testId="certificates"
            keyOf={(one) => `${one.host_id}-${one.path}`}
            rowTestId={(one) => `certificate-${one.hostname}-${one.path}`}
            empty={list.isLoading
              ? t("Reading certificates…")
              : t("No host reports a certificate yet. Open a host, watch a path and scan it.")}
            columns={[
              {
                key: "expires",
                head: t("Expires"),
                cell: (one) => (
                  <TwoLine sub={deadline(one.not_after) ?? <span className="fl-unknown">{t("no date read")}</span>}>
                    <Pill tone={expiryTone(one.status)}>{caption(t, one)}</Pill>
                  </TwoLine>
                ),
              },
              {
                key: "host",
                head: t("Host"),
                cell: (one) => <Link to={`/hosts/${one.host_id}/certificates`}>{one.hostname}</Link>,
              },
              {
                key: "path",
                head: t("Path"),
                tight: true,
                cell: (one) => (
                  <TwoLine sub={one.owner_service}>
                    <code title={one.path}>{one.path}</code>
                  </TwoLine>
                ),
              },
              {
                key: "subject",
                head: t("Subject"),
                minor: true,
                cell: (one) => (
                  // A certificate the agent could not read is not a
                  // certificate without a subject; it says why instead.
                  one.unavailable_reason
                    ? <Pill tone="unknown" title={one.unavailable_reason}>{t(one.unavailable_reason)}</Pill>
                    : one.subject ?? <span className="fl-faint">—</span>
                ),
              },
              {
                key: "issuer",
                head: t("Issuer"),
                minor: true,
                cell: (one) => one.issuer ?? <span className="fl-faint">—</span>,
              },
              {
                key: "renewal",
                head: t("Renewal"),
                cell: (one) => (
                  one.renewal === "tracked" ? <Pill tone="ok">certmonger</Pill>
                    : one.renewal === "manual" ? <Pill tone="warn">{t("by hand")}</Pill>
                    : <Pill tone="unknown">{t("unknown")}</Pill>
                ),
              },
            ]}
          />
        </Card>
      ),
      trust: (
        <Card
          title={t("Trusted authorities")}
          flush
          note={t("During a rotation a host trusts both the old authority and the new one; the old may only be withdrawn once nothing signs with it any more.")}
          foot={
            trust.data ? (
              <>
                {t("{n} hosts have not reported a trust store yet", { n: trust.data.hosts_unknown })}
                {(trust.data.hosts_without_trust_store ?? []).map((group) => `; ${group.count}: ${t(group.reason)}`).join("")}
              </>
            ) : undefined
          }
        >
          {trust.error ? <Empty>{t("The trust stores could not be read.")}</Empty> : (
            <>
              <Table
                rows={allAuthorities ? trust.data?.items ?? [] : (trust.data?.items ?? []).slice(0, AUTHORITIES_SHOWN)}
                testId="authorities"
                keyOf={(one, index) => one.fingerprint_sha256 || one.anchor_id || String(index)}
                rowTestId={(one) => `authority-${one.anchor_id || one.subject || one.fingerprint_sha256}`}
                empty={trust.isLoading ? t("Reading trust stores…") : t("No panel-managed authority on any host.")}
                columns={[
                  {
                    key: "authority",
                    head: t("Authority"),
                    cell: (one) => (
                      <TwoLine sub={one.unavailable_reason ? t(one.unavailable_reason) : (one.sample ?? []).join(", ")}>
                        {one.subject || one.anchor_id || <span className="fl-faint">—</span>}
                      </TwoLine>
                    ),
                  },
                  {
                    key: "hosts",
                    head: t("Hosts"),
                    num: true,
                    cell: (one) => t("{n} of {total}", { n: one.hosts, total: trust.data?.hosts_total ?? 0 }),
                  },
                  {
                    key: "leaves",
                    head: t("Leaves issued by it"),
                    num: true,
                    cell: (one) => {
                      const issued = issuedBy(rows, one);
                      return issued > 0 ? <b className="fl-warn">{issued}</b> : <span className="fl-faint">0</span>;
                    },
                  },
                  {
                    key: "until",
                    head: t("Valid until"),
                    minor: true,
                    cell: (one) => deadline(one.not_after) ?? <span className="fl-unknown">{t("no date read")}</span>,
                  },
                  {
                    key: "fingerprint",
                    head: t("Fingerprint"),
                    minor: true,
                    tight: true,
                    cell: (one) => (
                      one.fingerprint_sha256
                        ? <code title={one.fingerprint_sha256}>{one.fingerprint_sha256.slice(0, 16)}</code>
                        : <span className="fl-faint">—</span>
                    ),
                  },
                  {
                    key: "stage",
                    head: t("Stage"),
                    actions: true,
                    cell: (one) => <Stage anchor={one} trust={trust.data} leaves={rows} />,
                  },
                ]}
              />
              {(trust.data?.items.length ?? 0) > AUTHORITIES_SHOWN && (
                <button
                  type="button"
                  className="fl-quiet fl-small"
                  onClick={() => setAllAuthorities((shown) => !shown)}
                  aria-expanded={allAuthorities}
                  data-testid="all-authorities"
                >
                  {allAuthorities
                    ? t("Show the first {n} only", { n: AUTHORITIES_SHOWN })
                    : t("Show all {n} authorities", { n: trust.data?.items.length ?? 0 })}
                </button>
              )}
            </>
          )}
        </Card>
      ),
      distribute: (
        <Form
          title={t("Distribute a new authority")}
          note={t("Rotation in four stages, each an ordinary campaign: distribute the new authority, verify it reached every host, rotate the leaves, withdraw the old one.")}
          actions={
            <Link className="fl-btn" to={bulk(
              "certificate.trust.ensure",
              t("Distribute a new authority"),
              { certificate: { anchor_id: `fleet-ca-${new Date().getFullYear()}`, certificate: NEW_AUTHORITY } },
            )} data-testid="distribute-authority">{t("Open the campaign")}</Link>
          }
        >
          <Note>
            {t("The campaign opens with the order filled in; the authority certificate itself is pasted into it. A withdrawal is refused while any host is unverified or still holds a certificate issued by the old authority.")}
          </Note>
        </Form>
      ),
    }} />
  );
}

/** The sub-tabs: the leaves of the fleet, and what signed them. */
const CERTIFICATE_TABS = ["certificates", "authorities"] as const;

/**
 * The deadlines and the authorities, apart.
 *
 * They are read for different questions - "what expires this week" and
 * "what signs the fleet" - and the one decision on this screen, handing
 * the fleet a new authority, stands on its own face under the second
 * rather than as a link in the corner of a table nobody reads first.
 */
function Readings({ panels }: { panels: Record<string, ReactNode> }) {
  const t = useT();
  const [tab, go] = useTab(CERTIFICATE_TABS);
  return (
    <>
      <Kpis>
        {panels.expired}
        {panels.soon}
        {panels.unreadable}
        {panels.silent}
      </Kpis>

      <Tabs
        value={tab}
        onChange={go}
        tabs={[
          { value: "certificates", label: t("Certificates") },
          { value: "authorities", label: t("Authorities") },
        ]}
      />

      {tab === "certificates" && (
        <Grid>
          <C span={7}>{panels.expiry}</C>
          <C span={5}>{panels.hosts}</C>
          <C span={6}>{panels.timeline}</C>
          <C span={6}>{panels.renewal}</C>
          <C span={12}>{panels.list}</C>
        </Grid>
      )}
      {tab === "authorities" && (
        <Grid>
          <C span={12}>{panels.distribute}</C>
          <C span={12}>{panels.trust}</C>
        </Grid>
      )}
    </>
  );
}

/**
 * Where an authority stands in the rotation, and the one thing that can be
 * ordered from here.
 *
 * The order is deliberate: a certificate is still signed by it, so it is in
 * use and nothing may be withdrawn; it has not reached every host, so it is
 * still being distributed; otherwise it carries nothing and may go.
 */
function Stage({ anchor, trust, leaves }: { anchor: Anchor; trust?: TrustView; leaves: Item[] }) {
  const t = useT();
  const name = anchor.anchor_id || anchor.subject || "";
  if (!trust) return <Pill tone="unknown">{t("unknown")}</Pill>;
  if (issuedBy(leaves, anchor) > 0) return <Pill tone="ok">{t("in use")}</Pill>;
  if (anchor.hosts < trust.hosts_total || trust.hosts_unknown > 0) {
    return (
      <Link to={bulk("certificate.trust.ensure", t("Distribute {anchor}", { anchor: name }), {
        certificate: { anchor_id: anchor.anchor_id ?? "", certificate: NEW_AUTHORITY },
      })}>{t("distribute to the rest")}</Link>
    );
  }
  return (
    <Link to={bulk("certificate.trust.remove", t("Withdraw {anchor}", { anchor: name }), {
      certificate: { anchor_id: anchor.anchor_id ?? "" },
    })}>{t("withdraw")}</Link>
  );
}

/** The placeholder the operator replaces in the campaign form. */
const NEW_AUTHORITY =
  "-----BEGIN CERTIFICATE-----\nREPLACE WITH THE AUTHORITY CERTIFICATE\n-----END CERTIFICATE-----\n";

/**
 * How many of the loaded certificates this authority signed. It is a count
 * over what is loaded, and the column it fills is read as such: the point
 * is whether anything at all still depends on the authority.
 */
function issuedBy(leaves: Item[], anchor: Anchor): number {
  if (!anchor.subject) return 0;
  return leaves.filter((leaf) => leaf.issuer === anchor.subject).length;
}

/** The address of the campaign form, filled in from here. */
function bulk(action: string, name: string, payload: Record<string, unknown>): string {
  const query = new URLSearchParams({ action, name, payload: JSON.stringify(payload, null, 2) });
  return `/bulk?${query}`;
}

/**
 * A deadline is read as a date, not as a distance: the pill beside it
 * already says how many days are left, and a rotation is planned on a
 * calendar. Nothing to read gives nothing back, and the caller says so.
 */
function deadline(value?: string) {
  const absolute = absoluteTime(value);
  if (!absolute) return undefined;
  return <span title={`${absolute} · ${relativeTime(value)}`}>{absolute.slice(0, 10)}</span>;
}

/** What the pill says: days left, days overdue, or that nobody could tell. */
function caption(t: Translate, one: Item): string {
  if (one.status === "expired") {
    return one.days_to_expiry === undefined
      ? t("expired")
      : t("expired {n} d ago", { n: Math.abs(one.days_to_expiry) });
  }
  if (one.status === "unknown" || one.days_to_expiry === undefined) return t("unknown");
  return t("{n} d", { n: one.days_to_expiry });
}
