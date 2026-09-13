import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time, Empty } from "../../components/ui";
import {
  Check, Fact, Facts, Field, Fields, Form, FormActions, Message, ModuleFreshness, ModuleHeader, ModulePage, Section,
  Summary, Table, Widgets, countWhere, useHost, useModule,
} from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { useT } from "../../i18n";

type Link = {
  name: string;
  index?: number;
  servers?: string[];
  domains?: string[];
  default_route?: boolean;
  dnssec?: string;
  dns_over_tls?: string;
};

type Query = {
  name: string;
  addresses?: string[];
  server?: string;
  error?: string;
  took_millis: number;
};

type DNSResult = { kind?: string; queries?: { queries?: Query[] } };


type Snapshot = {
  owner?: string;
  mode?: string;
  resolv_conf?: string;
  resolv_conf_target?: string;
  servers?: string[];
  search_domains?: string[];
  links?: Link[];
  dnssec?: string;
  dns_over_tls?: string;
  writable?: boolean;
  write_adapter?: string;
  read_only_reason?: string;
  observed_at?: string;
  unavailable_reason?: string;
};

/**
 * The host's resolver.
 *
 * The panel shows the actual state together with its owner: a resolver file
 * owned by a service gets overwritten on the next network event, so the
 * owner decides whether the panel may change anything here.
 */
export function Resolver() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const module = useModule<Snapshot>(host.id, "dns");
  const [names, setNames] = useState("ipa.flotestro.test");
  const [intent, setIntent] = useState<{ description: string; payload: Record<string, unknown> } | null>(null);
  const [message, setMessage] = useState("");
  const [form, setForm] = useState(false);
  // The test result belongs to the job, so we wait for that specific job
  // instead of refreshing the whole list.
  const [testJob, setTestJob] = useState("");
  const unknown = <span className="badge unknown">{t("unknown")}</span>;

  // The job result lives on the attempt, not on the job: it is the attempt
  // that knows what the host answered and when.
  const test = useQuery({
    queryKey: ["job-attempts", testJob],
    queryFn: () =>
      api.get<{ items: { status?: string; detail?: DNSResult }[] }>(
        `/api/v1/jobs/${testJob}/attempts`,
      ),
    enabled: testJob !== "",
    refetchInterval: (query) => {
      const attempts = (query.state.data as { items?: { status?: string }[] } | undefined)?.items;
      const last = attempts?.[attempts.length - 1];
      return last?.status ? false : 2000;
    },
  });

  const attempts = test.data?.items ?? [];
  const lastAttempt = attempts[attempts.length - 1];
  const answers = lastAttempt?.detail?.queries?.queries ?? [];

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (job) => {
      setMessage(
        job.requires_approval
          ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
          : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }),
      );
      if (!job.requires_approval) setTestJob(job.id);
      setIntent(null);
      setForm(false);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const snapshot = module.data?.payload;
  if (!module.data) return <Empty>{t("This host has not reported its resolver yet.")}</Empty>;

  const nameList = names.split(",").map((name) => name.trim()).filter(Boolean);
  const managementLink = snapshot?.links?.find((link) => (link.servers ?? []).length > 0);
  // An unread resolver has nothing to count: the bar shows dashes then.
  const known = snapshot?.unavailable_reason ? undefined : snapshot;
  const links = known?.links ?? (known ? [] : undefined);

  return (
    <ModulePage>
      <ModuleHeader
        title={t("DNS")}
        description={t("What the host resolves with, and who writes that configuration. A file owned by a service is rewritten on the next network event, so ownership decides whether the panel can change anything here.")}
        actions={
          <button
            className="secondary"
            onClick={() => setForm((open) => !open)}
            disabled={!snapshot?.writable}
            title={snapshot?.writable ? "" : snapshot?.read_only_reason}
          >
            {form ? t("Cancel") : t("Change resolver")}
          </button>
        }
      />
      <ModuleFreshness fragment={module.data} />
      <Message text={message} />

      {snapshot?.unavailable_reason && (
        <p className="warning">
          <span>{t("Resolver state could not be read: {reason}", { reason: snapshot.unavailable_reason })}</span>
        </p>
      )}
      {snapshot?.read_only_reason && (
        <p className="warning">
          <span>{snapshot.read_only_reason}</span>
        </p>
      )}

      <Widgets>
      {/* What the host resolves with, counted; then who owns it and how it
          is protected, which decide whether the panel may touch it. */}
      <Summary
        title={t("Resolution")}
        description={t("The servers, the search domains and the links with resolvers of their own.")}
        span={8}
        segments={[
          { label: t("Servers"), value: known ? (known.servers ?? []).length : undefined, tone: "info" },
          { label: t("Search domains"), value: known ? (known.search_domains ?? []).length : undefined, tone: "info" },
          { label: t("Per-link resolvers"), value: countWhere(links, (link) => (link.servers ?? []).length > 0), tone: "neutral" },
          { label: t("links with DNS over TLS"), value: countWhere(links, (link) => link.dns_over_tls === "yes"), tone: "ok" },
        ]}
      />
      <Section title={t("Ownership")} span={4} flush>
        <Facts>
          <Fact label={t("Owner")}>
            {snapshot?.owner || unknown}
            {snapshot?.mode && <span className="source"> · {snapshot.mode}</span>}
          </Fact>
          <Fact label={t("Write adapter")}>
            {snapshot?.writable
              ? <span className="badge ok">{snapshot.write_adapter || t("yes")}</span>
              : <span className="badge unknown">{t("read only")}</span>}
          </Fact>
          {/* "unsupported" and "disabled" are two different answers, so we
              show what the host said, not yes/no. */}
          <Fact label="DNSSEC">{snapshot?.dnssec || unknown}</Fact>
          <Fact label="DNS over TLS">{snapshot?.dns_over_tls || unknown}</Fact>
        </Facts>
      </Section>

      {/* The facts on the left, the test the operator runs against them on
          the right; the change form and the per-link list follow in full
          width. */}
      <Section title={t("DNS")} span={6} flush>
        <Facts>
          <Fact label={t("Owner")}>{snapshot?.owner || unknown}</Fact>
          <Fact label={t("Mode")}>{snapshot?.mode || "—"}</Fact>
          <Fact label="resolv.conf">
            <span className="hm-mono">
              {snapshot?.resolv_conf}
              {snapshot?.resolv_conf_target && ` → ${snapshot.resolv_conf_target}`}
            </span>
          </Fact>
          <Fact label={t("Servers")}><span className="hm-mono">{(snapshot?.servers ?? []).join(", ") || "—"}</span></Fact>
          <Fact label={t("Search domains")}><span className="hm-mono">{(snapshot?.search_domains ?? []).join(", ") || "—"}</span></Fact>
          {/* "unsupported" and "disabled" are two different answers, so we
              show what the host said, not yes/no. */}
          <Fact label="DNSSEC">{snapshot?.dnssec || unknown}</Fact>
          <Fact label="DNS over TLS">{snapshot?.dns_over_tls || unknown}</Fact>
        </Facts>
      </Section>

      <Section
        title={t("Test resolution from the host")}
        description={t("The panel sits in a different network, so its own answer says nothing about what this host sees. The query runs on the host.")}
        span={6}
        flush
      >
        <div className="hm-section-body">
          <Form>
            <Fields>
              <Field label={t("Names, comma separated")} wide>
                <input
                  value={names}
                  onChange={(e) => setNames(e.target.value)}
                  placeholder={t("Names, comma separated")}
                />
              </Field>
            </Fields>
            <FormActions>
              <button
                onClick={() => request.mutate({ action: "dns.resolve.test", payload: { dns: { names: nameList } } })}
                disabled={!nameList.length || request.isPending}
              >
                {t("Resolve")}
              </button>
            </FormActions>
          </Form>
        </div>

        {/* The answers arrive with the job result: a fact from the host at a
            specific moment, not a state that could be refreshed. */}
        {testJob && (
          <Table>
            <thead><tr><th>{t("Name")}</th><th>{t("Addresses")}</th><th>{t("Answered by")}</th><th className="hm-num">{t("Took")}</th></tr></thead>
            <tbody>
              {answers.map((query) => (
                <tr key={query.name}>
                  <td className="hm-mono hm-primary">{query.name}</td>
                  <td className="hm-mono">
                    {query.addresses?.length
                      ? query.addresses.join(", ")
                      : <span className="badge unknown">{query.error || t("no answer")}</span>}
                  </td>
                  <td className="hm-mono">{query.server || "—"}</td>
                  <td className="hm-num">{query.took_millis} ms</td>
                </tr>
              ))}
              {!answers.length && (
                <tr><td colSpan={4}>{lastAttempt?.status ? t("No answers.") : t("Running…")}</td></tr>
              )}
            </tbody>
          </Table>
        )}
      </Section>

      {form && (
        <ResolverChange
          defaultInterface={managementLink?.name ?? ""}
          defaultServers={(snapshot?.servers ?? []).join(", ")}
          defaultDomains={(snapshot?.search_domains ?? []).map((d) => d.replace(/^~/, "")).join(", ")}
          onIntent={setIntent}
        />
      )}

      <Section title={t("Per-link resolvers")} count={snapshot?.links?.length} span={12} flush>
        {!snapshot?.links?.length ? (
          <Empty>{t("This host does not report per-link resolvers; it has one global list.")}</Empty>
        ) : (
          <Table>
            <thead>
              <tr><th>{t("Link")}</th><th>{t("Servers")}</th><th>{t("Domains")}</th><th>{t("Answers other names")}</th><th>DNSSEC</th><th>DoT</th></tr>
            </thead>
            <tbody>
              {snapshot.links.map((link) => (
                <tr key={link.name}>
                  <td className="hm-mono hm-primary">{link.name}</td>
                  <td className="hm-mono">{(link.servers ?? []).join(", ") || "—"}</td>
                  <td className="hm-mono">{(link.domains ?? []).join(", ") || "—"}</td>
                  {/* The default route decides which link answers a name
                      outside its domains - and that is the operator's
                      question. */}
                  <td>
                    {link.default_route === undefined ? (
                      unknown
                    ) : link.default_route ? (
                      t("yes")
                    ) : (
                      t("no")
                    )}
                  </td>
                  <td>{link.dnssec || "—"}</td>
                  <td>{link.dns_over_tls || "—"}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>
      </Widgets>

      {snapshot?.observed_at && (
        <p className="hm-freshness">
          <span>{t("Resolver read")} <Time value={snapshot.observed_at} /></span>
        </p>
      )}

      {intent && (
        <TargetConfirmation
          host={host}
          label={t("Change resolver")}
          description={intent.description}
          busy={request.isPending}
          onConfirm={(reason) =>
            request.mutate({ action: "dns.host.apply", reason, payload: intent.payload })
          }
          onCancel={() => setIntent(null)}
        />
      )}
    </ModulePage>
  );
}

/**
 * The resolver change form. The change goes through the connection profile,
 * so it asks for the interface: the resolver belongs to the interface, and
 * the file is only what the service computed from it.
 */
function ResolverChange({
  defaultInterface, defaultServers, defaultDomains, onIntent,
}: {
  defaultInterface: string;
  defaultServers: string;
  defaultDomains: string;
  onIntent: (intent: { description: string; payload: Record<string, unknown> }) => void;
}) {
  const t = useT();
  const [iface, setIface] = useState(defaultInterface);
  const [servers, setServers] = useState(defaultServers);
  const [domains, setDomains] = useState(defaultDomains);
  const [ignoreDHCP, setIgnoreDHCP] = useState(true);
  const [window, setWindow] = useState("120");

  const list = (value: string) =>
    value.split(",").map((element) => element.trim()).filter(Boolean);

  return (
    <Section
      title={t("Change resolver")}
      description={t("A host that cannot resolve names loses the directory, Kerberos and with them logins — so this change is armed with the same rollback timer as an address change.")}
      span={12}
    >
      <Form>
        <Fields>
          <Field label={t("Interface")} narrow>
            <input value={iface} onChange={(e) => setIface(e.target.value)} placeholder={t("Interface")} />
          </Field>
          <Field label={t("DNS servers, comma separated")}>
            <input
              value={servers}
              onChange={(e) => setServers(e.target.value)}
              placeholder={t("DNS servers, comma separated")}
            />
          </Field>
          <Field label={t("Search domains")}>
            <input value={domains} onChange={(e) => setDomains(e.target.value)} placeholder={t("Search domains")} />
          </Field>
          <Field label={t("Rollback seconds")} narrow>
            <input value={window} onChange={(e) => setWindow(e.target.value)} placeholder={t("Rollback seconds")} />
          </Field>
        </Fields>
        <Check checked={ignoreDHCP} onChange={setIgnoreDHCP}>
          {t("Ignore DNS servers offered by DHCP")}
        </Check>
        <FormActions>
          <button
            onClick={() =>
              onIntent({
                description: t("{iface} will resolve through {servers}{domains}. The host rolls back after {seconds}s unless the agent confirms it still reaches the panel.", {
                  iface,
                  servers: list(servers).join(", "),
                  domains: list(domains).length ? `, ${t("searching {domains}", { domains: list(domains).join(", ") })}` : "",
                  seconds: Number(window) || 0,
                }),
                payload: {
                  dns: {
                    interface: iface,
                    servers: list(servers),
                    search_domains: list(domains),
                    ignore_auto_dns: ignoreDHCP,
                    rollback_seconds: Number(window) || 0,
                  },
                },
              })
            }
            disabled={!iface || list(servers).length === 0}
          >
            {t("Apply resolver")}
          </button>
        </FormActions>
      </Form>
    </Section>
  );
}
