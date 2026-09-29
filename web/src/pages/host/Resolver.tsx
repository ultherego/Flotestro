import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time, Empty } from "../../components/ui";
import {
  Fact, Facts, Field, Fields, Form, FormActions, Message, ModuleFreshness, ModuleHeader, ModulePage, Section,
  Summary, Table, Widgets, countWhere, orderReady, refusalOf, registryOrder, useHost, useModule,
  type RegistryOrder,
} from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { OperationForm } from "../../components/OperationForm";
import { ActionGuard, ReadOnlyModuleNotice } from "../../components/ActionGuard";
import {
  emptyForm, list as listOf, operationForm, text as textOf,
  type FieldSuggestions, type FormValue,
} from "../../lib/operations";
import { useT } from "../../i18n";

/**
 * The resolver change as an order. It goes through the operation registry,
 * so this page sends the payload the Bulk workspace sends and refuses the
 * values it refuses - a name server that is not an address among them.
 */
export function resolverOrder(form: FormValue): RegistryOrder {
  return registryOrder("dns.host.apply", form);
}

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


/**
 * What each owner of resolv.conf means for the operator: who rewrites the
 * file, and so whether a change written by the panel would last.
 */
export function ownerMeaning(owner: string): string {
  switch (owner) {
    case "systemd-resolved": return "systemd-resolved writes resolv.conf; the servers come from its per-link configuration.";
    case "networkmanager": return "NetworkManager writes resolv.conf from the connection profiles; the panel changes it through those.";
    case "dhcp-client": return "A DHCP client writes resolv.conf on every lease; a change by hand is overwritten at the next renewal.";
    case "manual": return "resolv.conf was written by hand; no service rewrites it.";
    default: return "";
  }
}

/** What the resolver mode means: how resolv.conf relates to the daemon. */
export function modeMeaning(mode: string): string {
  switch (mode) {
    case "stub": return "resolv.conf points at the local stub of systemd-resolved; the real servers are per link.";
    case "static": return "resolv.conf lists the upstream servers as systemd-resolved knows them, without the stub.";
    case "uplink": return "resolv.conf lists the upstream servers of systemd-resolved directly.";
    case "foreign": return "resolv.conf is not managed by systemd-resolved; something else wrote it.";
    case "file": return "A plain file read by the libc resolver directly; there is no daemon in between.";
    default: return "";
  }
}

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
 */
/** The changes this page offers; when every one is refused, the page says so once. */
const RESOLVER_CHANGES = ["dns.host.apply"];

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
          <ActionGuard action="dns.host.apply" host={host.id}>
            <button
              className="secondary"
              onClick={() => setForm((open) => !open)}
              disabled={!snapshot?.writable}
              title={snapshot?.writable ? "" : snapshot?.read_only_reason}
            >
              {form ? t("Cancel") : t("Change resolver")}
            </button>
          </ActionGuard>
        }
      />
      <ModuleFreshness fragment={module.data} />
      <ReadOnlyModuleNotice host={host.id} actions={RESOLVER_CHANGES} />
      <Message text={message} />

      {snapshot?.unavailable_reason && (
        <p className="warning">
          <span>{t("Resolver state could not be read: {reason}", { reason: snapshot.unavailable_reason })}</span>
        </p>
      )}
      {snapshot?.read_only_reason && (
        <p className="warning">
          <span>{t("Read-only on this host: {reason}", { reason: snapshot.read_only_reason })}</span>
        </p>
      )}

      <Widgets>
      {/* What the host resolves with, counted; then who owns it and how it
          is protected, which decide whether the panel may touch it. */}
      <Summary
        title={t("Resolution")}
        description={t("The servers, the search domains, and the links that carry servers or encrypt their queries.")}
        span={8}
        segments={[
          { label: t("Servers"), value: known ? (known.servers ?? []).length : undefined, tone: "info" },
          { label: t("Search domains"), value: known ? (known.search_domains ?? []).length : undefined, tone: "info" },
          { label: t("Links with servers"), value: countWhere(links, (link) => (link.servers ?? []).length > 0), tone: "neutral" },
          { label: t("Links with DoT"), value: countWhere(links, (link) => link.dns_over_tls === "yes"), tone: "ok" },
        ]}
      />
      <Section title={t("Ownership")} span={4} flush>
        <Facts>
          {/* The owner and the mode are the daemon's words; the hover
              says what each means for a change written here. */}
          <Fact label={t("Owner")}>
            {snapshot?.owner ? <span title={t(ownerMeaning(snapshot.owner)) || undefined}>{snapshot.owner}</span> : unknown}
            {snapshot?.mode && <span className="source" title={t(modeMeaning(snapshot.mode)) || undefined}> · {snapshot.mode}</span>}
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
          {/* What the owner means for a change made here, in a sentence
              rather than on hover alone: it is the answer to "why can I
              not change this". */}
          {snapshot?.owner && ownerMeaning(snapshot.owner) && (
            <Fact label={t("Meaning")} wide>{t(ownerMeaning(snapshot.owner))}</Fact>
          )}
        </Facts>
      </Section>

      {/* The facts on the left, the test the operator runs against them on
          the right; the change form and the per-link list follow in full
          width. */}
      {/* The owner, DNSSEC and DoT stand in the ownership card above;
          here is what the file itself says. */}
      <Section title={t("Configuration")} span={6} flush>
        <Facts>
          <Fact label={t("Mode")}>
            {snapshot?.mode ? <span title={t(modeMeaning(snapshot.mode)) || undefined}>{snapshot.mode}</span> : "—"}
            {snapshot?.mode && modeMeaning(snapshot.mode) && <span className="source"> · {t(modeMeaning(snapshot.mode))}</span>}
          </Fact>
          <Fact label="resolv.conf">
            <span className="hm-mono">
              {snapshot?.resolv_conf}
              {snapshot?.resolv_conf_target && ` → ${snapshot.resolv_conf_target}`}
            </span>
          </Fact>
          <Fact label={t("Servers")}><span className="hm-mono">{(snapshot?.servers ?? []).join(", ") || "—"}</span></Fact>
          <Fact label={t("Search domains")}><span className="hm-mono">{(snapshot?.search_domains ?? []).join(", ") || "—"}</span></Fact>
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
              <ActionGuard action="dns.resolve.test" host={host.id} explain>
                <button
                  onClick={() => request.mutate({ action: "dns.resolve.test", payload: { dns: { names: nameList } } })}
                  disabled={!nameList.length || request.isPending}
                >
                  {t("Resolve")}
                </button>
              </ActionGuard>
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
        <ActionGuard action="dns.host.apply" host={host.id}>
          <ResolverChange
            seed={{
              interface: managementLink?.name ?? "",
              servers: (snapshot?.servers ?? []).join("\n"),
              // A domain the host reports with a leading tilde is routed, not
              // searched; the name under it is what a search domain is.
              search_domains: (snapshot?.search_domains ?? []).map((d) => d.replace(/^~/, "")).join("\n"),
              ignore_auto_dns: true,
              rollback_seconds: 120,
            }}
            suggestions={{ interface: (snapshot?.links ?? []).map((link) => link.name) }}
            onIntent={setIntent}
          />
        </ActionGuard>
      )}

      <Section title={t("Per-link resolvers")} count={snapshot?.links?.length} span={12} flush>
        {!snapshot?.links?.length ? (
          <Empty>{t("This host does not report per-link resolvers; it has one global list.")}</Empty>
        ) : (
          <Table>
            <thead>
              <tr><th>{t("Link")}</th><th>{t("Servers")}</th><th>{t("Domains")}</th><th>{t("Answers other names")}</th><th>DNSSEC</th><th title="DNS over TLS">DoT</th></tr>
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
 * The resolver change form, drawn from the operation registry: the fields,
 * the refusals and the payload are the ones the Bulk workspace uses.
 */
function ResolverChange({ seed, suggestions, onIntent }: {
  /** What this host resolves with now, as the form's starting value. */
  seed: FormValue;
  suggestions?: FieldSuggestions;
  onIntent: (intent: { description: string; payload: Record<string, unknown> }) => void;
}) {
  const t = useT();
  const entry = operationForm("dns.host.apply");
  const [value, setValue] = useState<FormValue>(() => (entry ? { ...emptyForm(entry), ...seed } : seed));
  // A payload typed by hand in the advanced view is not one this page sends:
  // the change is armed with a rollback the form's own fields carry.
  const [json, setJson] = useState("");
  if (!entry) return null;
  const order = resolverOrder(value);
  const domains = listOf(value, "search_domains");

  return (
    <Section
      title={t("Change resolver")}
      description={t("A host that cannot resolve names loses the directory, Kerberos and with them logins — so this change is armed with the same rollback timer as an address change.")}
      span={12}
    >
      <Form>
        <OperationForm
          entry={entry}
          value={value}
          onChange={setValue}
          json={json}
          onJson={setJson}
          suggestions={suggestions}
        />
        <FormActions>
          <button
            onClick={() =>
              onIntent({
                description: t("{iface} will resolve through {servers}{domains}. The host rolls back after {seconds}s unless the agent confirms it still reaches the panel.", {
                  iface: textOf(value, "interface"),
                  servers: listOf(value, "servers").join(", "),
                  domains: domains.length ? `, ${t("searching {domains}", { domains: domains.join(", ") })}` : "",
                  seconds: Number(value.rollback_seconds) || 0,
                }),
                payload: order.payload,
              })
            }
            disabled={!orderReady(order) || json !== ""}
            title={refusalOf(t, order)}
          >
            {t("Apply resolver")}
          </button>
        </FormActions>
      </Form>
    </Section>
  );
}
