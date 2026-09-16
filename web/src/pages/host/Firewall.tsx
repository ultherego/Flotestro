import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time, Empty } from "../../components/ui";
import { bytes } from "../../lib/format";
import { Breakdown, Meter } from "../../components/widgets";
import {
  Check, Fact, Facts, Field, Fields, Foot, Form, FormActions, Message, ModuleFreshness, ModuleHeader, ModulePage,
  Section, Summary, Table, Widgets, countWhere, useHost, useModule,
} from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { useT } from "../../i18n";

type Rule = {
  family: string;
  table: string;
  chain: string;
  handle: number;
  text: string;
  source: string;
  comment?: string;
  packets?: number;
  bytes?: number;
};

type Zone = {
  name: string;
  active: boolean;
  default: boolean;
  target?: string;
  interfaces?: string[];
  sources?: string[];
  services?: string[];
  ports?: string[];
};

type Snapshot = {
  adapter?: string;
  hash?: string;
  tables?: { family: string; name: string; source: string; owner?: string }[];
  rules?: Rule[];
  zones?: Zone[];
  /** The header of "ufw status" where ufw is installed: the default policy
      is what a packet meets when no rule matches, and no rule list says
      that. An inactive ufw carries the reason the panel writes elsewhere. */
  ufw?: { active: boolean; defaults?: string; logging?: string; reason?: string };
  writable?: boolean;
  read_only_reason?: string;
  observed_at?: string;
  unavailable_reason?: string;
};

type Intent = { action: string; label: string; description: string; payload: Record<string, unknown> };

/** The adapters as the host names them, in the spelling the operator knows. */
const ADAPTER_LABELS: Record<string, string> = {
  nftables: "nftables",
  firewalld: "firewalld",
  ufw: "UFW",
};

/** The label of an adapter; an unknown name is shown as the host sent it. */
function adapterLabel(adapter: string): string {
  return ADAPTER_LABELS[adapter] ?? adapter;
}

/**
 * The host's firewall.
 *
 * The panel changes only its own nftables table or firewalld zone. Other
 * people's chains - docker's, firewalld's, iptables-nft's - are rewritten
 * without its participation, so a rule in them would vanish at the first
 * container start or service reload. The operator sees them but does not
 * edit them.
 */
export function Firewall() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const module = useModule<Snapshot>(host.id, "firewall");
  const [intent, setIntent] = useState<Intent | null>(null);
  const [message, setMessage] = useState("");
  const [wizard, setWizard] = useState(false);
  const [filter, setFilter] = useState("");
  const [ownOnly, setOwnOnly] = useState(false);

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, body),
    onSuccess: (job) => {
      setMessage(
        job.requires_approval
          ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
          : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }),
      );
      setIntent(null);
      setWizard(false);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  const snapshot = module.data?.payload;
  if (!module.data) return <Empty>{t("This host has not reported its firewall yet.")}</Empty>;

  const rules = (snapshot?.rules ?? []).filter((rule) => {
    if (ownOnly && rule.source !== "managed") return false;
    if (!filter) return true;
    const needle = filter.toLowerCase();
    return (
      rule.text.toLowerCase().includes(needle) ||
      rule.chain.toLowerCase().includes(needle) ||
      rule.table.toLowerCase().includes(needle)
    );
  });
  const own = (snapshot?.rules ?? []).filter((rule) => rule.source === "managed");
  const zones = (snapshot?.zones ?? []).filter((zone) => zone.active || zone.default || (zone.ports ?? []).length > 0);
  // The rules by who wrote them: ours are the durable ones, the rest belong
  // to docker, firewalld or whoever else rewrites its table without asking.
  // An unread rule set has no counts, only dashes.
  const knownRules = snapshot?.unavailable_reason ? undefined : snapshot?.rules ?? [];
  const otherSources = Array.from(new Set((knownRules ?? []).map((rule) => rule.source))).filter((source) => source !== "managed").sort();
  const tables = Object.entries((knownRules ?? []).reduce<Record<string, number>>((acc, rule) => {
    const key = `${rule.family} ${rule.table}`;
    acc[key] = (acc[key] ?? 0) + 1;
    return acc;
  }, {})).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const maxPackets = Math.max(1, ...(snapshot?.rules ?? []).map((rule) => rule.packets ?? 0));

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Firewall")}
        description={t("Read from the kernel with nft. Flotestro owns one table of its own — docker, firewalld and iptables-nft rewrite theirs without asking, so a rule placed in those would vanish at the next container start or reload.")}
        actions={
          <button
            onClick={() => setWizard((open) => !open)}
            disabled={!snapshot?.writable}
            title={snapshot?.writable ? undefined : snapshot?.read_only_reason || t("The panel cannot write rules on this host.")}
          >
            {wizard ? t("Cancel") : t("New rule")}
          </button>
        }
      />
      <ModuleFreshness fragment={module.data} />
      <Message text={message} />

      {snapshot?.unavailable_reason && (
        <p className="warning">
          <span>{t("Firewall state could not be read: {reason}", { reason: snapshot.unavailable_reason })}</span>
        </p>
      )}

      <Widgets>
      {/* The rules by owner and the facts of the rule set make one summary
          row: whose rules these are is the first question, because only
          ours survive the next container start or reload. */}
      <Summary
        title={t("Effective rules")}
        description={t("By who wrote them; only the rules in the Flotestro table are durable.")}
        span={8}
        segments={[
          { label: "Flotestro", value: countWhere(knownRules, (rule) => rule.source === "managed"), tone: "ok" },
          // A rule set with nobody else's rules still says so: one
          // segment alone reads as a bar that lost its other half.
          ...(otherSources.length
            ? otherSources.map((source) => ({
                label: source, value: countWhere(knownRules, (rule) => rule.source === source), tone: "neutral" as const,
              }))
            : [{ label: t("others"), value: countWhere(knownRules, (rule) => rule.source !== "managed"), tone: "neutral" as const }]),
          ...(snapshot?.zones?.length ? [{ label: t("Zones"), value: zones.length, tone: "info" as const }] : []),
        ]}
      />

      <Section title={t("Firewall")} span={4} flush>
        <Facts>
          <Fact label={t("Adapter")}>
            {snapshot?.adapter
              ? <span className={snapshot.writable ? "badge ok" : "badge unknown"}>{adapterLabel(snapshot.adapter)}</span>
              : <span className="badge unknown">{t("unknown")}</span>}
            {snapshot?.read_only_reason && <span className="source"> · {snapshot.read_only_reason}</span>}
          </Fact>
          {snapshot?.ufw && (
            <Fact label={t("Default policy (ufw)")}>
              {snapshot.ufw.active
                ? <span className="hm-mono">{snapshot.ufw.defaults || "—"}</span>
                : <span className="badge unknown">{t("ufw inactive")}</span>}
              {!snapshot.ufw.active && snapshot.ufw.reason && <span className="source"> · {snapshot.ufw.reason}</span>}
            </Fact>
          )}
          {/* The fingerprint ties the plan to the rule set: a change
              requested against a different set is not the same change the
              operator looked at. */}
          <Fact label={t("Ruleset fingerprint")}><span className="hm-mono">{snapshot?.hash || "—"}</span></Fact>
          <Fact label={t("Rules owned by Flotestro")}>{own.length}</Fact>
          <Fact label={t("Read")}>{snapshot?.observed_at ? <Time value={snapshot.observed_at} /> : "—"}</Fact>
          <Fact label={t("By table")} wide>
            {tables.length
              ? <Breakdown items={tables.map(([table, count]) => ({ label: <span className="hm-mono">{table}</span>, value: count }))} />
              : "—"}
          </Fact>
        </Facts>
      </Section>

      {wizard && <RuleWizard fingerprint={snapshot?.hash ?? ""} onIntent={setIntent} />}

      {snapshot?.zones?.length ? (
        <Section
          title={t("Zones")}
          count={zones.length}
          span={12}
          description={t("firewalld describes access by zone, not by rule order: the question is what is open on an interface, not which rule matches first.")}
          flush
        >
          <Table>
            <thead>
              <tr><th>{t("Zone")}</th><th>{t("State")}</th><th>{t("Target")}</th><th>{t("Interfaces")}</th><th>{t("Services")}</th><th>{t("Ports")}</th><th>{t("Actions")}</th></tr>
            </thead>
            <tbody>
              {zones.map((zone) => (
                <tr key={zone.name}>
                  <td className="hm-mono hm-primary">{zone.name}</td>
                  <td>
                    {zone.active ? <span className="badge ok">{t("active")}</span> : <span className="badge">{t("inactive")}</span>}
                    {zone.default && <span className="badge"> {t("default")}</span>}
                  </td>
                  <td>{zone.target || "—"}</td>
                  <td className="hm-mono">{(zone.interfaces ?? []).join(", ") || "—"}</td>
                  <td>{(zone.services ?? []).join(", ") || "—"}</td>
                  <td className="hm-mono">{(zone.ports ?? []).join(", ") || "—"}</td>
                  <td>
                    <ZonePort zone={zone.name} onIntent={setIntent} hostname={host.hostname} />
                    <ZoneService zone={zone.name} services={zone.services ?? []} onIntent={setIntent} hostname={host.hostname} />
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Section>
      ) : null}

      <Section
        title={t("Effective rules")}
        count={rules.length}
        span={12}
        tools={
          <>
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder={t("Filter by rule, chain or table")}
            />
            <label className="toggle">
              <input type="checkbox" checked={ownOnly} onChange={(e) => setOwnOnly(e.target.checked)} />
              {t("Only rules owned by Flotestro")}
            </label>
          </>
        }
        flush
      >
        {/* An empty rule set and an empty match are two different things:
            a host without rules filters nothing, and that is worth a
            sentence of its own. */}
        {!rules.length ? (
          <Empty>
            {snapshot?.unavailable_reason
              ? t("The rules could not be read.")
              : (snapshot?.rules ?? []).length === 0
                ? t("This host has no firewall rules: nothing filters its traffic.")
                : t("No rules match.")}
          </Empty>
        ) : (
          <Table>
            <thead>
              <tr><th>{t("Table")}</th><th>{t("Chain")}</th><th>{t("Rule")}</th><th>{t("Owner")}</th><th>{t("Counters")}</th><th>{t("Actions")}</th></tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={`${rule.family}-${rule.table}-${rule.chain}-${rule.handle}`}>
                  <td className="hm-mono">{rule.family} {rule.table}</td>
                  <td className="hm-mono">{rule.chain}</td>
                  <td className="hm-mono" title={rule.text}>
                    {rule.text.slice(0, 70)}
                  </td>
                  {/* A rule in somebody else's table is neither ours nor durable. */}
                  <td>
                    {rule.source === "managed" ? (
                      "Flotestro"
                    ) : (
                      <span className="badge unknown">{rule.source}</span>
                    )}
                  </td>
                  {/* A rule without a counter must not pretend nothing passed
                      through it. */}
                  <td>
                    {rule.packets === undefined ? (
                      <span className="badge unknown">{t("no counter")}</span>
                    ) : (
                      <Meter value={rule.packets} max={maxPackets} tone="info" text={`${rule.packets} pkt / ${bytes(rule.bytes ?? 0)}`} />
                    )}
                  </td>
                  <td>
                    {rule.source === "managed" && (
                      <button
                        className="hm-danger"
                        onClick={() =>
                          setIntent({
                            action: "firewall.rule.remove",
                            label: t("Remove rule"),
                            description: t("{rule} will be removed from {host}. The remaining Flotestro rules are rebuilt in order.", { rule: ruleName(rule), host: host.hostname }),
                            payload: { firewall: { rule_id: ruleName(rule), rollback_seconds: 120 } },
                          })
                        }
                      >
                        {t("Remove")}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
        <Foot>
          <span>{t("{shown} of {total} rules shown", { shown: rules.length, total: (snapshot?.rules ?? []).length })}</span>
        </Foot>
      </Section>
      </Widgets>

      {intent && (
        <TargetConfirmation
          host={host}
          label={intent.label}
          description={intent.description}
          busy={request.isPending}
          onConfirm={(reason) =>
            request.mutate({ action: intent.action, reason, payload: intent.payload })
          }
          onCancel={() => setIntent(null)}
        />
      )}
    </ModulePage>
  );
}

/** The name of a panel rule is recorded in its comment. */
function ruleName(rule: Rule): string {
  const stripped = (rule.comment ?? "").replace(/^flotestro:\s*/, "");
  return stripped.split(" - ")[0] || "";
}

/**
 * The rule wizard. The panel does not accept raw nft syntax: the rule text
 * is a language, and accepting a language would mean the host executes
 * everything that can be written in it.
 */
function RuleWizard({ fingerprint, onIntent }: { fingerprint: string; onIntent: (intent: Intent) => void }) {
  const t = useT();
  const [id, setId] = useState("");
  const [chain, setChain] = useState("input");
  const [action, setAction] = useState("accept");
  const [protocol, setProtocol] = useState("tcp");
  const [ports, setPorts] = useState("");
  const [sources, setSources] = useState("");
  const [comment, setComment] = useState("");
  const [breakGlass, setBreakGlass] = useState(false);

  const list = (value: string) =>
    value.split(",").map((element) => element.trim()).filter(Boolean);

  return (
    <Section
      title={t("New rule")}
      description={t("The rule goes into Flotestro's own table. The host arms a rollback before applying it and cancels it only after the agent proves it can still reach the panel.")}
      span={12}
    >
      <Form>
        <Fields>
          <Field label={t("Rule")}>
            <input value={id} onChange={(e) => setId(e.target.value)} placeholder={t("Rule name, e.g. block-smtp")} />
          </Field>
          <Field label={t("Chain")} narrow>
            <select value={chain} onChange={(e) => setChain(e.target.value)}>
              <option value="input">{t("incoming")}</option>
              <option value="output">{t("outgoing")}</option>
            </select>
          </Field>
          <Field label={t("Action")} narrow>
            <select value={action} onChange={(e) => setAction(e.target.value)}>
              <option value="accept">accept</option>
              <option value="drop">drop</option>
              <option value="reject">reject</option>
            </select>
          </Field>
          <Field label={t("Protocol")} narrow>
            <select value={protocol} onChange={(e) => setProtocol(e.target.value)}>
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
              <option value="icmp">icmp</option>
              <option value="">{t("any protocol")}</option>
            </select>
          </Field>
          <Field label={t("Ports")}>
            <input value={ports} onChange={(e) => setPorts(e.target.value)} placeholder={t("Ports, e.g. 25, 1000-2000")} />
          </Field>
          <Field label={t("Sources")}>
            <input
              value={sources}
              onChange={(e) => setSources(e.target.value)}
              placeholder={t("Sources with masks, e.g. 10.0.0.0/8")}
            />
          </Field>
          <Field label={t("Comment (optional)")}>
            <input value={comment} onChange={(e) => setComment(e.target.value)} />
          </Field>
        </Fields>
        {/* Breaking the management channel protection is an explicit
            decision: the consequence tends to be a host one has to drive to. */}
        <Check checked={breakGlass} onChange={setBreakGlass}>
          {t("Allow a rule that can cut this host off from the panel (break glass)")}
        </Check>
        <FormActions>
          <button
            onClick={() =>
              onIntent({
                action: "firewall.rule.ensure",
                label: t("Create rule"),
                description: `${action} ${protocol || t("any protocol")}${
                  list(ports).length ? ` ${t("port")} ${list(ports).join(", ")}` : ""
                }${list(sources).length ? ` ${t("from")} ${list(sources).join(", ")}` : ""} (${
                  chain === "input" ? t("incoming") : t("outgoing")
                })`,
                payload: {
                  firewall: {
                    rule_id: id,
                    chain,
                    action,
                    protocol,
                    ports: list(ports),
                    sources: list(sources),
                    comment,
                    break_glass: breakGlass,
                    rollback_seconds: 120,
                    expected_hash: fingerprint,
                  },
                },
              })
            }
            disabled={!id}
          >
            {t("Create rule")}
          </button>
        </FormActions>
      </Form>
    </Section>
  );
}

/** Opening or closing a port in a firewalld zone. */
function ZonePort({
  zone, onIntent, hostname,
}: {
  zone: string;
  onIntent: (intent: Intent) => void;
  hostname: string;
}) {
  const t = useT();
  const [port, setPort] = useState("");

  return (
    <div className="operations">
      <input
        value={port}
        onChange={(e) => setPort(e.target.value)}
        placeholder="port/tcp"
        style={{ width: 100 }}
      />
      {["open", "close"].map((operation) => (
        <button
          key={operation}
          className="secondary"
          onClick={() => {
            const [number, protocol = "tcp"] = port.split("/");
            onIntent({
              action: "firewall.zone.port",
              label: operation === "open" ? t("Open port") : t("Close port"),
              description: operation === "open"
                ? t("{port} will be opened in zone {zone} on {host}, permanently and reloaded now.", { port: `${number}/${protocol}`, zone, host: hostname })
                : t("{port} will be closed in zone {zone} on {host}, permanently and reloaded now.", { port: `${number}/${protocol}`, zone, host: hostname }),
              payload: {
                firewall: {
                  zone,
                  ports: [number],
                  protocol,
                  enable: operation === "open",
                },
              },
            });
          }}
          disabled={!port}
        >
          {operation === "open" ? t("Open") : t("Close")}
        </button>
      ))}
    </div>
  );
}

/** A firewalld service name as the host validates it. */
const SERVICE_NAME_PATTERN = /^[a-z0-9][a-z0-9_.-]{0,31}$/;

/**
 * Adding or removing a firewalld service in a zone. A service is a named
 * set of ports (ssh, https, nfs) that firewalld ships or the administrator
 * defined; the change is permanent and reloaded at once, like a port.
 */
function ZoneService({
  zone, services, onIntent, hostname,
}: {
  zone: string;
  /** The services the zone allows now, so removing one offers a name that exists. */
  services: string[];
  onIntent: (intent: Intent) => void;
  hostname: string;
}) {
  const t = useT();
  const [service, setService] = useState("");
  const name = service.trim();
  const valid = SERVICE_NAME_PATTERN.test(name);

  return (
    <div className="operations">
      <input
        value={service}
        onChange={(e) => setService(e.target.value)}
        placeholder={t("service, e.g. https")}
        list={`zone-services-${zone}`}
        style={{ width: 130 }}
      />
      <datalist id={`zone-services-${zone}`}>
        {services.map((entry) => <option key={entry} value={entry} />)}
      </datalist>
      {["add", "remove"].map((operation) => (
        <button
          key={operation}
          className="secondary"
          onClick={() =>
            onIntent({
              action: "firewall.zone.service",
              label: operation === "add" ? t("Add service") : t("Remove service"),
              description: operation === "add"
                ? t("The service {service} will be allowed in zone {zone} on {host}, permanently and reloaded now.", { service: name, zone, host: hostname })
                : t("The service {service} will be removed from zone {zone} on {host}, permanently and reloaded now.", { service: name, zone, host: hostname }),
              payload: {
                firewall: {
                  zone,
                  service: name,
                  enable: operation === "add",
                },
              },
            })
          }
          disabled={!valid || (operation === "remove" && !services.includes(name))}
        >
          {operation === "add" ? t("Add service") : t("Remove service")}
        </button>
      ))}
    </div>
  );
}
