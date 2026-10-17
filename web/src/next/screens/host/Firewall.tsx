import { useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../../lib/api";
import { useAllowed, useModuleAccess } from "../../../lib/actions";
import { bytes, relativeTime, absoluteTime } from "../../../lib/format";
import type { Host, InventoryFragment, Job } from "../../../lib/types";
import { useT } from "../../../i18n";
import { Board } from "../../Board";
import type { BoardEntry } from "../../../components/board";
import {
  Banner, Bars, Bones, Button, Card, Check, Empty, Fact, Facts, Field, Fields, Find, Kpi, Meter,
  Modal, Note, Pill, Row, Stack, Table, Toolbar,
} from "../../kit";
import {
  orderReady, refusalOf, registryOrder, type RegistryOrder,
} from "../../../lib/host/module";

/**
 * The host's firewall, read from the kernel with nft.
 *
 * Flotestro owns one table of its own: docker, firewalld and iptables-nft
 * rewrite theirs without asking, so a rule placed in those would vanish at
 * the next container start or reload. Every change here can cut the panel
 * off from the machine, so it is bound to the ruleset the operator read,
 * armed with a rollback, and confirmed by name with a reason first.
 */

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

type Drift = {
  reason: string; rule?: string; rule_id?: string; family?: string;
  table?: string; chain?: string; zone?: string; detail?: string;
};

/**
 * What rebuilds the panel's own table after a reboot. No boot file of a
 * distribution carries that table, so a missing answer here is unknown
 * rather than agreement.
 */
type BootRestore = {
  unit?: { name?: string; load_state?: string; boot_state?: string; active_state?: string; result?: string };
  ran?: boolean;
  at?: string;
  rules?: number;
  registered?: number;
  reason?: string;
  detail?: string;
};

type Persistence = {
  restore?: BootRestore;
  unit?: { name?: string; load_state?: string; boot_state?: string; files?: string[] };
  files?: string[];
  compared?: boolean;
  reason?: string;
  detail?: string;
};

/**
 * The panel's rules are back after a reboot only when the restore ran, or
 * when the host's own nftables unit carries the panel table itself.
 */
export function restoreInForce(restore: BootRestore): boolean {
  if (!restore.reason) return restore.ran === true;
  return restore.reason === "nft_boot_restore_not_needed";
}

type Snapshot = {
  adapter?: string;
  drift?: Drift[];
  persistent?: Persistence;
  hash?: string;
  tables?: { family: string; name: string; source: string; owner?: string }[];
  rules?: Rule[];
  zones?: Zone[];
  /** What firewalld keeps for its next start, which is also what a zone
      change writes and a reload makes running. */
  permanent_zones?: Zone[];
  permanent_zones_reason?: string;
  zones_digest?: string;
  permanent_zones_digest?: string;
  /** The header of "ufw status" where ufw is installed: the default policy
      is what a packet meets when no rule matches. */
  ufw?: { active: boolean; defaults?: string; logging?: string; reason?: string };
  writable?: boolean;
  read_only_reason?: string;
  observed_at?: string;
  unavailable_reason?: string;
};

type Intent = { action: string; label: string; description: string; payload: Record<string, unknown> };

/* ------------------------------------------------------- the registry */

/* The registry's order model is lib/host/module's: every module of a host
   page composes its order the same way, through the registry entry, so
   there is one copy of what "ready" and "refused" mean. */
export { orderReady, refusalOf, registryOrder, type RegistryOrder };

/** The shortest reason the API takes for a change of this weight. */
export const MIN_REASON_LENGTH = 8;

/** The rollback window a change ordered from this screen carries. */
export const ROLLBACK_SECONDS = 120;

/** The composed order with this screen's own fields laid on top of it. */
function withFirewall(order: RegistryOrder, extra: Record<string, unknown>): RegistryOrder {
  const section = order.payload.firewall as Record<string, unknown> | undefined;
  if (!section) return order;
  return { ...order, payload: { firewall: { ...section, ...extra } } };
}

/** A rule as an order, bound to the ruleset the operator was looking at. */
export function ruleOrder(fields: {
  rule_id: string; chain: string; action: string; protocol: string;
  ports: string[]; sources: string[]; comment: string; break_glass: boolean;
}, fingerprint: string): RegistryOrder {
  // The registry reads a list one entry per line; the fields on this screen
  // are single lines separated by commas.
  const composed = registryOrder("firewall.rule.ensure", {
    ...fields,
    ports: fields.ports.join("\n"),
    sources: fields.sources.join("\n"),
    rollback_seconds: ROLLBACK_SECONDS,
  });
  return withFirewall(composed, { expected_hash: fingerprint });
}

/** Taking a rule away, as an order. */
export function ruleRemoveOrder(ruleID: string): RegistryOrder {
  return registryOrder("firewall.rule.remove", { rule_id: ruleID, rollback_seconds: ROLLBACK_SECONDS });
}

/** Opening or closing one port in a zone, as an order. */
export function zonePortOrder(zone: string, port: string, protocol: string, enable: boolean): RegistryOrder {
  const composed = registryOrder("firewall.zone.port", { zone, ports: port, protocol, enable });
  return withFirewall(composed, { rollback_seconds: ROLLBACK_SECONDS });
}

/** Allowing or stopping a service in a zone, as an order. */
export function zoneServiceOrder(zone: string, service: string, enable: boolean): RegistryOrder {
  const composed = registryOrder("firewall.zone.service", { zone, service, enable });
  return withFirewall(composed, { rollback_seconds: ROLLBACK_SECONDS });
}

/** The changes this screen offers; when every one is refused, it says so once. */
export const FIREWALL_CHANGES = [
  "firewall.rule.ensure", "firewall.rule.remove", "firewall.zone.port", "firewall.zone.service",
];

/** The adapters as the host names them, in the spelling the operator knows. */
const ADAPTER_LABELS: Record<string, string> = {
  nftables: "nftables",
  firewalld: "firewalld",
  ufw: "UFW",
};

/** The label of an adapter; an unknown name is shown as the host sent it. */
export function adapterLabel(adapter: string): string {
  return ADAPTER_LABELS[adapter] ?? adapter;
}

/** The name of a panel rule is recorded in its comment. */
export function ruleName(rule: Rule): string {
  const stripped = (rule.comment ?? "").replace(/^flotestro:\s*/, "");
  return stripped.split(" - ")[0] || "";
}

/** A count of the items that satisfy a test, or undefined when the list itself is unknown. */
export function countWhere<T>(items: T[] | undefined, test: (item: T) => boolean): number | undefined {
  return items === undefined ? undefined : items.filter(test).length;
}

/** A control that is drawn only where the order it places would be taken. */
function Allowed({ host, action, children }: { host: string; action: string; children: ReactNode }) {
  const verdict = useAllowed(host, action);
  return verdict.allowed ? <>{children}</> : null;
}

/* -------------------------------------------------------- the screen */

export function Firewall({ host }: { host: Host }) {
  const t = useT();
  const queryClient = useQueryClient();
  const access = useModuleAccess(host.id, FIREWALL_CHANGES);

  const module = useQuery({
    queryKey: ["inventory", host.id, "firewall"],
    queryFn: () => api.get<InventoryFragment<Snapshot>>(`/api/v1/hosts/${host.id}/inventory/firewall`),
    retry: false,
  });

  const [intent, setIntent] = useState<Intent | null>(null);
  const [message, setMessage] = useState("");
  const [wizard, setWizard] = useState(false);
  const [filter, setFilter] = useState("");
  const [ownOnly, setOwnOnly] = useState(false);

  const request = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      api.post<Job>(`/api/v1/hosts/${host.id}/operations`, payload),
    onSuccess: (job) => {
      setMessage(
        job.requires_approval
          ? t("Job {id} is waiting for approval.", { id: job.id.slice(0, 8) })
          : t("Job {id} has been queued.", { id: job.id.slice(0, 8) }),
      );
      setIntent(null);
      setWizard(false);
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  if (module.isLoading) return <Bones rows={5} />;
  if (!module.data) return <Empty>{t("This host has not reported its firewall yet.")}</Empty>;

  const snapshot = module.data.payload;
  const rules = (snapshot?.rules ?? []).filter((rule) => {
    if (ownOnly && rule.source !== "managed") return false;
    if (!filter) return true;
    const needle = filter.toLowerCase();
    return rule.text.toLowerCase().includes(needle)
      || rule.chain.toLowerCase().includes(needle)
      || rule.table.toLowerCase().includes(needle);
  });
  const own = (snapshot?.rules ?? []).filter((rule) => rule.source === "managed");
  const zones = (snapshot?.zones ?? []).filter((zone) => zone.active || zone.default || (zone.ports ?? []).length > 0);
  // The rules by who wrote them: ours are the durable ones, the rest
  // belong to docker, firewalld or whoever else rewrites its table.
  const knownRules = snapshot?.unavailable_reason ? undefined : snapshot?.rules ?? [];
  const otherSources = Array.from(new Set((knownRules ?? []).map((rule) => rule.source)))
    .filter((source) => source !== "managed").sort();
  const tables = Object.entries((knownRules ?? []).reduce<Record<string, number>>((into, rule) => {
    const key = `${rule.family} ${rule.table}`;
    into[key] = (into[key] ?? 0) + 1;
    return into;
  }, {})).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const maxPackets = Math.max(1, ...(snapshot?.rules ?? []).map((rule) => rule.packets ?? 0));

  const byOwner = [
    { label: "Flotestro", value: countWhere(knownRules, (rule) => rule.source === "managed"), tone: "ok" as const },
    // A ruleset with nobody else's rules still says so: one segment alone
    // reads as a bar that lost its other half.
    ...(otherSources.length
      ? otherSources.map((source) => ({
          label: source, value: countWhere(knownRules, (rule) => rule.source === source), tone: "neutral" as const,
        }))
      : [{ label: t("others"), value: countWhere(knownRules, (rule) => rule.source !== "managed"), tone: "neutral" as const }]),
    ...(snapshot?.zones?.length ? [{ label: t("Zones"), value: zones.length, tone: "info" as const }] : []),
  ];

  const notices: ReactNode[] = [];
  if (snapshot?.unavailable_reason) {
    notices.push(
      <Banner key="unread" tone="error">
        {t("Firewall state could not be read: {reason}", { reason: snapshot.unavailable_reason })}
      </Banner>,
    );
  }
  if (access.known && !access.anyAllowed) {
    notices.push(
      <Banner key="access" tone="info">
        {access.permissions.length > 0 && access.reasons.length === 0
          ? t("You can read this module; changing it needs the permission {permissions}.", { permissions: access.permissions.join(", ") })
          : t("You can read this module; changing it is not possible here: {reasons}", {
              reasons: [
                ...access.reasons,
                ...access.permissions.map((one) => t("missing permission {permission}", { permission: one })),
              ].join("; "),
            })}
      </Banner>,
    );
  }
  if (message) notices.push(<Banner key="message" tone="info">{message}</Banner>);

  return (
    <>
      {intent && (
        <Confirm
          host={host}
          title={intent.label}
          what={intent.description}
          busy={request.isPending}
          danger={intent.action === "firewall.rule.remove"}
          onConfirm={(reason) => request.mutate({ action: intent.action, reason, payload: intent.payload })}
          onCancel={() => setIntent(null)}
        />
      )}
      <Board screen={FIREWALL_SCREEN} catalogue={FIREWALL_BOARD} notices={notices.length > 0 ? <Stack>{notices}</Stack> : undefined} drawn={{
        ours: (
          <Kpi
            hero
            icon="firewall"
            label={t("Rules owned by Flotestro")}
            value={countWhere(knownRules, (rule) => rule.source === "managed") ?? null}
            note={t("the only ones that survive a reload")}
          />
        ),
        total: (
          <Kpi
            icon="firewall"
            label={t("Rules in force")}
            value={knownRules === undefined ? null : knownRules.length}
          />
        ),
        drift: (
          <Kpi
            icon="help"
            label={t("Differences from the boot source")}
            value={snapshot?.drift === undefined ? null : snapshot.drift.length}
            tone={(snapshot?.drift?.length ?? 0) > 0 ? "warn" : "ok"}
          />
        ),
        adapter: (
          <Kpi
            icon="settings"
            label={t("Adapter")}
            value={snapshot?.adapter ? adapterLabel(snapshot.adapter) : null}
            tone={snapshot?.writable ? "ok" : "warn"}
            note={snapshot?.writable ? undefined : snapshot?.read_only_reason || t("read only")}
          />
        ),
        owners: (
          <Card
            title={t("Effective rules")}
            note={t("By who wrote them; only the rules in the Flotestro table are durable.")}
          >
            <Bars items={byOwner.map((one) => ({
              label: one.label,
              value: one.value ?? 0,
              tone: one.value === undefined ? "unknown" : one.tone,
            }))} />
            {knownRules === undefined && <Note>{t("Nothing was counted: the snapshot could not be read.")}</Note>}
          </Card>
        ),
        firewall: (
          <Card
            title={t("Firewall")}
            tools={
              <Allowed host={host.id} action="firewall.rule.ensure">
                <Button
                  kind="quiet"
                  testId="new-rule"
                  onClick={() => setWizard((open) => !open)}
                  disabled={!snapshot?.writable}
                  title={snapshot?.writable ? undefined : snapshot?.read_only_reason || t("The panel cannot write rules on this host.")}
                >
                  {wizard ? t("Cancel") : t("New rule")}
                </Button>
              </Allowed>
            }
          >
            <Facts>
              <Fact label={t("Adapter")}>
                {snapshot?.adapter
                  ? <Pill tone={snapshot.writable ? "ok" : "unknown"}>{adapterLabel(snapshot.adapter)}</Pill>
                  : <Pill tone="unknown">{t("unknown")}</Pill>}
                {snapshot?.read_only_reason && <span className="fl-faint"> · {snapshot.read_only_reason}</span>}
              </Fact>
              {snapshot?.ufw && (
                <Fact label={t("Default policy (ufw)")}>
                  {snapshot.ufw.active
                    ? <span className="fl-mono">{snapshot.ufw.defaults || "—"}</span>
                    : <Pill tone="unknown">{t("ufw inactive")}</Pill>}
                  {!snapshot.ufw.active && snapshot.ufw.reason && <span className="fl-faint"> · {snapshot.ufw.reason}</span>}
                </Fact>
              )}
              {snapshot?.adapter === "nftables" && (
                <Fact label={t("Restored at boot")}>
                  {!snapshot.persistent
                    ? <Pill tone="unknown">{t("not reported by this agent")}</Pill>
                    : snapshot.persistent.compared
                      ? <span className="fl-mono">{(snapshot.persistent.files ?? []).join(", ") || "—"}</span>
                      : <Pill tone="warn">{snapshot.persistent.reason}</Pill>}
                  {snapshot.persistent?.detail && <span className="fl-faint"> · {snapshot.persistent.detail}</span>}
                </Fact>
              )}
              {snapshot?.adapter === "nftables" && (
                <Fact label={t("Panel rules after a reboot")}>
                  {!snapshot.persistent?.restore?.unit?.load_state
                    ? <Pill tone="unknown">{t("not reported by this agent")}</Pill>
                    : restoreInForce(snapshot.persistent.restore)
                      ? <Pill tone="ok">{t("restored by the agent")}</Pill>
                      : <Pill tone="warn">{snapshot.persistent.restore.reason}</Pill>}
                  {snapshot.persistent?.restore?.detail && <span className="fl-faint"> · {snapshot.persistent.restore.detail}</span>}
                </Fact>
              )}
              {/* The fingerprint ties the plan to the ruleset: a change
                  requested against a different set is not the same change
                  the operator looked at. */}
              <Fact label={t("Ruleset fingerprint")}>
                <span className="fl-mono">{snapshot?.hash || "—"}</span>
              </Fact>
              <Fact label={t("Rules owned by Flotestro")}>{own.length}</Fact>
              <Fact label={t("Read")}>
                {snapshot?.observed_at
                  ? <span title={absoluteTime(snapshot.observed_at)}>{relativeTime(snapshot.observed_at)}</span>
                  : <span className="fl-faint">—</span>}
              </Fact>
              <Fact label={t("By table")}>
                {tables.length
                  ? <Bars items={tables.map(([table, n]) => ({ label: table, value: n }))} />
                  : <span className="fl-faint">—</span>}
              </Fact>
            </Facts>
          </Card>
        ),
        wizard: wizard ? (
          <Allowed host={host.id} action="firewall.rule.ensure">
            <RuleWizard fingerprint={snapshot?.hash ?? ""} onIntent={setIntent} onCancel={() => setWizard(false)} />
          </Allowed>
        ) : undefined,
        differences: snapshot?.drift?.length ? (
          <Card
            title={t("Differences from the boot source")}
            note={t("What the host filters with now against what it restores at the next boot. A rule the boot source does not carry is in force only until the machine restarts.")}
            flush
          >
            <Table
              testId="drift"
              rows={snapshot.drift}
              keyOf={(_one, index) => String(index)}
              columns={[
                { key: "reason", head: t("Reason"), cell: (one) => <Pill tone="warn">{one.reason}</Pill> },
                { key: "rule", head: t("Rule"), tight: true, cell: (one) => (
                  one.rule ? <span className="fl-mono">{one.rule}</span> : <span className="fl-faint">—</span>
                ) },
                { key: "where", head: t("Where"), tight: true, cell: (one) => (
                  <span className="fl-mono">
                    {[one.family, one.table, one.chain, one.zone].filter(Boolean).join(" ") || "—"}
                  </span>
                ) },
                { key: "detail", head: t("What it means"), cell: (one) => one.detail },
              ]}
            />
          </Card>
        ) : undefined,
        zones: snapshot?.zones?.length ? (
          <Card
            title={t("Zones")}
            note={t("firewalld describes access by zone, not by rule order: the question is what is open on an interface, not which rule matches first.")}
            flush
          >
            <Table
              testId="zones"
              rows={zones}
              keyOf={(one) => one.name}
              rowTestId={(one) => `zone-${one.name}`}
              empty={t("No zone is active on this host.")}
              columns={[
                { key: "name", head: t("Zone"), tight: true, cell: (one) => <span className="fl-mono">{one.name}</span> },
                { key: "state", head: t("State"), cell: (one) => (
                  <Stack>
                    {one.active ? <Pill tone="ok">{t("active")}</Pill> : <Pill tone="neutral">{t("inactive")}</Pill>}
                    {one.default && <Pill tone="info">{t("default")}</Pill>}
                  </Stack>
                ) },
                { key: "target", head: t("Target"), minor: true, cell: (one) => one.target || <span className="fl-faint">—</span> },
                { key: "interfaces", head: t("Interfaces"), cell: (one) => (
                  <span className="fl-mono">{(one.interfaces ?? []).join(", ") || "—"}</span>
                ) },
                { key: "services", head: t("Services"), cell: (one) => (one.services ?? []).join(", ") || "—" },
                { key: "ports", head: t("Ports"), cell: (one) => (
                  <span className="fl-mono">{(one.ports ?? []).join(", ") || "—"}</span>
                ) },
                { key: "act", head: t("Actions"), actions: true, cell: (one) => (
                  <Stack>
                    <Allowed host={host.id} action="firewall.zone.port">
                      <ZonePort zone={one.name} onIntent={setIntent} hostname={host.hostname} />
                    </Allowed>
                    <Allowed host={host.id} action="firewall.zone.service">
                      <ZoneService zone={one.name} services={one.services ?? []} onIntent={setIntent} hostname={host.hostname} />
                    </Allowed>
                  </Stack>
                ) },
              ]}
            />
          </Card>
        ) : undefined,
        rules: (
          <Card
            title={t("Effective rules")}
            foot={t("{shown} of {total} rules shown", { shown: rules.length, total: (snapshot?.rules ?? []).length })}
            flush
          >
            <Toolbar>
              <Find
                value={filter}
                onChange={setFilter}
                placeholder={t("Filter by rule, chain or table")}
                testId="rule-filter"
              />
              <Check checked={ownOnly} onChange={setOwnOnly}>
                {t("Only rules owned by Flotestro")}
              </Check>
            </Toolbar>
            {/* An empty ruleset and an empty match are two different things:
                a host without rules filters nothing, and that is worth a
                sentence of its own. */}
            {rules.length === 0 ? (
              <Empty>
                {snapshot?.unavailable_reason
                  ? t("The rules could not be read.")
                  : (snapshot?.rules ?? []).length === 0
                    ? t("This host has no firewall rules: nothing filters its traffic.")
                    : t("No rules match.")}
              </Empty>
            ) : (
              <Table
                testId="rules"
                rows={rules}
                keyOf={(one) => `${one.family}-${one.table}-${one.chain}-${one.handle}`}
                rowTestId={(one) => `rule-${one.handle}`}
                columns={[
                  { key: "table", head: t("Table"), tight: true, cell: (one) => (
                    <span className="fl-mono">{one.family} {one.table}</span>
                  ) },
                  { key: "chain", head: t("Chain"), tight: true, cell: (one) => <span className="fl-mono">{one.chain}</span> },
                  { key: "text", head: t("Rule"), tight: true, cell: (one) => (
                    <span className="fl-mono" title={one.text}>{one.text.slice(0, 70)}</span>
                  ) },
                  // A rule in somebody else's table is neither ours nor durable.
                  { key: "owner", head: t("Owner"), cell: (one) => (
                    one.source === "managed" ? "Flotestro" : <Pill tone="unknown">{one.source}</Pill>
                  ) },
                  // A rule without a counter must not pretend nothing passed
                  // through it.
                  { key: "counters", head: t("Counters"), minor: true, cell: (one) => (
                    one.packets === undefined
                      ? <Pill tone="unknown">{t("no counter")}</Pill>
                      : (
                        <Meter
                          share={one.packets / maxPackets}
                          tone="info"
                          text={`${one.packets} pkt / ${bytes(one.bytes ?? 0)}`}
                        />
                      )
                  ) },
                  { key: "act", head: t("Actions"), actions: true, cell: (one) => (
                    one.source === "managed" ? (
                      <Allowed host={host.id} action="firewall.rule.remove">
                        <RuleRemove rule={one} hostname={host.hostname} onIntent={setIntent} />
                      </Allowed>
                    ) : null
                  ) },
                ]}
              />
            )}
          </Card>
        ),
        source: (
          <Card title={t("Where this came from")}>
            <Facts>
              <Fact label={t("Source")}>{module.data.source}</Fact>
              <Fact label={t("Revision")}><span className="fl-mono">{module.data.revision.slice(0, 12)}</span></Fact>
              <Fact label={t("Observed")}>
                <span title={absoluteTime(module.data.observed_at)}>{relativeTime(module.data.observed_at)}</span>
              </Fact>
              {module.data.unavailable_reason && (
                <Fact label={t("Could not be read")}>{module.data.unavailable_reason}</Fact>
              )}
            </Facts>
          </Card>
        ),
      }} />
    </>
  );
}

/* ------------------------------------------------------ the new rule */

/** The rule wizard: the rule goes into Flotestro's own table. */
function RuleWizard({ fingerprint, onIntent, onCancel }: {
  fingerprint: string;
  onIntent: (intent: Intent) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const [id, setId] = useState("");
  const [chain, setChain] = useState("input");
  const [action, setAction] = useState("accept");
  const [protocol, setProtocol] = useState("tcp");
  const [ports, setPorts] = useState("");
  const [sources, setSources] = useState("");
  const [comment, setComment] = useState("");
  const [breakGlass, setBreakGlass] = useState(false);

  const list = (value: string) => value.split(",").map((one) => one.trim()).filter(Boolean);
  const order = ruleOrder({
    rule_id: id, chain, action, protocol,
    ports: list(ports), sources: list(sources), comment, break_glass: breakGlass,
  }, fingerprint);

  return (
    <Card
      title={t("New rule")}
      note={t("The rule goes into Flotestro's own table. The host arms a rollback before applying it and cancels it only after the agent proves it can still reach the panel.")}
      tools={<Button kind="quiet" onClick={onCancel}>{t("Cancel")}</Button>}
    >
      <Stack>
        <Fields>
          <Field label={t("Rule")}>
            <input value={id} onChange={(event) => setId(event.target.value)} placeholder={t("Rule name, e.g. block-smtp")} data-testid="rule-id" />
          </Field>
          <Field label={t("Chain")}>
            <select value={chain} onChange={(event) => setChain(event.target.value)} data-testid="rule-chain">
              <option value="input">{t("incoming")}</option>
              <option value="output">{t("outgoing")}</option>
            </select>
          </Field>
          <Field label={t("Action")}>
            <select value={action} onChange={(event) => setAction(event.target.value)} data-testid="rule-action">
              <option value="accept">accept</option>
              <option value="drop">drop</option>
              <option value="reject">reject</option>
            </select>
          </Field>
          <Field label={t("Protocol")}>
            <select value={protocol} onChange={(event) => setProtocol(event.target.value)} data-testid="rule-protocol">
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
              <option value="icmp">icmp</option>
              <option value="">{t("any protocol")}</option>
            </select>
          </Field>
          <Field label={t("Ports")}>
            <input value={ports} onChange={(event) => setPorts(event.target.value)} placeholder={t("Ports, e.g. 25, 1000-2000")} data-testid="rule-ports" />
          </Field>
          <Field label={t("Sources")}>
            <input
              value={sources}
              onChange={(event) => setSources(event.target.value)}
              placeholder={t("Sources with masks, e.g. 10.0.0.0/8")}
              data-testid="rule-sources"
            />
          </Field>
          <Field label={t("Comment (optional)")}>
            <input value={comment} onChange={(event) => setComment(event.target.value)} />
          </Field>
        </Fields>
        {/* Breaking the management channel protection is an explicit
            decision: the consequence tends to be a host one has to drive to. */}
        <Check checked={breakGlass} onChange={setBreakGlass}>
          {t("Allow a rule that can cut this host off from the panel (break glass)")}
        </Check>
        <Button
          testId="create-rule"
          disabled={!orderReady(order)}
          title={refusalOf(t, order)}
          onClick={() => onIntent({
            action: "firewall.rule.ensure",
            label: t("Create rule"),
            description: `${action} ${protocol || t("any protocol")}${
              list(ports).length ? ` ${t("port")} ${list(ports).join(", ")}` : ""
            }${list(sources).length ? ` ${t("from")} ${list(sources).join(", ")}` : ""} (${
              chain === "input" ? t("incoming") : t("outgoing")
            })`,
            payload: order.payload,
          })}
        >
          {t("Create rule")}
        </Button>
      </Stack>
    </Card>
  );
}

/**
 * Taking one of the panel's own rules away. A rule the panel cannot name
 * is a rule it cannot take away, and the row says so rather than sending it.
 */
function RuleRemove({ rule, hostname, onIntent }: {
  rule: Rule;
  hostname: string;
  onIntent: (intent: Intent) => void;
}) {
  const t = useT();
  const order = ruleRemoveOrder(ruleName(rule));
  return (
    <Button
      kind="danger"
      testId={`remove-rule-${rule.handle}`}
      disabled={!orderReady(order)}
      title={refusalOf(t, order)}
      onClick={() => onIntent({
        action: "firewall.rule.remove",
        label: t("Remove rule"),
        description: t("{rule} will be removed from {host}. The remaining Flotestro rules are rebuilt in order.", {
          rule: ruleName(rule), host: hostname,
        }),
        payload: order.payload,
      })}
    >
      {t("Remove")}
    </Button>
  );
}

/** Opening or closing a port in a firewalld zone. */
function ZonePort({ zone, onIntent, hostname }: {
  zone: string;
  onIntent: (intent: Intent) => void;
  hostname: string;
}) {
  const t = useT();
  const [port, setPort] = useState("");
  const portOrder = (operation: string) => {
    const [number, protocol = "tcp"] = port.split("/");
    return zonePortOrder(zone, number, protocol, operation === "open");
  };

  return (
    <Row>
      <input
        value={port}
        onChange={(event) => setPort(event.target.value)}
        placeholder="port/tcp"
        aria-label={t("Port to open or close in {zone}", { zone })}
        data-testid={`zone-port-${zone}`}
      />
      {["open", "close"].map((operation) => (
        <Button
          key={operation}
          kind="quiet"
          testId={`zone-${operation}-${zone}`}
          disabled={!orderReady(portOrder(operation))}
          title={refusalOf(t, portOrder(operation))}
          onClick={() => {
            const [number, protocol = "tcp"] = port.split("/");
            onIntent({
              action: "firewall.zone.port",
              label: operation === "open" ? t("Open port") : t("Close port"),
              description: operation === "open"
                ? t("{port} will be opened in zone {zone} on {host}, permanently and reloaded now.", { port: `${number}/${protocol}`, zone, host: hostname })
                : t("{port} will be closed in zone {zone} on {host}, permanently and reloaded now.", { port: `${number}/${protocol}`, zone, host: hostname }),
              payload: portOrder(operation).payload,
            });
          }}
        >
          {operation === "open" ? t("Open") : t("Close")}
        </Button>
      ))}
    </Row>
  );
}

/** Adding or removing a firewalld service in a zone. */
function ZoneService({ zone, services, onIntent, hostname }: {
  zone: string;
  /** The services the zone allows now, so removing one offers a name that exists. */
  services: string[];
  onIntent: (intent: Intent) => void;
  hostname: string;
}) {
  const t = useT();
  const [service, setService] = useState("");
  const name = service.trim();

  return (
    <Row>
      <input
        value={service}
        onChange={(event) => setService(event.target.value)}
        placeholder={t("service, e.g. https")}
        aria-label={t("Service to allow or stop in {zone}", { zone })}
        list={`fl-zone-services-${zone}`}
        data-testid={`zone-service-${zone}`}
      />
      <datalist id={`fl-zone-services-${zone}`}>
        {services.map((one) => <option key={one} value={one} />)}
      </datalist>
      {["add", "remove"].map((operation) => (
        <Button
          key={operation}
          kind="quiet"
          testId={`zone-service-${operation}-${zone}`}
          // The service already being in the zone is this screen's own
          // refusal: the registry sees the form, not the zone.
          disabled={!orderReady(zoneServiceOrder(zone, name, operation === "add"))
            || (operation === "remove" && !services.includes(name))}
          title={refusalOf(t, zoneServiceOrder(zone, name, operation === "add"))}
          onClick={() => onIntent({
            action: "firewall.zone.service",
            label: operation === "add" ? t("Add service") : t("Remove service"),
            description: operation === "add"
              ? t("The service {service} will be allowed in zone {zone} on {host}, permanently and reloaded now.", { service: name, zone, host: hostname })
              : t("The service {service} will be removed from zone {zone} on {host}, permanently and reloaded now.", { service: name, zone, host: hostname }),
            payload: zoneServiceOrder(zone, name, operation === "add").payload,
          })}
        >
          {operation === "add" ? t("Add service") : t("Remove service")}
        </Button>
      ))}
    </Row>
  );
}

/* ----------------------------------------------------- the one change */

/** The confirmation of a change that can take the host away from the panel. */
function Confirm({ host, title, what, busy, danger, onConfirm, onCancel }: {
  host: Host;
  title: string;
  what: ReactNode;
  busy: boolean;
  danger?: boolean;
  onConfirm: (reason: string, confirmation: string) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [typed, setTyped] = useState("");
  const ready = reason.trim().length >= MIN_REASON_LENGTH && typed === host.hostname;

  return (
    <Modal
      title={title}
      onClose={onCancel}
      actions={
        <>
          <Button kind="quiet" onClick={onCancel} disabled={busy}>{t("Cancel")}</Button>
          <Button
            kind={danger ? "danger" : "do"}
            disabled={!ready || busy}
            onClick={() => onConfirm(reason, typed)}
            testId="confirm"
          >
            {busy ? t("Requesting…") : title}
          </Button>
        </>
      }
    >
      <Stack>
        <Note>{what}</Note>
        {/* The target repeated in the dialog: the operator approves a
            specific machine, not "the host I think I have open". */}
        <Note>
          {t("Target: {host}", { host: host.hostname })}
          {host.management_address ? ` · ${host.management_address}` : ` · ${t("address unknown")}`}
          {` · ${host.site} / ${host.environment}`}
        </Note>
        <Fields>
          <Field label={t("Reason (at least 8 characters, kept in the audit trail)")} wide>
            <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="confirm-reason" />
          </Field>
          <Field label={t("Type the hostname to confirm:")} hint={host.hostname} wide>
            <input value={typed} onChange={(event) => setTyped(event.target.value)} data-testid="confirm-target" />
          </Field>
        </Fields>
      </Stack>
    </Modal>
  );
}

/** The name this screen's arrangement is stored under. */
export const FIREWALL_SCREEN = "next_host_firewall";

/** The containers this screen can draw, and the shape each ships with. */
export const FIREWALL_BOARD: BoardEntry[] = [
  { key: "ours", title: "Rules owned by Flotestro", width: 3, height: 1 },
  { key: "total", title: "Rules in force", width: 3, height: 1 },
  { key: "drift", title: "Differences from the boot source", width: 3, height: 1 },
  { key: "adapter", title: "Adapter", width: 3, height: 1 },
  { key: "owners", title: "Effective rules by owner", width: 8, height: 2 },
  { key: "firewall", title: "Firewall", width: 4, height: 3 },
  { key: "wizard", title: "New rule", width: 12, height: 4 },
  { key: "differences", title: "Differences from the boot source", width: 12, height: 3 },
  { key: "zones", title: "Zones", width: 12, height: 3 },
  { key: "rules", title: "Effective rules", width: 12, height: 5 },
  { key: "source", title: "Where this came from", width: 12, height: 1 },
];
