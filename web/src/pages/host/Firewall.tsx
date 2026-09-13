import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time, Empty } from "../../components/ui";
import { ModuleFreshness, useHost, useModule } from "./shared";
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
  writable?: boolean;
  read_only_reason?: string;
  observed_at?: string;
  unavailable_reason?: string;
};

type Intent = { action: string; label: string; description: string; payload: Record<string, unknown> };

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

  return (
    <>
      <p className="subtitle">
        {t("Read from the kernel with nft. Flotestro owns one table of its own — docker, firewalld and iptables-nft rewrite theirs without asking, so a rule placed in those would vanish at the next container start or reload.")}
      </p>

      {snapshot?.unavailable_reason && (
        <p className="warning">
          <span>{t("Firewall state could not be read: {reason}", { reason: snapshot.unavailable_reason })}</span>
        </p>
      )}

      <table>
        <tbody>
          <tr><th>{t("Adapter")}</th><td>{snapshot?.adapter || <span className="badge unknown">{t("unknown")}</span>}</td></tr>
          {/* The fingerprint ties the plan to the rule set: a change
              requested against a different set is not the same change the
              operator looked at. */}
          <tr><th>{t("Ruleset fingerprint")}</th><td>{snapshot?.hash || "—"}</td></tr>
          <tr><th>{t("Rules owned by Flotestro")}</th><td>{own.length}</td></tr>
          <tr><th>{t("Read")}</th><td>{snapshot?.observed_at ? <Time value={snapshot.observed_at} /> : "—"}</td></tr>
        </tbody>
      </table>

      {snapshot?.zones?.length ? (
        <>
          <h2>{t("Zones")}</h2>
          <p className="subtitle">
            {t("firewalld describes access by zone, not by rule order: the question is what is open on an interface, not which rule matches first.")}
          </p>
          <table>
            <thead>
              <tr><th>{t("Zone")}</th><th>{t("State")}</th><th>{t("Target")}</th><th>{t("Interfaces")}</th><th>{t("Services")}</th><th>{t("Ports")}</th><th>{t("Actions")}</th></tr>
            </thead>
            <tbody>
              {snapshot.zones
                .filter((zone) => zone.active || zone.default || (zone.ports ?? []).length > 0)
                .map((zone) => (
                  <tr key={zone.name}>
                    <td>{zone.name}</td>
                    <td>
                      {zone.active ? t("active") : t("inactive")}
                      {zone.default && <span className="badge"> {t("default")}</span>}
                    </td>
                    <td>{zone.target || "—"}</td>
                    <td>{(zone.interfaces ?? []).join(", ") || "—"}</td>
                    <td>{(zone.services ?? []).join(", ") || "—"}</td>
                    <td>{(zone.ports ?? []).join(", ") || "—"}</td>
                    <td>
                      <ZonePort zone={zone.name} onIntent={setIntent} hostname={host.hostname} />
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </>
      ) : null}

      <h2>{t("Effective rules")}</h2>
      <div className="filters">
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder={t("Filter by rule, chain or table")}
          style={{ minWidth: 280 }}
        />
        <label className="toggle">
          <input type="checkbox" checked={ownOnly} onChange={(e) => setOwnOnly(e.target.checked)} />
          {t("Only rules owned by Flotestro")}
        </label>
        <button onClick={() => setWizard((open) => !open)} disabled={!snapshot?.writable}>
          {wizard ? t("Cancel") : t("New rule")}
        </button>
      </div>

      {message && <p className="source" style={{ marginBottom: 12 }}>{message}</p>}

      {wizard && <RuleWizard fingerprint={snapshot?.hash ?? ""} onIntent={setIntent} />}

      {!rules.length ? (
        <Empty>{t("No rules match.")}</Empty>
      ) : (
        <table>
          <thead>
            <tr><th>{t("Table")}</th><th>{t("Chain")}</th><th>{t("Rule")}</th><th>{t("Owner")}</th><th>{t("Counters")}</th><th>{t("Actions")}</th></tr>
          </thead>
          <tbody>
            {rules.map((rule) => (
              <tr key={`${rule.family}-${rule.table}-${rule.chain}-${rule.handle}`}>
                <td>{rule.family} {rule.table}</td>
                <td>{rule.chain}</td>
                <td title={rule.text} style={{ fontFamily: "ui-monospace, monospace", fontSize: 12 }}>
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
                    `${rule.packets} pkt / ${rule.bytes} B`
                  )}
                </td>
                <td>
                  {rule.source === "managed" && (
                    <button
                      className="secondary"
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
        </table>
      )}

      <p className="source" style={{ marginTop: 12 }}>
        {t("{shown} of {total} rules shown", { shown: rules.length, total: (snapshot?.rules ?? []).length })}
      </p>
      <ModuleFreshness fragment={module.data} />

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
    </>
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
    <div className="form" style={{ marginBottom: 16 }}>
      <h2>{t("New rule")}</h2>
      <p className="subtitle" style={{ margin: 0 }}>
        {t("The rule goes into Flotestro's own table. The host arms a rollback before applying it and cancels it only after the agent proves it can still reach the panel.")}
      </p>
      <div className="filters">
        <input value={id} onChange={(e) => setId(e.target.value)} placeholder={t("Rule name, e.g. block-smtp")} />
        <select value={chain} onChange={(e) => setChain(e.target.value)}>
          <option value="input">{t("incoming")}</option>
          <option value="output">{t("outgoing")}</option>
        </select>
        <select value={action} onChange={(e) => setAction(e.target.value)}>
          <option value="accept">accept</option>
          <option value="drop">drop</option>
          <option value="reject">reject</option>
        </select>
        <select value={protocol} onChange={(e) => setProtocol(e.target.value)}>
          <option value="tcp">tcp</option>
          <option value="udp">udp</option>
          <option value="icmp">icmp</option>
          <option value="">{t("any protocol")}</option>
        </select>
      </div>
      <div className="filters">
        <input value={ports} onChange={(e) => setPorts(e.target.value)} placeholder={t("Ports, e.g. 25, 1000-2000")} />
        <input
          value={sources}
          onChange={(e) => setSources(e.target.value)}
          placeholder={t("Sources with masks, e.g. 10.0.0.0/8")}
          style={{ minWidth: 220 }}
        />
        <input value={comment} onChange={(e) => setComment(e.target.value)} placeholder={t("Comment (optional)")} />
      </div>
      {/* Breaking the management channel protection is an explicit
          decision: the consequence tends to be a host one has to drive to. */}
      <label className="toggle">
        <input type="checkbox" checked={breakGlass} onChange={(e) => setBreakGlass(e.target.checked)} />
        {t("Allow a rule that can cut this host off from the panel (break glass)")}
      </label>
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
    </div>
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
        style={{ width: 110 }}
      />
      {["open", "close"].map((operation) => (
        <button
          key={operation}
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
