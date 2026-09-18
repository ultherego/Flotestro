import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time, Empty } from "../../components/ui";
import { Breakdown } from "../../components/widgets";
import {
  Fact, Facts, Field, Fields, Foot, Form, FormActions, Message, ModuleFreshness, ModuleHeader, ModulePage, Section,
  Summary, Table, Widgets, countWhere, useHost, useModule,
} from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { ActionGuard, ReadOnlyModuleNotice } from "../../components/ActionGuard";
import { useModuleAccess } from "../../lib/actions";
import { useT } from "../../i18n";

type Address = {
  family: string;
  address: string;
  scope: string;
  source?: string;
  permanent: boolean;
};

/**
 * What the host reports about a bond.
 *
 * The members come from the links that name this bond as their master, not
 * from the bond itself: the kernel keeps the relation on the member side.
 * The active member and the state of each member come from the bonding
 * driver, which knows what "ip" does not - and a bond whose active member
 * is not its primary is a bond that failed over and nobody noticed.
 */
type BondDetails = {
  mode?: string;
  members?: string[];
  miimon_ms: number;
  primary?: string;
  lacp_rate?: string;
  xmit_hash_policy?: string;
  active_member?: string;
  member_states?: Record<string, string>;
};

type BridgePortVLAN = {
  port: string;
  vid: number;
  pvid?: boolean;
  untagged?: boolean;
};

type BridgeDetails = {
  members?: string[];
  stp: boolean;
  vlan_filtering: boolean;
  vlan_protocol?: string;
  vlans?: BridgePortVLAN[];
};

type VLANDetails = {
  parent?: string;
  id: number;
  protocol?: string;
};

/**
 * The kernel's own switches for the second family. Every field is optional
 * on purpose: a setting that could not be read is unknown, and unknown is
 * not "off".
 */
type IPv6Settings = {
  disabled?: boolean;
  accept_ra?: number;
  privacy?: number;
};

export type Interface = {
  name: string;
  index: number;
  kind?: string;
  mac?: string;
  mtu: number;
  oper_state: string;
  carrier?: boolean;
  speed_mbps?: number;
  driver?: string;
  addresses?: Address[];
  /** The layer that owns this interface: the bond or the bridge it was enslaved to. */
  master?: string;
  bond?: BondDetails;
  bridge?: BridgeDetails;
  vlan?: VLANDetails;
  ipv6?: IPv6Settings;
  management: boolean;
};

type Route = {
  destination: string;
  gateway?: string;
  interface?: string;
  source?: string;
  protocol?: string;
  scope?: string;
  metric: number;
  family: string;
  table?: string;
};

type Snapshot = {
  interfaces?: Interface[];
  routes?: Route[];
  management_interface?: string;
  management_address?: string;
  write_adapter?: string;
  /** Set when the host has the second family switched off for every interface, or has no IPv6 at all. */
  ipv6_disabled?: boolean;
  /** Why the bonds, the bridges and the VLANs could not be read; the addresses may still be there. */
  layering_unavailable_reason?: string;
  observed_at?: string;
  unavailable_reason?: string;
};

/** The write adapters as the host names them, in the spelling the operator knows. */
const ADAPTER_LABELS: Record<string, string> = {
  networkmanager: "NetworkManager",
  nmstate: "nmstate",
  netplan: "netplan",
};

/** The label of a write adapter; an unknown name is shown as the host sent it. */
function adapterLabel(adapter: string): string {
  return ADAPTER_LABELS[adapter] ?? adapter;
}

/**
 * The origin of a route in words. The kernel's names are terse - "ra" is
 * a router advertisement, "boot" a route set at boot by a script - and
 * the operator asks who put the route there, not what the field is called.
 */
export function routeProtocolWords(protocol: string | undefined): string {
  switch (protocol) {
    case "kernel": return "kernel (from an address)";
    case "dhcp": return "DHCP";
    case "ra": return "router advertisement";
    case "static": return "static";
    case "boot": return "set at boot";
    case "bird":
    case "bgp":
    case "ospf": return `routing daemon (${protocol})`;
    default: return protocol || "—";
  }
}

type Intent = {
  action: string;
  label: string;
  description: string;
  payload: Record<string, unknown>;
};

/**
 * The host's network: interfaces, addresses and routes read from the kernel.
 *
 * The panel shows the actual state, not the content of configuration files:
 * what the host has up and what somebody once wrote into a configuration
 * can drift apart - and the operator asks about the former.
 */
/** The changes this page offers; when every one is refused, the page says so once. */
const NETWORK_CHANGES = [
  "network.mtu.set", "network.route.ensure", "network.profile.apply",
  "network.link.apply", "network.link.remove",
];

/** The layered kind of an interface, or an empty string for a plain link. */
export function layerKind(iface: Interface): string {
  if (iface.bond) return "bond";
  if (iface.bridge) return "bridge";
  if (iface.vlan) return "vlan";
  return "";
}

/** The members of a layer, whichever kind it is. */
export function layerMembers(iface: Interface): string[] {
  return iface.bond?.members ?? iface.bridge?.members ?? [];
}

/**
 * The layering of an interface in one line, as the operator would say it:
 * what the layer is made of, or what it sits on.
 */
export function layerSummary(iface: Interface): string {
  if (iface.vlan) return `vlan ${iface.vlan.id} on ${iface.vlan.parent || "?"}`;
  if (iface.bond) {
    const mode = iface.bond.mode || "unknown mode";
    return `bond (${mode}) of ${(iface.bond.members ?? []).join(", ") || "nothing"}`;
  }
  if (iface.bridge) {
    return `bridge of ${(iface.bridge.members ?? []).join(", ") || "nothing yet"}`;
  }
  if (iface.master) return `member of ${iface.master}`;
  return "";
}

/** The kernel's accept_ra number in the panel's words. */
export function acceptRAWords(value: number | undefined): string {
  if (value === undefined) return "unknown";
  if (value === 0) return "ignored";
  if (value === 2) return "accepted, even while forwarding";
  return "accepted";
}

/** The kernel's use_tempaddr number in the panel's words. */
export function privacyWords(value: number | undefined): string {
  if (value === undefined) return "unknown";
  if (value === 0) return "off";
  if (value === 2) return "temporary preferred";
  return "public preferred";
}

/**
 * The settings of a layer, each kind in its own terms. A bond that does not
 * watch its members is said so in words, because a zero in a column reads
 * as "nothing to report" and this one is a decision.
 */
function layerSettings(iface: Interface, t: (text: string, params?: Record<string, string | number>) => string) {
  if (iface.bond) {
    const parts = [t("mode {mode}", { mode: iface.bond.mode || t("unknown") })];
    parts.push(iface.bond.miimon_ms === 0
      ? t("link monitoring off")
      : t("monitored every {ms} ms", { ms: iface.bond.miimon_ms }));
    if (iface.bond.primary) parts.push(t("primary {member}", { member: iface.bond.primary }));
    if (iface.bond.lacp_rate) parts.push(t("LACP {rate}", { rate: iface.bond.lacp_rate }));
    if (iface.bond.xmit_hash_policy) parts.push(iface.bond.xmit_hash_policy);
    return parts.join(" · ");
  }
  if (iface.bridge) {
    const parts = [iface.bridge.stp ? t("spanning tree on") : t("spanning tree off")];
    parts.push(iface.bridge.vlan_filtering ? t("VLAN filtering on") : t("VLAN filtering off"));
    if (iface.bridge.vlan_filtering && (iface.bridge.vlans ?? []).length > 0) {
      parts.push(t("{n} port VLANs", { n: (iface.bridge.vlans ?? []).length }));
    }
    return parts.join(" · ");
  }
  if (iface.vlan) {
    return `${t("tag")} ${iface.vlan.id} · ${iface.vlan.protocol || "802.1Q"}`;
  }
  return "—";
}

export function Network() {
  const t = useT();
  const host = useHost();
  // The interface editor gathers three changes; it opens when at least one
  // of them may be ordered, and each of its buttons stands behind its own.
  const access = useModuleAccess(host.id, NETWORK_CHANGES);
  const queryClient = useQueryClient();
  const module = useModule<Snapshot>(host.id, "network");
  const [intent, setIntent] = useState<Intent | null>(null);
  const [message, setMessage] = useState("");
  const [edited, setEdited] = useState<Interface | null>(null);
  const [building, setBuilding] = useState(false);

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
      setEdited(null);
      setBuilding(false);
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });
  // A host with docker has a dozen virtual interfaces and only some of them
  // mean anything. By default we show the ones that do.
  const [all, setAll] = useState(false);

  const snapshot = module.data?.payload;
  // Without a write adapter no row has an action; a column of greyed
  // buttons would only repeat the warning above the table.
  const writable = !!snapshot?.write_adapter;
  const interfaces = snapshot?.interfaces ?? [];
  const visible = all ? interfaces : interfaces.filter(relevant);
  const routes = snapshot?.routes ?? [];
  // The layers are their own list: an operator asking about a bond is not
  // asking which network cards the host has.
  const layers = interfaces.filter((iface) => layerKind(iface) !== "");
  // An unread snapshot has nothing to count; the bar shows dashes then.
  const known = snapshot?.unavailable_reason ? undefined : interfaces;
  const kinds = Object.entries(interfaces.reduce<Record<string, number>>((acc, iface) => {
    const kind = iface.kind || t("unknown");
    acc[kind] = (acc[kind] ?? 0) + 1;
    return acc;
  }, {})).sort((a, b) => b[1] - a[1]).slice(0, 6);

  if (!module.data) return <Empty>{t("This host has not reported its network state yet.")}</Empty>;

  return (
    <ModulePage>
      <ModuleHeader
        title={t("Network")}
        description={t("Read from the kernel, not from configuration files: what the host has up and what someone once wrote into a config file can differ.")}
      />
      <ModuleFreshness fragment={module.data} />
      <ReadOnlyModuleNotice host={host.id} actions={NETWORK_CHANGES} />
      <Message text={message} />

      {snapshot?.unavailable_reason && (
        <p className="warning">
          <span>{t("Network state could not be read: {reason}", { reason: snapshot.unavailable_reason })}</span>
        </p>
      )}

      {/* A missing write mechanism is an answer, not a failure: the module
          works, only read-only, and says why. */}
      {!snapshot?.write_adapter && (
        <p className="warning">
          <span>
            {t("Read-only on this host: no NetworkManager, nmstate or netplan, so the panel will not change its network configuration.")}
          </span>
        </p>
      )}

      {/* The layering read failing is not the absence of layers: the panel
          says so, because a plan computed against silence would happily
          take a member another bond already owns. */}
      {snapshot?.layering_unavailable_reason && (
        <p className="warning">
          <span>
            {t("Bonds, bridges and VLANs could not be read: {reason}. The addresses above are still what the host reports.", { reason: snapshot.layering_unavailable_reason })}
          </span>
        </p>
      )}

      {/* IPv6 switched off host-wide is a fact the operator has to see
          before ordering an IPv6 address the host would silently drop. */}
      {snapshot?.ipv6_disabled && (
        <p className="warning">
          <span>
            {t("This host has IPv6 switched off for every interface. An IPv6 address, route or router advertisement setting ordered here would never take effect, and the host refuses it rather than writing it into the void.")}
          </span>
        </p>
      )}

      <Widgets>
      {/* The interfaces by link state, then the channel the panel itself
          comes through - the one whose change cuts the branch we sit on. */}
      <Summary
        title={t("Interfaces")}
        description={t("Every interface the kernel lists, by its operational state.")}
        span={8}
        segments={[
          { label: t("up"), value: countWhere(known, (iface) => iface.oper_state === "up"), tone: "ok" },
          { label: t("down"), value: countWhere(known, (iface) => iface.oper_state === "down"), tone: "neutral" },
          { label: t("other"), value: countWhere(known, (iface) => iface.oper_state !== "up" && iface.oper_state !== "down"), tone: "unknown" },
        ]}
      />
      <Section title={t("Management channel")} span={4} flush>
        <Facts>
          <Fact label={t("Interface")}>
            {snapshot?.management_interface
              ? <span className="hm-mono">{snapshot.management_interface}</span>
              : <span className="badge unknown">{t("unknown")}</span>}
          </Fact>
          <Fact label={t("Address")}>
            {snapshot?.management_address ? <span className="hm-mono">{snapshot.management_address}</span> : "—"}
          </Fact>
          <Fact label={t("Write adapter")}>
            {snapshot?.write_adapter
              ? <span className="badge ok">{adapterLabel(snapshot.write_adapter)}</span>
              : <span className="badge unknown">{t("none")}</span>}
          </Fact>
          {/* The routes are a count of their own, not a state of an
              interface: they stand here, not in the bar of link states. */}
          <Fact label={t("Routes")}>{snapshot?.unavailable_reason ? <span className="badge unknown">{t("unknown")}</span> : routes.length}</Fact>
          <Fact label={t("By kind")} wide>
            {kinds.length ? <Breakdown items={kinds.map(([kind, count]) => ({ label: kind, value: count }))} /> : "—"}
          </Fact>
        </Facts>
      </Section>

      <Section
        title={t("Interfaces")}
        count={visible.length}
        span={12}
        tools={
          <label className="toggle">
            <input
              type="checkbox"
              checked={all}
              onChange={(e) => setAll(e.target.checked)}
            />
            {t("Show virtual interfaces ({n} hidden)", { n: interfaces.length - visible.length })}
          </label>
        }
        flush
      >
        <Table>
          <thead>
            <tr>
              <th>{t("Interface")}</th><th>{t("Kind")}</th><th>{t("Layering")}</th><th>{t("State")}</th><th>{t("Addresses")}</th>
              <th className="hm-num">MTU</th><th>{t("Link")}</th><th>MAC</th><th>{t("Driver")}</th>{writable && <th>{t("Actions")}</th>}
            </tr>
          </thead>
          <tbody>
            {visible.map((iface) => (
              <tr key={iface.name} className={edited?.name === iface.name ? "selected" : undefined}>
                <td>
                  <span className="hm-mono hm-primary">{iface.name}</span>
                  {/* The management interface is the one the command came
                      through. Changing that one is changing the branch we sit
                      on. */}
                  {iface.management && <span className="badge"> {t("management")}</span>}
                </td>
                <td>{iface.kind || "—"}</td>
                {/* What the interface is made of, or what owns it. An
                    interface a layer owns has no addressing of its own
                    worth speaking of - the layer above carries it - and
                    changing it as if it had is how a bond comes apart by
                    accident. */}
                <td className="hm-mono">
                  {layerSummary(iface) || "—"}
                  {iface.master && layerKind(iface) === "" && (
                    <span className="source"> · {t("its address lives on {owner}", { owner: iface.master })}</span>
                  )}
                </td>
                {/* The state is the kernel's word. A loopback has no
                    carrier to report, so "unknown" is its normal state
                    and not a fault; the hover says so. */}
                <td>
                  <span
                    className={iface.oper_state === "up" ? "badge ok" : iface.oper_state === "down" ? "badge" : "badge unknown"}
                    title={iface.oper_state === "unknown" && iface.kind === "loopback"
                      ? t("The kernel reports no operational state for a loopback; this is its normal state.")
                      : t("The operational state as the kernel reports it.")}
                  >
                    {iface.oper_state}
                  </span>
                </td>
                <td className="hm-mono">
                  {(iface.addresses ?? []).length === 0
                    ? "—"
                    : (iface.addresses ?? []).map((address) => (
                        <div key={address.address}>
                          {address.address}
                          {!address.permanent && <span className="source"> · {t("temporary")}</span>}
                          {address.source && <span className="source"> · {address.source}</span>}
                        </div>
                      ))}
                </td>
                <td className="hm-num">{iface.mtu}</td>
                {/* An unknown carrier and an unknown speed stay unknown: a
                    missing value is not the same as a missing cable. */}
                <td>
                  {iface.carrier === undefined ? (
                    <span className="badge unknown">{t("unknown")}</span>
                  ) : iface.carrier ? (
                    iface.speed_mbps ? `${t("up")}, ${iface.speed_mbps} Mbps` : t("up")
                  ) : (
                    t("no carrier")
                  )}
                </td>
                <td className="hm-mono">{iface.mac || "—"}</td>
                <td>{iface.driver || "—"}</td>
                {/* Without a write mechanism there is nothing to edit: the
                    panel does not change a configuration the host will not
                    keep after a reboot. */}
                {writable && (
                  <td>
                    {access.anyAllowed && (
                      <button className="secondary" onClick={() => setEdited(iface)}>
                        {t("Change")}
                      </button>
                    )}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </Table>
      </Section>

      {edited && (
        <InterfaceChange
          hostID={host.id}
          iface={edited}
          management={edited.management}
          onIntent={setIntent}
          onCancel={() => setEdited(null)}
        />
      )}

      <Section
        title={t("Layering")}
        description={t("What sits on what: a bond joins links into one, a bridge puts them on one segment, a VLAN rides tagged on one of them. A layer takes the addressing of its members, so building one is a change of the same weight as rewriting an address.")}
        count={layers.length}
        span={12}
        tools={writable ? (
          <ActionGuard action="network.link.apply" host={host.id}>
            <button className="secondary" onClick={() => setBuilding((open) => !open)}>
              {building ? t("Cancel") : t("Build a layer")}
            </button>
          </ActionGuard>
        ) : undefined}
        flush
      >
        {!layers.length ? (
          <Empty>{t("This host reports no bond, bridge or VLAN.")}</Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>{t("Interface")}</th><th>{t("Kind")}</th><th>{t("Members")}</th>
                <th>{t("Settings")}</th><th>{t("State")}</th>{writable && <th>{t("Actions")}</th>}
              </tr>
            </thead>
            <tbody>
              {layers.map((iface) => (
                <tr key={iface.name}>
                  <td>
                    <span className="hm-mono hm-primary">{iface.name}</span>
                    {iface.management && <span className="badge"> {t("management")}</span>}
                  </td>
                  <td>{layerKind(iface)}</td>
                  <td className="hm-mono">
                    {iface.vlan
                      ? t("on {parent}", { parent: iface.vlan.parent || "—" })
                      : layerMembers(iface).length === 0
                        ? "—"
                        : layerMembers(iface).map((member) => {
                            // The driver's own word about the member. An
                            // absent entry is not "down": it is a member the
                            // driver said nothing about.
                            const state = iface.bond?.member_states?.[member] ?? "";
                            const carrying = iface.bond?.active_member === member;
                            return (
                              <div key={member}>
                                {member}
                                {state !== "" && <span className="source"> · {state}</span>}
                                {carrying && <span className="badge ok"> {t("carrying")}</span>}
                              </div>
                            );
                          })}
                  </td>
                  <td>{layerSettings(iface, t)}</td>
                  <td>
                    <span className={iface.oper_state === "up" ? "badge ok" : "badge"}>{iface.oper_state}</span>
                    {/* A bond that failed over is a bond running on its
                        spare: the operator asks this page exactly that. */}
                    {iface.bond?.primary && iface.bond.active_member &&
                      iface.bond.active_member !== iface.bond.primary && (
                        <span className="badge warn"> {t("failed over")}</span>
                      )}
                  </td>
                  {writable && (
                    <td>
                      <ActionGuard action="network.link.remove" host={host.id}>
                        <button
                          className="secondary"
                          onClick={() =>
                            setIntent({
                              action: "network.link.remove",
                              label: t("Remove {iface}", { iface: iface.name }),
                              description: t("{iface} is taken away and {members} go back to carrying their own traffic. The host rolls the removal back unless the agent proves it can still reach the panel.", {
                                iface: iface.name,
                                members: layerMembers(iface).join(", ") || t("nothing"),
                              }),
                              payload: { network: { interface: iface.name, rollback_seconds: 120 } },
                            })
                          }
                        >
                          {t("Remove")}
                        </button>
                      </ActionGuard>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>

      {building && writable && (
        <LayerBuild
          hostID={host.id}
          interfaces={interfaces}
          onIntent={setIntent}
          onCancel={() => setBuilding(false)}
        />
      )}

      <Section title={t("Routes")} count={routes.length} span={12} flush>
        {!routes.length ? (
          <Empty>{t("No routes reported.")}</Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>{t("Destination")}</th><th>{t("Gateway")}</th><th>{t("Interface")}</th>
                <th>{t("Source")}</th><th>{t("Protocol")}</th><th className="hm-num">{t("Metric")}</th><th>{t("Family")}</th>
              </tr>
            </thead>
            <tbody>
              {routes.map((route, i) => (
                <tr key={`${route.family}-${route.destination}-${route.interface}-${i}`}>
                  <td className="hm-mono">{route.destination}</td>
                  <td className="hm-mono">{route.gateway || "—"}</td>
                  <td className="hm-mono">{route.interface || "—"}</td>
                  <td className="hm-mono">{route.source || "—"}</td>
                  <td title={route.protocol || undefined}>{t(routeProtocolWords(route.protocol))}</td>
                  <td className="hm-num">{route.metric}</td>
                  <td>{route.family === "inet6" ? "IPv6" : "IPv4"}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
        <Foot>
          <span>
            {t("Management channel")}: {snapshot?.management_interface || t("unknown")}
            {snapshot?.management_address && ` · ${snapshot.management_address}`}
            {snapshot?.write_adapter && ` · ${t("write adapter {name}", { name: adapterLabel(snapshot.write_adapter) })}`}
          </span>
          {snapshot?.observed_at && (
            <span>
              {t("read")} <Time value={snapshot.observed_at} />
            </span>
          )}
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

/**
 * The interface change form.
 *
 * Every change is armed with a rollback on the host side: if the agent does
 * not confirm connectivity after the change, the host returns to the
 * previous configuration by itself. That is why the form asks for the
 * rollback window instead of hiding it as a detail.
 */
function InterfaceChange({
  hostID, iface, management, onIntent, onCancel,
}: {
  hostID: string;
  iface: Interface;
  management: boolean;
  onIntent: (intent: Intent) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const [mtu, setMtu] = useState(String(iface.mtu));
  const [method, setMethod] = useState<"auto" | "manual">("manual");
  const [addresses, setAddresses] = useState(
    (iface.addresses ?? [])
      .filter((address) => address.family === "inet")
      .map((address) => address.address)
      .join(", "),
  );
  const [gateway, setGateway] = useState("");
  const [dns, setDns] = useState("");
  const [routes, setRoutes] = useState("");
  const [window, setWindow] = useState("120");
  // The second family is asked separately, because it is a separate
  // decision: a host can take its IPv4 address from DHCP and hold a static
  // IPv6 one at the same time. Left alone, it keeps what the host has.
  const [method6, setMethod6] = useState("");
  const [addresses6, setAddresses6] = useState(
    (iface.addresses ?? [])
      .filter((address) => address.family === "inet6")
      .map((address) => address.address)
      .join(", "),
  );
  const [gateway6, setGateway6] = useState("");
  const [acceptRA, setAcceptRA] = useState("");
  const [privacy, setPrivacy] = useState("");
  const ipv6Off = iface.ipv6?.disabled === true;

  const list = (value: string) =>
    value.split(",").map((element) => element.trim()).filter(Boolean);
  const seconds = Number(window) || 0;

  return (
    <Section
      title={t("Change {iface}", { iface: iface.name })}
      description={t("The host arms a rollback before it applies anything and cancels it only after the agent proves it can still reach the panel.")}
      tools={<button className="secondary" onClick={onCancel}>{t("Cancel")}</button>}
      span={12}
    >
      {/* Changing the management interface is changing the branch we sit
          on: the operator is to read this before, not see it after. */}
      {management && (
        <p className="warning" style={{ margin: 0 }}>
          <span>
            {t("This is the interface the panel talks to. If the change breaks it, the host will roll back on its own after the rollback window — but until then it is unreachable, and no further command will arrive.")}
          </span>
        </p>
      )}
      <Form>
        <Fields>
          <Field label={t("Rollback window (seconds, 30–900)")} narrow>
            <input value={window} onChange={(e) => setWindow(e.target.value)} />
          </Field>
        </Fields>

        <Fields>
          <Field label="MTU" narrow>
            <input value={mtu} onChange={(e) => setMtu(e.target.value)} placeholder={t("MTU or auto")} />
          </Field>
        </Fields>
        <FormActions>
          <ActionGuard action="network.mtu.set" host={hostID}>
            <button
              onClick={() =>
                onIntent({
                  action: "network.mtu.set",
                  label: t("Set MTU on {iface}", { iface: iface.name }),
                  description: t("{iface} will use MTU {mtu}. The host rolls back after {seconds}s unless the agent confirms connectivity.", { iface: iface.name, mtu, seconds }),
                  payload: {
                    network: { interface: iface.name, mtu, rollback_seconds: seconds },
                  },
                })
              }
              disabled={!mtu}
            >
              {t("Set MTU")}
            </button>
          </ActionGuard>
        </FormActions>

        <Fields>
          <Field label={t("Routes")} wide>
            <input
              value={routes}
              onChange={(e) => setRoutes(e.target.value)}
              placeholder={t("Routes, e.g. 10.0.0.0/8 192.168.56.1, 172.16.0.0/12")}
            />
          </Field>
        </Fields>
        <FormActions>
          <ActionGuard action="network.route.ensure" host={hostID}>
            <button
              onClick={() =>
                onIntent({
                  action: "network.route.ensure",
                  label: t("Replace routes on {iface}", { iface: iface.name }),
                  description: t("{iface} will carry exactly these routes: {routes}. Routes not listed here are removed from the profile.", {
                    iface: iface.name, routes: list(routes).join("; ") || t("none"),
                  }),
                  payload: {
                    network: {
                      interface: iface.name,
                      routes: list(routes),
                      rollback_seconds: seconds,
                    },
                  },
                })
              }
            >
              {t("Replace routes")}
            </button>
          </ActionGuard>
        </FormActions>

        <Fields>
          <Field label={t("Addresses")}>
            <select value={method} onChange={(e) => setMethod(e.target.value as "auto" | "manual")}>
              <option value="manual">{t("static addresses")}</option>
              <option value="auto">DHCP</option>
            </select>
          </Field>
          <Field label={t("Addresses")}>
            <input
              value={addresses}
              onChange={(e) => setAddresses(e.target.value)}
              placeholder={t("Addresses with masks, e.g. 192.168.56.30/24")}
              disabled={method === "auto"}
            />
          </Field>
          <Field label={t("Gateway")}>
            <input value={gateway} onChange={(e) => setGateway(e.target.value)} placeholder={t("Gateway")} disabled={method === "auto"} />
          </Field>
          <Field label={t("DNS servers")}>
            <input value={dns} onChange={(e) => setDns(e.target.value)} placeholder={t("DNS servers")} disabled={method === "auto"} />
          </Field>
        </Fields>
        {/* The second family, held to the same standard as the first: its
            own method, its own addresses with prefix lengths, and a
            gateway that may be link-local, because that is how an IPv6
            router ordinarily announces itself. */}
        <Fields>
          <Field label={t("IPv6")}>
            <select value={method6} onChange={(e) => setMethod6(e.target.value)} disabled={ipv6Off}>
              <option value="">{t("leave as it is")}</option>
              <option value="auto">{t("from the network")}</option>
              <option value="manual">{t("static addresses")}</option>
              <option value="disabled">{t("no IPv6 here")}</option>
            </select>
          </Field>
          <Field label={t("IPv6 addresses")}>
            <input
              value={addresses6}
              onChange={(e) => setAddresses6(e.target.value)}
              placeholder={t("Addresses with prefix lengths, e.g. 2001:db8::5/64")}
              disabled={ipv6Off || method6 !== "manual"}
            />
          </Field>
          <Field label={t("IPv6 gateway")}>
            <input
              value={gateway6}
              onChange={(e) => setGateway6(e.target.value)}
              placeholder="fe80::1"
              disabled={ipv6Off || method6 === "" || method6 === "disabled"}
            />
          </Field>
          <Field label={t("Router advertisements")}>
            <select value={acceptRA} onChange={(e) => setAcceptRA(e.target.value)} disabled={ipv6Off}>
              <option value="">{t("leave as it is")} ({t(acceptRAWords(iface.ipv6?.accept_ra))})</option>
              <option value="off">{t("ignored")}</option>
              <option value="on">{t("accepted")}</option>
              <option value="on-forwarding">{t("accepted, even while forwarding")}</option>
            </select>
          </Field>
          <Field label={t("Privacy extensions")}>
            <select value={privacy} onChange={(e) => setPrivacy(e.target.value)} disabled={ipv6Off}>
              <option value="">{t("leave as it is")} ({t(privacyWords(iface.ipv6?.privacy))})</option>
              <option value="off">{t("off")}</option>
              <option value="prefer-public">{t("public preferred")}</option>
              <option value="prefer-temporary">{t("temporary preferred")}</option>
            </select>
          </Field>
        </Fields>
        {/* A host with the family switched off would take every IPv6
            setting and report none of them back. The panel says so instead
            of offering the fields. */}
        {ipv6Off && (
          <p className="warning" style={{ margin: 0 }}>
            <span>{t("IPv6 is switched off on {iface}, so nothing written there would take effect. That is a kernel setting, not a profile one.", { iface: iface.name })}</span>
          </p>
        )}
        <FormActions>
          <ActionGuard action="network.profile.apply" host={hostID}>
            <button
              onClick={() =>
                onIntent({
                  action: "network.profile.apply",
                  label: t("Apply address profile to {iface}", { iface: iface.name }),
                  description:
                    method === "auto"
                      ? t("{iface} will take its address from DHCP. Its current address is dropped.", { iface: iface.name })
                      : t("{iface} will use {addresses}{gateway}. Addresses not listed here are removed.", {
                          iface: iface.name,
                          addresses: [...list(addresses), ...(method6 === "manual" ? list(addresses6) : [])].join(", "),
                          gateway: gateway ? ` ${t("via {gateway}", { gateway })}` : "",
                        }),
                  payload: {
                    network: {
                      interface: iface.name,
                      method,
                      addresses: method === "auto" ? [] : list(addresses),
                      gateway: method === "auto" ? "" : gateway,
                      dns: method === "auto" ? [] : list(dns),
                      // A family the order says nothing about keeps what
                      // the host has, down to its routes.
                      method6,
                      addresses6: method6 === "manual" ? list(addresses6) : [],
                      gateway6: method6 === "" || method6 === "disabled" ? "" : gateway6,
                      accept_ra: acceptRA,
                      privacy,
                      rollback_seconds: seconds,
                    },
                  },
                })
              }
              disabled={method === "manual" && list(addresses).length === 0}
            >
              {t("Apply profile")}
            </button>
          </ActionGuard>
        </FormActions>
      </Form>
    </Section>
  );
}

/**
 * The form that builds a bond, a bridge or a VLAN.
 *
 * The refusals are named here before the order is ever sent, not because
 * the panel is the authority - the host is, and it checks every one of them
 * again against its own layering - but because an operator about to fold
 * three interfaces into a bond should not learn from a failed job that one
 * of them already belongs to somebody else.
 */
function LayerBuild({
  hostID, interfaces, onIntent, onCancel,
}: {
  hostID: string;
  interfaces: Interface[];
  onIntent: (intent: Intent) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const [name, setName] = useState("");
  const [kind, setKind] = useState<"bond" | "bridge" | "vlan">("bond");
  const [members, setMembers] = useState("");
  const [mode, setMode] = useState("active-backup");
  const [monitoring, setMonitoring] = useState("100");
  const [primary, setPrimary] = useState("");
  const [lacpRate, setLacpRate] = useState("");
  const [stp, setStp] = useState(false);
  const [parent, setParent] = useState("");
  const [vlanID, setVlanID] = useState("");
  const [window, setWindow] = useState("120");

  const chosen = members.split(",").map((element) => element.trim()).filter(Boolean);
  const seconds = Number(window) || 0;
  const byName = new Map<string, Interface>(interfaces.map((iface) => [iface.name, iface]));
  // The lower interfaces are the host's own: an interface is called
  // whatever the host calls it - enp2s0, ens192, eno1np0 - so the form
  // offers the names this host reports rather than an example that would
  // be wrong on most machines.
  const lower = interfaces.filter((iface) => iface.name !== "lo").map((iface) => iface.name);

  // The refusals, in the order the questions come: is the name free, is the
  // lower interface there, is the layer worth building, and would it take
  // the interface the panel itself comes through.
  const problems: string[] = [];
  if (name === "") problems.push(t("Name the layer the host is to carry."));
  if (byName.has(name)) {
    problems.push(t("The host already has an interface called {name}; the panel does not turn it into a {kind} under the same name.", { name, kind }));
  }
  if (kind === "vlan") {
    const owner = byName.get(parent);
    if (parent === "") problems.push(t("Name the interface the tagged traffic runs on."));
    else if (!owner) problems.push(t("The host does not report the interface {name}.", { name: parent }));
    else if (owner.master) {
      problems.push(t("The parent {name} is a member of {owner}; a VLAN belongs on the layer above.", { name: parent, owner: owner.master }));
    }
    const tag = Number(vlanID);
    if (!Number.isInteger(tag) || tag < 1 || tag > 4094) {
      problems.push(t("The VLAN identifier lies between 1 and 4094."));
    }
  } else {
    if (kind === "bond" && chosen.length < 2) {
      problems.push(t("A bond carries traffic over at least two members; with one it is the same link with a driver in between."));
    }
    for (const member of chosen) {
      const link = byName.get(member);
      if (!link) {
        problems.push(t("The host does not report the interface {name}.", { name: member }));
        continue;
      }
      if (link.management) {
        problems.push(t("{name} is the interface the panel talks to this host over; a layer would take its address and the host would be unreachable before the change finished.", { name: member }));
      }
      if (link.master && link.master !== name) {
        problems.push(t("{name} is already a member of {owner}; taking it would stop whatever runs over that layer.", { name: member, owner: link.master }));
      }
    }
    if (primary !== "" && !chosen.includes(primary)) {
      problems.push(t("The primary member has to be one of the members."));
    }
    if (lacpRate !== "" && mode !== "802.3ad") {
      problems.push(t("The LACP rate belongs to the mode 802.3ad and to no other."));
    }
  }

  const link: Record<string, unknown> = { name, kind };
  if (kind === "vlan") {
    link.parent = parent;
    link.vlan_id = Number(vlanID) || 0;
  } else {
    link.members = chosen;
    if (kind === "bond") {
      link.mode = mode;
      // Zero travels as it is: a bond that does not watch its members is a
      // decision, and a field left out would let the host fill in a default
      // the operator never saw.
      link.miimon_ms = Number(monitoring) || 0;
      if (primary !== "") link.primary = primary;
      if (lacpRate !== "") link.lacp_rate = lacpRate;
    }
    if (kind === "bridge" && stp) link.stp = true;
  }

  return (
    <Section
      title={t("Build a layer")}
      description={t("The host computes its own plan first and refuses what would not hold: a member another layer owns, a bond of one member, a VLAN on a parent it does not have, or a layer that would swallow the interface the panel talks over.")}
      tools={<button className="secondary" onClick={onCancel}>{t("Cancel")}</button>}
      span={12}
    >
      <Form>
        <Fields>
          <Field label={t("Name")} narrow>
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder={`${kind}0`} />
          </Field>
          <Field label={t("Kind")} narrow>
            <select value={kind} onChange={(e) => setKind(e.target.value as "bond" | "bridge" | "vlan")}>
              <option value="bond">{t("Bond")}</option>
              <option value="bridge">{t("Bridge")}</option>
              <option value="vlan">VLAN</option>
            </select>
          </Field>
          <Field label={t("Rollback window (seconds, 30–900)")} narrow>
            <input value={window} onChange={(e) => setWindow(e.target.value)} />
          </Field>
        </Fields>

        {kind === "vlan" ? (
          <Fields>
            <Field label={t("Parent")}>
              <select value={parent} onChange={(e) => setParent(e.target.value)}>
                <option value="">{t("Pick the interface the host reports")}</option>
                {lower.map((option) => <option key={option} value={option}>{option}</option>)}
              </select>
            </Field>
            <Field label={t("VLAN identifier")} narrow>
              <input value={vlanID} onChange={(e) => setVlanID(e.target.value)} placeholder="100" />
            </Field>
          </Fields>
        ) : (
          <Fields>
            <Field label={t("Members")} wide>
              <input
                value={members}
                onChange={(e) => setMembers(e.target.value)}
                list="layer-members"
                placeholder={t("Interfaces of this host, separated by commas")}
              />
              <datalist id="layer-members">
                {lower.map((option) => <option key={option} value={option} />)}
              </datalist>
            </Field>
          </Fields>
        )}

        {kind === "bond" && (
          <Fields>
            <Field label={t("Mode")}>
              <select value={mode} onChange={(e) => setMode(e.target.value)}>
                {["active-backup", "802.3ad", "balance-rr", "balance-xor", "broadcast", "balance-tlb", "balance-alb"]
                  .map((option) => <option key={option} value={option}>{option}</option>)}
              </select>
            </Field>
            <Field label={t("Link monitoring (ms, 0 switches it off)")} narrow>
              <input value={monitoring} onChange={(e) => setMonitoring(e.target.value)} />
            </Field>
            <Field label={t("Primary member")}>
              <select value={primary} onChange={(e) => setPrimary(e.target.value)}>
                <option value="">{t("The driver's own choice")}</option>
                {chosen.map((option) => <option key={option} value={option}>{option}</option>)}
              </select>
            </Field>
            <Field label={t("LACP rate")} narrow>
              <select value={lacpRate} onChange={(e) => setLacpRate(e.target.value)}>
                <option value="">{t("the driver's own")}</option>
                <option value="slow">slow</option>
                <option value="fast">fast</option>
              </select>
            </Field>
          </Fields>
        )}

        {kind === "bridge" && (
          <Fields>
            <Field label={t("Spanning tree")}>
              <label className="toggle">
                <input type="checkbox" checked={stp} onChange={(e) => setStp(e.target.checked)} />
                {t("Keep a loop between switches from flooding the segment")}
              </label>
            </Field>
          </Fields>
        )}

        {problems.length > 0 && (
          <p className="warning" style={{ margin: 0 }}>
            <span>{problems[0]}</span>
          </p>
        )}

        <FormActions>
          <ActionGuard action="network.link.apply" host={hostID}>
            <button
              onClick={() =>
                onIntent({
                  action: "network.link.apply",
                  label: t("Build {kind} {name}", { kind, name }),
                  description: kind === "vlan"
                    ? t("{name} will carry the tag {tag} on {parent}. The host rolls it back after {seconds}s unless the agent confirms connectivity.", { name, tag: vlanID, parent, seconds })
                    : t("{name} will be built from {members}. Those interfaces lose their own addressing to it. The host rolls it back after {seconds}s unless the agent confirms connectivity.", { name, members: chosen.join(", "), seconds }),
                  payload: { network: { interface: name, link, rollback_seconds: seconds } },
                })
              }
              disabled={problems.length > 0}
            >
              {t("Build")}
            </button>
          </ActionGuard>
        </FormActions>
      </Form>
    </Section>
  );
}

/**
 * An interface is relevant when the operator may ask about it: physical,
 * with an address or being the management channel. The rest are veths and
 * container bridges that would obscure the picture.
 */
function relevant(iface: Interface): boolean {
  if (iface.management) return true;
  if (iface.kind === "veth") return false;
  if (iface.name.startsWith("br-") || iface.name.startsWith("veth")) return false;
  // A layer and the interfaces it owns always mean something: a member has
  // given its addressing away, and an operator who cannot see that will
  // wonder why the card has no address.
  if (layerKind(iface) !== "" || iface.master) return true;
  return (iface.addresses ?? []).length > 0 || iface.kind === "ethernet";
}
