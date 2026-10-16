import { useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../../lib/api";
import { useAllowed, useModuleAccess } from "../../../lib/actions";
import { emptyForm, operationForm, type FormProblem, type FormValue } from "../../../lib/operations";
import { relativeTime, absoluteTime } from "../../../lib/format";
import type { Host, InventoryFragment, Job } from "../../../lib/types";
import { useT, type Translate } from "../../../i18n";
import { Board } from "../../Board";
import type { BoardEntry } from "../../../components/board";
import {
  Banner, Bars, Bones, Button, Card, Check, Empty, Fact, Facts, Field, Fields, Kpi, Modal, Note,
  Pill, Problem, Stack, Table, Toolbar, type Segment,
} from "../../kit";

/**
 * The host's network: what the kernel has up, what it is addressed with,
 * and what the panel may change about it.
 *
 * Everything on this screen is read from the kernel rather than from a
 * configuration file - what a host has up and what somebody once wrote
 * into a config can differ, and only the first one carries traffic. Every
 * change here can cut the panel off from the machine, so every one of them
 * is armed with a rollback the host cancels only after the agent proves it
 * can still be reached, and every one of them is confirmed by name first.
 */

type Address = {
  family: string;
  address: string;
  scope: string;
  source?: string;
  permanent: boolean;
};

/** What the host reports about a bond. */
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

type BridgePortVLAN = { port: string; vid: number; pvid?: boolean; untagged?: boolean };

type BridgeDetails = {
  members?: string[];
  stp: boolean;
  vlan_filtering: boolean;
  vlan_protocol?: string;
  vlans?: BridgePortVLAN[];
};

type VLANDetails = { parent?: string; id: number; protocol?: string };

/** The kernel's own switches for the second family. */
type IPv6Settings = { disabled?: boolean; accept_ra?: number; privacy?: number };

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
  read_only_reason?: string;
  /** Set when the host has the second family switched off everywhere. */
  ipv6_disabled?: boolean;
  /** Why the bonds, bridges and VLANs could not be read. */
  layering_unavailable_reason?: string;
  observed_at?: string;
  unavailable_reason?: string;
};

type Intent = {
  action: string;
  label: string;
  description: string;
  payload: Record<string, unknown>;
};

/* ------------------------------------------------------- the registry */

/** One order as the registry composes it: what would be sent, and what is wrong with it. */
export type RegistryOrder = {
  action: string;
  payload: Record<string, unknown>;
  problems: FormProblem[];
};

/**
 * Puts an order through the registry entry of its action, so this screen
 * and the Bulk workspace send one payload and refuse one set of values.
 */
export function registryOrder(action: string, seed: FormValue): RegistryOrder {
  const entry = operationForm(action);
  if (!entry) {
    return {
      action,
      payload: {},
      problems: [{ message: "The registry has no form for {action} yet.", params: { action } }],
    };
  }
  const form = { ...emptyForm(entry), ...seed };
  return { action, payload: entry.toPayload(form), problems: entry.validate(form) };
}

/** Whether the registry would take this order as it stands. */
export function orderReady(order: RegistryOrder): boolean {
  return order.problems.length === 0;
}

/** The first refusal of an order as a sentence, or an empty string. */
export function refusalOf(t: Translate, order: RegistryOrder): string {
  const problem = order.problems[0];
  return problem ? t(problem.message, problem.params) : "";
}

/** The shortest reason the API takes for a change of this weight. */
export const MIN_REASON_LENGTH = 8;

/* --------------------------------------------------------- the words */

/** The write adapters as the host names them, in the spelling the operator knows. */
const ADAPTER_LABELS: Record<string, string> = {
  networkmanager: "NetworkManager",
  nmstate: "nmstate",
  netplan: "netplan",
};

/** The label of a write adapter; an unknown name is shown as the host sent it. */
export function adapterLabel(adapter: string): string {
  return ADAPTER_LABELS[adapter] ?? adapter;
}

/** The origin of a route in words. */
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

/** The settings of a layer, each kind in its own terms. */
export function layerSettings(iface: Interface, t: Translate): string {
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

/**
 * An interface is relevant when the operator may ask about it: physical,
 * with an address, or being the management channel.
 */
export function relevant(iface: Interface): boolean {
  if (iface.management) return true;
  if (iface.kind === "veth") return false;
  if (iface.name.startsWith("br-") || iface.name.startsWith("veth")) return false;
  // A layer and the interfaces it owns always mean something: a member has
  // given its addressing away, and an operator who cannot see that will
  // wonder why the card has no address.
  if (layerKind(iface) !== "" || iface.master) return true;
  return (iface.addresses ?? []).length > 0 || iface.kind === "ethernet";
}

/** A count of the items that satisfy a test, or undefined when the list itself is unknown. */
export function countWhere<T>(items: T[] | undefined, test: (item: T) => boolean): number | undefined {
  return items === undefined ? undefined : items.filter(test).length;
}

/* -------------------------------------------------------- the orders */

/** The rollback window a change ordered from a row carries. */
export const ROW_ROLLBACK_SECONDS = 120;

/** The size of the frames one interface carries, as an order. */
export function mtuOrder(iface: string, mtu: string, rollbackSeconds: number): RegistryOrder {
  return registryOrder("network.mtu.set", { interface: iface, mtu, rollback_seconds: rollbackSeconds });
}

/** The routes one interface is to carry, as an order. */
export function routesOrder(iface: string, routes: string[], rollbackSeconds: number): RegistryOrder {
  // The registry reads a list one entry per line; the field here is one
  // comma-separated line.
  return registryOrder("network.route.ensure", {
    interface: iface, routes: routes.join("\n"), rollback_seconds: rollbackSeconds,
  });
}

/** Taking a bond, a bridge or a VLAN away, as an order. */
export function layerRemoveOrder(iface: string, rollbackSeconds: number): RegistryOrder {
  return registryOrder("network.link.remove", { interface: iface, rollback_seconds: rollbackSeconds });
}

/** The changes this screen offers; when every one is refused, it says so once. */
export const NETWORK_CHANGES = [
  "network.mtu.set", "network.route.ensure", "network.profile.apply",
  "network.link.apply", "network.link.remove",
];

/* --------------------------------------------------------- the guard */

/**
 * A control that is drawn only where the order it places would be taken.
 *
 * The verdict is the server's own preview of what this operator may do on
 * this host: a viewer sees no button at all, rather than learning about a
 * missing permission from a refusal.
 */
function Allowed({ host, action, children }: { host: string; action: string; children: ReactNode }) {
  const verdict = useAllowed(host, action);
  return verdict.allowed ? <>{children}</> : null;
}

/* -------------------------------------------------------- the screen */

export function Network({ host }: { host: Host }) {
  const t = useT();
  const queryClient = useQueryClient();
  const access = useModuleAccess(host.id, NETWORK_CHANGES);

  const module = useQuery({
    queryKey: ["inventory", host.id, "network"],
    queryFn: () => api.get<InventoryFragment<Snapshot>>(`/api/v1/hosts/${host.id}/inventory/network`),
    retry: false,
  });

  const [intent, setIntent] = useState<Intent | null>(null);
  const [message, setMessage] = useState("");
  const [edited, setEdited] = useState<Interface | null>(null);
  const [building, setBuilding] = useState(false);
  // A host with docker has a dozen virtual interfaces and only some of
  // them mean anything. By default we show the ones that do.
  const [all, setAll] = useState(false);

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
      void queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  if (module.isLoading) return <Bones rows={5} />;
  if (!module.data) return <Empty>{t("This host has not reported its network state yet.")}</Empty>;

  const snapshot = module.data.payload;
  // Without a write adapter no row has an action; a column of greyed
  // buttons would only repeat the warning above the table.
  const writable = !!snapshot?.write_adapter;
  const interfaces = snapshot?.interfaces ?? [];
  const visible = all ? interfaces : interfaces.filter(relevant);
  const routes = snapshot?.routes ?? [];
  // The layers are their own list: an operator asking about a bond is not
  // asking which network cards the host has.
  const layers = interfaces.filter((iface) => layerKind(iface) !== "");
  // An unread snapshot has nothing to count: a dash, never a nought.
  const known = snapshot?.unavailable_reason ? undefined : interfaces;
  const kinds = Object.entries(interfaces.reduce<Record<string, number>>((into, iface) => {
    const kind = iface.kind || t("unknown");
    into[kind] = (into[kind] ?? 0) + 1;
    return into;
  }, {})).sort((a, b) => b[1] - a[1]).slice(0, 6);

  const states: Segment[] = [
    { label: t("up"), value: countWhere(known, (iface) => iface.oper_state === "up"), tone: "ok" },
    { label: t("down"), value: countWhere(known, (iface) => iface.oper_state === "down"), tone: "neutral" },
    {
      label: t("other"),
      value: countWhere(known, (iface) => iface.oper_state !== "up" && iface.oper_state !== "down"),
      tone: "unknown",
    },
  ];

  const notices: ReactNode[] = [];
  if (snapshot?.unavailable_reason) {
    notices.push(
      <Banner key="unread" tone="error">
        {t("Network state could not be read: {reason}", { reason: snapshot.unavailable_reason })}
      </Banner>,
    );
  }
  // A missing write mechanism is an answer, not a failure: the module
  // works, only read-only, and says why.
  if (!snapshot?.write_adapter) {
    notices.push(
      <Banner key="readonly" tone="info">
        {snapshot?.read_only_reason
          ? t("Read-only on this host: {reason}", { reason: snapshot.read_only_reason })
          : t("Read-only on this host: no NetworkManager, nmstate or netplan, so the panel will not change its network configuration.")}
      </Banner>,
    );
  }
  // The layering read failing is not the absence of layers: a plan
  // computed against silence would happily take a member another bond
  // already owns.
  if (snapshot?.layering_unavailable_reason) {
    notices.push(
      <Banner key="layering" tone="warn">
        {t("Bonds, bridges and VLANs could not be read: {reason}. The addresses are still what the host reports.", { reason: snapshot.layering_unavailable_reason })}
      </Banner>,
    );
  }
  if (snapshot?.ipv6_disabled) {
    notices.push(
      <Banner key="ipv6" tone="warn">
        {t("This host has IPv6 switched off for every interface. An IPv6 address, route or router advertisement setting ordered here would never take effect, and the host refuses it rather than writing it into the void.")}
      </Banner>,
    );
  }
  // When every change is refused the screen says so once, rather than
  // quietly losing its buttons.
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
          onConfirm={(reason) => request.mutate({ action: intent.action, reason, payload: intent.payload })}
          onCancel={() => setIntent(null)}
        />
      )}
      <Board screen={NETWORK_SCREEN} catalogue={NETWORK_BOARD} notices={notices.length > 0 ? <Stack>{notices}</Stack> : undefined} drawn={{
        up: (
          <Kpi
            hero
            icon="network"
            label={t("Interfaces up")}
            value={countWhere(known, (iface) => iface.oper_state === "up") ?? null}
            note={known === undefined ? undefined : t("of {n} the kernel lists", { n: interfaces.length })}
          />
        ),
        addressed: (
          <Kpi
            icon="network"
            label={t("Interfaces with an address")}
            value={countWhere(known, (iface) => (iface.addresses ?? []).length > 0) ?? null}
          />
        ),
        routecount: (
          <Kpi
            icon="dashboard"
            label={t("Routes")}
            value={snapshot?.unavailable_reason ? null : routes.length}
          />
        ),
        adapter: (
          <Kpi
            icon="settings"
            label={t("Write adapter")}
            value={snapshot?.write_adapter ? adapterLabel(snapshot.write_adapter) : null}
            tone={snapshot?.write_adapter ? "ok" : undefined}
            note={snapshot?.write_adapter ? undefined : t("the panel will not change this host's network")}
          />
        ),
        states: (
          <Card
            title={t("Interfaces by state")}
            note={t("Every interface the kernel lists, by its operational state.")}
          >
            <Bars items={states.map((one) => ({
              label: one.label,
              value: one.value ?? 0,
              tone: one.value === undefined ? "unknown" : one.tone,
            }))} />
            {known === undefined && <Note>{t("Nothing was counted: the snapshot could not be read.")}</Note>}
          </Card>
        ),
        channel: (
          <Card title={t("Management channel")}>
            <Facts>
              <Fact label={t("Interface")}>
                {snapshot?.management_interface
                  ? <span className="fl-mono">{snapshot.management_interface}</span>
                  : <Pill tone="unknown">{t("unknown")}</Pill>}
              </Fact>
              <Fact label={t("Address")}>
                {snapshot?.management_address
                  ? <span className="fl-mono">{snapshot.management_address}</span>
                  : <span className="fl-faint">—</span>}
              </Fact>
              <Fact label={t("Write adapter")}>
                {snapshot?.write_adapter
                  ? <Pill tone="ok">{adapterLabel(snapshot.write_adapter)}</Pill>
                  : <Pill tone="unknown">{t("none")}</Pill>}
              </Fact>
              <Fact label={t("Routes")}>
                {snapshot?.unavailable_reason ? <Pill tone="unknown">{t("unknown")}</Pill> : routes.length}
              </Fact>
              <Fact label={t("By kind")}>
                {kinds.length
                  ? <Bars items={kinds.map(([kind, count]) => ({ label: kind, value: count }))} />
                  : <span className="fl-faint">—</span>}
              </Fact>
            </Facts>
          </Card>
        ),
        interfaces: (
          <Card title={t("Interfaces")} flush>
            <Toolbar end={<span className="fl-note">{t("{n} shown", { n: visible.length })}</span>}>
              <Check checked={all} onChange={setAll}>
                {t("Show virtual interfaces ({n} hidden)", { n: interfaces.length - visible.length })}
              </Check>
            </Toolbar>
            <Table
              testId="interfaces"
              rows={visible}
              keyOf={(one) => one.name}
              rowTestId={(one) => `interface-${one.name}`}
              empty={t("The kernel lists no interface here.")}
              columns={[
                { key: "name", head: t("Interface"), cell: (one) => (
                  <Stack>
                    <span className="fl-mono">{one.name}</span>
                    {/* The management interface is the one the command came
                        through: changing it is changing the branch we sit on. */}
                    {one.management && <Pill tone="info">{t("management")}</Pill>}
                  </Stack>
                ) },
                { key: "kind", head: t("Kind"), cell: (one) => one.kind || <span className="fl-faint">—</span> },
                // What the interface is made of, or what owns it. An
                // interface a layer owns has no addressing of its own worth
                // speaking of, and changing it as if it had is how a bond
                // comes apart by accident.
                { key: "layering", head: t("Layering"), tight: true, cell: (one) => (
                  <Stack>
                    <span className="fl-mono">{layerSummary(one) || "—"}</span>
                    {one.master && layerKind(one) === "" && (
                      <span className="fl-faint">{t("its address lives on {owner}", { owner: one.master })}</span>
                    )}
                  </Stack>
                ) },
                // The state is the kernel's word. A loopback has no carrier
                // to report, so "unknown" is its normal state, not a fault.
                { key: "state", head: t("State"), cell: (one) => (
                  <Pill
                    tone={one.oper_state === "up" ? "ok" : one.oper_state === "down" ? "neutral" : "unknown"}
                    title={one.oper_state === "unknown" && one.kind === "loopback"
                      ? t("The kernel reports no operational state for a loopback; this is its normal state.")
                      : t("The operational state as the kernel reports it.")}
                  >
                    {one.oper_state}
                  </Pill>
                ) },
                { key: "addresses", head: t("Addresses"), cell: (one) => (
                  (one.addresses ?? []).length === 0
                    ? <span className="fl-faint">—</span>
                    : (
                      <Stack>
                        {(one.addresses ?? []).map((address) => (
                          <span key={address.address} className="fl-mono">
                            {address.address}
                            {!address.permanent && <span className="fl-faint"> · {t("temporary")}</span>}
                            {address.source && <span className="fl-faint"> · {address.source}</span>}
                          </span>
                        ))}
                      </Stack>
                    )
                ) },
                { key: "mtu", head: "MTU", num: true, cell: (one) => one.mtu },
                // An unknown carrier and an unknown speed stay unknown: a
                // missing value is not the same as a missing cable.
                { key: "link", head: t("Link"), cell: (one) => (
                  one.carrier === undefined
                    ? <Pill tone="unknown">{t("unknown")}</Pill>
                    : one.carrier
                      ? (one.speed_mbps ? `${t("up")}, ${one.speed_mbps} Mbps` : t("up"))
                      : t("no carrier")
                ) },
                { key: "mac", head: "MAC", minor: true, tight: true, cell: (one) => (
                  one.mac ? <span className="fl-mono">{one.mac}</span> : <span className="fl-faint">—</span>
                ) },
                { key: "driver", head: t("Driver"), minor: true, cell: (one) => one.driver || <span className="fl-faint">—</span> },
                // Without a write mechanism there is nothing to edit: the
                // panel does not change a configuration the host will not
                // keep after a reboot.
                ...(writable ? [{
                  key: "act", head: t("Actions"), actions: true, cell: (one: Interface) => (
                    access.anyAllowed
                      ? (
                        <Button kind="quiet" testId={`change-${one.name}`} onClick={() => setEdited(one)}>
                          {t("Change")}
                        </Button>
                      )
                      : null
                  ),
                }] : []),
              ]}
            />
          </Card>
        ),
        change: edited ? (
          <InterfaceChange
            key={edited.name}
            hostID={host.id}
            iface={edited}
            management={edited.management}
            onIntent={setIntent}
            onCancel={() => setEdited(null)}
          />
        ) : undefined,
        layers: (
          <Card
            title={t("Layering")}
            note={t("What sits on what: a bond joins links into one, a bridge puts them on one segment, a VLAN rides tagged on one of them. A layer takes the addressing of its members, so building one is a change of the same weight as rewriting an address.")}
            tools={writable ? (
              <Allowed host={host.id} action="network.link.apply">
                <Button kind="quiet" testId="build-layer" onClick={() => setBuilding((open) => !open)}>
                  {building ? t("Cancel") : t("Build a layer")}
                </Button>
              </Allowed>
            ) : undefined}
            flush
          >
            <Table
              testId="layers"
              rows={layers}
              keyOf={(one) => one.name}
              rowTestId={(one) => `layer-${one.name}`}
              empty={t("This host reports no bond, bridge or VLAN.")}
              columns={[
                { key: "name", head: t("Interface"), cell: (one) => (
                  <Stack>
                    <span className="fl-mono">{one.name}</span>
                    {one.management && <Pill tone="info">{t("management")}</Pill>}
                  </Stack>
                ) },
                { key: "kind", head: t("Kind"), cell: (one) => layerKind(one) },
                { key: "members", head: t("Members"), cell: (one) => (
                  one.vlan
                    ? <span className="fl-mono">{t("on {parent}", { parent: one.vlan.parent || "—" })}</span>
                    : layerMembers(one).length === 0
                      ? <span className="fl-faint">—</span>
                      : (
                        <Stack>
                          {layerMembers(one).map((member) => {
                            // The driver's own word about the member.
                            const state = one.bond?.member_states?.[member] ?? "";
                            const carrying = one.bond?.active_member === member;
                            return (
                              <span key={member} className="fl-mono">
                                {member}
                                {state !== "" && <span className="fl-faint"> · {state}</span>}
                                {carrying && <Pill tone="ok">{t("carrying")}</Pill>}
                              </span>
                            );
                          })}
                        </Stack>
                      )
                ) },
                { key: "settings", head: t("Settings"), minor: true, cell: (one) => layerSettings(one, t) },
                { key: "state", head: t("State"), cell: (one) => (
                  <Stack>
                    <Pill tone={one.oper_state === "up" ? "ok" : "neutral"}>{one.oper_state}</Pill>
                    {/* A bond that failed over is a bond running on its
                        spare: the operator asks this screen exactly that. */}
                    {one.bond?.primary && one.bond.active_member
                      && one.bond.active_member !== one.bond.primary && (
                        <Pill tone="warn">{t("failed over")}</Pill>
                      )}
                  </Stack>
                ) },
                ...(writable ? [{
                  key: "act", head: t("Actions"), actions: true, cell: (one: Interface) => (
                    <Allowed host={host.id} action="network.link.remove">
                      <LayerRemove iface={one} onIntent={setIntent} />
                    </Allowed>
                  ),
                }] : []),
              ]}
            />
          </Card>
        ),
        build: building && writable ? (
          <LayerBuild
            hostID={host.id}
            interfaces={interfaces}
            onIntent={setIntent}
            onCancel={() => setBuilding(false)}
          />
        ) : undefined,
        routes: (
          <Card
            title={t("Routes")}
            foot={
              <>
                {t("Management channel")}: {snapshot?.management_interface || t("unknown")}
                {snapshot?.management_address ? ` · ${snapshot.management_address}` : ""}
                {snapshot?.write_adapter ? ` · ${t("write adapter {name}", { name: adapterLabel(snapshot.write_adapter) })}` : ""}
                {snapshot?.observed_at ? ` · ${t("read")} ${relativeTime(snapshot.observed_at)}` : ""}
              </>
            }
            flush
          >
            <Table
              testId="routes"
              rows={routes}
              keyOf={(one, index) => `${one.family}-${one.destination}-${one.interface}-${index}`}
              empty={t("No routes reported.")}
              columns={[
                { key: "destination", head: t("Destination"), tight: true, cell: (one) => <span className="fl-mono">{one.destination}</span> },
                { key: "gateway", head: t("Gateway"), tight: true, cell: (one) => one.gateway ? <span className="fl-mono">{one.gateway}</span> : <span className="fl-faint">—</span> },
                { key: "interface", head: t("Interface"), cell: (one) => one.interface ? <span className="fl-mono">{one.interface}</span> : <span className="fl-faint">—</span> },
                { key: "source", head: t("Source"), minor: true, tight: true, cell: (one) => one.source ? <span className="fl-mono">{one.source}</span> : <span className="fl-faint">—</span> },
                { key: "protocol", head: t("Protocol"), cell: (one) => <span title={one.protocol || undefined}>{t(routeProtocolWords(one.protocol))}</span> },
                { key: "metric", head: t("Metric"), num: true, cell: (one) => one.metric },
                { key: "family", head: t("Family"), cell: (one) => one.family === "inet6" ? "IPv6" : "IPv4" },
              ]}
            />
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

/* ----------------------------------------------------- the one change */

/**
 * The confirmation of a change that can take the host away from the panel.
 *
 * Two things are asked for: the reason the trail keeps, and the name of
 * the machine, typed out. A change ordered from the wrong tab is the one
 * mistake the panel cannot undo for anybody.
 */
function Confirm({ host, title, what, busy, danger, target, reasonOnly, onConfirm, onCancel }: {
  host: Host;
  title: string;
  what: ReactNode;
  busy: boolean;
  danger?: boolean;
  /** What is typed to confirm; the hostname unless something narrower goes. */
  target?: string;
  /** Ask for the reason and nothing else: the order destroys nothing. */
  reasonOnly?: boolean;
  onConfirm: (reason: string, confirmation: string) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [typed, setTyped] = useState("");
  const expected = target ?? host.hostname;
  const ready = reason.trim().length >= MIN_REASON_LENGTH && (reasonOnly === true || typed === expected);

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
          {!reasonOnly && (
            <Field
              label={target === undefined ? t("Type the hostname to confirm:") : t("Type the name to confirm:")}
              hint={expected}
              wide
            >
              <input value={typed} onChange={(event) => setTyped(event.target.value)} data-testid="confirm-target" />
            </Field>
          )}
        </Fields>
      </Stack>
    </Modal>
  );
}

/* ------------------------------------------------ changing one link */

/** The interface change form: the MTU, the routes and the address profile. */
function InterfaceChange({ hostID, iface, management, onIntent, onCancel }: {
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
    (iface.addresses ?? []).filter((one) => one.family === "inet").map((one) => one.address).join(", "),
  );
  const [gateway, setGateway] = useState("");
  const [dns, setDns] = useState("");
  const [routes, setRoutes] = useState("");
  const [window, setWindow] = useState("120");
  // The second family is asked separately, because it is a separate
  // decision: a host can take its IPv4 address from DHCP and hold a static
  // IPv6 one at the same time.
  const [method6, setMethod6] = useState("");
  const [addresses6, setAddresses6] = useState(
    (iface.addresses ?? []).filter((one) => one.family === "inet6").map((one) => one.address).join(", "),
  );
  const [gateway6, setGateway6] = useState("");
  const [acceptRA, setAcceptRA] = useState("");
  const [privacy, setPrivacy] = useState("");
  const ipv6Off = iface.ipv6?.disabled === true;

  const list = (value: string) => value.split(",").map((one) => one.trim()).filter(Boolean);
  const seconds = Number(window) || 0;
  const mtuRequest = mtuOrder(iface.name, mtu, seconds);
  const routesRequest = routesOrder(iface.name, list(routes), seconds);

  return (
    <Card
      title={t("Change {iface}", { iface: iface.name })}
      note={t("The host arms a rollback before it applies anything and cancels it only after the agent proves it can still reach the panel.")}
      tools={<Button kind="quiet" onClick={onCancel}>{t("Cancel")}</Button>}
    >
      <Stack>
        {/* Changing the management interface is changing the branch we sit
            on: the operator is to read this before, not see it after. */}
        {management && (
          <Banner tone="warn">
            {t("This is the interface the panel talks to. If the change breaks it, the host will roll back on its own after the rollback window — but until then it is unreachable, and no further command will arrive.")}
          </Banner>
        )}

        <Fields>
          <Field label={t("Rollback window (seconds, 30–900)")}>
            <input value={window} onChange={(event) => setWindow(event.target.value)} data-testid="rollback" />
          </Field>
          <Field label="MTU">
            <input value={mtu} onChange={(event) => setMtu(event.target.value)} placeholder={t("MTU or auto")} data-testid="mtu" />
          </Field>
        </Fields>
        <Allowed host={hostID} action="network.mtu.set">
          <Button
            testId="set-mtu"
            disabled={!orderReady(mtuRequest)}
            title={refusalOf(t, mtuRequest)}
            onClick={() => onIntent({
              action: "network.mtu.set",
              label: t("Set MTU on {iface}", { iface: iface.name }),
              description: t("{iface} will use MTU {mtu}. The host rolls back after {seconds}s unless the agent confirms connectivity.", { iface: iface.name, mtu, seconds }),
              payload: mtuRequest.payload,
            })}
          >
            {t("Set MTU")}
          </Button>
        </Allowed>

        <Fields>
          <Field label={t("Routes")} wide>
            <input
              value={routes}
              onChange={(event) => setRoutes(event.target.value)}
              placeholder={t("Routes, e.g. 10.0.0.0/8 192.168.56.1, 172.16.0.0/12")}
              data-testid="routes"
            />
          </Field>
        </Fields>
        <Allowed host={hostID} action="network.route.ensure">
          <Button
            testId="replace-routes"
            disabled={!orderReady(routesRequest)}
            title={refusalOf(t, routesRequest)}
            onClick={() => onIntent({
              action: "network.route.ensure",
              label: t("Replace routes on {iface}", { iface: iface.name }),
              description: t("{iface} will carry exactly these routes: {routes}. Routes not listed here are removed from the profile.", {
                iface: iface.name, routes: list(routes).join("; ") || t("none"),
              }),
              payload: routesRequest.payload,
            })}
          >
            {t("Replace routes")}
          </Button>
        </Allowed>

        <Fields>
          <Field label={t("How it is addressed")}>
            <select value={method} onChange={(event) => setMethod(event.target.value as "auto" | "manual")} data-testid="method">
              <option value="manual">{t("static addresses")}</option>
              <option value="auto">DHCP</option>
            </select>
          </Field>
          <Field label={t("Addresses")}>
            <input
              value={addresses}
              onChange={(event) => setAddresses(event.target.value)}
              placeholder={t("Addresses with masks, e.g. 192.168.56.30/24")}
              disabled={method === "auto"}
              data-testid="addresses"
            />
          </Field>
          <Field label={t("Gateway")}>
            <input value={gateway} onChange={(event) => setGateway(event.target.value)} placeholder={t("Gateway")} disabled={method === "auto"} />
          </Field>
          <Field label={t("DNS servers")}>
            <input value={dns} onChange={(event) => setDns(event.target.value)} placeholder={t("DNS servers")} disabled={method === "auto"} />
          </Field>
        </Fields>

        {/* The second family, held to the same standard as the first: its
            own method, its own addresses with prefix lengths, and a gateway
            that may be link-local, because that is how an IPv6 router
            ordinarily announces itself. */}
        <Fields>
          <Field label={t("IPv6")}>
            <select value={method6} onChange={(event) => setMethod6(event.target.value)} disabled={ipv6Off} data-testid="method6">
              <option value="">{t("leave as it is")}</option>
              <option value="auto">{t("from the network")}</option>
              <option value="manual">{t("static addresses")}</option>
              <option value="disabled">{t("no IPv6 here")}</option>
            </select>
          </Field>
          <Field label={t("IPv6 addresses")}>
            <input
              value={addresses6}
              onChange={(event) => setAddresses6(event.target.value)}
              placeholder={t("Addresses with prefix lengths, e.g. 2001:db8::5/64")}
              disabled={ipv6Off || method6 !== "manual"}
            />
          </Field>
          <Field label={t("IPv6 gateway")}>
            <input
              value={gateway6}
              onChange={(event) => setGateway6(event.target.value)}
              placeholder="fe80::1"
              disabled={ipv6Off || method6 === "" || method6 === "disabled"}
            />
          </Field>
          <Field label={t("Router advertisements")}>
            <select value={acceptRA} onChange={(event) => setAcceptRA(event.target.value)} disabled={ipv6Off}>
              <option value="">{`${t("leave as it is")} (${t(acceptRAWords(iface.ipv6?.accept_ra))})`}</option>
              <option value="off">{t("ignored")}</option>
              <option value="on">{t("accepted")}</option>
              <option value="on-forwarding">{t("accepted, even while forwarding")}</option>
            </select>
          </Field>
          <Field label={t("Privacy extensions")}>
            <select value={privacy} onChange={(event) => setPrivacy(event.target.value)} disabled={ipv6Off}>
              <option value="">{`${t("leave as it is")} (${t(privacyWords(iface.ipv6?.privacy))})`}</option>
              <option value="off">{t("off")}</option>
              <option value="prefer-public">{t("public preferred")}</option>
              <option value="prefer-temporary">{t("temporary preferred")}</option>
            </select>
          </Field>
        </Fields>

        {/* A host with the family switched off would take every IPv6 setting
            and report none of them back. */}
        {ipv6Off && (
          <Banner tone="warn">
            {t("IPv6 is switched off on {iface}, so nothing written there would take effect. That is a kernel setting, not a profile one.", { iface: iface.name })}
          </Banner>
        )}

        <Allowed host={hostID} action="network.profile.apply">
          <Button
            testId="apply-profile"
            disabled={method === "manual" && list(addresses).length === 0}
            onClick={() => onIntent({
              action: "network.profile.apply",
              label: t("Apply address profile to {iface}", { iface: iface.name }),
              description: method === "auto"
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
                  // A family the order says nothing about keeps what the
                  // host has, down to its routes.
                  method6,
                  addresses6: method6 === "manual" ? list(addresses6) : [],
                  gateway6: method6 === "" || method6 === "disabled" ? "" : gateway6,
                  accept_ra: acceptRA,
                  privacy,
                  rollback_seconds: seconds,
                },
              },
            })}
          >
            {t("Apply profile")}
          </Button>
        </Allowed>
      </Stack>
    </Card>
  );
}

/* ------------------------------------------------- building a layer */

/**
 * What is wrong with a layer as described, in the order the questions
 * come: is the name free, is the lower interface there, is the layer worth
 * building, and would it take the interface the panel itself comes through.
 */
export function layerProblems(t: Translate, interfaces: Interface[], asked: {
  name: string; kind: "bond" | "bridge" | "vlan"; members: string[];
  mode: string; primary: string; lacpRate: string; parent: string; vlanID: string;
}): string[] {
  const byName = new Map<string, Interface>(interfaces.map((iface) => [iface.name, iface]));
  const problems: string[] = [];
  if (asked.name === "") problems.push(t("Name the layer the host is to carry."));
  if (byName.has(asked.name)) {
    problems.push(t("The host already has an interface called {name}; the panel does not turn it into a {kind} under the same name.", { name: asked.name, kind: asked.kind }));
  }
  if (asked.kind === "vlan") {
    const owner = byName.get(asked.parent);
    if (asked.parent === "") problems.push(t("Name the interface the tagged traffic runs on."));
    else if (!owner) problems.push(t("The host does not report the interface {name}.", { name: asked.parent }));
    else if (owner.master) {
      problems.push(t("The parent {name} is a member of {owner}; a VLAN belongs on the layer above.", { name: asked.parent, owner: owner.master }));
    }
    const tag = Number(asked.vlanID);
    if (!Number.isInteger(tag) || tag < 1 || tag > 4094) {
      problems.push(t("The VLAN identifier lies between 1 and 4094."));
    }
    return problems;
  }
  if (asked.kind === "bond" && asked.members.length < 2) {
    problems.push(t("A bond carries traffic over at least two members; with one it is the same link with a driver in between."));
  }
  for (const member of asked.members) {
    const link = byName.get(member);
    if (!link) {
      problems.push(t("The host does not report the interface {name}.", { name: member }));
      continue;
    }
    if (link.management) {
      problems.push(t("{name} is the interface the panel talks to this host over; a layer would take its address and the host would be unreachable before the change finished.", { name: member }));
    }
    if (link.master && link.master !== asked.name) {
      problems.push(t("{name} is already a member of {owner}; taking it would stop whatever runs over that layer.", { name: member, owner: link.master }));
    }
  }
  if (asked.primary !== "" && !asked.members.includes(asked.primary)) {
    problems.push(t("The primary member has to be one of the members."));
  }
  if (asked.lacpRate !== "" && asked.mode !== "802.3ad") {
    problems.push(t("The LACP rate belongs to the mode 802.3ad and to no other."));
  }
  return problems;
}

/** The form that builds a bond, a bridge or a VLAN. */
function LayerBuild({ hostID, interfaces, onIntent, onCancel }: {
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

  const chosen = members.split(",").map((one) => one.trim()).filter(Boolean);
  const seconds = Number(window) || 0;
  // The lower interfaces are the host's own: an interface is called
  // whatever the host calls it - enp2s0, ens192, eno1np0 - so the form
  // offers the names this host reports rather than an example.
  const lower = interfaces.filter((iface) => iface.name !== "lo").map((iface) => iface.name);
  const problems = layerProblems(t, interfaces, {
    name, kind, members: chosen, mode, primary, lacpRate, parent, vlanID,
  });

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
    <Card
      title={t("Build a layer")}
      note={t("The host computes its own plan first and refuses what would not hold: a member another layer owns, a bond of one member, a VLAN on a parent it does not have, or a layer that would swallow the interface the panel talks over.")}
      tools={<Button kind="quiet" onClick={onCancel}>{t("Cancel")}</Button>}
    >
      <Stack>
        <Fields>
          <Field label={t("Name")}>
            <input value={name} onChange={(event) => setName(event.target.value)} placeholder={`${kind}0`} data-testid="layer-name" />
          </Field>
          <Field label={t("Kind")}>
            <select value={kind} onChange={(event) => setKind(event.target.value as "bond" | "bridge" | "vlan")} data-testid="layer-kind">
              <option value="bond">{t("Bond")}</option>
              <option value="bridge">{t("Bridge")}</option>
              <option value="vlan">VLAN</option>
            </select>
          </Field>
          <Field label={t("Rollback window (seconds, 30–900)")}>
            <input value={window} onChange={(event) => setWindow(event.target.value)} />
          </Field>
        </Fields>

        {kind === "vlan" ? (
          <Fields>
            <Field label={t("Parent")}>
              <select value={parent} onChange={(event) => setParent(event.target.value)} data-testid="layer-parent">
                <option value="">{t("Pick the interface the host reports")}</option>
                {lower.map((one) => <option key={one} value={one}>{one}</option>)}
              </select>
            </Field>
            <Field label={t("VLAN identifier")}>
              <input value={vlanID} onChange={(event) => setVlanID(event.target.value)} placeholder="100" data-testid="layer-vlan" />
            </Field>
          </Fields>
        ) : (
          <Fields>
            <Field label={t("Members")} hint={lower.join(", ")} wide>
              <input
                value={members}
                onChange={(event) => setMembers(event.target.value)}
                list="fl-layer-members"
                placeholder={t("Interfaces of this host, separated by commas")}
                data-testid="layer-members"
              />
              <datalist id="fl-layer-members">
                {lower.map((one) => <option key={one} value={one} />)}
              </datalist>
            </Field>
          </Fields>
        )}

        {kind === "bond" && (
          <Fields>
            <Field label={t("Mode")}>
              <select value={mode} onChange={(event) => setMode(event.target.value)}>
                {["active-backup", "802.3ad", "balance-rr", "balance-xor", "broadcast", "balance-tlb", "balance-alb"]
                  .map((one) => <option key={one} value={one}>{one}</option>)}
              </select>
            </Field>
            <Field label={t("Link monitoring (ms, 0 switches it off)")}>
              <input value={monitoring} onChange={(event) => setMonitoring(event.target.value)} />
            </Field>
            <Field label={t("Primary member")}>
              <select value={primary} onChange={(event) => setPrimary(event.target.value)}>
                <option value="">{t("The driver's own choice")}</option>
                {chosen.map((one) => <option key={one} value={one}>{one}</option>)}
              </select>
            </Field>
            <Field label={t("LACP rate")}>
              <select value={lacpRate} onChange={(event) => setLacpRate(event.target.value)}>
                <option value="">{t("the driver's own")}</option>
                <option value="slow">slow</option>
                <option value="fast">fast</option>
              </select>
            </Field>
          </Fields>
        )}

        {kind === "bridge" && (
          <Check checked={stp} onChange={setStp}>
            {t("Keep a loop between switches from flooding the segment")}
          </Check>
        )}

        {problems.length > 0 && <Problem>{problems[0]}</Problem>}

        <Allowed host={hostID} action="network.link.apply">
          <Button
            testId="build"
            disabled={problems.length > 0}
            onClick={() => onIntent({
              action: "network.link.apply",
              label: t("Build {kind} {name}", { kind, name }),
              description: kind === "vlan"
                ? t("{name} will carry the tag {tag} on {parent}. The host rolls it back after {seconds}s unless the agent confirms connectivity.", { name, tag: vlanID, parent, seconds })
                : t("{name} will be built from {members}. Those interfaces lose their own addressing to it. The host rolls it back after {seconds}s unless the agent confirms connectivity.", { name, members: chosen.join(", "), seconds }),
              payload: { network: { interface: name, link, rollback_seconds: seconds } },
            })}
          >
            {t("Build")}
          </Button>
        </Allowed>
      </Stack>
    </Card>
  );
}

/**
 * The button that takes a layer away. The registry composes the order, so a
 * rollback window or an interface name the panel would not send says why
 * here rather than coming back as a refusal from the host.
 */
function LayerRemove({ iface, onIntent }: { iface: Interface; onIntent: (intent: Intent) => void }) {
  const t = useT();
  const order = layerRemoveOrder(iface.name, ROW_ROLLBACK_SECONDS);
  return (
    <Button
      kind="danger"
      testId={`remove-${iface.name}`}
      disabled={!orderReady(order)}
      title={refusalOf(t, order)}
      onClick={() => onIntent({
        action: order.action,
        label: t("Remove {iface}", { iface: iface.name }),
        description: t("{iface} is taken away and {members} go back to carrying their own traffic. The host rolls the removal back unless the agent proves it can still reach the panel.", {
          iface: iface.name,
          members: layerMembers(iface).join(", ") || t("nothing"),
        }),
        payload: order.payload,
      })}
    >
      {t("Remove")}
    </Button>
  );
}

/** The name this screen's arrangement is stored under. */
export const NETWORK_SCREEN = "next_host_network";

/** The containers this screen can draw, and the shape each ships with. */
export const NETWORK_BOARD: BoardEntry[] = [
  { key: "up", title: "Interfaces up", width: 3, height: 1 },
  { key: "addressed", title: "Interfaces with an address", width: 3, height: 1 },
  { key: "routecount", title: "Routes", width: 3, height: 1 },
  { key: "adapter", title: "Write adapter", width: 3, height: 1 },
  { key: "states", title: "Interfaces by state", width: 8, height: 2 },
  { key: "channel", title: "Management channel", width: 4, height: 2 },
  { key: "interfaces", title: "Interfaces", width: 12, height: 4 },
  { key: "change", title: "Change an interface", width: 12, height: 5 },
  { key: "layers", title: "Layering", width: 12, height: 3 },
  { key: "build", title: "Build a layer", width: 12, height: 4 },
  { key: "routes", title: "Routes", width: 12, height: 3 },
  { key: "source", title: "Where this came from", width: 12, height: 1 },
];
