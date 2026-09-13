import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import type { Job } from "../../lib/types";
import { Time, Empty } from "../../components/ui";
import { ModuleFreshness, useHost, useModule } from "./shared";
import { TargetConfirmation } from "./TargetConfirmation";
import { useT } from "../../i18n";

type Address = {
  family: string;
  address: string;
  scope: string;
  source?: string;
  permanent: boolean;
};

type Interface = {
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
  observed_at?: string;
  unavailable_reason?: string;
};

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
export function Network() {
  const t = useT();
  const host = useHost();
  const queryClient = useQueryClient();
  const module = useModule<Snapshot>(host.id, "network");
  const [intent, setIntent] = useState<Intent | null>(null);
  const [message, setMessage] = useState("");
  const [edited, setEdited] = useState<Interface | null>(null);

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
      queryClient.invalidateQueries({ queryKey: ["jobs", host.id] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });
  // A host with docker has a dozen virtual interfaces and only some of them
  // mean anything. By default we show the ones that do.
  const [all, setAll] = useState(false);

  const snapshot = module.data?.payload;
  const interfaces = snapshot?.interfaces ?? [];
  const visible = all ? interfaces : interfaces.filter(relevant);
  const routes = snapshot?.routes ?? [];

  if (!module.data) return <Empty>{t("This host has not reported its network state yet.")}</Empty>;

  return (
    <>
      <p className="subtitle">
        {t("Read from the kernel, not from configuration files: what the host has up and what someone once wrote into a config file can differ.")}
      </p>

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

      <div className="filters">
        <label className="toggle">
          <input
            type="checkbox"
            checked={all}
            onChange={(e) => setAll(e.target.checked)}
          />
          {t("Show virtual interfaces ({n} hidden)", { n: interfaces.length - visible.length })}
        </label>
      </div>

      <h2>{t("Interfaces")}</h2>
      <table>
        <thead>
          <tr>
            <th>{t("Interface")}</th><th>{t("Kind")}</th><th>{t("State")}</th><th>{t("Addresses")}</th>
            <th>MTU</th><th>{t("Link")}</th><th>MAC</th><th>{t("Driver")}</th><th>{t("Actions")}</th>
          </tr>
        </thead>
        <tbody>
          {visible.map((iface) => (
            <tr key={iface.name}>
              <td>
                {iface.name}
                {/* The management interface is the one the command came
                    through. Changing that one is changing the branch we sit
                    on. */}
                {iface.management && <span className="badge"> {t("management")}</span>}
              </td>
              <td>{iface.kind || "—"}</td>
              <td>{iface.oper_state}</td>
              <td>
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
              <td>{iface.mtu}</td>
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
              <td>{iface.mac || "—"}</td>
              <td>{iface.driver || "—"}</td>
              <td>
                {/* Without a write mechanism there is nothing to edit: the
                    panel does not change a configuration the host will not
                    keep after a reboot. */}
                <button
                  onClick={() => setEdited(iface)}
                  disabled={!snapshot?.write_adapter}
                  title={
                    snapshot?.write_adapter
                      ? ""
                      : t("This host has no NetworkManager, nmstate or netplan.")
                  }
                >
                  {t("Change")}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {message && <p className="source" style={{ marginBottom: 12 }}>{message}</p>}

      {edited && (
        <InterfaceChange
          iface={edited}
          management={edited.management}
          onIntent={setIntent}
          onCancel={() => setEdited(null)}
        />
      )}

      <h2>{t("Routes")}</h2>
      {!routes.length ? (
        <Empty>{t("No routes reported.")}</Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th>{t("Destination")}</th><th>{t("Gateway")}</th><th>{t("Interface")}</th>
              <th>{t("Source")}</th><th>{t("Protocol")}</th><th>{t("Metric")}</th><th>{t("Family")}</th>
            </tr>
          </thead>
          <tbody>
            {routes.map((route, i) => (
              <tr key={`${route.family}-${route.destination}-${route.interface}-${i}`}>
                <td>{route.destination}</td>
                <td>{route.gateway || "—"}</td>
                <td>{route.interface || "—"}</td>
                <td>{route.source || "—"}</td>
                <td>{route.protocol || "—"}</td>
                <td>{route.metric}</td>
                <td>{route.family === "inet6" ? "IPv6" : "IPv4"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <p className="source" style={{ marginTop: 12 }}>
        {t("Management channel")}: {snapshot?.management_interface || t("unknown")}
        {snapshot?.management_address && ` · ${snapshot.management_address}`}
        {snapshot?.write_adapter && ` · ${t("write adapter {name}", { name: snapshot.write_adapter })}`}
        {snapshot?.observed_at && (
          <>
            {` · ${t("read")} `}
            <Time value={snapshot.observed_at} />
          </>
        )}
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

/**
 * The interface change form.
 *
 * Every change is armed with a rollback on the host side: if the agent does
 * not confirm connectivity after the change, the host returns to the
 * previous configuration by itself. That is why the form asks for the
 * rollback window instead of hiding it as a detail.
 */
function InterfaceChange({
  iface, management, onIntent, onCancel,
}: {
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

  const list = (value: string) =>
    value.split(",").map((element) => element.trim()).filter(Boolean);
  const seconds = Number(window) || 0;

  return (
    <div className="form" style={{ marginBottom: 16 }}>
      <h2>{t("Change {iface}", { iface: iface.name })}</h2>
      {/* Changing the management interface is changing the branch we sit
          on: the operator is to read this before, not see it after. */}
      {management && (
        <p className="warning">
          <span>
            {t("This is the interface the panel talks to. If the change breaks it, the host will roll back on its own after the rollback window — but until then it is unreachable, and no further command will arrive.")}
          </span>
        </p>
      )}
      <p className="subtitle" style={{ margin: 0 }}>
        {t("The host arms a rollback before it applies anything and cancels it only after the agent proves it can still reach the panel.")}
      </p>
      <label>
        {t("Rollback window (seconds, 30–900)")}
        <input value={window} onChange={(e) => setWindow(e.target.value)} />
      </label>

      <div className="filters" style={{ marginTop: 8 }}>
        <input value={mtu} onChange={(e) => setMtu(e.target.value)} placeholder={t("MTU or auto")} />
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
      </div>

      <div className="filters">
        <input
          value={routes}
          onChange={(e) => setRoutes(e.target.value)}
          placeholder={t("Routes, e.g. 10.0.0.0/8 192.168.56.1, 172.16.0.0/12")}
          style={{ minWidth: 380 }}
        />
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
      </div>

      <div className="filters">
        <select value={method} onChange={(e) => setMethod(e.target.value as "auto" | "manual")}>
          <option value="manual">{t("static addresses")}</option>
          <option value="auto">DHCP</option>
        </select>
        <input
          value={addresses}
          onChange={(e) => setAddresses(e.target.value)}
          placeholder={t("Addresses with masks, e.g. 192.168.56.30/24")}
          style={{ minWidth: 260 }}
          disabled={method === "auto"}
        />
        <input value={gateway} onChange={(e) => setGateway(e.target.value)} placeholder={t("Gateway")} disabled={method === "auto"} />
        <input value={dns} onChange={(e) => setDns(e.target.value)} placeholder={t("DNS servers")} disabled={method === "auto"} />
        <button
          onClick={() =>
            onIntent({
              action: "network.profile.apply",
              label: t("Apply address profile to {iface}", { iface: iface.name }),
              description:
                method === "auto"
                  ? t("{iface} will take its address from DHCP. Its current address is dropped.", { iface: iface.name })
                  : t("{iface} will use {addresses}{gateway}. Addresses not listed here are removed.", {
                      iface: iface.name, addresses: list(addresses).join(", "), gateway: gateway ? ` ${t("via {gateway}", { gateway })}` : "",
                    }),
              payload: {
                network: {
                  interface: iface.name,
                  method,
                  addresses: method === "auto" ? [] : list(addresses),
                  gateway: method === "auto" ? "" : gateway,
                  dns: method === "auto" ? [] : list(dns),
                  rollback_seconds: seconds,
                },
              },
            })
          }
          disabled={method === "manual" && list(addresses).length === 0}
        >
          {t("Apply profile")}
        </button>
      </div>

      <button className="secondary" onClick={onCancel}>{t("Cancel")}</button>
    </div>
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
  return (iface.addresses ?? []).length > 0 || iface.kind === "ethernet";
}
