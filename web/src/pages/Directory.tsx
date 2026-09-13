import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../lib/api";
import type { DirectoryGroup, DirectoryUser, HBACRule, SudoRule } from "../lib/types";
import { ErrorBox, Empty } from "../components/ui";
import { useT } from "../i18n";

type Tab = "users" | "groups" | "hbac" | "sudo" | "dns";

// The tab key is an identifier in code, not a caption for the operator.
const TAB_TITLES: Record<Tab, string> = {
  users: "Users",
  groups: "Groups",
  hbac: "HBAC rules",
  sudo: "sudo rules",
  dns: "DNS",
};

/**
 * The identity directory view. HBAC and sudo rules have a permission of
 * their own: they describe who may enter a host and raise their privileges.
 */
export function Directory() {
  const t = useT();
  const [tab, setTab] = useState<Tab>("users");

  const status = useQuery({
    queryKey: ["identity-status"],
    queryFn: () => api.get<{ configured: boolean; reachable?: boolean; principal?: string; summary?: string; error?: string }>("/api/v1/identity/status"),
  });

  return (
    <>
      <h1>{t("Identity directory")}</h1>
      <p className="subtitle">
        {status.data?.configured === false
          ? t("No directory connector is configured.")
          : status.data?.reachable
            ? `${status.data.summary} · ${t("connector")}: ${status.data.principal}`
            : status.data?.error
              ? t("Directory unavailable: {error}", { error: status.data.error })
              : t("Checking…")}
      </p>

      <div className="tabs">
        {(["users", "groups", "hbac", "sudo", "dns"] as Tab[]).map((key) => (
          <button key={key} className={tab === key ? "active" : ""} onClick={() => setTab(key)}>
            {t(TAB_TITLES[key])}
          </button>
        ))}
      </div>

      {tab === "users" && <Users />}
      {tab === "groups" && <Groups />}
      {tab === "hbac" && <HBACRules />}
      {tab === "sudo" && <SudoRules />}
      {tab === "dns" && <DirectoryDNS />}
    </>
  );
}

function Forbidden() {
  const t = useT();
  return <Empty>{t("You do not have permission to read this resource.")}</Empty>;
}

function Users() {
  const t = useT();
  const { data, error } = useQuery({
    queryKey: ["identity-users"],
    queryFn: () => api.get<Collection<DirectoryUser>>("/api/v1/identity/users"),
    retry: false,
  });
  if (error instanceof ApiError && error.forbidden) return <Forbidden />;
  if (error) return <ErrorBox error={error} />;
  if (!data?.items.length) return <Empty>{t("No accounts.")}</Empty>;

  return (
    <table>
      <thead><tr><th>{t("Account")}</th><th>{t("Full name")}</th><th>UID</th><th>{t("Groups")}</th><th>{t("SSH keys")}</th><th>{t("State")}</th></tr></thead>
      <tbody>
        {data.items.map((user) => (
          <tr key={user.uid}>
            <td>{user.uid}</td>
            <td>{[user.first_name, user.last_name].filter(Boolean).join(" ")}</td>
            <td>{user.uid_number || "—"}</td>
            <td>{(user.groups ?? []).join(", ") || "—"}</td>
            <td>{user.ssh_key_fingerprints?.length ?? 0}</td>
            <td>{user.disabled ? <span className="badge error">{t("locked")}</span> : <span className="badge ok">{t("active")}</span>}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Groups() {
  const t = useT();
  const { data, error } = useQuery({
    queryKey: ["identity-groups"],
    queryFn: () => api.get<Collection<DirectoryGroup>>("/api/v1/identity/groups"),
    retry: false,
  });
  if (error instanceof ApiError && error.forbidden) return <Forbidden />;
  if (error) return <ErrorBox error={error} />;
  if (!data?.items.length) return <Empty>{t("No groups.")}</Empty>;

  return (
    <table>
      <thead><tr><th>{t("Group")}</th><th>GID</th><th>{t("Description")}</th><th>{t("Members")}</th></tr></thead>
      <tbody>
        {data.items.map((group) => (
          <tr key={group.name}>
            <td>{group.name}</td>
            <td>{group.gid_number || "—"}</td>
            <td>{group.description || "—"}</td>
            <td>{(group.members ?? []).join(", ") || "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function HBACRules() {
  const t = useT();
  const { data, error } = useQuery({
    queryKey: ["identity-hbac"],
    queryFn: () => api.get<Collection<HBACRule>>("/api/v1/identity/hbac-rules"),
    retry: false,
  });
  if (error instanceof ApiError && error.forbidden) return <Forbidden />;
  if (error) return <ErrorBox error={error} />;
  if (!data?.items.length) return <Empty>{t("No rules.")}</Empty>;

  return (
    <table>
      <thead><tr><th>{t("Rule")}</th><th>{t("Enabled")}</th><th>{t("Groups")}</th><th>{t("Hosts")}</th><th>{t("Risk")}</th></tr></thead>
      <tbody>
        {data.items.map((rule) => (
          <tr key={rule.name}>
            <td>{rule.name}</td>
            <td>{rule.enabled ? t("yes") : t("no")}</td>
            <td>{(rule.user_groups ?? []).join(", ") || "—"}</td>
            <td>{[...(rule.hosts ?? []), ...(rule.host_groups ?? [])].join(", ") || "—"}</td>
            <td>
              {rule.allows_everything
                ? <span className="badge error">{t("covers the whole fleet")}</span>
                : <span className="badge">{t("narrowed")}</span>}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function SudoRules() {
  const t = useT();
  const { data, error } = useQuery({
    queryKey: ["identity-sudo"],
    queryFn: () => api.get<Collection<SudoRule>>("/api/v1/identity/sudo-rules"),
    retry: false,
  });
  if (error instanceof ApiError && error.forbidden) return <Forbidden />;
  if (error) return <ErrorBox error={error} />;
  if (!data?.items.length) return <Empty>{t("No sudo rules.")}</Empty>;

  return (
    <table>
      <thead><tr><th>{t("Rule")}</th><th>{t("Enabled")}</th><th>{t("Applies to")}</th><th>{t("Risk")}</th></tr></thead>
      <tbody>
        {data.items.map((rule) => (
          <tr key={rule.name}>
            <td>{rule.name}</td>
            <td>{rule.enabled ? t("yes") : t("no")}</td>
            <td>{[...(rule.users ?? []), ...(rule.user_groups ?? [])].join(", ") || "—"}</td>
            <td>
              {rule.critical
                ? <span className="badge error" title={(rule.critical_reasons ?? []).join("; ")}>{t("critical")}</span>
                : "—"}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

type Zone = { name: string; reverse: boolean };

type DNSRecord = { zone: string; name: string; type: string; values: string[]; ttl?: number };

type DirectoryChange = { id: string; state: string; plan?: { summary?: string; steps?: string[]; conflicts?: string[] } };

/**
 * The directory DNS.
 *
 * This is a different scope than the host resolver: there the panel tells
 * one host whom to ask, here - what the directory answers to the whole
 * network. That is why a record goes the same way as an account change:
 * plan, approval, execution phase by phase - not as a job for the agent.
 */
function DirectoryDNS() {
  const t = useT();
  const queryClient = useQueryClient();
  const [zone, setZone] = useState("");
  const [name, setName] = useState("");
  const [type, setType] = useState("A");
  const [value, setValue] = useState("");
  const [ttl, setTtl] = useState("");
  const [reverse, setReverse] = useState(true);
  const [message, setMessage] = useState("");

  const zones = useQuery({
    queryKey: ["dns-zones"],
    queryFn: () => api.get<Collection<Zone>>("/api/v1/identity/dns/zones"),
    retry: false,
  });
  const selected = zone || zones.data?.items?.[0]?.name || "";

  const records = useQuery({
    queryKey: ["dns-records", selected],
    queryFn: () =>
      api.get<Collection<DNSRecord>>(`/api/v1/identity/dns/records?zone=${encodeURIComponent(selected)}`),
    enabled: selected !== "",
    retry: false,
  });

  const request = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api.post<DirectoryChange>("/api/v1/identity/changes", body),
    onSuccess: (change) => {
      const conflicts = change.plan?.conflicts ?? [];
      setMessage(
        conflicts.length
          ? t("Change {id} planned with conflicts: {conflicts}", { id: change.id.slice(0, 8), conflicts: conflicts.join("; ") })
          : t("Change {id} is {state}.", { id: change.id.slice(0, 8), state: change.state.replace("_", " ") }),
      );
      queryClient.invalidateQueries({ queryKey: ["dns-records", selected] });
      queryClient.invalidateQueries({ queryKey: ["directory-changes"] });
    },
    onError: (error) => setMessage(error instanceof Error ? error.message : String(error)),
  });

  if (zones.error instanceof ApiError && zones.error.forbidden) return <Forbidden />;
  if (zones.error) return <ErrorBox error={zones.error} />;

  const record = (ensure: boolean) => ({
    action: ensure ? "dns.record.ensure" : "dns.record.remove",
    payload: {
      dns: {
        zone: selected, name, type, value,
        ttl: Number(ttl) || 0,
        reverse: reverse && (type === "A" || type === "AAAA"),
      },
    },
  });

  return (
    <>
      <p className="subtitle">
        {t("Zones and records live in the directory, not in anyone's /etc/hosts. A record here answers for the whole network, so it goes the same way as a directory account: plan first, then approval, then execution — and the reverse record is a separate, visible step of that plan.")}
      </p>

      <div className="filters">
        <select value={selected} onChange={(e) => setZone(e.target.value)}>
          {(zones.data?.items ?? []).map((item) => (
            <option key={item.name} value={item.name}>
              {item.name}{item.reverse ? ` (${t("reverse")})` : ""}
            </option>
          ))}
        </select>
        <span className="source">{t("{n} records", { n: (records.data?.items ?? []).length })}</span>
      </div>

      <div className="form" style={{ marginBottom: 16 }}>
        <div className="filters">
          <input value={name} onChange={(e) => setName(e.target.value)}
                 placeholder={t("name (web, @, _ldap._tcp)")} style={{ minWidth: 200 }} />
          <select value={type} onChange={(e) => setType(e.target.value)}>
            {["A", "AAAA", "CNAME", "TXT", "SRV", "PTR"].map((item) => (
              <option key={item} value={item}>{item}</option>
            ))}
          </select>
          <input value={value} onChange={(e) => setValue(e.target.value)}
                 placeholder={t("value (10.0.0.5)")} style={{ minWidth: 240 }} />
          <input value={ttl} onChange={(e) => setTtl(e.target.value)}
                 placeholder="TTL" style={{ width: 90 }} />
        </div>
        {(type === "A" || type === "AAAA") && (
          <label style={{ flexDirection: "row", alignItems: "center", gap: 8 }}>
            <input type="checkbox" checked={reverse} onChange={(e) => setReverse(e.target.checked)} />
            {t("Also write the reverse (PTR) record — forgetting it is the usual mistake")}
          </label>
        )}
        <div className="operations">
          <button disabled={!selected || !name || !value} onClick={() => request.mutate(record(true))}>
            {t("Plan record")}
          </button>
          <button className="secondary" disabled={!selected || !name || !value}
                  onClick={() => request.mutate(record(false))}>
            {t("Plan removal")}
          </button>
        </div>
        {message && <p className="source" style={{ margin: 0 }}>{message}</p>}
      </div>

      {records.error ? (
        <ErrorBox error={records.error} />
      ) : !(records.data?.items ?? []).length ? (
        <Empty>{t("This zone has no records the panel can read.")}</Empty>
      ) : (
        <table>
          <thead><tr><th>{t("Name")}</th><th>{t("Type")}</th><th>{t("Value")}</th><th>TTL</th></tr></thead>
          <tbody>
            {(records.data?.items ?? []).map((item, index) => (
              <tr key={`${item.name}-${item.type}-${index}`}>
                <td>{item.name}</td>
                <td>{item.type}</td>
                <td className="source">{item.values.join(", ")}</td>
                <td>{item.ttl || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
