import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../lib/api";
import type { AccessSimulation, DirectoryChange, DirectoryGroup, DirectoryUser, HBACRule, SudoRule } from "../lib/types";
import { ErrorBox, Empty } from "../components/ui";
import { Actions, Card, Field, FieldGrid, PageHeader, Toolbar } from "../components/layout";
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
      <PageHeader
        title={t("Identity directory")}
        description={status.data?.configured === false
          ? t("No directory connector is configured.")
          : status.data?.reachable
            ? `${status.data.summary} · ${t("connector")}: ${status.data.principal}`
            : status.data?.error
              ? t("Directory unavailable: {error}", { error: status.data.error })
              : t("Checking…")}
      />

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
  return <Card><Empty>{t("You do not have permission to read this resource.")}</Empty></Card>;
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
  if (!data?.items.length) return <Card><Empty>{t("No accounts.")}</Empty></Card>;

  return (
    <Card flush>
      <table>
        <thead><tr><th>{t("Account")}</th><th>{t("Full name")}</th><th className="num">UID</th><th>{t("Groups")}</th><th className="num">{t("SSH keys")}</th><th>{t("State")}</th></tr></thead>
        <tbody>
          {data.items.map((user) => (
            <tr key={user.uid}>
              <td className="mono">{user.uid}</td>
              <td>{[user.first_name, user.last_name].filter(Boolean).join(" ")}</td>
              <td className="num">{user.uid_number || "—"}</td>
              <td>{(user.groups ?? []).join(", ") || "—"}</td>
              <td className="num">{user.ssh_key_fingerprints?.length ?? 0}</td>
              <td>{user.disabled ? <span className="badge error">{t("locked")}</span> : <span className="badge ok">{t("active")}</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
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
  if (!data?.items.length) return <Card><Empty>{t("No groups.")}</Empty></Card>;

  return (
    <Card flush>
      <table>
        <thead><tr><th>{t("Group")}</th><th className="num">GID</th><th>{t("Description")}</th><th>{t("Members")}</th></tr></thead>
        <tbody>
          {data.items.map((group) => (
            <tr key={group.name}>
              <td className="mono">{group.name}</td>
              <td className="num">{group.gid_number || "—"}</td>
              <td>{group.description || "—"}</td>
              <td>{(group.members ?? []).join(", ") || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

/** Splits a comma-separated field into names; blanks fall out. */
function names(text: string): string[] {
  return text.split(",").map((item) => item.trim()).filter(Boolean);
}

/** A field holding a list of names, typed as one comma-separated line. */
function ListField({ label, value, onChange, placeholder, disabled }: {
  label: string; value: string; onChange: (value: string) => void; placeholder?: string; disabled?: boolean;
}) {
  return (
    <Field label={label}>
      <input value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} disabled={disabled} />
    </Field>
  );
}

/**
 * The impact of a planned change, shown as the plan came back: the hosts
 * and users the rule reaches, the diff against the rule of the same name,
 * the warnings and the conflicts. The approval by a second person happens
 * on the change itself; this is what that person is going to read.
 */
function PlanImpact({ change }: { change: DirectoryChange }) {
  const t = useT();
  const plan = change.plan;
  if (!plan) return null;
  const conflicts = plan.conflicts ?? [];
  const warnings = plan.warnings ?? [];
  return (
    <Card
      title={plan.summary}
      tone={conflicts.length ? "error" : warnings.length ? "warn" : undefined}
      description={
        conflicts.length
          ? t("Change {id} is blocked by conflicts and cannot be approved.", { id: change.id.slice(0, 8) })
          : t("Change {id} is {state}; a second person approves it with a reason.", { id: change.id.slice(0, 8), state: change.state.replace("_", " ") })
      }
    >
      {conflicts.map((conflict, index) => (
        <p key={index} className="warning"><span>{conflict}</span></p>
      ))}
      {warnings.map((warning, index) => (
        <p key={index} className="warning"><span>{warning}</span></p>
      ))}
      <ul className="source">
        {(plan.steps ?? []).map((step, index) => <li key={index}>{step}</li>)}
      </ul>
      <p className="source">
        <strong>{t("Hosts reached ({n})", { n: (plan.reachable_hosts ?? []).length })}:</strong>{" "}
        <span className="mono">{(plan.reachable_hosts ?? []).join(", ") || "—"}</span>
      </p>
      <p className="source">
        <strong>{t("Users reached ({n})", { n: (plan.affected_users ?? []).length })}:</strong>{" "}
        <span className="mono">{(plan.affected_users ?? []).join(", ") || "—"}</span>
      </p>
    </Card>
  );
}

/** Orders a directory change and keeps the answer for the impact card. */
function useDirectoryChange(invalidate: string[]) {
  const t = useT();
  const queryClient = useQueryClient();
  const [change, setChange] = useState<DirectoryChange | null>(null);
  const [message, setMessage] = useState("");
  const mutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post<DirectoryChange>("/api/v1/identity/changes", body),
    onSuccess: (result) => {
      setChange(result);
      setMessage("");
      for (const key of invalidate) queryClient.invalidateQueries({ queryKey: [key] });
      queryClient.invalidateQueries({ queryKey: ["directory-changes"] });
    },
    onError: (error) => {
      setChange(null);
      setMessage(error instanceof ApiError && error.code === "reason_required"
        ? t("A change of access needs a reason of at least 8 characters.")
        : error instanceof Error ? error.message : String(error));
    },
  });
  return { mutation, change, message };
}

const EMPTY_HBAC = {
  name: "", description: "", enabled: true,
  users: "", user_groups: "", hosts: "", host_groups: "", services: "sshd", service_groups: "",
  all_users: false, all_hosts: false, all_services: false,
};

type HBACForm = typeof EMPTY_HBAC;

function hbacFormOf(rule: HBACRule): HBACForm {
  return {
    name: rule.name, description: rule.description ?? "", enabled: rule.enabled,
    users: (rule.users ?? []).join(", "), user_groups: (rule.user_groups ?? []).join(", "),
    hosts: (rule.hosts ?? []).join(", "), host_groups: (rule.host_groups ?? []).join(", "),
    services: (rule.services ?? []).join(", "), service_groups: (rule.service_groups ?? []).join(", "),
    all_users: rule.all_users, all_hosts: rule.all_hosts, all_services: rule.all_services,
  };
}

function HBACRules() {
  const t = useT();
  const [form, setForm] = useState<HBACForm | null>(null);
  const [editing, setEditing] = useState(false);
  const [reason, setReason] = useState("");
  const { mutation, change, message } = useDirectoryChange(["identity-hbac"]);

  const { data, error } = useQuery({
    queryKey: ["identity-hbac"],
    queryFn: () => api.get<Collection<HBACRule>>("/api/v1/identity/hbac-rules"),
    retry: false,
  });
  if (error instanceof ApiError && error.forbidden) return <Forbidden />;
  if (error) return <ErrorBox error={error} />;

  const set = <K extends keyof HBACForm>(key: K, value: HBACForm[K]) =>
    setForm((current) => (current ? { ...current, [key]: value } : current));

  const payload = (f: HBACForm) => ({
    hbac_rule: {
      name: f.name.trim(), description: f.description.trim(), enabled: f.enabled,
      users: names(f.users), user_groups: names(f.user_groups),
      hosts: names(f.hosts), host_groups: names(f.host_groups),
      services: names(f.services), service_groups: names(f.service_groups),
      all_users: f.all_users, all_hosts: f.all_hosts, all_services: f.all_services,
    },
  });

  return (
    <>
      <p className="subtitle">
        {t("An HBAC rule says who may enter which hosts through which services. A rule is declared as a whole and the directory is brought to it; the plan shows the hosts and users it reaches and the diff against the rule of the same name before a second person approves.")}
      </p>

      <Toolbar end={<span>{t("{n} rules", { n: (data?.items ?? []).length })}</span>}>
        <button onClick={() => { setForm({ ...EMPTY_HBAC }); setEditing(false); }}>{t("New rule")}</button>
      </Toolbar>

      {form && (
        <Card
          title={editing ? t("Edit rule {name}", { name: form.name }) : t("New HBAC rule")}
          footer={
            <Actions>
              <button disabled={!form.name || reason.trim().length < 8 || mutation.isPending}
                      onClick={() => mutation.mutate({ action: "identity.hbac.rule.ensure", reason, payload: payload(form) })}>
                {t("Plan rule")}
              </button>
              {editing && (
                <button className="secondary" disabled={reason.trim().length < 8 || mutation.isPending}
                        onClick={() => mutation.mutate({ action: "identity.hbac.rule.remove", reason, payload: { hbac_rule: { name: form.name } } })}>
                  {t("Plan removal")}
                </button>
              )}
              <button className="secondary" onClick={() => setForm(null)}>{t("Close")}</button>
              {message && <p className="page-error">{message}</p>}
            </Actions>
          }
        >
          <FieldGrid>
            <Field label={t("Name")}>
              <input value={form.name} onChange={(e) => set("name", e.target.value)} disabled={editing}
                     placeholder="ops-ssh" />
            </Field>
            <Field label={t("Description")} wide>
              <input value={form.description} onChange={(e) => set("description", e.target.value)} />
            </Field>
            <ListField label={t("Users")} value={form.users} onChange={(v) => set("users", v)}
                       placeholder="alice, bob" disabled={form.all_users} />
            <ListField label={t("User groups")} value={form.user_groups} onChange={(v) => set("user_groups", v)}
                       placeholder="ops" disabled={form.all_users} />
            <ListField label={t("Hosts")} value={form.hosts} onChange={(v) => set("hosts", v)}
                       placeholder="web1.example.test" disabled={form.all_hosts} />
            <ListField label={t("Host groups")} value={form.host_groups} onChange={(v) => set("host_groups", v)}
                       placeholder="web" disabled={form.all_hosts} />
            <ListField label={t("Services")} value={form.services} onChange={(v) => set("services", v)}
                       placeholder="sshd, sudo" disabled={form.all_services} />
            <ListField label={t("Service groups")} value={form.service_groups} onChange={(v) => set("service_groups", v)}
                       placeholder="Sudo" disabled={form.all_services} />
          </FieldGrid>
          <label className="toggle">
            <input type="checkbox" checked={form.enabled} onChange={(e) => set("enabled", e.target.checked)} />
            {t("Enabled — a disabled rule is a draft and may be incomplete")}
          </label>
          <label className="toggle">
            <input type="checkbox" checked={form.all_users} onChange={(e) => set("all_users", e.target.checked)} />
            {t("Every user, instead of the listed users and groups")}
          </label>
          <label className="toggle">
            <input type="checkbox" checked={form.all_hosts} onChange={(e) => set("all_hosts", e.target.checked)} />
            {t("Every host, instead of the listed hosts and host groups")}
          </label>
          <label className="toggle">
            <input type="checkbox" checked={form.all_services} onChange={(e) => set("all_services", e.target.checked)} />
            {t("Every service, instead of the listed services")}
          </label>
          <FieldGrid>
            <Field label={t("Reason")} wide hint={t("A change of access is recorded with a reason and fresh authentication.")}>
              <input value={reason} onChange={(e) => setReason(e.target.value)}
                     placeholder={t("why this rule changes (min. 8 characters)")} />
            </Field>
          </FieldGrid>
        </Card>
      )}

      {change && <PlanImpact change={change} />}

      <Card flush>
        {!data?.items.length ? (
          <Empty>{t("No rules.")}</Empty>
        ) : (
          <table>
            <thead><tr><th>{t("Rule")}</th><th>{t("Enabled")}</th><th>{t("Who")}</th><th>{t("Hosts")}</th><th>{t("Services")}</th><th>{t("Risk")}</th><th></th></tr></thead>
            <tbody>
              {data.items.map((rule) => (
                <tr key={rule.name}>
                  <td>{rule.name}</td>
                  <td>{rule.enabled ? t("yes") : t("no")}</td>
                  <td>{rule.all_users ? t("every user") : [...(rule.users ?? []), ...(rule.user_groups ?? [])].join(", ") || "—"}</td>
                  <td>{rule.all_hosts ? t("every host") : [...(rule.hosts ?? []), ...(rule.host_groups ?? [])].join(", ") || "—"}</td>
                  <td>{rule.all_services ? t("every service") : [...(rule.services ?? []), ...(rule.service_groups ?? [])].join(", ") || "—"}</td>
                  <td>
                    {rule.allows_everything
                      ? <span className="badge error">{t("covers the whole fleet")}</span>
                      : <span className="badge">{t("narrowed")}</span>}
                  </td>
                  <td className="num">
                    <button className="secondary" onClick={() => { setForm(hbacFormOf(rule)); setEditing(true); }}>{t("Edit")}</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <SimulateAccess />
    </>
  );
}

/**
 * The directory's own answer to "may this user use this service on this
 * host". The verdict comes from the directory rather than from the panel,
 * so it is the one the host applies.
 */
function SimulateAccess() {
  const t = useT();
  const [user, setUser] = useState("");
  const [host, setHost] = useState("");
  const [service, setService] = useState("sshd");
  const simulate = useMutation({
    mutationFn: () => api.post<AccessSimulation>("/api/v1/identity/access/simulate", { user, host, service }),
  });
  const result = simulate.data;

  return (
    <Card
      title={t("Simulate access")}
      description={t("Ask the directory whether a user may use a service on a host. The answer is the directory's verdict, not a guess of the panel.")}
      footer={
        <Actions>
          <button disabled={!user || !host || simulate.isPending} onClick={() => simulate.mutate()}>{t("Simulate")}</button>
          {simulate.error && <p className="page-error">{simulate.error instanceof Error ? simulate.error.message : String(simulate.error)}</p>}
          {result && (
            <p className="source">
              {result.allowed
                ? <span className="badge ok">{t("allowed")}</span>
                : <span className="badge error">{t("denied")}</span>}
              {" "}
              {t("matched: {rules}", { rules: result.matched.join(", ") || "—" })}
              {" · "}
              {t("not matched: {rules}", { rules: result.not_matched.join(", ") || "—" })}
              {(result.errors ?? []).length > 0 && ` · ${t("could not evaluate: {rules}", { rules: (result.errors ?? []).join(", ") })}`}
              {(result.warnings ?? []).length > 0 && ` · ${(result.warnings ?? []).join("; ")}`}
            </p>
          )}
        </Actions>
      }
    >
      <FieldGrid>
        <Field label={t("User")}>
          <input value={user} onChange={(e) => setUser(e.target.value)} placeholder="alice" />
        </Field>
        <Field label={t("Host")}>
          <input value={host} onChange={(e) => setHost(e.target.value)} placeholder="web1.example.test" />
        </Field>
        <Field label={t("Service")}>
          <input value={service} onChange={(e) => setService(e.target.value)} placeholder="sshd" />
        </Field>
      </FieldGrid>
    </Card>
  );
}

const EMPTY_SUDO = {
  name: "", description: "", enabled: true,
  users: "", user_groups: "", hosts: "", host_groups: "",
  commands: "", command_groups: "", run_as_users: "root", run_as_groups: "", options: "",
  all_users: false, all_hosts: false, all_commands: false, run_as_any_user: false,
};

type SudoForm = typeof EMPTY_SUDO;

function sudoFormOf(rule: SudoRule): SudoForm {
  return {
    name: rule.name, description: rule.description ?? "", enabled: rule.enabled,
    users: (rule.users ?? []).join(", "), user_groups: (rule.user_groups ?? []).join(", "),
    hosts: (rule.hosts ?? []).join(", "), host_groups: (rule.host_groups ?? []).join(", "),
    commands: (rule.commands ?? []).join(", "), command_groups: (rule.command_groups ?? []).join(", "),
    run_as_users: (rule.run_as ?? []).join(", "), run_as_groups: (rule.run_as_groups ?? []).join(", "),
    options: (rule.options ?? []).join(", "),
    all_users: rule.all_users, all_hosts: rule.all_hosts, all_commands: rule.all_commands,
    run_as_any_user: rule.run_as_any_user,
  };
}

function SudoRules() {
  const t = useT();
  const [form, setForm] = useState<SudoForm | null>(null);
  const [editing, setEditing] = useState(false);
  const [reason, setReason] = useState("");
  const { mutation, change, message } = useDirectoryChange(["identity-sudo"]);

  const { data, error } = useQuery({
    queryKey: ["identity-sudo"],
    queryFn: () => api.get<Collection<SudoRule>>("/api/v1/identity/sudo-rules"),
    retry: false,
  });
  if (error instanceof ApiError && error.forbidden) return <Forbidden />;
  if (error) return <ErrorBox error={error} />;

  const set = <K extends keyof SudoForm>(key: K, value: SudoForm[K]) =>
    setForm((current) => (current ? { ...current, [key]: value } : current));

  const payload = (f: SudoForm) => ({
    sudo_rule: {
      name: f.name.trim(), description: f.description.trim(), enabled: f.enabled,
      users: names(f.users), user_groups: names(f.user_groups),
      hosts: names(f.hosts), host_groups: names(f.host_groups),
      commands: names(f.commands), command_groups: names(f.command_groups),
      run_as_users: names(f.run_as_users), run_as_groups: names(f.run_as_groups),
      options: names(f.options),
      all_users: f.all_users, all_hosts: f.all_hosts, all_commands: f.all_commands,
      run_as_any_user: f.run_as_any_user,
    },
  });

  return (
    <>
      <p className="subtitle">
        {t("A sudo rule says who may run which commands as whom on which hosts. Every command, no password (!authenticate) and running as root are named in the plan one by one, so the person approving reads what the rule grants rather than a single word.")}
      </p>

      <Toolbar end={<span>{t("{n} rules", { n: (data?.items ?? []).length })}</span>}>
        <button onClick={() => { setForm({ ...EMPTY_SUDO }); setEditing(false); }}>{t("New rule")}</button>
      </Toolbar>

      {form && (
        <Card
          title={editing ? t("Edit rule {name}", { name: form.name }) : t("New sudo rule")}
          footer={
            <Actions>
              <button disabled={!form.name || reason.trim().length < 8 || mutation.isPending}
                      onClick={() => mutation.mutate({ action: "identity.sudo.rule.ensure", reason, payload: payload(form) })}>
                {t("Plan rule")}
              </button>
              {editing && (
                <button className="secondary" disabled={reason.trim().length < 8 || mutation.isPending}
                        onClick={() => mutation.mutate({ action: "identity.sudo.rule.remove", reason, payload: { sudo_rule: { name: form.name } } })}>
                  {t("Plan removal")}
                </button>
              )}
              <button className="secondary" onClick={() => setForm(null)}>{t("Close")}</button>
              {message && <p className="page-error">{message}</p>}
            </Actions>
          }
        >
          <FieldGrid>
            <Field label={t("Name")}>
              <input value={form.name} onChange={(e) => set("name", e.target.value)} disabled={editing}
                     placeholder="ops-restart" />
            </Field>
            <Field label={t("Description")} wide>
              <input value={form.description} onChange={(e) => set("description", e.target.value)} />
            </Field>
            <ListField label={t("Users")} value={form.users} onChange={(v) => set("users", v)}
                       placeholder="alice, bob" disabled={form.all_users} />
            <ListField label={t("User groups")} value={form.user_groups} onChange={(v) => set("user_groups", v)}
                       placeholder="ops" disabled={form.all_users} />
            <ListField label={t("Hosts")} value={form.hosts} onChange={(v) => set("hosts", v)}
                       placeholder="web1.example.test" disabled={form.all_hosts} />
            <ListField label={t("Host groups")} value={form.host_groups} onChange={(v) => set("host_groups", v)}
                       placeholder="web" disabled={form.all_hosts} />
            <ListField label={t("Commands")} value={form.commands} onChange={(v) => set("commands", v)}
                       placeholder="/usr/bin/systemctl, /usr/bin/journalctl" disabled={form.all_commands} />
            <ListField label={t("Command groups")} value={form.command_groups} onChange={(v) => set("command_groups", v)}
                       placeholder="services" disabled={form.all_commands} />
            <ListField label={t("Run as users")} value={form.run_as_users} onChange={(v) => set("run_as_users", v)}
                       placeholder="root" disabled={form.run_as_any_user} />
            <ListField label={t("Run as groups")} value={form.run_as_groups} onChange={(v) => set("run_as_groups", v)}
                       placeholder="wheel" />
            <ListField label={t("Options")} value={form.options} onChange={(v) => set("options", v)}
                       placeholder="!authenticate, !requiretty" />
          </FieldGrid>
          <label className="toggle">
            <input type="checkbox" checked={form.enabled} onChange={(e) => set("enabled", e.target.checked)} />
            {t("Enabled — a disabled rule is a draft and may be incomplete")}
          </label>
          <label className="toggle">
            <input type="checkbox" checked={form.all_users} onChange={(e) => set("all_users", e.target.checked)} />
            {t("Every user, instead of the listed users and groups")}
          </label>
          <label className="toggle">
            <input type="checkbox" checked={form.all_hosts} onChange={(e) => set("all_hosts", e.target.checked)} />
            {t("Every host, instead of the listed hosts and host groups")}
          </label>
          <label className="toggle">
            <input type="checkbox" checked={form.all_commands} onChange={(e) => set("all_commands", e.target.checked)} />
            {t("Every command — together with root this is full root access")}
          </label>
          <label className="toggle">
            <input type="checkbox" checked={form.run_as_any_user} onChange={(e) => set("run_as_any_user", e.target.checked)} />
            {t("Run as any user, instead of the listed run-as users")}
          </label>
          <FieldGrid>
            <Field label={t("Reason")} wide hint={t("A change of access is recorded with a reason and fresh authentication.")}>
              <input value={reason} onChange={(e) => setReason(e.target.value)}
                     placeholder={t("why this rule changes (min. 8 characters)")} />
            </Field>
          </FieldGrid>
        </Card>
      )}

      {change && <PlanImpact change={change} />}

      <Card flush>
        {!data?.items.length ? (
          <Empty>{t("No sudo rules.")}</Empty>
        ) : (
          <table>
            <thead><tr><th>{t("Rule")}</th><th>{t("Enabled")}</th><th>{t("Applies to")}</th><th>{t("Hosts")}</th><th>{t("Commands")}</th><th>{t("Risk")}</th><th></th></tr></thead>
            <tbody>
              {data.items.map((rule) => (
                <tr key={rule.name}>
                  <td>{rule.name}</td>
                  <td>{rule.enabled ? t("yes") : t("no")}</td>
                  <td>{rule.all_users ? t("every user") : [...(rule.users ?? []), ...(rule.user_groups ?? [])].join(", ") || "—"}</td>
                  <td>{rule.all_hosts ? t("every host") : [...(rule.hosts ?? []), ...(rule.host_groups ?? [])].join(", ") || "—"}</td>
                  <td className="mono">{rule.all_commands ? t("every command") : [...(rule.commands ?? []), ...(rule.command_groups ?? [])].join(", ") || "—"}</td>
                  <td>
                    {rule.critical
                      ? <span className="badge error" title={(rule.critical_reasons ?? []).join("; ")}>{t("critical")}</span>
                      : "—"}
                  </td>
                  <td className="num">
                    <button className="secondary" onClick={() => { setForm(sudoFormOf(rule)); setEditing(true); }}>{t("Edit")}</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}

type Zone = { name: string; reverse: boolean };

type DNSRecord = { zone: string; name: string; type: string; values: string[]; ttl?: number };

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

      {/* The zone is chosen once, for the form and for the list below it. */}
      <Toolbar end={<span>{t("{n} records", { n: (records.data?.items ?? []).length })}</span>}>
        <select value={selected} onChange={(e) => setZone(e.target.value)}>
          {(zones.data?.items ?? []).map((item) => (
            <option key={item.name} value={item.name}>
              {item.name}{item.reverse ? ` (${t("reverse")})` : ""}
            </option>
          ))}
        </select>
      </Toolbar>

      <Card
        footer={
          <Actions>
            <button disabled={!selected || !name || !value} onClick={() => request.mutate(record(true))}>
              {t("Plan record")}
            </button>
            <button className="secondary" disabled={!selected || !name || !value}
                    onClick={() => request.mutate(record(false))}>
              {t("Plan removal")}
            </button>
            {message && <p className="source">{message}</p>}
          </Actions>
        }
      >
        <FieldGrid>
          <Field label={t("Name")}>
            <input value={name} onChange={(e) => setName(e.target.value)}
                   placeholder={t("name (web, @, _ldap._tcp)")} />
          </Field>
          <Field label={t("Type")}>
            <select value={type} onChange={(e) => setType(e.target.value)}>
              {["A", "AAAA", "CNAME", "TXT", "SRV", "PTR"].map((item) => (
                <option key={item} value={item}>{item}</option>
              ))}
            </select>
          </Field>
          <Field label={t("Value")}>
            <input value={value} onChange={(e) => setValue(e.target.value)}
                   placeholder={t("value (10.0.0.5)")} />
          </Field>
          <Field label="TTL">
            <input value={ttl} onChange={(e) => setTtl(e.target.value)}
                   placeholder="TTL" />
          </Field>
        </FieldGrid>
        {(type === "A" || type === "AAAA") && (
          <label className="toggle">
            <input type="checkbox" checked={reverse} onChange={(e) => setReverse(e.target.checked)} />
            {t("Also write the reverse (PTR) record — forgetting it is the usual mistake")}
          </label>
        )}
      </Card>

      <Card flush>
        {records.error ? (
          <ErrorBox error={records.error} />
        ) : !(records.data?.items ?? []).length ? (
          <Empty>{t("This zone has no records the panel can read.")}</Empty>
        ) : (
          <table>
            <thead><tr><th>{t("Name")}</th><th>{t("Type")}</th><th>{t("Value")}</th><th className="num">TTL</th></tr></thead>
            <tbody>
              {(records.data?.items ?? []).map((item, index) => (
                <tr key={`${item.name}-${item.type}-${index}`}>
                  <td className="mono">{item.name}</td>
                  <td>{item.type}</td>
                  <td className="source mono">{item.values.join(", ")}</td>
                  <td className="num">{item.ttl || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}
