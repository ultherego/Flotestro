import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../lib/api";
import type { GroupMapping, Principal } from "../lib/types";
import { ErrorBox, Time, Empty } from "../components/ui";
import { Actions, Card, EmptyState, Field, FieldGrid, PageHeader } from "../components/layout";
import { CertificateAuthority } from "./CertificateAuthority";
import { useT } from "../i18n";

const ROLES = [
  "viewer", "auditor", "operator", "approver", "identity_admin", "platform_admin",
];

/**
 * Panel access management.
 *
 * These operations change the access rules themselves, so the panel demands
 * a fresh authentication and a reason. The reason lands in the audit trail
 * together with the description of the change.
 */
export function Access() {
  const t = useT();
  const [tab, setTab] = useState<"mappings" | "identities" | "ca">("mappings");
  const [warning, setWarning] = useState<ApiError | null>(null);

  return (
    <>
      <PageHeader
        title={t("Access")}
        description={t("Mapping of identity provider groups to roles, plus local identities. A group in the token grants nothing by itself - the role comes from the mapping.")}
      />

      <div className="tabs">
        <button className={tab === "mappings" ? "active" : ""} onClick={() => setTab("mappings")}>
          {t("Group mappings")}
        </button>
        <button className={tab === "identities" ? "active" : ""} onClick={() => setTab("identities")}>
          {t("Identities")}
        </button>
        <button className={tab === "ca" ? "active" : ""} onClick={() => setTab("ca")}>
          {t("Fleet CA")}
        </button>
      </div>

      {tab === "ca" && <Warning error={warning} close={() => setWarning(null)} />}
      {tab === "mappings" && <Mappings />}
      {tab === "identities" && <Identities />}
      {tab === "ca" && <CertificateAuthority reportError={setWarning} />}
    </>
  );
}

function Mappings() {
  const t = useT();
  const queryClient = useQueryClient();
  const [warning, setWarning] = useState<ApiError | null>(null);
  const [form, setForm] = useState(false);
  const [group, setGroup] = useState("");
  const [role, setRole] = useState("viewer");
  const [site, setSite] = useState("");
  const [environment, setEnvironment] = useState("");
  const [reason, setReason] = useState("");

  const list = useQuery({
    queryKey: ["group-mappings"],
    queryFn: () => api.get<Collection<GroupMapping>>("/api/v1/group-mappings"),
    retry: false,
  });

  const refresh = () => queryClient.invalidateQueries({ queryKey: ["group-mappings"] });

  const add = useMutation({
    mutationFn: () =>
      api.post<GroupMapping>("/api/v1/group-mappings", {
        group_name: group.trim(), role,
        site: site.trim(), environment: environment.trim(), reason: reason.trim(),
      }),
    onSuccess: () => { setForm(false); setGroup(""); setReason(""); refresh(); },
    onError: (error) => setWarning(error instanceof ApiError ? error : null),
  });

  const remove = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.del(`/api/v1/group-mappings/${id}?reason=${encodeURIComponent(reason)}`),
    onSuccess: refresh,
    onError: (error) => setWarning(error instanceof ApiError ? error : null),
  });

  if (list.error instanceof ApiError && list.error.forbidden) {
    return <Card><Empty>{t("You do not have permission to manage access.")}</Empty></Card>;
  }
  if (list.error) return <ErrorBox error={list.error} />;

  return (
    <>
      <Warning error={warning} close={() => setWarning(null)} />

      <Card
        title={t("Group mappings")}
        actions={!form && <button onClick={() => setForm(true)}>{t("Add mapping")}</button>}
        flush
      >
        {list.data?.items.length ? (
          <table>
            <thead>
              <tr><th>{t("Group")}</th><th>{t("Role")}</th><th>{t("Scope")}</th><th>{t("Added by")}</th><th>{t("When")}</th><th /></tr>
            </thead>
            <tbody>
              {list.data.items.map((mapping) => (
                <tr key={mapping.id}>
                  <td className="mono">{mapping.group_name}</td>
                  <td>{mapping.role}</td>
                  <td className="source">
                    {mapping.site || "*"} / {mapping.environment || "*"}
                  </td>
                  <td className="source">{mapping.created_by}</td>
                  <td><Time value={mapping.created_at} /></td>
                  <td className="actions-cell">
                    <div className="row-actions">
                      <button
                        className="danger"
                        onClick={() => {
                          const reason = window.prompt(
                            t("Reason for removing the group mapping {group} (min. 8 characters):", { group: mapping.group_name }),
                          );
                          if (reason) remove.mutate({ id: mapping.id, reason });
                        }}
                      >
                        {t("Remove")}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <EmptyState action={!form && <button onClick={() => setForm(true)}>{t("Add mapping")}</button>}>
            {t("No mappings. Without them nobody gets a role from the identity provider.")}
          </EmptyState>
        )}
      </Card>

      {form && (
        <Card
          title={t("New mapping")}
          footer={
            <Actions>
              <button disabled={!group.trim() || reason.trim().length < 8 || add.isPending}
                      onClick={() => add.mutate()}>
                {t("Add mapping")}
              </button>
              <button className="secondary" onClick={() => setForm(false)}>{t("Cancel")}</button>
            </Actions>
          }
        >
          <FieldGrid>
            <Field label={t("Identity provider group")}>
              <input value={group} onChange={(e) => setGroup(e.target.value)} placeholder="flotestro-operators" />
            </Field>
            <Field label={t("Role")}>
              <select value={role} onChange={(e) => setRole(e.target.value)}>
                {ROLES.map((name) => <option key={name} value={name}>{name}</option>)}
              </select>
            </Field>
            <Field label={t("Site (empty = all)")}>
              <input value={site} onChange={(e) => setSite(e.target.value)} placeholder="lab" />
            </Field>
            <Field label={t("Environment (empty = all)")}>
              <input value={environment} onChange={(e) => setEnvironment(e.target.value)} placeholder="test" />
            </Field>
            <Field label={t("Reason for the change")} wide>
              <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder={t("e.g. new on-call team")} />
            </Field>
          </FieldGrid>
        </Card>
      )}
    </>
  );
}

function Identities() {
  const t = useT();
  const { data, error } = useQuery({
    queryKey: ["principals"],
    queryFn: () => api.get<Collection<Principal>>("/api/v1/principals"),
    retry: false,
  });
  if (error instanceof ApiError && error.forbidden) {
    return <Card><Empty>{t("You do not have permission to manage access.")}</Empty></Card>;
  }
  if (error) return <ErrorBox error={error} />;
  if (!data?.items.length) return <Card><Empty>{t("No identities.")}</Empty></Card>;

  return (
    <Card title={t("Identities")} flush>
      <table>
        <thead><tr><th>{t("Subject")}</th><th>{t("Name")}</th><th>{t("Kind")}</th><th>{t("Roles and scopes")}</th></tr></thead>
        <tbody>
          {data.items.map((principal) => (
            <tr key={principal.id}>
              <td className="mono">{principal.subject}</td>
              <td>{principal.display_name || "—"}</td>
              <td className="source">{principal.kind}</td>
              <td>
                {/* The field may not arrive at all. The interface must not
                    fall over because of it: one missing key used to take the
                    whole screen down. */}
                {(principal.bindings ?? []).length === 0
                  ? <span className="source">{t("no direct assignments; roles may come from group mappings")}</span>
                  : (principal.bindings ?? []).map((binding, index) => (
                      <div key={index}>
                        {binding.role}
                        <span className="source">
                          {" "}{binding.scope.site || "*"} / {binding.scope.environment || "*"}
                        </span>
                      </div>
                    ))}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

/**
 * A refusal because of a stale authentication is not an application error:
 * the panel is to offer signing in again and come back to the same place.
 */
function Warning({ error, close }: { error: ApiError | null; close: () => void }) {
  const t = useT();
  if (!error) return null;

  if (error.code === "reauthentication_required") {
    return (
      <div className="warning">
        <div>
          <strong>{t("Re-authentication required.")}</strong> {error.message}
        </div>
        <div className="operations">
          <button
            onClick={() => {
              const target = encodeURIComponent(window.location.pathname);
              window.location.href = `/auth/login?step_up=1&redirect=${target}`;
            }}
          >
            {t("Sign in again")}
          </button>
          <button className="secondary" onClick={close}>{t("Close")}</button>
        </div>
      </div>
    );
  }
  return (
    <div className="warning">
      <div>{error.message}</div>
      <div className="operations"><button onClick={close}>{t("Close")}</button></div>
    </div>
  );
}
