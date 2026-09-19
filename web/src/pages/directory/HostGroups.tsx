import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiError, type Collection } from "../../lib/api";
import type { DirectoryHostGroup } from "../../lib/types";
import { ErrorBox, Empty } from "../../components/ui";
import { Actions, Card, FieldGrid, Toolbar } from "../../components/layout";
import { useT } from "../../i18n";
import { Forbidden, ListField, PlanImpact, ReasonField, names, useDirectoryChange } from "./shared";

/**
 * The host groups of the directory.
 */
export function HostGroups() {
  const t = useT();
  const [editing, setEditing] = useState<DirectoryHostGroup | null>(null);
  const [add, setAdd] = useState("");
  const [remove, setRemove] = useState("");
  const [reason, setReason] = useState("");
  const { mutation, change, message } = useDirectoryChange(["identity-host-groups", "identity-hosts"]);

  const { data, error } = useQuery({
    queryKey: ["identity-host-groups"],
    queryFn: () => api.get<Collection<DirectoryHostGroup>>("/api/v1/identity/host-groups"),
    retry: false,
  });
  if (error instanceof ApiError && error.forbidden) return <Forbidden />;
  if (error) return <ErrorBox error={error} />;

  const open = (group: DirectoryHostGroup) => {
    setEditing(group);
    setAdd("");
    setRemove("");
  };

  return (
    <>
      <p className="subtitle">
        {t("Host groups are what the access and sudo rules point at, so a host moved into one gains every rule that names the group. The plan lists those rules before a second person approves. Directory host groups and panel groups have separate lifecycles: one is read by SSSD on the hosts, the other by the panel alone.")}
      </p>

      <Toolbar end={<span>{t("{n} host groups", { n: (data?.items ?? []).length })}</span>} />

      {editing && (
        <Card
          title={t("Members of the host group {name}", { name: editing.name })}
          description={t("Hosts by their FQDN, as the directory knows them. A host the directory has no entry for is a conflict of the plan.")}
          footer={
            <Actions>
              <button disabled={(!names(add).length && !names(remove).length) || reason.trim().length < 8 || mutation.isPending}
                      onClick={() => mutation.mutate({
                        action: "identity.hostgroup.members", reason,
                        payload: { host_group: { group: editing.name, add: names(add), remove: names(remove) } },
                      }, { onSuccess: () => setEditing(null) })}>
                {t("Plan membership change")}
              </button>
              <button className="secondary" onClick={() => setEditing(null)}>{t("Close")}</button>
              {message && <p className="page-error">{message}</p>}
            </Actions>
          }
        >
          <p className="source">
            <strong>{t("Current members ({n})", { n: (editing.hosts ?? []).length })}:</strong>{" "}
            <span className="mono">{(editing.hosts ?? []).join(", ") || "—"}</span>
          </p>
          <FieldGrid>
            <ListField label={t("Add hosts")} value={add} onChange={setAdd} placeholder="web1.example.test, web2.example.test" />
            <ListField label={t("Remove hosts")} value={remove} onChange={setRemove} placeholder="old.example.test" />
            <ReasonField value={reason} onChange={setReason} />
          </FieldGrid>
        </Card>
      )}

      {change && <PlanImpact change={change} />}

      <Card flush>
        {!data?.items.length ? (
          <Empty>{t("The directory has no host groups.")}</Empty>
        ) : (
          <table>
            <thead><tr><th>{t("Host group")}</th><th>{t("Description")}</th><th>{t("Hosts")}</th><th>{t("Nested groups")}</th><th></th></tr></thead>
            <tbody>
              {data.items.map((group) => (
                <tr key={group.name}>
                  <td className="mono">{group.name}</td>
                  <td>{group.description || "—"}</td>
                  <td className="mono">{(group.hosts ?? []).join(", ") || "—"}</td>
                  <td>{(group.host_groups ?? []).join(", ") || "—"}</td>
                  <td className="num">
                    <button className="secondary" onClick={() => open(group)}>{t("Edit members")}</button>
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
