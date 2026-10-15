import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { Card, Toolbar } from "../components/layout";
import { Empty, ErrorBox } from "../components/ui";
import { useT } from "../i18n";

/**
 * Who may sign in to this panel, and where each one's access comes from.
 *
 * The identities list answers a narrower question than it looks like it
 * answers: it holds the people the panel has a record of, and a person gets
 * a record at their first sign-in. The owner found that out on 15.10 - his
 * directory account holds a role through a group, so the panel had never
 * seen it and the screen showed him rows of leftovers from the test suites.
 *
 * This is the other question. A directory user in a mapped group is here
 * whether or not they have ever signed in, with the group that grants their
 * role and the scope it grants it in.
 */

type HolderRole = { role: string; scope: string; from: string; group?: string };

type Holder = {
  subject: string;
  display_name?: string;
  kind: string;
  principal_id?: string;
  signed_in: boolean;
  groups?: string[];
  directory_disabled?: boolean;
  roles: HolderRole[];
};

type Holders = {
  items: Holder[];
  count: number;
  directory: { configured: boolean; read: boolean; reason?: string; users?: number };
};

/** The scope as the server writes it, with the categories that say nothing left out. */
export function shortScope(scope: string): string {
  const kept = scope
    .split(" ")
    .filter((part) => !part.endsWith("=*"))
    .join(" ");
  return kept === "" ? "" : kept;
}

export function AccessHolders() {
  const t = useT();
  const [search, setSearch] = useState("");
  const { data, error } = useQuery({
    queryKey: ["access-holders"],
    queryFn: () => api.get<Holders>("/api/v1/access/holders"),
    retry: false,
  });

  if (error) return <ErrorBox error={error} />;

  const needle = search.trim().toLowerCase();
  const shown = (data?.items ?? []).filter((holder) =>
    needle === ""
    || holder.subject.toLowerCase().includes(needle)
    || (holder.display_name ?? "").toLowerCase().includes(needle)
    || holder.roles.some((role) => role.role.includes(needle))
    || (holder.groups ?? []).some((group) => group.toLowerCase().includes(needle)));

  return (
    <Card
      className="span-12"
      title={t("Who may sign in")}
      description={t("Everyone with a role here: bound by hand, or granted by a group of the identity provider. Somebody who has never signed in is here too - the panel makes their record at the first sign-in.")}
      flush
    >
      <Toolbar end={<span>{t("{n} of {total}", { n: shown.length, total: data?.count ?? 0 })}</span>}>
        <input
          placeholder={t("name, role or group")}
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          data-testid="holder-search"
        />
      </Toolbar>

      {/* What the directory side of this answer is worth. An unreadable
          directory is not a directory with nobody in it, and the screen says
          which of the two it is looking at. */}
      {data && data.directory.configured && !data.directory.read && (
        <p className="page-error" data-testid="directory-unread">
          {t("The directory did not answer, so only the access this panel records itself is listed: {reason}", {
            reason: data.directory.reason ?? t("no reason given"),
          })}
        </p>
      )}
      {data && !data.directory.configured && (
        <p className="source" data-testid="directory-absent">
          {t("No directory is configured, so this is the access the panel records itself.")}
        </p>
      )}

      {!data ? (
        <Empty>{t("Loading…")}</Empty>
      ) : shown.length === 0 ? (
        <Empty>{t("Nobody holds a role here yet.")}</Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th scope="col">{t("Who")}</th>
              <th scope="col">{t("Roles")}</th>
              <th scope="col">{t("Where the access comes from")}</th>
              <th scope="col">{t("Known to the panel")}</th>
              <th scope="col" />
            </tr>
          </thead>
          <tbody data-testid="access-holders">
            {shown.map((holder) => (
              <tr key={holder.subject} data-testid={`holder-${holder.subject}`}>
                <th scope="row">
                  <span className="mono">{holder.subject}</span>
                  {holder.display_name && <> <span className="source">{holder.display_name}</span></>}
                  {holder.directory_disabled && <> <span className="badge warn">{t("locked in the directory")}</span></>}
                </th>
                <td>
                  {holder.roles.map((role, index) => (
                    <div key={`${role.role}-${role.scope}-${index}`}>
                      <span className="mono">{role.role}</span>{" "}
                      <span className="source">{shortScope(role.scope) || t("everywhere")}</span>
                    </div>
                  ))}
                </td>
                <td className="source">
                  {holder.roles.some((role) => role.from === "binding") && (
                    <div>{t("bound to this identity")}</div>
                  )}
                  {(holder.groups ?? []).length > 0 && (
                    <div>{t("group {groups}", { groups: [...new Set(holder.groups)].join(", ") })}</div>
                  )}
                </td>
                <td>
                  {holder.signed_in
                    ? <span className="badge ok">{t("yes")}</span>
                    : <span className="badge unknown" title={t("The record is made at the first sign-in; the access is already theirs.")}>{t("not yet")}</span>}
                </td>
                <td className="actions-cell">
                  <div className="row-actions">
                    {holder.principal_id
                      ? (
                        <Link className="button secondary" to={`/settings?tab=users&q=${encodeURIComponent(holder.subject)}`}>
                          {t("Open the identity")}
                        </Link>
                      )
                      : (
                        <Link className="button secondary" to="/settings?tab=mappings">
                          {t("Open the mapping")}
                        </Link>
                      )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}
