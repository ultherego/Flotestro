import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { Card, Pager, Toolbar } from "../components/layout";
import { DataTable } from "../components/table";
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

/** Whether any of somebody's roles comes from a group of the directory. */
export function fromTheDirectory(holder: Pick<Holder, "roles">): boolean {
  return holder.roles.some((role) => role.from === "group");
}

/** Which of the holders a screen is asking about. */
export type Which = "directory" | "bound" | "everyone";

/**
 * The holders this view shows, in the order it shows them.
 *
 * The people of an installation come from its directory; the identities the
 * panel made for itself are tokens, runners and whatever a test suite left
 * behind - 1785 of them in the laboratory. So the directory's people are
 * first whichever filter is on, and the filter opens on them: an
 * administrator asking "who has access" means the people.
 */
export function holdersToShow(items: Holder[], which: Which, search: string): Holder[] {
  const needle = search.trim().toLowerCase();
  const matches = (holder: Holder) =>
    needle === ""
    || holder.subject.toLowerCase().includes(needle)
    || (holder.display_name ?? "").toLowerCase().includes(needle)
    || holder.roles.some((role) => role.role.includes(needle))
    || (holder.groups ?? []).some((group) => group.toLowerCase().includes(needle));
  const wanted = (holder: Holder) =>
    which === "everyone" ? true
      : which === "directory" ? fromTheDirectory(holder)
        : !fromTheDirectory(holder);
  return items
    .filter((holder) => wanted(holder) && matches(holder))
    .sort((a, b) => {
      const bySource = Number(fromTheDirectory(b)) - Number(fromTheDirectory(a));
      return bySource !== 0 ? bySource : a.subject.localeCompare(b.subject);
    });
}

export function AccessHolders() {
  const t = useT();
  const [search, setSearch] = useState("");
  const [which, setWhich] = useState<Which>("directory");
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(25);
  const { data, error } = useQuery({
    queryKey: ["access-holders"],
    queryFn: () => api.get<Holders>("/api/v1/access/holders"),
    retry: false,
  });

  if (error) return <ErrorBox error={error} />;

  const items = data?.items ?? [];
  const everyone = holdersToShow(items, "everyone", search);
  const matching = holdersToShow(items, which, search);
  const shown = matching.slice((page - 1) * size, page * size);
  const fromDirectory = items.filter(fromTheDirectory).length;

  return (
    <Card
      className="span-12"
      title={t("Who may sign in")}
      description={t("Everyone with a role here: bound by hand, or granted by a group of the identity provider. Somebody who has never signed in is here too - the panel makes their record at the first sign-in.")}
      flush
    >
      <Toolbar
        end={<Pager page={page} size={size} total={matching.length}
                    onPage={setPage} onSize={setSize} />}
      >
        <input
          placeholder={t("name, role or group")}
          value={search}
          onChange={(event) => { setSearch(event.target.value); setPage(1); }}
          data-testid="holder-search"
        />
        {/* The people come from the directory; the rest are the panel's own
            records - a token, a runner, whatever a suite left behind. The
            filter opens on the people, because that is what the question
            "who has access" means. */}
        <div className="segmented" role="group" aria-label={t("Whose access to show")}>
          <button
            className={which === "directory" ? "active" : ""}
            onClick={() => { setWhich("directory"); setPage(1); }}
            data-testid="holders-directory"
          >
            {t("From the directory ({n})", { n: fromDirectory })}
          </button>
          <button
            className={which === "bound" ? "active" : ""}
            onClick={() => { setWhich("bound"); setPage(1); }}
            data-testid="holders-bound"
          >
            {t("Bound by hand ({n})", { n: everyone.length - fromDirectory })}
          </button>
          <button
            className={which === "everyone" ? "active" : ""}
            onClick={() => { setWhich("everyone"); setPage(1); }}
            data-testid="holders-everyone"
          >
            {t("Everyone ({n})", { n: everyone.length })}
          </button>
        </div>
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
      ) : (
        <DataTable
          rows={shown}
          rowKey={(holder) => holder.subject}
          rowTestId={(holder) => `holder-${holder.subject}`}
          bodyTestId="access-holders"
          empty={which === "directory"
            ? t("No group of the directory grants a role here yet. A mapping is what gives one.")
            : t("Nobody holds a role here yet.")}
          columns={[
            {
              key: "who",
              head: t("Who"),
              rowHeader: true,
              cell: (holder) => (
                <>
                  <span className="mono">{holder.subject}</span>
                  {holder.display_name && <> <span className="source">{holder.display_name}</span></>}
                  {holder.directory_disabled && <> <span className="badge warn">{t("locked in the directory")}</span></>}
                </>
              ),
            },
            {
              key: "roles",
              head: t("Roles"),
              cell: (holder) => holder.roles.map((role, index) => (
                <div key={`${role.role}-${role.scope}-${index}`}>
                  <span className="mono">{role.role}</span>{" "}
                  <span className="source">{shortScope(role.scope) || t("everywhere")}</span>
                </div>
              )),
            },
            {
              key: "from",
              head: t("Where the access comes from"),
              wideOnly: true,
              cell: (holder) => (
                <span className="source">
                  {holder.roles.some((role) => role.from === "binding") && (
                    <div>{t("bound to this identity")}</div>
                  )}
                  {(holder.groups ?? []).length > 0 && (
                    <div>{t("group {groups}", { groups: [...new Set(holder.groups)].join(", ") })}</div>
                  )}
                </span>
              ),
            },
            {
              key: "known",
              head: t("Known to the panel"),
              cell: (holder) => holder.signed_in
                ? <span className="badge ok">{t("yes")}</span>
                : <span className="badge unknown" title={t("The record is made at the first sign-in; the access is already theirs.")}>{t("not yet")}</span>,
            },
            {
              key: "actions",
              actions: true,
              cell: (holder) => (
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
              ),
            },
          ]}
        />
      )}
    </Card>
  );
}
