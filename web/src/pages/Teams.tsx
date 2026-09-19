import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Collection, type Page } from "../lib/api";
import type { Host, Whoami } from "../lib/types";
import { Empty, ErrorBox, Time } from "../components/ui";
import { Actions, Card, EmptyState, Field, FieldGrid, PageHeader, Stat, StatGrid } from "../components/layout";
import { t, useT } from "../i18n";

/**
 * The register of teams. A team is the one word of the three a fleet is
 * described with that may decide who may touch what.
 */

/** One team as the register lists it, with the hosts placed in it counted. */
export type Team = {
  id: string;
  name: string;
  description?: string;
  created_by?: string;
  /** The hosts placed in the team; the deletion says how many it releases. */
  hosts: number;
  created_at: string;
  updated_at: string;
};

/**
 * The team a host carries.
 */
export type HostTeamFields = { team_id?: string; team_name?: string };

/** The permission every write in the register takes. */
export const TEAM_WRITE_PERMISSION = "team.binding.write";

/** The permission moving a host between teams takes. */
export const HOST_TEAM_PERMISSION = "host.scope.write";

/** The reason every change of the register is recorded with. */
export const TEAM_REASON_MIN_LENGTH = 8;

/** A reason long enough for the trail. */
export function reasonGiven(reason: string): boolean {
  return reason.trim().length >= TEAM_REASON_MIN_LENGTH;
}

/** The host list narrowed to one team; the count in the register leads to it. */
export function teamHostsAddress(teamID: string): string {
  return `/hosts?team=${encodeURIComponent(teamID)}`;
}

/**
 * The host list of the hosts nobody has placed in a team.
 */
export const UNPLACED_HOSTS_ADDRESS = "/hosts?team=none";

/**
 * A refusal of the teams API in words an operator can act on.
 */
export function refusalText(code: string, message: string): string {
  switch (code) {
    case "team_name_taken":
      return t("Another team already answers to that name. One name means one group, so the register keeps the names unique: rename the other team or choose another name.");
    case "team_not_found":
      return t("That team is gone - somebody deleted it while this screen was open. Reload the register.");
    case "invalid_team":
      return message || t("The register does not accept that name or description.");
    case "scope_conflict":
      return t("A binding names a team or a site, never both.");
    case "reason_required":
      return t("The change needs a reason of at least {n} characters; it is kept in the audit trail.", { n: TEAM_REASON_MIN_LENGTH });
    default:
      return message;
  }
}

/**
 * A refusal the operator can do something about: a stale authentication
 * sends them back to the login and returns them here, everything else is
 * said in the words above the register.
 */
function Refusal({ error, close }: { error: ApiError | null; close: () => void }) {
  const t = useT();
  if (!error) return null;
  if (error.code === "reauthentication_required") {
    return (
      <div className="warning" data-testid="teams-refusal">
        <div>
          <strong>{t("Re-authentication required.")}</strong> {error.message}
        </div>
        <div className="operations">
          <button
            onClick={() => {
              const target = encodeURIComponent(window.location.pathname + window.location.search);
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
    <div className="warning" data-testid="teams-refusal">
      <div>{refusalText(error.code, error.message)}</div>
      <div className="operations"><button onClick={close}>{t("Close")}</button></div>
    </div>
  );
}

/**
 * A control whose permission the identity does not hold, kept on the screen
 * and disabled with the reason beside it - the way ActionGuard keeps a
 * refused action in view on a host page.
 */
function Guarded({ allowed, children }: { allowed: boolean; children: ReactNode }) {
  const t = useT();
  if (allowed) return <>{children}</>;
  const reason = t("This needs the permission {permission}, which the platform administrator holds.", { permission: TEAM_WRITE_PERMISSION });
  return (
    <span className="action-guard action-guard-denied" title={reason} data-testid="teams-guard">
      <fieldset disabled aria-disabled="true" style={{ display: "contents" }}>
        {children}
      </fieldset>
      <span className="source action-guard-hint" style={{ marginLeft: 8 }}>{reason}</span>
    </span>
  );
}

/** What the register is doing beside the list; one at a time. */
type Aside =
  | { kind: "create" }
  | { kind: "edit"; team: Team }
  | { kind: "delete"; team: Team };

export function Teams() {
  const t = useT();
  const queryClient = useQueryClient();
  const [warning, setWarning] = useState<ApiError | null>(null);
  const [aside, setAside] = useState<Aside | null>(null);

  const whoami = useQuery({
    queryKey: ["whoami"],
    queryFn: () => api.get<Whoami>("/api/v1/whoami"),
    staleTime: 5 * 60 * 1000,
  });
  const canManage = (whoami.data?.permissions ?? []).includes(TEAM_WRITE_PERMISSION);

  // What the page says under its title, on every visit: the register is
  // read as another list of labels unless it says otherwise.
  const doctrine = t("A team is a boundary of authority: a role may be granted over it, and a host belongs to at most one. It is not a label - only the platform administrator draws these boundaries, and every change is recorded with its reason.");

  const list = useQuery({
    queryKey: ["teams"],
    queryFn: () => api.get<Collection<Team>>("/api/v1/teams"),
    retry: false,
  });
  // The hosts nobody has placed in a team.
  const unplaced = useQuery({
    queryKey: ["hosts", "team-none-count"],
    queryFn: () => api.get<Page<Host>>("/api/v1/hosts?team=none&limit=1"),
    retry: false,
  });

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ["teams"] });
    queryClient.invalidateQueries({ queryKey: ["hosts"] });
  };
  const onError = (error: unknown) => setWarning(error instanceof ApiError ? error : null);
  const settled = () => { setAside(null); setWarning(null); refresh(); };

  const remove = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.del<{ deleted: string }>(`/api/v1/teams/${id}`, { reason }),
    onSuccess: settled, onError,
  });

  if (list.error instanceof ApiError && list.error.forbidden) {
    return (
      <>
        <PageHeader title={t("Teams")} description={doctrine} />
        <Card><Empty>{t("You do not have permission to read the teams.")}</Empty></Card>
      </>
    );
  }
  if (list.error) return <ErrorBox error={list.error} />;

  const teams = list.data?.items ?? [];
  const placed = teams.reduce((sum, team) => sum + team.hosts, 0);
  // A count nobody could read is unknown, not zero: the tile shows a dash
  // rather than claiming every host has a team.
  const unplacedCount = unplaced.error ? undefined : unplaced.data?.total;

  return (
    <>
      <PageHeader title={t("Teams")} description={doctrine} />
      <Refusal error={warning} close={() => setWarning(null)} />

      <StatGrid>
        <Stat label={t("Teams")} value={list.data ? teams.length : "—"} hint={t("Each one is a boundary a role binding can name.")} />
        <Stat label={t("Hosts in a team")} value={list.data ? placed : "—"} hint={t("Reachable through their team as well as their site.")} />
        <Stat
          label={t("Hosts in no team")}
          value={unplacedCount ?? "—"}
          hint={t("Reachable through their site alone; that is a placement nobody has made, not a fault.")}
          to={UNPLACED_HOSTS_ADDRESS}
        />
      </StatGrid>

      <div className="widgets">
        <Card
          className={aside ? "span-6" : "span-9"}
          title={t("Teams")}
          actions={!aside && (
            <Guarded allowed={canManage}>
              <button onClick={() => setAside({ kind: "create" })}>{t("Create team")}</button>
            </Guarded>
          )}
          flush
        >
          {!list.data ? (
            <Empty>{t("Loading…")}</Empty>
          ) : teams.length === 0 ? (
            <EmptyState
              action={(
                <Guarded allowed={canManage}>
                  <button onClick={() => setAside({ kind: "create" })}>{t("Create team")}</button>
                </Guarded>
              )}
            >
              {t("No teams. Every host is reachable through its site, and every role binding names a site and an environment. Draw a team where the division of the work is not the geography of the machines.")}
            </EmptyState>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>{t("Team")}</th>
                  <th>{t("What belongs here")}</th>
                  <th className="num">{t("Hosts")}</th>
                  <th>{t("Created by")}</th>
                  <th>{t("When")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {teams.map((team) => (
                  <tr key={team.id} data-testid="team-row">
                    <td>
                      {team.name}
                      {/* The identifier is the boundary: a binding names it,
                          and a rename moves nobody. It is shown because the
                          audit trail and the address bar speak it. */}
                      <div className="source mono" title={t("The identifier a role binding names; a rename does not change it.")}>
                        {team.id}
                      </div>
                    </td>
                    <td className="source">{team.description || <span className="badge unknown">{t("nobody wrote one")}</span>}</td>
                    <td className="num">
                      <Link to={teamHostsAddress(team.id)} title={t("show the hosts of this team")}>{team.hosts}</Link>
                    </td>
                    <td className="source">{team.created_by || "—"}</td>
                    <td><Time value={team.created_at} /></td>
                    <td className="actions-cell">
                      <div className="row-actions">
                        <Guarded allowed={canManage}>
                          <button className="secondary" onClick={() => setAside({ kind: "edit", team })}>
                            {t("Rename")}
                          </button>
                          <button className="danger" onClick={() => setAside({ kind: "delete", team })}>
                            {t("Delete")}
                          </button>
                        </Guarded>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        {aside?.kind === "create" && (
          <TeamForm key="create" onDone={settled} onCancel={() => setAside(null)} onError={onError} />
        )}
        {aside?.kind === "edit" && (
          <TeamForm key={aside.team.id} team={aside.team} onDone={settled} onCancel={() => setAside(null)} onError={onError} />
        )}
        {aside?.kind === "delete" && (
          <DeleteTeam
            key={`delete-${aside.team.id}`}
            team={aside.team}
            busy={remove.isPending}
            onConfirm={(reason) => remove.mutate({ id: aside.team.id, reason })}
            onCancel={() => setAside(null)}
          />
        )}

        {!aside && (
          <Card className="span-3" title={t("A team is not a tag")}>
            <p className="source">
              {t("An operator edits tags, so a tag may never decide who may touch what: somebody who can widen their own scope has no scope. A team is a row with an identifier, and putting a host into one is an operation of its own, with its own permission and its own line in the trail.")}
            </p>
            <p className="source">
              {t("A team renamed is the same team: every binding and every host stay where they were. Use tags to choose hosts inside what you may already touch.")}
            </p>
          </Card>
        )}
      </div>
    </>
  );
}

/**
 * Creating a team, or rewriting the name and the description of one.
 */
function TeamForm({ team, onDone, onCancel, onError }: {
  team?: Team;
  onDone: () => void;
  onCancel: () => void;
  onError: (error: unknown) => void;
}) {
  const t = useT();
  const [name, setName] = useState(team?.name ?? "");
  const [description, setDescription] = useState(team?.description ?? "");
  const [reason, setReason] = useState("");
  const save = useMutation({
    mutationFn: () => {
      const body = { name: name.trim(), description: description.trim(), reason: reason.trim() };
      return team
        ? api.put<Team>(`/api/v1/teams/${team.id}`, body)
        : api.post<Team>("/api/v1/teams", body);
    },
    onSuccess: onDone, onError,
  });
  const ready = name.trim() !== "" && reasonGiven(reason) && !save.isPending;
  return (
    <Card
      className="span-3 fp-narrow"
      title={team ? t("Rename {name}", { name: team.name }) : t("New team")}
      footer={
        <Actions>
          <button disabled={!ready} onClick={() => save.mutate()} data-testid="team-save">
            {save.isPending ? t("Working…") : team ? t("Save team") : t("Create team")}
          </button>
          <button className="secondary" onClick={onCancel} disabled={save.isPending}>{t("Cancel")}</button>
        </Actions>
      }
    >
      <FieldGrid>
        <Field label={t("Name")} hint={t("What people call the team; it is unique, and it is not the boundary - the identifier is, so a rename keeps every binding and every host.")} wide>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder={t("payments platform")} data-testid="team-name" />
        </Field>
        <Field label={t("What belongs here")} hint={t("The sentence that says which machines are this team's; optional, and read by whoever places a host.")} wide>
          <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={3} data-testid="team-description" />
        </Field>
        <Field label={t("Reason (kept in the audit trail)")} hint={t("At least {n} characters; the button opens when they are there.", { n: TEAM_REASON_MIN_LENGTH })} wide>
          <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder={t("e.g. the payments group took over the database hosts")} data-testid="team-reason" />
        </Field>
      </FieldGrid>
      {!team && (
        <p className="source">
          {t("A new team holds nobody and grants nothing until a host is placed in it and a role is granted over it. Both are decisions of their own.")}
        </p>
      )}
    </Card>
  );
}

/**
 * Deleting a team.
 */
function DeleteTeam({ team, busy, onConfirm, onCancel }: {
  team: Team;
  busy: boolean;
  onConfirm: (reason: string) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  return (
    <Card
      className="span-3 fp-narrow"
      title={t("Delete {name}", { name: team.name })}
      footer={
        <Actions>
          <button className="danger" disabled={!reasonGiven(reason) || busy} onClick={() => onConfirm(reason.trim())} data-testid="team-delete">
            {busy ? t("Working…") : t("Delete team")}
          </button>
          <button className="secondary" onClick={onCancel} disabled={busy}>{t("Cancel")}</button>
        </Actions>
      }
    >
      <p className="source" data-testid="team-delete-text">
        {t("This releases {n} hosts. They keep existing and stay reachable through their site, as they were before anybody drew this boundary; no machine is touched.", { n: team.hosts })}
      </p>
      <p className="source">
        {t("Every role binding that named this team goes with it: whoever held a role here and nowhere else loses it on their next request.")}
      </p>
      <FieldGrid>
        <Field label={t("Reason (kept in the audit trail)")} hint={t("At least {n} characters; the button opens when they are there.", { n: TEAM_REASON_MIN_LENGTH })} wide>
          <input value={reason} onChange={(e) => setReason(e.target.value)} data-testid="team-reason" />
        </Field>
      </FieldGrid>
    </Card>
  );
}

/**
 * The teams as every other screen reads them: the filter on the host list,
 * the placement on a host page and the binding form of the access screen all
 * need the same names, and they all narrow nothing - a team name is printed
 */
export function useTeams(enabled = true) {
  return useQuery({
    queryKey: ["teams"],
    queryFn: () => api.get<Collection<Team>>("/api/v1/teams"),
    enabled,
    staleTime: 60 * 1000,
    retry: false,
  });
}
