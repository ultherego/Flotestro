import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, type Collection, type Page } from "../../lib/api";
import type { Host, Whoami } from "../../lib/types";
import { absoluteTime, relativeTime } from "../../lib/format";
import { t, useT } from "../../i18n";
import { Board } from "../Board";
import type { BoardEntry } from "../../components/board";
import {
  Actions, Banner, Card, Empty, Field, Fields, Kpi, Modal, Note, Pill, Problem, Table, TwoLine,
} from "../kit";

/**
 * The teams: the boundary of authority over hosts.
 *
 * A team is the one of the three words a fleet is described with that may
 * decide who may touch what, so the screen says so before it says
 * anything else. It is not a label an operator writes: it is a row with
 * an identifier, drawn by the platform administrator, and every change to
 * it is recorded with the reason it was made.
 */

/** One team as the register lists it, with the hosts placed in it counted. */
export type Team = {
  id: string;
  name: string;
  description?: string;
  created_by?: string;
  /** The hosts placed in the team; a deletion says how many it releases. */
  hosts: number;
  created_at: string;
  updated_at: string;
};

/** The permission every write in the register takes. */
export const TEAM_WRITE_PERMISSION = "team.binding.write";

/** The reason every change of the register is recorded with. */
export const TEAM_REASON_MIN_LENGTH = 8;

/** A reason long enough for the trail. */
export function reasonGiven(reason: string): boolean {
  return reason.trim().length >= TEAM_REASON_MIN_LENGTH;
}

/** The host list narrowed to one team; the team's name leads there. */
export function teamHostsAddress(teamID: string): string {
  return `/hosts?team=${encodeURIComponent(teamID)}`;
}

/** The hosts nobody has placed in a team. */
export const UNPLACED_HOSTS_ADDRESS = "/hosts?team=none";

/**
 * A refusal of the teams API in words an operator can act on. The server's
 * own wording is kept where it says more than a translation would.
 */
export function refusalText(code: string, message: string): string {
  switch (code) {
    case "team_name_taken":
      return t("Another team already answers to that name. One name means one group, so the register keeps the names unique: rename the other team or choose another name.");
    case "team_not_found":
      return t("That team is gone — somebody deleted it while this screen was open. Read the register again.");
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

/** What the register is doing beside the list; one thing at a time. */
type Aside = { kind: "create" } | { kind: "rename" } | { kind: "delete" };

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

  const list = useQuery({
    queryKey: ["teams"],
    queryFn: () => api.get<Collection<Team>>("/api/v1/teams"),
    retry: false,
  });
  // The hosts nobody has placed in a team; one row is asked for, the total
  // is the answer.
  const unplaced = useQuery({
    queryKey: ["hosts", "team-none-count"],
    queryFn: () => api.get<Page<Host>>("/api/v1/hosts?team=none&limit=1"),
    retry: false,
  });

  const settled = () => {
    setAside(null);
    setWarning(null);
    void queryClient.invalidateQueries({ queryKey: ["teams"] });
    void queryClient.invalidateQueries({ queryKey: ["hosts"] });
  };
  const refused = (error: unknown) => setWarning(error instanceof ApiError ? error : null);

  if (list.error instanceof ApiError && list.error.forbidden) {
    return (
      <Card title={t("Teams")}>
        <Empty>{t("You do not have permission to read the teams.")}</Empty>
      </Card>
    );
  }
  if (list.error) return <Problem>{String(list.error)}</Problem>;

  const teams = list.data?.items ?? [];
  const placed = teams.reduce((sum, one) => sum + one.hosts, 0);
  // A count nobody could read is unknown, not nought: the tile shows a dash
  // rather than claiming every host has been placed.
  const unplacedCount = unplaced.error ? null : unplaced.data?.total ?? null;
  const denied = t("This needs the permission {permission}, which the platform administrator holds.", { permission: TEAM_WRITE_PERMISSION });

  return (
    <>
      {aside?.kind === "delete" && (
        <DeleteTeam teams={teams} onDone={settled} onRefused={refused} onClose={() => setAside(null)} />
      )}
      {/* A refusal is not a container: an arrangement that took it off the
          screen would hide the one thing the operator has to read. */}
      {warning !== null && <Refusal error={warning} close={() => setWarning(null)} />}
      <Board screen={TEAMS_SCREEN} catalogue={TEAMS} drawn={{
        count: (
          <Kpi
            icon="access"
            label={t("Teams")}
            value={list.data ? teams.length : null}
            note={t("each one a boundary a role binding can name")}
          />
        ),
        placed: (
          <Kpi
            icon="hosts"
            label={t("Hosts in a team")}
            value={list.data ? placed : null}
            note={t("reachable through their team as well as their site")}
          />
        ),
        unplaced: (
          <Kpi
            icon="server"
            label={t("Hosts in no team")}
            value={unplacedCount}
            to={UNPLACED_HOSTS_ADDRESS}
            note={t("reachable through their site alone; a placement nobody has made, not a fault")}
          />
        ),
        doctrine: (
          <Card title={t("A team is not a tag")}>
            <Note>
              {t("An operator writes tags, so a tag may never decide who may touch what: somebody who can widen their own scope has no scope. A team is a row with an identifier, and placing a host in one is an operation of its own, with its own permission and its own line in the trail.")}
            </Note>
            <Note>
              {t("A team renamed is the same team: every binding and every host stay where they were. Tags are for choosing hosts inside what you may already touch.")}
            </Note>
          </Card>
        ),
        form: (aside?.kind === "create" || aside?.kind === "rename") && (
          <TeamForm
            key={aside.kind}
            renaming={aside.kind === "rename"}
            teams={teams}
            onDone={settled}
            onRefused={refused}
            onCancel={() => setAside(null)}
          />
        ),
        list: (
          <Card
            title={t("Teams")}
            note={list.data ? t("{n} teams", { n: teams.length }) : undefined}
            tools={
              <>
                <button type="button" onClick={() => setAside({ kind: "create" })} disabled={!canManage || aside !== null}
                        title={canManage ? undefined : denied} data-testid="new-team">
                  {t("New team")}
                </button>
                <button type="button" className="fl-quiet" onClick={() => setAside({ kind: "rename" })}
                        disabled={!canManage || aside !== null || teams.length === 0}
                        title={canManage ? undefined : denied} data-testid="rename-a-team">
                  {t("Rename a team…")}
                </button>
                <button type="button" className="fl-danger" onClick={() => setAside({ kind: "delete" })}
                        disabled={!canManage || teams.length === 0}
                        title={canManage ? undefined : denied} data-testid="delete-a-team">
                  {t("Delete a team…")}
                </button>
              </>
            }
            foot={canManage ? undefined : <Note>{denied}</Note>}
            flush
          >
            <Table
              rows={teams}
              keyOf={(one) => one.id}
              rowTestId={(one) => `team-${one.name}`}
              empty={list.data
                ? t("No teams. Every host is reachable through its site, and every role binding names a site and an environment. Draw a team where the division of the work is not the geography of the machines.")
                : t("Reading the register…")}
              columns={[
                // The identifier under the name is what a binding names and
                // what the trail and the address bar speak; a rename moves
                // nobody, so both are worth reading.
                { key: "name", head: t("Team"), cell: (one) => (
                  <TwoLine sub={one.id}>
                    <Link to={teamHostsAddress(one.id)} title={t("the hosts of this team")}>{one.name}</Link>
                  </TwoLine>
                ) },
                { key: "description", head: t("What belongs here"), cell: (one) => (
                  one.description
                    ? one.description
                    : <Pill tone="unknown">{t("nobody wrote one")}</Pill>
                ) },
                { key: "hosts", head: t("Hosts"), num: true, cell: (one) => one.hosts },
                { key: "by", head: t("Created by"), minor: true, tight: true, cell: (one) => (
                  one.created_by ? <span title={one.created_by}>{one.created_by}</span> : <span className="fl-faint">—</span>
                ) },
                { key: "created", head: t("When"), minor: true, cell: (one) => (
                  <span title={absoluteTime(one.created_at)}>{relativeTime(one.created_at)}</span>
                ) },
              ]}
            />
          </Card>
        ),
      }} />
    </>
  );
}

/**
 * A refusal the operator can do something about: an authentication the
 * server wants again sends them back to the sign-in and returns them
 * here, everything else is said in words above the register.
 */
function Refusal({ error, close }: { error: ApiError; close: () => void }) {
  const t = useT();
  if (error.code === "reauthentication_required") {
    return (
      <Banner
        tone="warn"
        actions={
          <>
            <button
              type="button"
              onClick={() => {
                const back = encodeURIComponent(window.location.pathname + window.location.search);
                window.location.href = `/auth/login?step_up=1&redirect=${back}`;
              }}
            >
              {t("Sign in again")}
            </button>
            <button type="button" className="fl-quiet" onClick={close}>{t("Close")}</button>
          </>
        }
      >
        {t("Re-authentication required.")} {error.message}
      </Banner>
    );
  }
  return (
    <Banner tone="error" actions={<button type="button" className="fl-quiet" onClick={close}>{t("Close")}</button>}>
      <span data-testid="teams-refusal">{refusalText(error.code, error.message)}</span>
    </Banner>
  );
}

/**
 * Drawing a team, or rewriting the name and the description of one.
 *
 * It stands on the page: naming a boundary is read against the boundaries
 * already drawn, and the register behind the form is what says whether
 * this one is a new division of the work or the same one twice.
 */
function TeamForm({ renaming, teams, onDone, onRefused, onCancel }: {
  renaming: boolean;
  teams: Team[];
  onDone: () => void;
  onRefused: (error: unknown) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const [id, setId] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [reason, setReason] = useState("");

  const save = useMutation({
    mutationFn: () => {
      const body = { name: name.trim(), description: description.trim(), reason: reason.trim() };
      return renaming ? api.put<Team>(`/api/v1/teams/${id}`, body) : api.post<Team>("/api/v1/teams", body);
    },
    onSuccess: onDone,
    onError: onRefused,
  });

  // The fields of a rename start as the record is, so a save that changes
  // one word changes one word.
  const choose = (next: string) => {
    const team = teams.find((one) => one.id === next);
    setId(next);
    setName(team?.name ?? "");
    setDescription(team?.description ?? "");
  };

  const ready = name.trim() !== "" && reasonGiven(reason) && (!renaming || id !== "") && !save.isPending;

  return (
    <Card
      title={renaming ? t("Rename a team") : t("New team")}
      note={renaming
        ? t("The name is what people call it; the identifier is the boundary, so a rename keeps every binding and every host.")
        : t("A new team holds nobody and grants nothing until a host is placed in it and a role is granted over it. Both are decisions of their own.")}
      foot={
        <Actions>
          <button type="button" disabled={!ready} onClick={() => save.mutate()} data-testid="team-save">
            {save.isPending ? t("Working…") : renaming ? t("Save team") : t("Create team")}
          </button>
          <button type="button" className="fl-quiet" onClick={onCancel} disabled={save.isPending}>{t("Cancel")}</button>
        </Actions>
      }
    >
      <Fields>
        {renaming && (
          <Field label={t("Team")} wide>
            <select value={id} onChange={(event) => choose(event.target.value)} data-testid="team-to-rename">
              <option value="">{t("choose a team…")}</option>
              {teams.map((one) => <option key={one.id} value={one.id}>{one.name}</option>)}
            </select>
          </Field>
        )}
        <Field
          label={t("Name")}
          wide
          hint={t("What people call the team; it is unique, and it is not the boundary — the identifier is, so a rename keeps every binding and every host.")}
        >
          <input value={name} onChange={(event) => setName(event.target.value)} placeholder={t("payments platform")} data-testid="team-name" />
        </Field>
        <Field
          label={t("What belongs here")}
          wide
          hint={t("The sentence that says which machines are this team's; optional, and read by whoever places a host.")}
        >
          <textarea value={description} onChange={(event) => setDescription(event.target.value)} rows={3} data-testid="team-description" />
        </Field>
        <Field
          label={t("Reason (kept in the audit trail)")}
          wide
          hint={t("At least {n} characters; the button opens when they are there.", { n: TEAM_REASON_MIN_LENGTH })}
        >
          <input value={reason} onChange={(event) => setReason(event.target.value)}
                 placeholder={t("e.g. the payments group took over the database hosts")} data-testid="team-reason" />
        </Field>
      </Fields>
    </Card>
  );
}

/**
 * Deleting a team.
 *
 * A boundary that goes takes every role binding that named it, so this is
 * a decision and it asks for its reason before it will go through. No
 * machine is touched: the hosts keep existing and stay reachable through
 * their site, as they were before anybody drew the boundary.
 */
function DeleteTeam({ teams, onDone, onRefused, onClose }: {
  teams: Team[];
  onDone: () => void;
  onRefused: (error: unknown) => void;
  onClose: () => void;
}) {
  const t = useT();
  const [id, setId] = useState(teams.length === 1 ? teams[0].id : "");
  const [reason, setReason] = useState("");
  const chosen = teams.find((one) => one.id === id);

  const remove = useMutation({
    mutationFn: () => api.del<{ deleted: string }>(`/api/v1/teams/${id}`, { reason: reason.trim() }),
    onSuccess: onDone,
    onError: onRefused,
  });

  return (
    <Modal
      title={t("Delete a team")}
      onClose={onClose}
      actions={
        <>
          <button type="button" className="fl-quiet" onClick={onClose} disabled={remove.isPending}>{t("Cancel")}</button>
          <button
            type="button"
            className="fl-danger"
            disabled={!chosen || !reasonGiven(reason) || remove.isPending}
            onClick={() => remove.mutate()}
            data-testid="team-delete"
          >
            {remove.isPending ? t("Working…") : t("Delete team")}
          </button>
        </>
      }
    >
      <Fields>
        <Field label={t("Team")} wide>
          <select value={id} onChange={(event) => setId(event.target.value)} data-testid="team-to-delete">
            <option value="">{t("choose a team…")}</option>
            {teams.map((one) => <option key={one.id} value={one.id}>{one.name}</option>)}
          </select>
        </Field>
        <Field
          label={t("Reason (kept in the audit trail)")}
          wide
          hint={t("At least {n} characters; the button opens when they are there.", { n: TEAM_REASON_MIN_LENGTH })}
        >
          <input value={reason} onChange={(event) => setReason(event.target.value)} data-testid="team-delete-reason" />
        </Field>
      </Fields>
      {chosen && (
        <Note>
          {t("This releases {n} hosts. They keep existing and stay reachable through their site, as they were before anybody drew this boundary; no machine is touched.", { n: chosen.hosts })}
        </Note>
      )}
      {chosen && (
        <Note>
          {t("Every role binding that named this team goes with it: whoever held a role here and nowhere else loses it on their next request.")}
        </Note>
      )}
    </Modal>
  );
}

export const TEAMS_SCREEN = "next_teams";

export const TEAMS: BoardEntry[] = [
  { key: "count", title: "Teams", width: 4, height: 2 },
  { key: "placed", title: "Hosts in a team", width: 4, height: 2 },
  { key: "unplaced", title: "Hosts in no team", width: 4, height: 2 },
  { key: "doctrine", title: "A team is not a tag", width: 4, height: 4 },
  { key: "form", title: "New team", width: 8, height: 4 },
  { key: "list", title: "Teams", width: 12, height: 6 },
];
