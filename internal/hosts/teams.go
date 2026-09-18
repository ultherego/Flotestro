package hosts

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ultherego/flotestro/internal/authz"
)

// Teams: the boundary of what somebody may touch, drawn where the fleet is
// really divided.
//
// A role binding used to name a site and an environment, and nothing else.
// That is the geography of the machines, not the division of the work: the
// database hosts of two sites belong to the same people, and those two
// sites hold other people's hosts as well. A team is the third vocabulary,
// and the only one of the three that may be an authorisation boundary:
//
//   - a tag cannot, because an operator edits tags, and somebody who can
//     widen their own scope has no scope;
//   - an owner cannot, because it is a name typed into a field - it is
//     spelt three ways by three people and nothing binds two of them to
//     one group;
//   - a team can, because it is a row with an identifier: renaming it
//     keeps every binding, and putting a host into it is an operation of
//     its own, with its own permission and its own line in the trail.
//
// A tag keeps the job it is good at - choosing hosts inside what somebody
// may already touch.

// The bounds of what a team may be called and be described as. A name is
// what people say to each other in a stand-up, a description is the
// sentence that says which machines belong here; neither is a document.
const (
	MaxTeamNameLength        = 128
	MaxTeamDescriptionLength = 1000
)

var (
	// ErrInvalidTeam means a name or a description the panel does not
	// accept; the message says what is wrong with it.
	ErrInvalidTeam = errors.New("invalid team")
	// ErrTeamNameTaken means another team already answers to that name.
	// The name is unique because people use it to mean one group.
	ErrTeamNameTaken = errors.New("the team name is taken")
	// ErrTeamNotFound means there is no team with the given identifier.
	ErrTeamNotFound = errors.New("the team does not exist")
)

// Team is a stable group of hosts that belong to the same people. A role
// binding may name one instead of a site, and a host belongs to at most
// one of them.
type Team struct {
	ID string `json:"id"`
	// Name is what people call the team. It is unique, and it is not the
	// identifier: a team renamed keeps every binding and every host.
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	CreatedBy   string `json:"created_by,omitempty"`
	// Hosts counts the hosts placed in the team. A listing carries it
	// because deleting a team leaves those hosts behind with no team at
	// all, and the person deleting it should see how many that is.
	Hosts     int       `json:"hosts"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TeamHost names one host of a team, as the trail describes the hosts a
// deleted team left behind.
type TeamHost struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
}

// NormalizeTeamName checks the name of a team. A team without a name
// could not be granted to anybody in words, so an empty one is refused;
// control characters are refused because the name is printed in tables
// and in the trail, where a line break would forge a second row.
func NormalizeTeamName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("%w: a team needs a name", ErrInvalidTeam)
	}
	if len([]rune(name)) > MaxTeamNameLength {
		return "", fmt.Errorf("%w: the name is longer than %d characters", ErrInvalidTeam, MaxTeamNameLength)
	}
	for _, r := range name {
		if r < ' ' || r == 0x7f {
			return "", fmt.Errorf("%w: control characters are not allowed in the name", ErrInvalidTeam)
		}
	}
	return name, nil
}

// NormalizeTeamDescription checks the description of a team. An empty
// description is allowed and means nobody wrote one.
func NormalizeTeamDescription(description string) (string, error) {
	description = strings.TrimSpace(strings.ReplaceAll(description, "\r\n", "\n"))
	if len([]rune(description)) > MaxTeamDescriptionLength {
		return "", fmt.Errorf("%w: the description is longer than %d characters",
			ErrInvalidTeam, MaxTeamDescriptionLength)
	}
	for _, r := range description {
		if (r < ' ' && r != '\n' && r != '\t') || r == 0x7f {
			return "", fmt.Errorf("%w: control characters are not allowed in the description", ErrInvalidTeam)
		}
	}
	return description, nil
}

// ValidTeamID says whether the value could be a team identifier. A value
// that could not be is a request's mistake, not an empty answer: passing
// it to the database would come back as a server fault.
func ValidTeamID(id string) bool {
	_, err := uuid.Parse(id)
	return err == nil
}

// teamColumns are the columns every team read returns, with the number of
// hosts placed in the team counted alongside.
const teamColumns = `
	select t.id, t.name, t.description, t.created_by, t.created_at, t.updated_at,
	       (select count(*) from hosts h where h.team_id = t.id)
	  from teams t`

func scanTeam(row pgx.Row) (*Team, error) {
	var team Team
	if err := row.Scan(&team.ID, &team.Name, &team.Description, &team.CreatedBy,
		&team.CreatedAt, &team.UpdatedAt, &team.Hosts); err != nil {
		return nil, err
	}
	return &team, nil
}

// ListTeams returns every team in the order people read them: by name.
// The list is not narrowed by scope - a team name is what a binding and a
// host row already say out loud, and somebody who may see a host in a
// team may see which team that is.
func (s *Store) ListTeams(ctx context.Context) ([]Team, error) {
	rows, err := s.pool.Query(ctx, teamColumns+` order by t.name`)
	if err != nil {
		return nil, fmt.Errorf("listing the teams: %w", err)
	}
	defer rows.Close()
	teams := make([]Team, 0)
	for rows.Next() {
		var team Team
		if err := rows.Scan(&team.ID, &team.Name, &team.Description, &team.CreatedBy,
			&team.CreatedAt, &team.UpdatedAt, &team.Hosts); err != nil {
			return nil, err
		}
		teams = append(teams, team)
	}
	return teams, rows.Err()
}

// Team reads one team. An identifier that is not one is not a team.
func (s *Store) Team(ctx context.Context, teamID string) (*Team, error) {
	if !ValidTeamID(teamID) {
		return nil, ErrTeamNotFound
	}
	team, err := scanTeam(s.pool.QueryRow(ctx, teamColumns+` where t.id = $1::uuid`, teamID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTeamNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("reading the team: %w", err)
	}
	return team, nil
}

// CreateTeam adds a team. The name is unique, so the second team with the
// same name is refused by name rather than created as a second group
// nobody can tell from the first.
func (s *Store) CreateTeam(ctx context.Context, name, description, createdBy string) (*Team, error) {
	normalizedName, err := NormalizeTeamName(name)
	if err != nil {
		return nil, err
	}
	normalizedDescription, err := NormalizeTeamDescription(description)
	if err != nil {
		return nil, err
	}
	const query = `
		insert into teams (id, name, description, created_by)
		values ($1, $2, $3, $4)
		returning id`
	var id string
	err = s.pool.QueryRow(ctx, query, uuid.NewString(), normalizedName,
		normalizedDescription, createdBy).Scan(&id)
	if isUniqueViolation(err) {
		return nil, ErrTeamNameTaken
	}
	if err != nil {
		return nil, fmt.Errorf("creating the team: %w", err)
	}
	return s.Team(ctx, id)
}

// UpdateTeam renames a team or rewrites its description. The identifier
// does not change, so every binding and every host stay where they are:
// that is the whole reason a team is a row rather than a string.
func (s *Store) UpdateTeam(ctx context.Context, teamID, name, description string) (*Team, error) {
	if !ValidTeamID(teamID) {
		return nil, ErrTeamNotFound
	}
	normalizedName, err := NormalizeTeamName(name)
	if err != nil {
		return nil, err
	}
	normalizedDescription, err := NormalizeTeamDescription(description)
	if err != nil {
		return nil, err
	}
	tag, err := s.pool.Exec(ctx, `
		update teams set name = $2, description = $3, updated_at = now()
		 where id = $1::uuid`, teamID, normalizedName, normalizedDescription)
	if isUniqueViolation(err) {
		return nil, ErrTeamNameTaken
	}
	if err != nil {
		return nil, fmt.Errorf("updating the team: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrTeamNotFound
	}
	return s.Team(ctx, teamID)
}

// DeleteTeam removes a team and returns the hosts it held.
//
// Deleting a team is not deleting machines. The hosts stay and become
// unassigned - the column is on delete set null - and the bindings that
// named the team go with it, because a binding to a group that no longer
// exists would be an access nobody can read. That is the point of the
// operation and the reason it is audited: it takes an access away from
// whoever held it, and it hands the hosts back to whoever holds their
// site.
func (s *Store) DeleteTeam(ctx context.Context, tx pgx.Tx, teamID string) (released []TeamHost, err error) {
	if !ValidTeamID(teamID) {
		return nil, ErrTeamNotFound
	}
	rows, err := tx.Query(ctx, `
		select id, hostname from hosts where team_id = $1::uuid order by hostname, id`, teamID)
	if err != nil {
		return nil, fmt.Errorf("reading the hosts of the team: %w", err)
	}
	for rows.Next() {
		var host TeamHost
		if err := rows.Scan(&host.ID, &host.Hostname); err != nil {
			rows.Close()
			return nil, err
		}
		released = append(released, host)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	tag, err := tx.Exec(ctx, `delete from teams where id = $1::uuid`, teamID)
	if err != nil {
		return nil, fmt.Errorf("deleting the team: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrTeamNotFound
	}
	return released, nil
}

// SetHostTeam puts a host into a team or takes it out; an empty team
// takes it out. The host is returned as it now reads, so the caller can
// put both sides on the trail.
func (s *Store) SetHostTeam(ctx context.Context, hostID, teamID string) (*Host, error) {
	if teamID != "" && !ValidTeamID(teamID) {
		return nil, ErrTeamNotFound
	}
	// The empty team travels as an empty string and becomes null in the
	// column, the way the other fields an operator may clear do.
	tag, err := s.pool.Exec(ctx,
		`update hosts set team_id = nullif($2, '')::uuid, updated_at = now() where id = $1`,
		hostID, teamID)
	if isForeignKeyViolation(err) {
		// The team was deleted between the check and the write. That is a
		// team that does not exist, not a failure of the panel.
		return nil, ErrTeamNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("placing the host in a team: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.Get(ctx, hostID)
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

// ScopeSQL narrows host rows to the given scopes, teams included.
//
// It is authz.ScopeSQL with the third vocabulary added, and it exists
// because that function cannot express a team: a team binding carries the
// wildcard site and environment the constraint gives it, so a site-only
// condition would read it as "the whole fleet" and hand a team's operator
// every host in the installation. That is exactly the scope leak the
// security document's chapter 8 is about, and it is the reason the
// narrowing is written in SQL here rather than by dropping rows in Go
// after the query: a page filtered afterwards reports a count and a
// cursor for rows the caller never sees.
//
// The semantics are those of authz.Scope.Matches, one for one:
//
//   - a binding that names a team matches the hosts of that team and
//     nothing else, a host with no team included - a host nobody placed
//     is reachable through its site alone;
//   - a binding that names no team matches on the site and the
//     environment, whatever team the host is in;
//   - an empty list of scopes is "false": no scope is no host, never
//     every host.
//
// teamColumn is the host row's team column; a listing that has no such
// column cannot express a team scope and must not call this function.
// offset is the number of parameters already used in the query.
func ScopeSQL(scopes []authz.Scope, siteColumn, envColumn, teamColumn string, offset int) (string, []any) {
	if len(scopes) == 0 {
		return "false", nil
	}
	var (
		conditions []string
		args       []any
	)
	for _, scope := range scopes {
		if scope.Team != "" {
			args = append(args, scope.Team)
			conditions = append(conditions,
				fmt.Sprintf("%s = $%d::uuid", teamColumn, offset+len(args)))
			continue
		}
		if scope.Site == authz.Wildcard && scope.Environment == authz.Wildcard {
			// A global scope covers everything, so no further condition
			// can narrow the answer.
			return "", nil
		}
		parts := make([]string, 0, 2)
		for _, dimension := range []struct {
			column string
			value  string
		}{{siteColumn, scope.Site}, {envColumn, scope.Environment}} {
			switch dimension.value {
			case authz.Wildcard:
				// Any value in this dimension.
			case "":
				// Not knowing the scope must not widen what is shown.
				parts = append(parts, "false")
			default:
				args = append(args, dimension.value)
				parts = append(parts, fmt.Sprintf("%s = $%d", dimension.column, offset+len(args)))
			}
		}
		if len(parts) == 0 {
			return "", nil
		}
		conditions = append(conditions, "("+strings.Join(parts, " and ")+")")
	}
	return "(" + strings.Join(conditions, " or ") + ")", args
}

// ScopeOf is the authorisation scope of a host: where it stands and whose
// it is. Every check on a host goes through it, so that a team binding
// and a site binding are read from the same three fields and one of them
// cannot be forgotten in a handler written later.
func ScopeOf(host *Host) authz.Scope {
	if host == nil {
		// An unknown host cannot be matched by a narrow binding, and an
		// empty scope is matched by none.
		return authz.Scope{}
	}
	return authz.Scope{Site: host.Site, Environment: host.Environment, Team: host.TeamID}
}
