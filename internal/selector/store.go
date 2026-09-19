package selector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	// ErrGroupNotFound means there is no group with the given identifier or name.
	ErrGroupNotFound = errors.New("the group does not exist")
	// ErrNameTaken means another group already carries the name.
	ErrNameTaken = errors.New("a group with this name already exists")
	// ErrNotStatic means a member list was given to a dynamic group, whose
	// members are the answer of its selector and cannot be set by hand.
	ErrNotStatic = errors.New("a dynamic group has no member list; change its selector")
	// ErrUnknownHosts means a member list naming hosts the panel does not
	// have or the caller may not see.
	ErrUnknownHosts = errors.New("the member list names unknown hosts")
)

// NamePattern is the shape of a group name: something an operator types into a
// selector and reads in an audit line.
var NamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

// MaxMembers bounds a static group. It matches the bound of one campaign:
// a group nobody could run a campaign on is not a group anybody meant.
const MaxMembers = 10000

// SavedGroup is a group as the API shows it.
type SavedGroup struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Kind        Kind        `json:"kind"`
	Selector    *Expression `json:"selector,omitempty"`
	CreatedBy   string      `json:"created_by"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
	// MemberCount is the size of a static group, counted in the database.
	MemberCount *int `json:"member_count,omitempty"`
}

// Validate checks the description of a group.
func (g SavedGroup) Validate() error {
	if !NamePattern.MatchString(g.Name) {
		return fmt.Errorf("%w: the name has to be 1-64 characters of letters, digits, '_', '.' or '-'", ErrInvalid)
	}
	if len(g.Description) > 1000 {
		return fmt.Errorf("%w: the description is longer than 1000 characters", ErrInvalid)
	}
	switch g.Kind {
	case KindStatic:
		if g.Selector != nil {
			return fmt.Errorf("%w: a static group has members, not a selector", ErrInvalid)
		}
	case KindDynamic:
		if g.Selector == nil {
			return fmt.Errorf("%w: a dynamic group needs a selector", ErrInvalid)
		}
		if err := g.Selector.Validate(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: the kind has to be static or dynamic", ErrInvalid)
	}
	return nil
}

// Store keeps the saved groups.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Lookup resolves a reference by identifier or by name for the expander.
func (s *Store) Lookup(ctx context.Context, ref string) (*Group, error) {
	saved, err := s.Get(ctx, ref)
	if errors.Is(err, ErrGroupNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &Group{ID: saved.ID, Name: saved.Name, Kind: saved.Kind, Selector: saved.Selector}, nil
}

const groupColumns = `
	select g.id, g.name, g.description, g.kind, g.selector, g.created_by, g.created_at, g.updated_at,
	       case when g.kind = 'static'
	            then (select count(*) from host_group_members m where m.group_id = g.id)
	       end
	from host_groups g`

// Get returns a group by identifier or by name. A reference that parses
// as an identifier is looked up as one; anything else is a name.
func (s *Store) Get(ctx context.Context, ref string) (*SavedGroup, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, ErrGroupNotFound
	}
	where := " where g.name = $1"
	if _, err := uuid.Parse(ref); err == nil {
		where = " where g.id = $1::uuid"
	}
	rows, err := s.pool.Query(ctx, groupColumns+where, ref)
	if err != nil {
		return nil, err
	}
	groups, err := scanGroups(rows)
	if err != nil {
		return nil, err
	}
	if len(groups) == 0 {
		return nil, ErrGroupNotFound
	}
	return &groups[0], nil
}

// List returns every group by name.
func (s *Store) List(ctx context.Context) ([]SavedGroup, error) {
	rows, err := s.pool.Query(ctx, groupColumns+" order by g.name")
	if err != nil {
		return nil, err
	}
	return scanGroups(rows)
}

func scanGroups(rows pgx.Rows) ([]SavedGroup, error) {
	defer rows.Close()
	groups := []SavedGroup{}
	for rows.Next() {
		var g SavedGroup
		var selector []byte
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.Kind, &selector,
			&g.CreatedBy, &g.CreatedAt, &g.UpdatedAt, &g.MemberCount); err != nil {
			return nil, err
		}
		if len(selector) > 0 {
			g.Selector = &Expression{}
			if err := json.Unmarshal(selector, g.Selector); err != nil {
				return nil, fmt.Errorf("the selector of the group %s: %w", g.Name, err)
			}
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

// Create records a new group.
func (s *Store) Create(ctx context.Context, g SavedGroup) (*SavedGroup, error) {
	if err := g.Validate(); err != nil {
		return nil, err
	}
	selector, err := selectorArg(g.Selector)
	if err != nil {
		return nil, err
	}
	id := uuid.NewString()
	// The name is unique; a collision comes back as no row rather than as
	// a database error the caller would have to recognise by its code.
	const query = `
		insert into host_groups (id, name, description, kind, selector, created_by)
		values ($1, $2, $3, $4, $5, $6)
		on conflict (name) do nothing
		returning id`
	var created string
	err = s.pool.QueryRow(ctx, query, id, g.Name, g.Description, string(g.Kind), selector, g.CreatedBy).Scan(&created)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNameTaken
	}
	if err != nil {
		return nil, fmt.Errorf("creating the group: %w", err)
	}
	return s.Get(ctx, created)
}

// Update changes the name, the description and - for a dynamic group - the
// selector.
func (s *Store) Update(ctx context.Context, id string, g SavedGroup) (*SavedGroup, error) {
	current, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	g.Kind = current.Kind
	if g.Kind == KindStatic {
		g.Selector = nil
	}
	if err := g.Validate(); err != nil {
		return nil, err
	}
	selector, err := selectorArg(g.Selector)
	if err != nil {
		return nil, err
	}
	const query = `
		update host_groups
		   set name = $2, description = $3, selector = $4, updated_at = now()
		 where id = $1::uuid
		   and not exists (select 1 from host_groups other where other.name = $2 and other.id <> $1::uuid)`
	tag, err := s.pool.Exec(ctx, query, current.ID, g.Name, g.Description, selector)
	if err != nil {
		return nil, fmt.Errorf("updating the group: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNameTaken
	}
	return s.Get(ctx, current.ID)
}

// Delete removes a group together with its member list.
func (s *Store) Delete(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `delete from host_groups where id = $1::uuid`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrGroupNotFound
	}
	return nil
}

// SetMembers replaces the member list of a static group. The list is the whole
// list: a member left out is a member removed.
func (s *Store) SetMembers(ctx context.Context, id string, hostIDs []string) error {
	group, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if group.Kind != KindStatic {
		return ErrNotStatic
	}
	if len(hostIDs) > MaxMembers {
		return fmt.Errorf("%w: a group holds at most %d hosts", ErrInvalid, MaxMembers)
	}
	unique := dedupe(hostIDs)
	for _, hostID := range unique {
		if _, err := uuid.Parse(hostID); err != nil {
			return fmt.Errorf("%w: %q is not a host identifier", ErrUnknownHosts, hostID)
		}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `delete from host_group_members where group_id = $1::uuid`, group.ID); err != nil {
		return fmt.Errorf("clearing the member list: %w", err)
	}
	// The identifiers travel as text and are cast in the query: the caller has
	// checked their shape, so the cast cannot fail, and the text form needs no
	// guesswork about how the driver encodes an identifier list.
	tag, err := tx.Exec(ctx, `
		insert into host_group_members (group_id, host_id)
		select $1::uuid, h.id from hosts h
		 where h.id in (select unnest($2::text[])::uuid)`, group.ID, unique)
	if err != nil {
		return fmt.Errorf("recording the member list: %w", err)
	}
	if int(tag.RowsAffected()) != len(unique) {
		return ErrUnknownHosts
	}
	if _, err := tx.Exec(ctx, `update host_groups set updated_at = now() where id = $1::uuid`, group.ID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Members returns the host identifiers of a static group.
func (s *Store) Members(ctx context.Context, id string) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`select host_id::text from host_group_members where group_id = $1::uuid order by host_id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	members := []string{}
	for rows.Next() {
		var hostID string
		if err := rows.Scan(&hostID); err != nil {
			return nil, err
		}
		members = append(members, hostID)
	}
	return members, rows.Err()
}

// selectorArg renders the selector for the jsonb column; nil stays NULL,
// which is what the table expects of a static group.
func selectorArg(e *Expression) (any, error) {
	if e == nil {
		return nil, nil
	}
	encoded, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func dedupe(values []string) []string {
	seen := map[string]bool{}
	unique := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		unique = append(unique, value)
	}
	return unique
}
