package authz

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The answers a caller has to tell apart when a role will not do what was
// asked. Each one is a different thing to say to whoever asked.
var (
	// ErrUnknownRole is a name that is neither the product's nor this
	// installation's. It is never an empty permission set: a role nobody can
	// resolve must stop the request, not grant nothing quietly.
	ErrUnknownRole = errors.New("no such role")
	// ErrBuiltInRole is an attempt to edit or delete a role of the product's.
	ErrBuiltInRole = errors.New("a built-in role is defined by the product")
	// ErrRoleInUse is a deletion refused because somebody is bound to the role
	// or a group maps to it.
	ErrRoleInUse = errors.New("the role is still granted to somebody")
	// ErrRoleExists is a name already taken, by either kind.
	ErrRoleExists = errors.New("a role of that name already exists")
)

// RoleDefinition is one role of this installation, of either kind.
type RoleDefinition struct {
	Name      string     `json:"role"`
	BuiltIn   bool       `json:"built_in"`
	Comment   string     `json:"description,omitempty"`
	CreatedBy string     `json:"created_by,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
	// Permissions is what the role carries: from the code for a built-in
	// role, from the database for one defined here.
	Permissions []string `json:"permissions"`
	// Bindings and Mappings say whether anybody is using the role. A role in
	// use cannot be deleted, and a screen that only found that out from a
	// refusal would be offering an action it knows will fail.
	Bindings int `json:"bindings"`
	Mappings int `json:"mappings"`
}

// ListRoles returns every role this installation has, the product's and its
// own, with what each one carries and how much it is used.
func (s *Store) ListRoles(ctx context.Context) ([]RoleDefinition, error) {
	const query = `
		select r.name, r.built_in, r.description, r.created_by, r.created_at,
		       coalesce(p.granted, '{}'),
		       (select count(*) from role_bindings b where b.role = r.name),
		       (select count(*) from group_role_mappings m where m.role = r.name)
		from roles r
		left join (
			select role, array_agg(permission order by permission) as granted
			from role_permissions group by role
		) p on p.role = r.name
		order by r.built_in desc, r.name`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	roles := make([]RoleDefinition, 0)
	for rows.Next() {
		var role RoleDefinition
		var created time.Time
		var granted []string
		if err := rows.Scan(&role.Name, &role.BuiltIn, &role.Comment, &role.CreatedBy, &created,
			&granted, &role.Bindings, &role.Mappings); err != nil {
			return nil, err
		}
		role.CreatedAt = &created
		if role.BuiltIn {
			// The code answers for a built-in role. Whatever rows exist are
			// not consulted, so the two can never disagree about one.
			granted = nil
			for _, permission := range Role(role.Name).Permissions() {
				granted = append(granted, string(permission))
			}
		}
		sort.Strings(granted)
		role.Permissions = granted
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

// RolePermissions answers what one role carries, for either kind, and refuses
// a name that is neither.
//
// This is the question every grant has to ask before it decides whether the
// person granting holds as much as they are handing out. Answering "nothing"
// for a role nobody could resolve would make that comparison pass.
func (s *Store) RolePermissions(ctx context.Context, role Role) ([]Permission, error) {
	if BuiltIn(role) {
		return role.Permissions(), nil
	}
	var builtIn bool
	var granted []string
	err := s.pool.QueryRow(ctx, `
		select r.built_in, coalesce(array_agg(p.permission) filter (where p.permission is not null), '{}')
		from roles r
		left join role_permissions p on p.role = r.name
		where r.name = $1
		group by r.built_in`, string(role)).Scan(&builtIn, &granted)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrUnknownRole, role)
	}
	if err != nil {
		return nil, err
	}
	if builtIn {
		// A name the product also defines: the code answers, always.
		return role.Permissions(), nil
	}
	permissions := make([]Permission, 0, len(granted))
	for _, permission := range granted {
		permissions = append(permissions, Permission(permission))
	}
	sort.Slice(permissions, func(i, j int) bool { return permissions[i] < permissions[j] })
	return permissions, nil
}

// ValidRoleName holds a name to what a binding, a mapping and an audit line
// can carry back: the same spelling the database constrains.
func ValidRoleName(name string) bool {
	if len(name) < 2 || len(name) > 63 {
		return false
	}
	if name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for _, letter := range name[1:] {
		switch {
		case letter >= 'a' && letter <= 'z', letter >= '0' && letter <= '9', letter == '_':
		default:
			return false
		}
	}
	return true
}

// CreateRole writes down a role of this installation's own.
func (s *Store) CreateRole(ctx context.Context, tx pgx.Tx,
	name, description string, permissions []Permission, by string) error {
	name = strings.TrimSpace(name)
	if !ValidRoleName(name) {
		return fmt.Errorf("a role name is lower case letters, digits and underscores, 2 to 63 of them: %q", name)
	}
	if BuiltIn(Role(name)) {
		return fmt.Errorf("%w: %s", ErrRoleExists, name)
	}
	if err := checkPermissions(permissions); err != nil {
		return err
	}
	_, err := tx.Exec(ctx,
		`insert into roles (name, built_in, description, created_by) values ($1, false, $2, $3)`,
		name, strings.TrimSpace(description), by)
	if isUniqueViolation(err) {
		return fmt.Errorf("%w: %s", ErrRoleExists, name)
	}
	if err != nil {
		return err
	}
	return writePermissions(ctx, tx, name, permissions)
}

// ReplaceRole sets what a role of this installation's own carries. The
// permissions are written whole rather than added to: an edit that could only
// widen a role would be a strange thing to offer on a screen about access.
func (s *Store) ReplaceRole(ctx context.Context, tx pgx.Tx,
	name, description string, permissions []Permission) error {
	if BuiltIn(Role(name)) {
		return fmt.Errorf("%w: %s", ErrBuiltInRole, name)
	}
	if err := checkPermissions(permissions); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx,
		`update roles set description = $2 where name = $1 and built_in = false`,
		name, strings.TrimSpace(description))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %s", ErrUnknownRole, name)
	}
	if _, err := tx.Exec(ctx, `delete from role_permissions where role = $1`, name); err != nil {
		return err
	}
	return writePermissions(ctx, tx, name, permissions)
}

// DeleteRole removes a role of this installation's own. A role somebody is
// bound to, or a group maps to, is refused: the database holds to that with a
// foreign key, and this turns the refusal into something to say.
func (s *Store) DeleteRole(ctx context.Context, tx pgx.Tx, name string) error {
	if BuiltIn(Role(name)) {
		return fmt.Errorf("%w: %s", ErrBuiltInRole, name)
	}
	tag, err := tx.Exec(ctx, `delete from roles where name = $1 and built_in = false`, name)
	if isForeignKeyViolation(err) {
		return fmt.Errorf("%w: %s", ErrRoleInUse, name)
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %s", ErrUnknownRole, name)
	}
	return nil
}

// checkPermissions refuses a role that carries a name this product does not
// define, and one that carries nothing at all. A role granting nothing is not
// a useful thing to have made by accident: it reads on every screen as a role
// somebody holds.
func checkPermissions(permissions []Permission) error {
	if len(permissions) == 0 {
		return errors.New("a role carries at least one permission")
	}
	for _, permission := range permissions {
		if !KnownPermission(permission) {
			return fmt.Errorf("%q is not a permission of this product", permission)
		}
	}
	return nil
}

func writePermissions(ctx context.Context, tx pgx.Tx, name string, permissions []Permission) error {
	seen := map[Permission]bool{}
	for _, permission := range permissions {
		if seen[permission] {
			continue
		}
		seen[permission] = true
		if _, err := tx.Exec(ctx,
			`insert into role_permissions (role, permission) values ($1, $2)`,
			name, string(permission)); err != nil {
			return err
		}
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

// roleBindable refuses a name no role has, inside the caller's transaction.
//
// The compiled list is not the answer: an installation's own roles are
// bindable too, so asking the code alone would refuse every one of them. The
// table is asked in the caller's transaction, which closes the gap between
// the question and the insert, and the foreign key is the last word after
// that. There is no fallback for a database without the table - the panel
// runs its migrations before it serves, and a check that lets a name through
// when it could not look it up is not a check.
func roleBindable(ctx context.Context, tx pgx.Tx, role Role) error {
	var exists bool
	if err := tx.QueryRow(ctx,
		`select exists (select 1 from roles where name = $1)`, string(role)).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: %s", ErrUnknownRole, role)
	}
	return nil
}
