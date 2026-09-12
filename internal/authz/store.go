package authz

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TokenPrefix distinguishes an API token from other secrets in logs and configuration.
const TokenPrefix = "flta_"

var (
	// ErrUnauthenticated means a missing or invalid token.
	ErrUnauthenticated = errors.New("no valid authentication")
	// ErrNotFound means the identity does not exist.
	ErrNotFound = errors.New("the identity does not exist")
)

// Store provides access to identities, tokens and role assignments.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Token describes an issued API token. The value is visible only at the
// moment it is created.
type Token struct {
	ID          string     `json:"id"`
	PrincipalID string     `json:"principal_id"`
	Subject     string     `json:"subject"`
	Value       string     `json:"value,omitempty"`
	Description string     `json:"description,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// EnsurePrincipal creates an identity or returns the existing one.
func (s *Store) EnsurePrincipal(ctx context.Context, tx pgx.Tx,
	subject, displayName, kind string) (string, error) {
	if kind == "" {
		kind = "user"
	}
	const query = `
		insert into principals (id, subject, display_name, kind)
		values ($1, $2, $3, $4)
		on conflict (subject) do update set
			display_name = coalesce(nullif(excluded.display_name, ''), principals.display_name),
			updated_at   = now()
		returning id`
	var id string
	err := tx.QueryRow(ctx, query, uuid.NewString(), subject, displayName, kind).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("saving the identity: %w", err)
	}
	return id, nil
}

// GrantRole assigns a role within a scope. Assigning it again is safe.
func (s *Store) GrantRole(ctx context.Context, tx pgx.Tx,
	principalID string, role Role, scope Scope, createdBy string) error {
	if !KnownRole(role) {
		return fmt.Errorf("unknown role %q", role)
	}
	const query = `
		insert into role_bindings (id, principal_id, role, site, environment, created_by)
		values ($1, $2, $3, $4, $5, $6)
		on conflict (principal_id, role, site, environment) do nothing`
	_, err := tx.Exec(ctx, query, uuid.NewString(), principalID, string(role),
		orWildcard(scope.Site), orWildcard(scope.Environment), createdBy)
	return err
}

// IssueToken issues a token for an identity. Only its digest is stored in the database.
func (s *Store) IssueToken(ctx context.Context, tx pgx.Tx, principalID, description string,
	ttl time.Duration, createdBy string) (*Token, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	value := TokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(value))

	token := &Token{ID: uuid.NewString(), PrincipalID: principalID, Value: value, Description: description}
	var expiresAt any
	if ttl > 0 {
		deadline := time.Now().Add(ttl)
		token.ExpiresAt = &deadline
		expiresAt = deadline
	}

	const query = `
		insert into api_tokens (id, principal_id, token_hash, description, expires_at, created_by)
		values ($1, $2, $3, $4, $5, $6)
		returning created_at`
	if err := tx.QueryRow(ctx, query, token.ID, principalID, hash[:],
		nullable(description), expiresAt, createdBy).Scan(&token.CreatedAt); err != nil {
		return nil, fmt.Errorf("saving the token: %w", err)
	}
	return token, nil
}

// Authenticate turns a token into an identity together with its roles.
// The digest comparison runs in constant time, so as not to reveal the
// token's prefix.
func (s *Store) Authenticate(ctx context.Context, value string) (*Principal, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, ErrUnauthenticated
	}
	hash := sha256.Sum256([]byte(value))

	const query = `
		select t.id, t.token_hash, p.id, p.subject, p.display_name, p.kind
		from api_tokens t
		join principals p on p.id = t.principal_id
		where t.token_hash = $1
		  and t.revoked_at is null
		  and (t.expires_at is null or t.expires_at > now())
		  and p.disabled_at is null
		  -- The local denial marker takes effect at once, regardless of
		  -- whether the lock has reached the directory yet.
		  and p.denied_at is null`
	var (
		tokenID    string
		storedHash []byte
		principal  Principal
	)
	err := s.pool.QueryRow(ctx, query, hash[:]).
		Scan(&tokenID, &storedHash, &principal.ID, &principal.Subject,
			&principal.DisplayName, &principal.Kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUnauthenticated
	}
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(storedHash, hash[:]) != 1 {
		return nil, ErrUnauthenticated
	}

	bindings, err := s.bindingsOf(ctx, principal.ID)
	if err != nil {
		return nil, err
	}
	principal.Bindings = bindings

	// Recording the use is auxiliary; its failure must not block the request.
	_, _ = s.pool.Exec(ctx, `update api_tokens set last_used_at = now() where id = $1`, tokenID)
	return &principal, nil
}

func (s *Store) bindingsOf(ctx context.Context, principalID string) ([]Binding, error) {
	const query = `select role, site, environment from role_bindings where principal_id = $1`
	rows, err := s.pool.Query(ctx, query, principalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bindings []Binding
	for rows.Next() {
		var binding Binding
		if err := rows.Scan(&binding.Role, &binding.Scope.Site, &binding.Scope.Environment); err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	return bindings, rows.Err()
}

// ListPrincipals returns the identities together with their roles.
func (s *Store) ListPrincipals(ctx context.Context) ([]Principal, error) {
	const query = `
		select id, subject, display_name, kind
		from principals
		where disabled_at is null
		order by subject`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	var principals []Principal
	for rows.Next() {
		var principal Principal
		if err := rows.Scan(&principal.ID, &principal.Subject,
			&principal.DisplayName, &principal.Kind); err != nil {
			rows.Close()
			return nil, err
		}
		principals = append(principals, principal)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for i := range principals {
		bindings, err := s.bindingsOf(ctx, principals[i].ID)
		if err != nil {
			return nil, err
		}
		// An empty list is not the same as a missing list. Empty assignments
		// rendered as null in JSON broke the interface that read their count;
		// besides, an identity without assignments of its own can still have
		// roles from the group mapping, so "none" is information here rather
		// than missing data.
		if bindings == nil {
			bindings = []Binding{}
		}
		principals[i].Bindings = bindings
	}
	return principals, nil
}

// CountPrincipals says whether the system has any identity yet.
func (s *Store) CountPrincipals(ctx context.Context) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `select count(*) from principals`).Scan(&count)
	return count, err
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// GroupMapping binds an external group to a role within a scope.
type GroupMapping struct {
	ID          string    `json:"id"`
	Issuer      string    `json:"issuer"`
	GroupName   string    `json:"group_name"`
	Role        Role      `json:"role"`
	Site        string    `json:"site"`
	Environment string    `json:"environment"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
}

// CreateGroupMapping adds a mapping from a group to a role.
func (s *Store) CreateGroupMapping(ctx context.Context, tx pgx.Tx,
	issuer, groupName string, role Role, scope Scope, createdBy string) (*GroupMapping, error) {
	if !KnownRole(role) {
		return nil, fmt.Errorf("unknown role %q", role)
	}
	if issuer == "" || groupName == "" {
		return nil, fmt.Errorf("a mapping requires an issuer and a group name")
	}
	mapping := &GroupMapping{
		ID: uuid.NewString(), Issuer: issuer, GroupName: groupName, Role: role,
		Site: orWildcard(scope.Site), Environment: orWildcard(scope.Environment),
		CreatedBy: createdBy,
	}
	const query = `
		insert into group_role_mappings (id, issuer, group_name, role, site, environment, created_by)
		values ($1, $2, $3, $4, $5, $6, $7)
		on conflict (issuer, group_name, role, site, environment) do update
			set created_by = group_role_mappings.created_by
		returning id, created_at`
	if err := tx.QueryRow(ctx, query, mapping.ID, issuer, groupName, string(role),
		mapping.Site, mapping.Environment, createdBy).Scan(&mapping.ID, &mapping.CreatedAt); err != nil {
		return nil, fmt.Errorf("saving the group mapping: %w", err)
	}
	return mapping, nil
}

// ListGroupMappings returns the group mappings.
func (s *Store) ListGroupMappings(ctx context.Context) ([]GroupMapping, error) {
	const query = `
		select id, issuer, group_name, role, site, environment, created_by, created_at
		from group_role_mappings
		order by issuer, group_name, role`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var mappings []GroupMapping
	for rows.Next() {
		var mapping GroupMapping
		if err := rows.Scan(&mapping.ID, &mapping.Issuer, &mapping.GroupName, &mapping.Role,
			&mapping.Site, &mapping.Environment, &mapping.CreatedBy, &mapping.CreatedAt); err != nil {
			return nil, err
		}
		mappings = append(mappings, mapping)
	}
	return mappings, rows.Err()
}

// DeleteGroupMapping removes a mapping. Users lose the role that followed
// from it on their next request, without having to log in again.
func (s *Store) DeleteGroupMapping(ctx context.Context, mappingID string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `delete from group_role_mappings where id = $1`, mappingID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}
