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

// BootstrapSubject is the identity created on the first start, before any
// other exists.
const BootstrapSubject = "bootstrap-admin"

var (
	// ErrUnauthenticated means a missing or invalid token.
	ErrUnauthenticated = errors.New("no valid authentication")
	// ErrNotFound means the identity does not exist.
	ErrNotFound = errors.New("the identity does not exist")
)

// Store provides access to identities, tokens and role assignments.
type Store struct {
	pool *pgxpool.Pool
	// sessionIdle is the idle window of a browser session, refreshed on
	// every request. Zero means defaultIdleWindow.
	sessionIdle time.Duration
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// SetSessionIdle sets the idle window the sessions are refreshed with.
func (s *Store) SetSessionIdle(idle time.Duration) {
	s.sessionIdle = idle
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
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
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

// GrantRole assigns a role within a scope, until the given moment or, with
// nil, until revoked.
func (s *Store) GrantRole(ctx context.Context, tx pgx.Tx,
	principalID string, role Role, scope Scope, validUntil *time.Time, createdBy string) error {
	if !KnownRole(role) {
		return fmt.Errorf("unknown role %q", role)
	}
	// A binding names a team or a site, never both: the two are different
	// vocabularies, and the insert follows the constraint rather than letting the
	// database explain it afterwards.
	if scope.Team != "" {
		const teamQuery = `
			insert into role_bindings (id, principal_id, role, site, environment, team_id, valid_until, created_by)
			values ($1, $2, $3, '*', '*', $4::uuid, $5, $6)
			on conflict (principal_id, role, team_id) where team_id is not null do update
				set valid_until = excluded.valid_until, expiry_noted = false`
		_, err := tx.Exec(ctx, teamQuery, uuid.NewString(), principalID, string(role),
			scope.Team, validUntil, createdBy)
		return err
	}
	const query = `
		insert into role_bindings (id, principal_id, role, site, environment, valid_until, created_by)
		values ($1, $2, $3, $4, $5, $6, $7)
		on conflict (principal_id, role, site, environment) do update
			set valid_until = excluded.valid_until, expiry_noted = false`
	_, err := tx.Exec(ctx, query, uuid.NewString(), principalID, string(role),
		orWildcard(scope.Site), orWildcard(scope.Environment), validUntil, createdBy)
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

// ListTokens returns the live tokens of an identity: neither revoked nor
// expired. The value is not among them - it was shown once.
func (s *Store) ListTokens(ctx context.Context, principalID string) ([]Token, error) {
	const query = `
		select t.id, t.principal_id, p.subject, coalesce(t.description, ''),
		       t.expires_at, t.last_used_at, t.created_at
		from api_tokens t
		join principals p on p.id = t.principal_id
		where t.principal_id = $1
		  and t.revoked_at is null
		  and (t.expires_at is null or t.expires_at > now())
		order by t.created_at`
	rows, err := s.pool.Query(ctx, query, principalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tokens := []Token{}
	for rows.Next() {
		var token Token
		if err := rows.Scan(&token.ID, &token.PrincipalID, &token.Subject, &token.Description,
			&token.ExpiresAt, &token.LastUsedAt, &token.CreatedAt); err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	return tokens, rows.Err()
}

// RevokeToken ends one token of an identity.
func (s *Store) RevokeToken(ctx context.Context, tx pgx.Tx, principalID, tokenID string) (bool, error) {
	tag, err := tx.Exec(ctx, `
		update api_tokens set revoked_at = now()
		where id = $2 and principal_id = $1 and revoked_at is null`, principalID, tokenID)
	if err != nil {
		return false, fmt.Errorf("revoking the token: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// RevokeTokensOf ends every live token of an identity.
func (s *Store) RevokeTokensOf(ctx context.Context, tx pgx.Tx, principalID string) (int64, error) {
	tag, err := tx.Exec(ctx, `
		update api_tokens set revoked_at = now()
		where principal_id = $1 and revoked_at is null`, principalID)
	if err != nil {
		return 0, fmt.Errorf("revoking the tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}

// DisablePrincipal takes the access of an identity away without deleting it:
// the trail keeps naming it, and its bindings show what it could do.
func (s *Store) DisablePrincipal(ctx context.Context, tx pgx.Tx, principalID, reason string) error {
	tag, err := tx.Exec(ctx, `
		update principals set disabled_at = now(), updated_at = now()
		where id = $1 and disabled_at is null`, principalID)
	if err != nil {
		return fmt.Errorf("disabling the identity: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `
		update web_sessions set revoked_at = now(), revocation_reason = $2, refresh_token = null
		where principal_id = $1 and revoked_at is null`, principalID, nullable(reason)); err != nil {
		return fmt.Errorf("ending the sessions: %w", err)
	}
	if _, err := s.RevokeTokensOf(ctx, tx, principalID); err != nil {
		return err
	}
	return nil
}

// RevokeRole removes one binding of an identity. The scope is part of the
// key: an operator on one site keeps the role on the other.
func (s *Store) RevokeRole(ctx context.Context, tx pgx.Tx, principalID string,
	role Role, scope Scope) (bool, error) {
	if scope.Team != "" {
		tag, err := tx.Exec(ctx, `
			delete from role_bindings
			where principal_id = $1 and role = $2 and team_id = $3::uuid`,
			principalID, string(role), scope.Team)
		if err != nil {
			return false, fmt.Errorf("removing the binding: %w", err)
		}
		return tag.RowsAffected() > 0, nil
	}
	tag, err := tx.Exec(ctx, `
		delete from role_bindings
		where principal_id = $1 and role = $2 and site = $3 and environment = $4
		  and team_id is null`,
		principalID, string(role), orWildcard(scope.Site), orWildcard(scope.Environment))
	if err != nil {
		return false, fmt.Errorf("removing the binding: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// PrincipalByID reads one identity, disabled or not, with its bindings.
func (s *Store) PrincipalByID(ctx context.Context, principalID string) (*Principal, error) {
	const query = `select id, subject, display_name, kind from principals where id = $1`
	var principal Principal
	err := s.pool.QueryRow(ctx, query, principalID).
		Scan(&principal.ID, &principal.Subject, &principal.DisplayName, &principal.Kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	bindings, err := s.allBindingsOf(ctx, principal.ID)
	if err != nil {
		return nil, err
	}
	if bindings == nil {
		bindings = []Binding{}
	}
	principal.Bindings = bindings
	return &principal, nil
}

// BootstrapTokenState says whether the bootstrap token still works and whether
// anybody else holds the platform administrator role.
func (s *Store) BootstrapTokenState(ctx context.Context) (live, otherAdmins bool, err error) {
	const query = `
		select exists (
			select 1 from api_tokens t
			join principals p on p.id = t.principal_id
			where p.subject = $1 and p.disabled_at is null
			  and t.revoked_at is null and (t.expires_at is null or t.expires_at > now())),
		exists (
			select 1 from role_bindings b
			join principals p on p.id = b.principal_id
			where b.role = $2 and p.subject <> $1 and p.disabled_at is null
			  and (b.valid_until is null or b.valid_until > now()))`
	err = s.pool.QueryRow(ctx, query, BootstrapSubject, string(RolePlatformAdmin)).Scan(&live, &otherAdmins)
	return live, otherAdmins, err
}

// Authenticate turns a token into an identity together with its roles.
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

// PrincipalBySubject resolves an identity by its subject with its current
// bindings.
func (s *Store) PrincipalBySubject(ctx context.Context, subject string) (*Principal, error) {
	const query = `
		select id, subject, display_name, kind, coalesce(issuer, '') from principals
		where subject = $1 and disabled_at is null and denied_at is null`
	var principal Principal
	var issuer string
	err := s.pool.QueryRow(ctx, query, subject).
		Scan(&principal.ID, &principal.Subject, &principal.DisplayName, &principal.Kind, &issuer)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUnauthenticated
	}
	if err != nil {
		return nil, err
	}
	bindings, err := s.bindingsOf(ctx, principal.ID)
	if err != nil {
		return nil, err
	}
	var groups []string
	err = s.pool.QueryRow(ctx, `
		select groups from web_sessions
		 where principal_id = $1
		 order by coalesce(groups_refreshed_at, created_at) desc
		 limit 1`, principal.ID).Scan(&groups)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if len(groups) > 0 && issuer != "" {
		mapped, err := s.MappedBindings(ctx, issuer, groups)
		if err != nil {
			return nil, err
		}
		bindings = mergeBindings(bindings, mapped)
	}
	principal.Bindings = bindings
	return &principal, nil
}

// bindingsOf returns the bindings that grant something now.
func (s *Store) bindingsOf(ctx context.Context, principalID string) ([]Binding, error) {
	return s.readBindings(ctx, principalID, true)
}

// allBindingsOf returns every binding on record, the expired ones included.
func (s *Store) allBindingsOf(ctx context.Context, principalID string) ([]Binding, error) {
	return s.readBindings(ctx, principalID, false)
}

func (s *Store) readBindings(ctx context.Context, principalID string, liveOnly bool) ([]Binding, error) {
	query := `select role, site, environment, coalesce(team_id::text, ''), valid_until
		from role_bindings where principal_id = $1`
	if liveOnly {
		query += ` and (valid_until is null or valid_until > now())`
	}
	rows, err := s.pool.Query(ctx, query+` order by role, site, environment`, principalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bindings []Binding
	for rows.Next() {
		var binding Binding
		if err := rows.Scan(&binding.Role, &binding.Scope.Site, &binding.Scope.Environment,
			&binding.Scope.Team, &binding.ValidUntil); err != nil {
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
		bindings, err := s.allBindingsOf(ctx, principals[i].ID)
		if err != nil {
			return nil, err
		}
		// An empty list is not the same as a missing list.
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

// The thresholds of the access review.
const (
	ReviewUnusedAfter  = 90 * 24 * time.Hour
	ReviewExpiringSoon = 14 * 24 * time.Hour
	ReviewTokenMaxAge  = 365 * 24 * time.Hour
)

// The flags the review raises.
const (
	FlagUnused90Days       = "unused_90_days"
	FlagExpiresSoon        = "expires_soon"
	FlagAdminWithoutExpiry = "admin_without_expiry"
	FlagTokenOlderThanYear = "token_older_than_year"
)

// ReviewedBinding is a binding as the access review shows it: with its
// validity, whether it has ended, and who granted it when.
type ReviewedBinding struct {
	Role       Role       `json:"role"`
	Scope      Scope      `json:"scope"`
	ValidUntil *time.Time `json:"valid_until,omitempty"`
	Expired    bool       `json:"expired"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
}

// ReviewedPrincipal is one identity of the access review.
type ReviewedPrincipal struct {
	ID          string    `json:"id"`
	Subject     string    `json:"subject"`
	DisplayName string    `json:"display_name,omitempty"`
	Kind        string    `json:"kind"`
	CreatedAt   time.Time `json:"created_at"`
	// LastLoginAt is the last sign-in through the identity provider,
	// LastTokenUseAt the last request with one of the identity's tokens, and
	// LastSeenAt the later of the two.
	LastLoginAt    *time.Time `json:"last_login_at,omitempty"`
	LastTokenUseAt *time.Time `json:"last_token_use_at,omitempty"`
	LastSeenAt     *time.Time `json:"last_seen_at,omitempty"`
	DaysSinceUse   *int       `json:"days_since_use,omitempty"`
	// EarliestExpiry is the first moment one of the live bindings ends.
	EarliestExpiry *time.Time        `json:"earliest_expiry,omitempty"`
	Bindings       []ReviewedBinding `json:"bindings"`
	Tokens         []Token           `json:"tokens"`
	Flags          []string          `json:"flags"`
}

// ReviewAccess lists every enabled identity with what it can do, when it was
// last used and what the reviewer should look at.
func (s *Store) ReviewAccess(ctx context.Context, now time.Time) ([]ReviewedPrincipal, error) {
	rows, err := s.pool.Query(ctx, `
		select p.id, p.subject, p.display_name, p.kind, p.created_at, p.last_login_at,
		       (select max(t.last_used_at) from api_tokens t where t.principal_id = p.id)
		from principals p
		where p.disabled_at is null
		order by p.subject`)
	if err != nil {
		return nil, err
	}
	principals := []ReviewedPrincipal{}
	index := map[string]int{}
	for rows.Next() {
		var principal ReviewedPrincipal
		if err := rows.Scan(&principal.ID, &principal.Subject, &principal.DisplayName, &principal.Kind,
			&principal.CreatedAt, &principal.LastLoginAt, &principal.LastTokenUseAt); err != nil {
			rows.Close()
			return nil, err
		}
		principal.Bindings = []ReviewedBinding{}
		principal.Tokens = []Token{}
		principal.Flags = []string{}
		index[principal.ID] = len(principals)
		principals = append(principals, principal)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	bindings, err := s.pool.Query(ctx, `
		select principal_id, role, site, environment, valid_until, created_by, created_at
		from role_bindings order by principal_id, role, site, environment`)
	if err != nil {
		return nil, err
	}
	for bindings.Next() {
		var principalID string
		var binding ReviewedBinding
		if err := bindings.Scan(&principalID, &binding.Role, &binding.Scope.Site, &binding.Scope.Environment,
			&binding.ValidUntil, &binding.CreatedBy, &binding.CreatedAt); err != nil {
			bindings.Close()
			return nil, err
		}
		binding.Expired = binding.ValidUntil != nil && !now.Before(*binding.ValidUntil)
		if i, ok := index[principalID]; ok {
			principals[i].Bindings = append(principals[i].Bindings, binding)
		}
	}
	bindings.Close()
	if err := bindings.Err(); err != nil {
		return nil, err
	}

	tokens, err := s.pool.Query(ctx, `
		select t.id, t.principal_id, p.subject, coalesce(t.description, ''),
		       t.expires_at, t.last_used_at, t.created_at
		from api_tokens t
		join principals p on p.id = t.principal_id
		where t.revoked_at is null
		  and (t.expires_at is null or t.expires_at > now())
		order by t.created_at`)
	if err != nil {
		return nil, err
	}
	for tokens.Next() {
		var token Token
		if err := tokens.Scan(&token.ID, &token.PrincipalID, &token.Subject, &token.Description,
			&token.ExpiresAt, &token.LastUsedAt, &token.CreatedAt); err != nil {
			tokens.Close()
			return nil, err
		}
		if i, ok := index[token.PrincipalID]; ok {
			principals[i].Tokens = append(principals[i].Tokens, token)
		}
	}
	tokens.Close()
	if err := tokens.Err(); err != nil {
		return nil, err
	}

	for i := range principals {
		principals[i].review(now)
	}
	return principals, nil
}

// review fills in what follows from the facts: the last use, the earliest
// expiry and the flags.
func (p *ReviewedPrincipal) review(now time.Time) {
	p.LastSeenAt = laterOf(p.LastLoginAt, p.LastTokenUseAt)
	if p.LastSeenAt != nil {
		days := int(now.Sub(*p.LastSeenAt).Hours() / 24)
		p.DaysSinceUse = &days
	}

	// An identity that was never used is unused since it was created: a
	// fresh one is not flagged, a forgotten one is.
	since := p.CreatedAt
	if p.LastSeenAt != nil {
		since = *p.LastSeenAt
	}
	if now.Sub(since) > ReviewUnusedAfter {
		p.Flags = append(p.Flags, FlagUnused90Days)
	}

	expiresSoon, adminWithoutExpiry := false, false
	for _, binding := range p.Bindings {
		if binding.Expired {
			continue
		}
		if binding.ValidUntil == nil {
			if binding.Role == RolePlatformAdmin {
				adminWithoutExpiry = true
			}
			continue
		}
		if p.EarliestExpiry == nil || binding.ValidUntil.Before(*p.EarliestExpiry) {
			expiry := *binding.ValidUntil
			p.EarliestExpiry = &expiry
		}
		if binding.ValidUntil.Sub(now) <= ReviewExpiringSoon {
			expiresSoon = true
		}
	}
	if expiresSoon {
		p.Flags = append(p.Flags, FlagExpiresSoon)
	}
	if adminWithoutExpiry {
		p.Flags = append(p.Flags, FlagAdminWithoutExpiry)
	}
	for _, token := range p.Tokens {
		if now.Sub(token.CreatedAt) > ReviewTokenMaxAge {
			p.Flags = append(p.Flags, FlagTokenOlderThanYear)
			break
		}
	}
}

func laterOf(a, b *time.Time) *time.Time {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	case a.After(*b):
		return a
	default:
		return b
	}
}
