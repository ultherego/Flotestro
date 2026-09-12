package authz

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SessionTokenPrefix distinguishes a session reference from other secrets.
const SessionTokenPrefix = "flts_"

// defaultIdleWindow is the idle window refreshed on every request.
const defaultIdleWindow = 8 * time.Hour

// ErrSessionInvalid means the session is missing, expired or revoked.
var ErrSessionInvalid = errors.New("the session is invalid")

// SessionTokens is the material that stays on the server's side.
type SessionTokens struct {
	RefreshToken    string
	IDToken         string
	AccessExpiresAt time.Time
}

// Authentication describes when and how the provider authenticated the user.
// The panel does not reinterpret these values on its own: MFA belongs to the
// provider, and the panel checks only the match with the required level and
// the freshness.
type Authentication struct {
	// At is the moment of authentication. A zero time means an unknown state.
	At  time.Time
	ACR string
	AMR []string
}

// SessionLimits describes the lifetimes of a session.
type SessionLimits struct {
	// Idle ends an unused session. Absolute ends it regardless of activity.
	Idle     time.Duration
	Absolute time.Duration
}

// Session describes an active browser session.
type Session struct {
	ID           string
	PrincipalID  string
	Groups       []string
	RefreshToken string
	IDToken      string
	// Auth describes the authentication that created this session.
	Auth Authentication
}

// CreateSession creates a session and returns the cookie value. The value is
// visible only here; only its digest stays in the database.
func (s *Store) CreateSession(ctx context.Context, tx pgx.Tx, principalID string,
	groups []string, tokens SessionTokens, auth Authentication, limits SessionLimits,
	userAgent, remoteAddr string) (sessionID, cookieValue string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	cookieValue = SessionTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(cookieValue))

	if limits.Idle <= 0 {
		limits.Idle = 8 * time.Hour
	}
	if limits.Absolute <= 0 {
		limits.Absolute = 24 * time.Hour
	}
	if groups == nil {
		groups = []string{}
	}

	sessionID = uuid.NewString()
	now := time.Now()
	amr := auth.AMR
	if amr == nil {
		amr = []string{}
	}
	const query = `
		insert into web_sessions (id, token_hash, principal_id, groups, refresh_token, id_token,
		                          access_expires_at, absolute_expires_at, idle_expires_at,
		                          user_agent, remote_addr, authenticated_at, acr, amr)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`
	if _, err := tx.Exec(ctx, query, sessionID, hash[:], principalID, groups,
		nullable(tokens.RefreshToken), nullable(tokens.IDToken),
		nullableTime(tokens.AccessExpiresAt), now.Add(limits.Absolute), now.Add(limits.Idle),
		nullable(userAgent), nullable(remoteAddr),
		nullableTime(auth.At), nullable(auth.ACR), amr); err != nil {
		return "", "", fmt.Errorf("saving the session: %w", err)
	}
	return sessionID, cookieValue, nil
}

// AuthenticateSession turns a cookie into an identity together with its
// roles. The roles come from manual assignments and from the mapping of the
// groups stored in the session.
func (s *Store) AuthenticateSession(ctx context.Context, cookieValue string) (*Principal, *Session, error) {
	if cookieValue == "" {
		return nil, nil, ErrSessionInvalid
	}
	hash := sha256.Sum256([]byte(cookieValue))

	const query = `
		select w.id, w.token_hash, w.principal_id, w.groups,
		       coalesce(w.refresh_token, ''), coalesce(w.id_token, ''),
		       w.authenticated_at, coalesce(w.acr, ''), w.amr,
		       p.subject, p.display_name, p.kind, coalesce(p.issuer, '')
		from web_sessions w
		join principals p on p.id = w.principal_id
		where w.token_hash = $1
		  and w.revoked_at is null
		  and w.absolute_expires_at > now()
		  and w.idle_expires_at > now()
		  and p.disabled_at is null
		  -- A denial marker destroys an ongoing session as well.
		  and p.denied_at is null`
	var (
		session    Session
		storedHash []byte
		principal  Principal
		issuer     string
	)
	var authenticatedAt *time.Time
	err := s.pool.QueryRow(ctx, query, hash[:]).Scan(&session.ID, &storedHash,
		&session.PrincipalID, &session.Groups, &session.RefreshToken, &session.IDToken,
		&authenticatedAt, &session.Auth.ACR, &session.Auth.AMR,
		&principal.Subject, &principal.DisplayName, &principal.Kind, &issuer)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrSessionInvalid
	}
	if err != nil {
		return nil, nil, err
	}
	if subtle.ConstantTimeCompare(storedHash, hash[:]) != 1 {
		return nil, nil, ErrSessionInvalid
	}
	if authenticatedAt != nil {
		session.Auth.At = *authenticatedAt
	}
	principal.ID = session.PrincipalID

	bindings, err := s.bindingsOf(ctx, principal.ID)
	if err != nil {
		return nil, nil, err
	}
	// We compute the group mapping on every request, so a change of policy
	// takes effect without the user logging in again.
	mapped, err := s.MappedBindings(ctx, issuer, session.Groups)
	if err != nil {
		return nil, nil, err
	}
	principal.Bindings = mergeBindings(bindings, mapped)

	// Refreshing the idle window; an error must not block the request.
	// make_interval takes a number directly; concatenating text would require
	// a cast and would silently break on the argument's type.
	_, _ = s.pool.Exec(ctx,
		`update web_sessions set last_seen_at = now(),
		        idle_expires_at = now() + make_interval(secs => $2)
		 where id = $1`, session.ID, int(defaultIdleWindow/time.Second))
	return &principal, &session, nil
}

// RevokeSession ends a session.
func (s *Store) RevokeSession(ctx context.Context, sessionID, reason string) error {
	_, err := s.pool.Exec(ctx, `
		update web_sessions set revoked_at = now(), revocation_reason = $2,
		                        refresh_token = null
		where id = $1 and revoked_at is null`, sessionID, nullable(reason))
	return err
}

// RevokeSessionsOf ends every session of an identity. Used when locking an
// account: disabling it in the directory alone does not destroy an ongoing
// panel session.
func (s *Store) RevokeSessionsOf(ctx context.Context, principalID, reason string) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		update web_sessions set revoked_at = now(), revocation_reason = $2, refresh_token = null
		where principal_id = $1 and revoked_at is null`, principalID, nullable(reason))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// PurgeExpired deletes expired sessions and abandoned login flows.
func (s *Store) PurgeExpired(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx,
		`delete from web_sessions where absolute_expires_at < now() - interval '7 days'`); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `delete from auth_flows where expires_at < now()`)
	return err
}

// SaveAuthFlow records the state of a login that has started. The PKCE
// verifier does not reach the browser, so intercepting the redirect is not
// enough.
func (s *Store) SaveAuthFlow(ctx context.Context, state, verifier, nonce, redirectAfter string,
	ttl time.Duration) error {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	_, err := s.pool.Exec(ctx, `
		insert into auth_flows (state, code_verifier, nonce, redirect_after, expires_at)
		values ($1, $2, $3, $4, now() + make_interval(secs => $5))`,
		state, verifier, nonce, nullable(redirectAfter), int(ttl/time.Second))
	return err
}

// TakeAuthFlow reads and deletes the login state. An authorisation code can
// be exchanged only once, so the state is single-use.
func (s *Store) TakeAuthFlow(ctx context.Context, state string) (verifier, nonce, redirectAfter string, err error) {
	const query = `
		delete from auth_flows
		where state = $1 and expires_at > now()
		returning code_verifier, nonce, coalesce(redirect_after, '')`
	err = s.pool.QueryRow(ctx, query, state).Scan(&verifier, &nonce, &redirectAfter)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", ErrSessionInvalid
	}
	return verifier, nonce, redirectAfter, err
}

// MappedBindings turns external groups into roles within scopes.
func (s *Store) MappedBindings(ctx context.Context, issuer string, groups []string) ([]Binding, error) {
	if issuer == "" || len(groups) == 0 {
		return nil, nil
	}
	const query = `
		select role, site, environment
		from group_role_mappings
		where issuer = $1 and group_name = any($2)`
	rows, err := s.pool.Query(ctx, query, issuer, groups)
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

// UpsertExternalPrincipal binds a provider account to a Flotestro identity.
// The key is the pair issuer and subject: the user name can change, the
// subject identifier cannot.
func (s *Store) UpsertExternalPrincipal(ctx context.Context, tx pgx.Tx,
	issuer, subjectID, username, displayName, email string) (string, error) {
	if issuer == "" || subjectID == "" {
		return "", fmt.Errorf("the issuer or the subject identifier is missing")
	}
	subject := username
	if subject == "" {
		subject = subjectID
	}

	var id string
	err := tx.QueryRow(ctx, `
		update principals set
			subject = $3, display_name = coalesce(nullif($4, ''), display_name),
			email = coalesce(nullif($5, ''), email), last_login_at = now(), updated_at = now()
		where issuer = $1 and subject_id = $2
		returning id`, issuer, subjectID, subject, displayName, email).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}

	err = tx.QueryRow(ctx, `
		insert into principals (id, subject, display_name, kind, issuer, subject_id, email, last_login_at)
		values ($1, $2, $3, 'user', $4, $5, $6, now())
		on conflict (subject) do update set
			issuer = excluded.issuer, subject_id = excluded.subject_id,
			display_name = coalesce(nullif(excluded.display_name, ''), principals.display_name),
			email = excluded.email, last_login_at = now(), updated_at = now()
		returning id`,
		uuid.NewString(), subject, displayName, issuer, subjectID, nullable(email)).Scan(&id)
	return id, err
}

// mergeBindings joins manual assignments with those following from groups, without duplicates.
func mergeBindings(manual, mapped []Binding) []Binding {
	seen := map[Binding]bool{}
	result := make([]Binding, 0, len(manual)+len(mapped))
	for _, binding := range append(append([]Binding{}, manual...), mapped...) {
		if seen[binding] {
			continue
		}
		seen[binding] = true
		result = append(result, binding)
	}
	return result
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}
