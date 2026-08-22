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

// SessionTokenPrefix odroznia referencje do sesji od innych sekretow.
const SessionTokenPrefix = "flts_"

// defaultIdleWindow jest oknem bezczynnosci odswiezanym przy kazdym zadaniu.
const defaultIdleWindow = 8 * time.Hour

// ErrSessionInvalid oznacza brak, wygasniecie lub uniewaznienie sesji.
var ErrSessionInvalid = errors.New("sesja jest nieprawidlowa")

// SessionTokens to material, ktory pozostaje po stronie serwera.
type SessionTokens struct {
	RefreshToken    string
	IDToken         string
	AccessExpiresAt time.Time
}

// SessionLimits opisuje czasy zycia sesji.
type SessionLimits struct {
	// Idle konczy sesje nieuzywana. Absolute konczy ja niezaleznie od aktywnosci.
	Idle     time.Duration
	Absolute time.Duration
}

// Session opisuje aktywna sesje przegladarki.
type Session struct {
	ID           string
	PrincipalID  string
	Groups       []string
	RefreshToken string
	IDToken      string
}

// CreateSession zaklada sesje i zwraca wartosc ciasteczka. Wartosc jest
// widoczna wylacznie tutaj; w bazie zostaje sam skrot.
func (s *Store) CreateSession(ctx context.Context, tx pgx.Tx, principalID string,
	groups []string, tokens SessionTokens, limits SessionLimits,
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
	const query = `
		insert into web_sessions (id, token_hash, principal_id, groups, refresh_token, id_token,
		                          access_expires_at, absolute_expires_at, idle_expires_at,
		                          user_agent, remote_addr)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	if _, err := tx.Exec(ctx, query, sessionID, hash[:], principalID, groups,
		nullable(tokens.RefreshToken), nullable(tokens.IDToken),
		nullableTime(tokens.AccessExpiresAt), now.Add(limits.Absolute), now.Add(limits.Idle),
		nullable(userAgent), nullable(remoteAddr)); err != nil {
		return "", "", fmt.Errorf("zapis sesji: %w", err)
	}
	return sessionID, cookieValue, nil
}

// AuthenticateSession zamienia ciasteczko na tozsamosc wraz z rolami.
// Role pochodza z przypisan recznych oraz z mapowania grup zapisanych w sesji.
func (s *Store) AuthenticateSession(ctx context.Context, cookieValue string) (*Principal, *Session, error) {
	if cookieValue == "" {
		return nil, nil, ErrSessionInvalid
	}
	hash := sha256.Sum256([]byte(cookieValue))

	const query = `
		select w.id, w.token_hash, w.principal_id, w.groups,
		       coalesce(w.refresh_token, ''), coalesce(w.id_token, ''),
		       p.subject, p.display_name, p.kind, coalesce(p.issuer, '')
		from web_sessions w
		join principals p on p.id = w.principal_id
		where w.token_hash = $1
		  and w.revoked_at is null
		  and w.absolute_expires_at > now()
		  and w.idle_expires_at > now()
		  and p.disabled_at is null
		  -- Znacznik odmowy unicestwia takze trwajaca sesje.
		  and p.denied_at is null`
	var (
		session    Session
		storedHash []byte
		principal  Principal
		issuer     string
	)
	err := s.pool.QueryRow(ctx, query, hash[:]).Scan(&session.ID, &storedHash,
		&session.PrincipalID, &session.Groups, &session.RefreshToken, &session.IDToken,
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
	principal.ID = session.PrincipalID

	bindings, err := s.bindingsOf(ctx, principal.ID)
	if err != nil {
		return nil, nil, err
	}
	// Mapowanie grup liczymy przy kazdym zadaniu, wiec zmiana polityki dziala
	// bez ponownego logowania uzytkownika.
	mapped, err := s.MappedBindings(ctx, issuer, session.Groups)
	if err != nil {
		return nil, nil, err
	}
	principal.Bindings = mergeBindings(bindings, mapped)

	// Odswiezenie okna bezczynnosci; blad nie moze zablokowac zadania.
	// make_interval przyjmuje liczbe wprost; konkatenacja tekstu wymagalaby
	// rzutowania i cicho psula sie na typie argumentu.
	_, _ = s.pool.Exec(ctx,
		`update web_sessions set last_seen_at = now(),
		        idle_expires_at = now() + make_interval(secs => $2)
		 where id = $1`, session.ID, int(defaultIdleWindow/time.Second))
	return &principal, &session, nil
}

// RevokeSession konczy sesje.
func (s *Store) RevokeSession(ctx context.Context, sessionID, reason string) error {
	_, err := s.pool.Exec(ctx, `
		update web_sessions set revoked_at = now(), revocation_reason = $2,
		                        refresh_token = null
		where id = $1 and revoked_at is null`, sessionID, nullable(reason))
	return err
}

// RevokeSessionsOf konczy wszystkie sesje tozsamosci. Uzywane przy blokadzie
// konta: samo wylaczenie w katalogu nie unicestwia trwajacej sesji panelu.
func (s *Store) RevokeSessionsOf(ctx context.Context, principalID, reason string) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		update web_sessions set revoked_at = now(), revocation_reason = $2, refresh_token = null
		where principal_id = $1 and revoked_at is null`, principalID, nullable(reason))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// PurgeExpired kasuje wygasle sesje i porzucone przeplywy logowania.
func (s *Store) PurgeExpired(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx,
		`delete from web_sessions where absolute_expires_at < now() - interval '7 days'`); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `delete from auth_flows where expires_at < now()`)
	return err
}

// SaveAuthFlow zapisuje stan rozpoczetego logowania. Weryfikator PKCE nie
// trafia do przegladarki, wiec przechwycenie przekierowania nie wystarcza.
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

// TakeAuthFlow odczytuje i kasuje stan logowania. Kod autoryzacyjny mozna
// wymienic tylko raz, wiec stan jest jednorazowy.
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

// MappedBindings zamienia grupy zewnetrzne na role w zakresach.
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

// UpsertExternalPrincipal wiaze konto dostawcy z tozsamoscia Flotestro.
// Kluczem jest para issuer i subject: nazwa uzytkownika moze sie zmienic,
// identyfikator podmiotu nie.
func (s *Store) UpsertExternalPrincipal(ctx context.Context, tx pgx.Tx,
	issuer, subjectID, username, displayName, email string) (string, error) {
	if issuer == "" || subjectID == "" {
		return "", fmt.Errorf("brak issuer lub identyfikatora podmiotu")
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

// mergeBindings laczy przypisania reczne z wynikajacymi z grup, bez duplikatow.
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
