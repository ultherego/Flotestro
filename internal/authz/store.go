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

// TokenPrefix odroznia token API od innych sekretow w logach i konfiguracji.
const TokenPrefix = "flta_"

var (
	// ErrUnauthenticated oznacza brak lub nieprawidlowy token.
	ErrUnauthenticated = errors.New("brak waznego uwierzytelnienia")
	// ErrNotFound oznacza brak tozsamosci.
	ErrNotFound = errors.New("tozsamosc nie istnieje")
)

// Store realizuje dostep do tozsamosci, tokenow i przypisan rol.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Token opisuje wystawiony token API. Wartosc jest widoczna wylacznie
// w chwili utworzenia.
type Token struct {
	ID          string     `json:"id"`
	PrincipalID string     `json:"principal_id"`
	Subject     string     `json:"subject"`
	Value       string     `json:"value,omitempty"`
	Description string     `json:"description,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// EnsurePrincipal tworzy tozsamosc lub zwraca istniejaca.
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
		return "", fmt.Errorf("zapis tozsamosci: %w", err)
	}
	return id, nil
}

// GrantRole przypisuje role w zakresie. Ponowne przypisanie jest bezpieczne.
func (s *Store) GrantRole(ctx context.Context, tx pgx.Tx,
	principalID string, role Role, scope Scope, createdBy string) error {
	if !KnownRole(role) {
		return fmt.Errorf("nieznana rola %q", role)
	}
	const query = `
		insert into role_bindings (id, principal_id, role, site, environment, created_by)
		values ($1, $2, $3, $4, $5, $6)
		on conflict (principal_id, role, site, environment) do nothing`
	_, err := tx.Exec(ctx, query, uuid.NewString(), principalID, string(role),
		orWildcard(scope.Site), orWildcard(scope.Environment), createdBy)
	return err
}

// IssueToken wystawia token dla tozsamosci. W bazie zapisujemy tylko skrot.
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
		return nil, fmt.Errorf("zapis tokenu: %w", err)
	}
	return token, nil
}

// Authenticate zamienia token na tozsamosc wraz z rolami.
// Porownanie skrotu idzie w stalym czasie, zeby nie ujawniac prefiksu tokenu.
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
		  and p.disabled_at is null`
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

	// Zapis uzycia jest pomocniczy; jego blad nie moze zablokowac zadania.
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

// ListPrincipals zwraca tozsamosci wraz z rolami.
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
		principals[i].Bindings = bindings
	}
	return principals, nil
}

// CountPrincipals mowi, czy system ma juz jakakolwiek tozsamosc.
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
