// Package enrollment realizuje przyjmowanie nowych hostow do floty.
// Token jest krotko wazny, ograniczony liczba uzyc i zwiazany z site/environment.
package enrollment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TokenPrefix odroznia token enrollmentu od innych sekretow w logach i configach.
const TokenPrefix = "flt_"

// ErrInvalidToken jest zwracany dla kazdego powodu odrzucenia tokenu, aby nie
// ujawniac, czy token istnieje, wygasl, czy wyczerpal limit uzyc.
var ErrInvalidToken = errors.New("token enrollmentu jest nieprawidlowy")

// Token opisuje wystawiony token wraz z jawna wartoscia, ktora jest widoczna
// wylacznie w chwili utworzenia.
type Token struct {
	ID          string `json:"id"`
	Value       string `json:"value,omitempty"`
	Description string `json:"description,omitempty"`
	Site        string `json:"site"`
	Environment string `json:"environment"`
	// Kind odroznia token dla agenta od tokenu dla relaya. Relay konczy
	// polaczenia agentow i swiadczy panelowi, czyj to ruch, wiec jego
	// rejestracja nie moze byc mozliwa tokenem wystawionym dla hosta.
	Kind      string    `json:"kind"`
	MaxUses   int       `json:"max_uses"`
	Uses      int       `json:"uses"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// Scope to zakres, w ktorym token pozwala zarejestrowac hosta.
type Scope struct {
	TokenID     string
	Site        string
	Environment string
	Kind        string
}

// KindAgent i KindRelay sa rodzajami tozsamosci, ktore mozna zarejestrowac.
const (
	KindAgent = "agent"
	KindRelay = "relay"
)

// TokenStore zarzadza tokenami enrollmentu.
type TokenStore struct {
	pool *pgxpool.Pool
}

func NewTokenStore(pool *pgxpool.Pool) *TokenStore {
	return &TokenStore{pool: pool}
}

// Create wystawia nowy token. W bazie zapisywany jest wylacznie skrot.
func (s *TokenStore) Create(ctx context.Context, description, site, environment, kind string,
	maxUses int, ttl time.Duration, createdBy string) (*Token, error) {
	// Nieznany rodzaj tozsamosci nie moze cicho stac sie agentem: token
	// otwiera droge do floty i jego zakres musi byc jawny.
	if kind == "" {
		kind = KindAgent
	}
	if kind != KindAgent && kind != KindRelay {
		return nil, fmt.Errorf("nieznany rodzaj tozsamosci %q", kind)
	}
	if maxUses <= 0 {
		maxUses = 1
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	value := TokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	hash := hashToken(value)

	token := &Token{
		ID:          uuid.NewString(),
		Value:       value,
		Description: description,
		Site:        site,
		Environment: environment,
		Kind:        kind,
		MaxUses:     maxUses,
		ExpiresAt:   time.Now().Add(ttl),
	}
	const query = `
		insert into enrollment_tokens
			(id, token_hash, description, site, environment, kind, max_uses, expires_at, created_by)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		returning created_at`
	err := s.pool.QueryRow(ctx, query, token.ID, hash[:], nullable(description),
		site, environment, kind, maxUses, token.ExpiresAt, createdBy).Scan(&token.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("zapis tokenu: %w", err)
	}
	return token, nil
}

// Redeem weryfikuje token i podnosi licznik uzyc w tej samej transakcji, w
// ktorej powstaje host. Wiersz jest blokowany, wiec rownolegly enrollment nie
// przekroczy limitu uzyc.
func (s *TokenStore) Redeem(ctx context.Context, tx pgx.Tx, value string) (Scope, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return Scope{}, ErrInvalidToken
	}
	hash := hashToken(value)

	const query = `
		select id, site, environment, kind, max_uses, uses, expires_at, revoked_at
		from enrollment_tokens
		where token_hash = $1
		for update`
	var (
		scope     Scope
		maxUses   int
		uses      int
		expiresAt time.Time
		revokedAt *time.Time
	)
	err := tx.QueryRow(ctx, query, hash[:]).
		Scan(&scope.TokenID, &scope.Site, &scope.Environment, &scope.Kind,
			&maxUses, &uses, &expiresAt, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Scope{}, ErrInvalidToken
	}
	if err != nil {
		return Scope{}, err
	}
	switch {
	case revokedAt != nil:
		return Scope{}, ErrInvalidToken
	case time.Now().After(expiresAt):
		return Scope{}, ErrInvalidToken
	case uses >= maxUses:
		return Scope{}, ErrInvalidToken
	}

	if _, err := tx.Exec(ctx, "update enrollment_tokens set uses = uses + 1 where id = $1", scope.TokenID); err != nil {
		return Scope{}, err
	}
	return scope, nil
}

// List zwraca tokeny bez wartosci jawnej.
func (s *TokenStore) List(ctx context.Context) ([]Token, error) {
	const query = `
		select id, coalesce(description, ''), site, environment, max_uses, uses, expires_at, created_at
		from enrollment_tokens
		where revoked_at is null
		order by created_at desc
		limit 100`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []Token
	for rows.Next() {
		var t Token
		if err := rows.Scan(&t.ID, &t.Description, &t.Site, &t.Environment,
			&t.MaxUses, &t.Uses, &t.ExpiresAt, &t.CreatedAt); err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

func hashToken(value string) [32]byte {
	return sha256.Sum256([]byte(value))
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}
