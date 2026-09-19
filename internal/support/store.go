package support

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
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ultherego/flotestro/internal/secrets"
)

// The states of a bundle. A bundle is never "deleted": the retention removes
// the row, and a row that is not there is a bundle that is gone.
const (
	StatePending = "pending"
	StateReady   = "ready"
	StateFailed  = "failed"
)

// TokenTTL is how long the right to download a bundle lasts. It is short on
// purpose: the link is followed by the browser that asked for it, not kept.
const TokenTTL = 5 * time.Minute

// TokenPrefix marks a download token, as the other tokens of the panel are
// marked, so that one found anywhere is recognised for what it is.
const TokenPrefix = "fltsb_"

// The retentions of a bundle. A support bundle is made for one conversation,
// and one nobody came for is the likelier of the two to be forgotten.
const (
	DefaultRetention          = 7 * 24 * time.Hour
	DefaultUnfetchedRetention = 24 * time.Hour
)

// The refusals of the store. Each becomes a typed code at the edge; none of
// them is a technical error.
var (
	ErrNotFound     = errors.New("there is no such support bundle")
	ErrNotReady     = errors.New("the support bundle is not assembled yet")
	ErrTokenUnknown = errors.New("no such download token")
	ErrTokenExpired = errors.New("the download token has expired")
	ErrTokenSpent   = errors.New("the download token has already been used")
	ErrTokenForeign = errors.New("the download token was issued to another identity")
)

// Retention says when a bundle goes.
type Retention struct {
	// Age is how long any bundle is kept.
	Age time.Duration
	// Unfetched is how long a bundle nobody downloaded is kept.
	Unfetched time.Duration
}

// WithDefaults fills what an installation did not set.
func (r Retention) WithDefaults() Retention {
	if r.Age <= 0 {
		r.Age = DefaultRetention
	}
	if r.Unfetched <= 0 {
		r.Unfetched = DefaultUnfetchedRetention
	}
	// A bundle nobody fetched must not outlive one somebody did.
	if r.Unfetched > r.Age {
		r.Unfetched = r.Age
	}
	return r
}

// Drop says whether a bundle is past its retention, and under which of the two
// rules. The sweep runs the same decision in SQL; this is the one that is read.
func (r Retention) Drop(bundle Bundle, now time.Time) (reason string, drop bool) {
	r = r.WithDefaults()
	if now.Sub(bundle.RequestedAt) >= r.Age {
		return "age", true
	}
	if bundle.DownloadedAt == nil && now.Sub(bundle.RequestedAt) >= r.Unfetched {
		return "never_fetched", true
	}
	return "", false
}

// Bundle is one support bundle as the screen and the trail see it. It has
// deliberately no field carrying any part of the archive.
type Bundle struct {
	ID          string     `json:"id"`
	State       string     `json:"state"`
	Reason      string     `json:"reason"`
	RequestedBy string     `json:"requested_by"`
	RequestedAt time.Time  `json:"requested_at"`
	ReadyAt     *time.Time `json:"ready_at,omitempty"`
	// ErrorCode is why the assembly was refused; empty for one that was made.
	ErrorCode string `json:"error_code,omitempty"`
	// SizeBytes and ArchiveSHA256 describe the sealed archive, Files how many
	// readings are in it.
	SizeBytes       int64  `json:"size_bytes"`
	ArchiveSHA256   string `json:"archive_sha256,omitempty"`
	Files           int    `json:"files"`
	RedactionPolicy string `json:"redaction_policy,omitempty"`
	Scanned         bool   `json:"scanned"`
	// KeyID names the key encryption key the archive is sealed under.
	KeyID        string     `json:"key_id,omitempty"`
	DownloadedAt *time.Time `json:"downloaded_at,omitempty"`
	Downloads    int        `json:"downloads"`
}

// Token is the right to download one bundle once. Value is filled only when
// the token is issued: afterwards only its digest is kept.
type Token struct {
	Value     string    `json:"value"`
	BundleID  string    `json:"bundle_id"`
	IssuedTo  string    `json:"issued_to"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Store keeps the bundles and the rights to download them.
type Store struct {
	pool *pgxpool.Pool
	// keys wraps the data key of every bundle; without it nothing is sealed.
	keys secrets.KeyProvider
}

// NewStore builds the store over the key provider of the installation.
func NewStore(pool *pgxpool.Pool, keys secrets.KeyProvider) *Store {
	return &Store{pool: pool, keys: keys}
}

const bundleColumns = `id::text, state, reason, requested_by, requested_at, ready_at, error_code,
	size_bytes, archive_sha256, files, redaction_policy, scanned, key_id, downloaded_at, downloads`

func scanBundle(row pgx.Row) (Bundle, error) {
	var bundle Bundle
	err := row.Scan(&bundle.ID, &bundle.State, &bundle.Reason, &bundle.RequestedBy, &bundle.RequestedAt,
		&bundle.ReadyAt, &bundle.ErrorCode, &bundle.SizeBytes, &bundle.ArchiveSHA256, &bundle.Files,
		&bundle.RedactionPolicy, &bundle.Scanned, &bundle.KeyID, &bundle.DownloadedAt, &bundle.Downloads)
	if errors.Is(err, pgx.ErrNoRows) {
		return Bundle{}, ErrNotFound
	}
	return bundle, err
}

// Request records that a bundle was asked for, before anything is collected:
// the row is what the screen shows as in flight and what the trail names.
func (s *Store) Request(ctx context.Context, requestedBy, reason string) (Bundle, error) {
	row := s.pool.QueryRow(ctx, `
		insert into support_bundles (state, reason, requested_by)
		values ($1, $2, $3)
		returning `+bundleColumns, StatePending, reason, requestedBy)
	return scanBundle(row)
}

// Seal writes the assembled archive into the row under a data key of its own.
// The archive never reaches the database readable.
func (s *Store) Seal(ctx context.Context, id string, archive []byte, manifest Manifest) error {
	if s.keys == nil {
		return secrets.ErrKeyUnavailable
	}
	envelope, err := secrets.Seal(ctx, s.keys, archive, associated(id))
	if err != nil {
		return fmt.Errorf("sealing the support bundle: %w", err)
	}
	tag, err := s.pool.Exec(ctx, `
		update support_bundles
		   set state = $2, ready_at = now(), error_code = '',
		       envelope_version = $3, key_id = $4, wrapped_dek = $5, nonce = $6, ciphertext = $7,
		       size_bytes = $8, archive_sha256 = $9, files = $10, redaction_policy = $11, scanned = $12
		 where id = $1::uuid and state = $13`,
		id, StateReady, envelope.Version, envelope.KeyID, envelope.WrappedDEK, envelope.Nonce,
		envelope.Ciphertext, int64(len(archive)), Digest(archive), len(manifest.Entries),
		manifest.RedactionPolicy, manifest.Scanned, StatePending)
	if err != nil {
		return fmt.Errorf("saving the support bundle: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Fail records why a bundle was not assembled. Only the typed code goes on the
// row: a refusal of the scanner names the file it found something in.
func (s *Store) Fail(ctx context.Context, id, code string) error {
	_, err := s.pool.Exec(ctx, `
		update support_bundles set state = $2, error_code = $3
		 where id = $1::uuid and state = $4`, id, StateFailed, code, StatePending)
	return err
}

// Get returns one bundle without its archive.
func (s *Store) Get(ctx context.Context, id string) (Bundle, error) {
	if uuid.Validate(id) != nil {
		return Bundle{}, ErrNotFound
	}
	return scanBundle(s.pool.QueryRow(ctx,
		`select `+bundleColumns+` from support_bundles where id = $1::uuid`, id))
}

// List returns the bundles, newest first.
func (s *Store) List(ctx context.Context, limit int) ([]Bundle, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx,
		`select `+bundleColumns+` from support_bundles order by requested_at desc limit $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	bundles := []Bundle{}
	for rows.Next() {
		bundle, err := scanBundle(rows)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, bundle)
	}
	return bundles, rows.Err()
}

// Issue hands out the right to download one ready bundle once, within TokenTTL.
func (s *Store) Issue(ctx context.Context, bundleID, subject string, now time.Time) (Token, error) {
	bundle, err := s.Get(ctx, bundleID)
	if err != nil {
		return Token{}, err
	}
	if bundle.State != StateReady {
		return Token{}, ErrNotReady
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return Token{}, err
	}
	token := Token{
		Value:    TokenPrefix + base64.RawURLEncoding.EncodeToString(raw),
		BundleID: bundle.ID, IssuedTo: subject,
		ExpiresAt: now.Add(TokenTTL).UTC(),
	}
	digest := hashToken(token.Value)
	if _, err := s.pool.Exec(ctx, `
		insert into support_bundle_tokens (token_sha256, bundle_id, issued_to, issued_at, expires_at)
		values ($1, $2::uuid, $3, $4, $5)`,
		digest[:], token.BundleID, subject, now.UTC(), token.ExpiresAt); err != nil {
		return Token{}, fmt.Errorf("issuing the download token: %w", err)
	}
	return token, nil
}

// Redeem spends a download token and returns the bundle it opens. A token that
// is unknown, expired, spent or issued to somebody else opens nothing.
func (s *Store) Redeem(ctx context.Context, value, subject string, now time.Time) (Bundle, error) {
	digest := hashToken(value)
	var bundleID, issuedTo string
	var expiresAt time.Time
	var redeemedAt *time.Time
	err := s.pool.QueryRow(ctx, `
		select bundle_id::text, issued_to, expires_at, redeemed_at
		  from support_bundle_tokens where token_sha256 = $1`, digest[:]).
		Scan(&bundleID, &issuedTo, &expiresAt, &redeemedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Bundle{}, ErrTokenUnknown
	}
	if err != nil {
		return Bundle{}, err
	}
	if err := tokenState(issuedTo, subject, expiresAt, redeemedAt, now); err != nil {
		return Bundle{}, err
	}
	// The single use is decided by the database, not by the check above: two
	// requests arriving together must not both be the one use.
	tag, err := s.pool.Exec(ctx, `
		update support_bundle_tokens set redeemed_at = $2
		 where token_sha256 = $1 and redeemed_at is null and expires_at > $2`, digest[:], now.UTC())
	if err != nil {
		return Bundle{}, err
	}
	if tag.RowsAffected() == 0 {
		return Bundle{}, ErrTokenSpent
	}
	return s.Get(ctx, bundleID)
}

// Open returns the archive of a ready bundle. It is the only way out of the
// store, and it needs the key material of the installation.
func (s *Store) Open(ctx context.Context, id string) ([]byte, error) {
	if s.keys == nil {
		return nil, secrets.ErrKeyUnavailable
	}
	// A path segment that is not an identifier names a bundle that does not
	// exist; it is not a failure of the database.
	if uuid.Validate(id) != nil {
		return nil, ErrNotFound
	}
	var envelope secrets.Envelope
	var state string
	err := s.pool.QueryRow(ctx, `
		select state, envelope_version, key_id, wrapped_dek, nonce, ciphertext
		  from support_bundles where id = $1::uuid`, id).
		Scan(&state, &envelope.Version, &envelope.KeyID, &envelope.WrappedDEK,
			&envelope.Nonce, &envelope.Ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if state != StateReady {
		return nil, ErrNotReady
	}
	return envelope.Open(ctx, s.keys, associated(id))
}

// Fetched records that the archive left the panel.
func (s *Store) Fetched(ctx context.Context, id string, now time.Time) error {
	_, err := s.pool.Exec(ctx, `
		update support_bundles
		   set downloaded_at = coalesce(downloaded_at, $2), downloads = downloads + 1
		 where id = $1::uuid`, id, now.UTC())
	return err
}

// Sweep removes the bundles past their retention and the tokens that can no
// longer open anything. It runs the decision of Drop in SQL.
func (s *Store) Sweep(ctx context.Context, retention Retention, now time.Time) (int64, error) {
	retention = retention.WithDefaults()
	tag, err := s.pool.Exec(ctx, `
		delete from support_bundles
		 where requested_at <= $1
		    or (downloaded_at is null and requested_at <= $2)`,
		now.Add(-retention.Age).UTC(), now.Add(-retention.Unfetched).UTC())
	if err != nil {
		return 0, fmt.Errorf("sweeping the support bundles: %w", err)
	}
	// A token outlives its few minutes by nothing; the rows of the bundles it
	// named go with them by the cascade.
	if _, err := s.pool.Exec(ctx,
		`delete from support_bundle_tokens where expires_at <= $1`, now.UTC()); err != nil {
		return tag.RowsAffected(), fmt.Errorf("sweeping the download tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}

// associated binds the sealed archive to the row it lies in: an envelope moved
// to another bundle does not open.
func associated(id string) []byte {
	return secrets.AssociatedData(id, 1, "support_bundle", secrets.EnvelopeVersion)
}

func hashToken(value string) [32]byte { return sha256.Sum256([]byte(value)) }

// tokenState says what a token found in the database is worth now. The caller
// spends only what this lets through.
func tokenState(issuedTo, subject string, expiresAt time.Time, redeemedAt *time.Time, now time.Time) error {
	// The subject is compared in constant time: the answer must not say how
	// much of another identity's name was guessed right.
	if subtle.ConstantTimeCompare([]byte(issuedTo), []byte(subject)) != 1 {
		return ErrTokenForeign
	}
	if redeemedAt != nil {
		return ErrTokenSpent
	}
	if !now.Before(expiresAt) {
		return ErrTokenExpired
	}
	return nil
}
