// Package enrollment admits new hosts into the fleet.
//
// An enrollment request is a durable record of a pending installation: who
// ordered it, for what purpose, in what scope and how it ended. The token is
// only a secret authorising one attempt - its clear value exists solely in
// the response to creating the request, and only its digest stays in the
// database.
//
// The purpose of the request is the most important field here. "A new host"
// and "restoring the identity of an existing host" are two different
// decisions: without that distinction anybody with a token could silently
// take over the identity of a running machine.
package enrollment

import (
	"bytes"
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

// TokenPrefix distinguishes an enrollment token from other secrets in logs and configuration.
const TokenPrefix = "flt_"

// ErrInvalidToken is returned for every reason a token is refused, so as not
// to reveal whether the token exists, has expired or has used up its uses.
var ErrInvalidToken = errors.New("the enrollment token is invalid")

// ErrUnknownRequest means a request that does not exist.
var ErrUnknownRequest = errors.New("the enrollment request does not exist")

// The kinds of identity that can be registered.
const (
	KindAgent = "agent"
	KindRelay = "relay"
)

// The purposes of a request.
const (
	// PurposeNew admits a machine the panel does not know yet.
	PurposeNew = "new"
	// PurposeReplace restores the identity of an existing host - after a
	// reinstall or after the key was lost. It always names one specific host.
	PurposeReplace = "replace_identity"
	// PurposeRelay registers a site's relay.
	PurposeRelay = "relay"
)

// The statuses of a request. They are for the operator and the audit trail,
// never a basis for authorisation - that is settled solely by the state of
// the token checked inside the transaction.
const (
	StatusPending  = "pending"
	StatusEnrolled = "enrolled"
	StatusExpired  = "expired"
	StatusRevoked  = "revoked"
	StatusFailed   = "failed"
)

// MaxTTL bounds the lifetime of a request.
//
// A token that lies around for weeks is a secret waiting to leak. Longer
// automations are to fetch short tokens on demand rather than keep one in
// reserve.
const MaxTTL = 24 * time.Hour

// Request describes a pending installation.
type Request struct {
	ID string `json:"id"`
	// Value is the clear token and appears solely in the response to creating
	// the request. Nowhere else - neither in a listing nor in the audit
	// trail.
	Value       string `json:"token,omitempty"`
	Description string `json:"description,omitempty"`
	Site        string `json:"site"`
	Environment string `json:"environment"`
	Kind        string `json:"kind"`
	Purpose     string `json:"purpose"`
	// ExpectedMachineID and ExpectedHostID narrow the request to one specific
	// machine and one specific host.
	ExpectedMachineID string `json:"expected_machine_id,omitempty"`
	ExpectedHostID    string `json:"expected_host_id,omitempty"`
	// RelayID limits the route of the request to one relay.
	RelayID        string `json:"relay_id,omitempty"`
	MaxUses        int    `json:"max_uses"`
	Uses           int    `json:"uses"`
	Status         string `json:"status"`
	EnrolledHostID string `json:"enrolled_host_id,omitempty"`

	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// Scope is the scope within which a request allows registering an identity.
type Scope struct {
	// TokenID is the identifier of the request. The name stays for the sake
	// of the audit trail, which has recorded it since the fleet began.
	TokenID           string
	Site              string
	Environment       string
	Kind              string
	Purpose           string
	ExpectedMachineID string
	ExpectedHostID    string
	// RelayID limits the route of the request. Empty means "any": a token
	// bound to a relay will not work outside its site, and a token without
	// such a binding works as before.
	RelayID string
}

// Replay is the record of an attempt that has already succeeded.
//
// The answer can be lost in the network after the server recorded the host
// and issued the certificate. The agent then retries and has to get exactly
// what was already issued - otherwise the token is used up and the host is
// left without an identity.
type Replay struct {
	HostID            string
	CertificatePEM    []byte
	CABundlePEM       []byte
	CertificateSerial string
}

// AttemptInput describes one enrollment attempt.
type AttemptInput struct {
	Token           string
	MachineID       string
	ClientRequestID string
	CSR             []byte
}

// Outcome says what to do with an attempt: issue a new identity or repeat the
// old one.
type Outcome struct {
	Scope  Scope
	Replay *Replay
}

// Store manages the enrollment requests.
type Store struct {
	pool *pgxpool.Pool
}

// NewTokenStore creates the store of requests.
func NewTokenStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// CreateInput describes a new request.
type CreateInput struct {
	Description       string
	Site              string
	Environment       string
	Kind              string
	Purpose           string
	ExpectedMachineID string
	ExpectedHostID    string
	// RelayID closes the request within one site. A token taken outside it
	// registers nothing: the centre checks which relay signed the request
	// with its own mTLS channel.
	RelayID   string
	MaxUses   int
	TTL       time.Duration
	CreatedBy string
}

// Create issues a new request. Only the digest is recorded in the database.
func (s *Store) Create(ctx context.Context, input CreateInput) (*Request, error) {
	kind := input.Kind
	if kind == "" {
		kind = KindAgent
	}
	if kind != KindAgent && kind != KindRelay {
		return nil, fmt.Errorf("unknown kind of identity %q", kind)
	}
	purpose := input.Purpose
	if purpose == "" {
		if kind == KindRelay {
			purpose = PurposeRelay
		} else {
			purpose = PurposeNew
		}
	}
	if err := checkPurpose(kind, purpose, input.ExpectedHostID); err != nil {
		return nil, err
	}

	maxUses := input.MaxUses
	if maxUses <= 0 {
		maxUses = 1
	}
	// Replacing an identity concerns one host, so it concerns one use as
	// well: a multi-use request would be a spare key to the same machine.
	if purpose == PurposeReplace {
		maxUses = 1
	}
	ttl := input.TTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	if ttl > MaxTTL {
		return nil, fmt.Errorf("the lifetime of the request exceeds %s", MaxTTL)
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	value := TokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	hash := hashToken(value)

	request := &Request{
		ID: uuid.NewString(), Value: value, Description: input.Description,
		Site: input.Site, Environment: input.Environment,
		Kind: kind, Purpose: purpose,
		ExpectedMachineID: input.ExpectedMachineID, ExpectedHostID: input.ExpectedHostID,
		RelayID: input.RelayID,
		MaxUses: maxUses, Status: StatusPending,
		ExpiresAt: time.Now().Add(ttl), CreatedBy: input.CreatedBy,
	}
	const query = `
		insert into enrollment_requests
			(id, token_hash, description, site, environment, kind, purpose,
			 expected_machine_id, expected_host_id, relay_id, max_uses, expires_at, created_by)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9::uuid, nullif($10, '')::uuid, $11, $12, $13)
		returning created_at, updated_at`
	err := s.pool.QueryRow(ctx, query, request.ID, hash[:], nullable(input.Description),
		input.Site, input.Environment, kind, purpose,
		nullable(input.ExpectedMachineID), nullable(input.ExpectedHostID),
		input.RelayID, maxUses, request.ExpiresAt, input.CreatedBy).
		Scan(&request.CreatedAt, &request.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("recording the request: %w", err)
	}
	return request, nil
}

// checkPurpose guards that the purpose, the kind and the named host hold
// together.
func checkPurpose(kind, purpose, hostID string) error {
	switch purpose {
	case PurposeNew:
		if kind != KindAgent {
			return fmt.Errorf("the purpose %q requires the kind %q", purpose, KindAgent)
		}
		if hostID != "" {
			return fmt.Errorf("the purpose %q does not name an existing host", purpose)
		}
	case PurposeReplace:
		if kind != KindAgent {
			return fmt.Errorf("the purpose %q requires the kind %q", purpose, KindAgent)
		}
		if hostID == "" {
			return fmt.Errorf("the purpose %q requires naming a host", purpose)
		}
	case PurposeRelay:
		if kind != KindRelay {
			return fmt.Errorf("the purpose %q requires the kind %q", purpose, KindRelay)
		}
		if hostID != "" {
			return fmt.Errorf("the purpose %q does not name a host", purpose)
		}
	default:
		return fmt.Errorf("unknown purpose of a request %q", purpose)
	}
	return nil
}

// Redeem checks the token and decides whether this is a new attempt or a
// replay.
//
// The row is locked, so a parallel enrollment will not exceed the limit of
// uses. A replay uses none: it is the same attempt whose answer was lost.
func (s *Store) Redeem(ctx context.Context, tx pgx.Tx, input AttemptInput) (Outcome, error) {
	value := strings.TrimSpace(input.Token)
	if value == "" {
		return Outcome{}, ErrInvalidToken
	}
	hash := hashToken(value)

	const query = `
		select id, site, environment, kind, purpose,
		       coalesce(expected_machine_id, ''), coalesce(expected_host_id::text, ''),
		       coalesce(relay_id::text, ''),
		       max_uses, uses, expires_at, revoked_at
		from enrollment_requests
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
		Scan(&scope.TokenID, &scope.Site, &scope.Environment, &scope.Kind, &scope.Purpose,
			&scope.ExpectedMachineID, &scope.ExpectedHostID, &scope.RelayID,
			&maxUses, &uses, &expiresAt, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Outcome{}, ErrInvalidToken
	}
	if err != nil {
		return Outcome{}, err
	}

	// We check the replay before the limits: an attempt that has already
	// succeeded is to get its answer even when the request has used itself
	// up in the meantime.
	replay, err := s.replay(ctx, tx, scope.TokenID, input)
	if err != nil {
		return Outcome{}, err
	}
	if replay != nil {
		return Outcome{Scope: scope, Replay: replay}, nil
	}

	switch {
	case revokedAt != nil:
		return Outcome{}, ErrInvalidToken
	case time.Now().After(expiresAt):
		return Outcome{}, ErrInvalidToken
	case uses >= maxUses:
		return Outcome{}, ErrInvalidToken
	}
	// A request bound to a machine matches no other one.
	if scope.ExpectedMachineID != "" && scope.ExpectedMachineID != input.MachineID {
		return Outcome{}, ErrInvalidToken
	}

	if _, err := tx.Exec(ctx,
		`update enrollment_requests set uses = uses + 1, updated_at = now() where id = $1::uuid`,
		scope.TokenID); err != nil {
		return Outcome{}, err
	}
	return Outcome{Scope: scope}, nil
}

// replay looks for an attempt that has already succeeded.
//
// We look by the attempt identifier and by the CSR digest: an agent that lost
// the answer and retries with a new identifier but the same key is asking for
// exactly the same identity.
func (s *Store) replay(ctx context.Context, tx pgx.Tx, requestID string,
	input AttemptInput) (*Replay, error) {
	fingerprint := sha256.Sum256(input.CSR)
	const query = `
		select coalesce(host_id::text, ''), certificate_pem, ca_bundle_pem,
		       coalesce(certificate_serial, ''), csr_sha256
		from enrollment_attempts
		where request_id = $1::uuid and (client_request_id = $2::uuid or csr_sha256 = $3)
		  and completed_at is not null
		limit 1`
	client := input.ClientRequestID
	if client == "" {
		// An agent without an attempt identifier can only be recognised by its CSR.
		client = uuid.Nil.String()
	}
	var (
		hostID      string
		certPEM     []byte
		bundlePEM   []byte
		serial      string
		storedCSR []byte
	)
	err := tx.QueryRow(ctx, query, requestID, client, fingerprint[:]).
		Scan(&hostID, &certPEM, &bundlePEM, &serial, &storedCSR)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// The same attempt identifier with a different CSR is not a replay but a
	// different attempt under somebody else's number. We refuse instead of
	// issuing an identity.
	if !bytes.Equal(storedCSR, fingerprint[:]) {
		return nil, ErrInvalidToken
	}
	return &Replay{
		HostID: hostID, CertificatePEM: certPEM,
		CABundlePEM: bundlePEM, CertificateSerial: serial,
	}, nil
}

// RecordAttempt persists a successful attempt together with the issued
// certificate.
//
// In the same transaction in which the host and the certificate come into
// being: recording the attempt after the commit might never happen, and the
// whole idempotency would be make-believe.
func (s *Store) RecordAttempt(ctx context.Context, tx pgx.Tx, requestID string,
	input AttemptInput, result Replay) error {
	fingerprint := sha256.Sum256(input.CSR)
	client := input.ClientRequestID
	if client == "" {
		client = uuid.NewString()
	}
	const query = `
		insert into enrollment_attempts
			(request_id, client_request_id, csr_sha256, machine_id, host_id,
			 certificate_pem, ca_bundle_pem, certificate_serial, completed_at)
		values ($1::uuid, $2::uuid, $3, $4, $5::uuid, $6, $7, $8, now())
		on conflict (request_id, client_request_id) do update set
			host_id = excluded.host_id, certificate_pem = excluded.certificate_pem,
			ca_bundle_pem = excluded.ca_bundle_pem,
			certificate_serial = excluded.certificate_serial, completed_at = now()`
	if _, err := tx.Exec(ctx, query, requestID, client, fingerprint[:], input.MachineID,
		nullable(result.HostID), result.CertificatePEM, result.CABundlePEM,
		nullable(result.CertificateSerial)); err != nil {
		return fmt.Errorf("recording the enrollment attempt: %w", err)
	}

	const settle = `
		update enrollment_requests
		set enrolled_host_id = coalesce($2::uuid, enrolled_host_id),
		    status = case when uses >= max_uses then $3 else status end,
		    updated_at = now()
		where id = $1::uuid`
	if _, err := tx.Exec(ctx, settle, requestID, nullable(result.HostID),
		StatusEnrolled); err != nil {
		return fmt.Errorf("settling the request: %w", err)
	}
	return nil
}

// Revoke blocks the remaining uses of a request.
//
// It works also when part of the pool has already been used: revoking is to
// close what is left rather than pretend nothing happened.
func (s *Store) Revoke(ctx context.Context, id string) error {
	const query = `
		update enrollment_requests
		set revoked_at = coalesce(revoked_at, now()),
		    status = $2, updated_at = now()
		where id = $1::uuid`
	tag, err := s.pool.Exec(ctx, query, id, StatusRevoked)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrUnknownRequest
	}
	return nil
}

// Request returns one request without the token value.
func (s *Store) Request(ctx context.Context, id string) (*Request, error) {
	const query = requestColumns + ` where id = $1::uuid`
	row := s.pool.QueryRow(ctx, query, id)
	request, err := scanRequest(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUnknownRequest
	}
	if err != nil {
		return nil, err
	}
	return request, nil
}

// List returns the requests without the clear value.
//
// Settled and revoked ones too: the operator has to see what happened to the
// installation they ordered, not only what is still waiting.
func (s *Store) List(ctx context.Context) ([]Request, error) {
	const query = requestColumns + ` order by created_at desc limit 200`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var requests []Request
	for rows.Next() {
		request, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		requests = append(requests, *request)
	}
	return requests, rows.Err()
}

// requestColumns is the shared list of columns for reads.
const requestColumns = `
	select id, coalesce(description, ''), site, environment, kind, purpose,
	       coalesce(expected_machine_id, ''), coalesce(expected_host_id::text, ''),
	       coalesce(relay_id::text, ''),
	       max_uses, uses, status, coalesce(enrolled_host_id::text, ''),
	       expires_at, revoked_at, created_by, created_at, updated_at
	from enrollment_requests`

// scanner allows reading a request from a row and from a cursor.
type scanner interface {
	Scan(targets ...any) error
}

func scanRequest(row scanner) (*Request, error) {
	var z Request
	if err := row.Scan(&z.ID, &z.Description, &z.Site, &z.Environment, &z.Kind, &z.Purpose,
		&z.ExpectedMachineID, &z.ExpectedHostID, &z.RelayID, &z.MaxUses, &z.Uses, &z.Status,
		&z.EnrolledHostID, &z.ExpiresAt, &z.RevokedAt, &z.CreatedBy,
		&z.CreatedAt, &z.UpdatedAt); err != nil {
		return nil, err
	}
	// The status "pending" past the deadline is untrue: the token no longer works.
	if z.Status == StatusPending && time.Now().After(z.ExpiresAt) {
		z.Status = StatusExpired
	}
	return &z, nil
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
