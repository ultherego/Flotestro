package authz

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Signing in without an identity provider.
//
// The rules are in one place because they are the ones somebody will try to
// read off a screen at three in the morning: how many wrong passwords lock
// an account, for how long, and what the panel says while it is locked.

const (
	// MaxFailedSignIns is how many wrong passwords in a row lock an account.
	// Ten is enough that a person who mistypes twice and then remembers is
	// never locked out, and few enough that guessing is not a strategy.
	MaxFailedSignIns = 10
	// LockWindow is how long a locked account stays locked. It is short
	// because a lock that needs an administrator turns an attack on one
	// account into an outage for its owner.
	LockWindow = 15 * time.Minute
)

// Credential is what the access screen says about an identity's password.
// It never carries the hash: a screen has no use for one.
type Credential struct {
	SetAt       time.Time  `json:"set_at"`
	SetBy       string     `json:"set_by"`
	MustChange  bool       `json:"must_change"`
	LockedUntil *time.Time `json:"locked_until,omitempty"`
	FailedSince int        `json:"failed_attempts"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

// The reasons a local sign-in does not happen. The caller tells the person
// one thing - that the name or the password is wrong - and the trail gets
// the truth, which is the only place it belongs.
var (
	ErrNoSuchLocalIdentity = errors.New("no identity of that name signs in with a password here")
	ErrWrongPassword       = errors.New("the password does not match")
	ErrAccountLocked       = errors.New("too many wrong passwords; the account is locked for a while")
)

// SetPassword writes or replaces the password of an identity.
//
// It clears the failed attempts and the lock: an administrator setting a
// password has just answered the question a lock was asking.
func (s *Store) SetPassword(ctx context.Context, tx pgx.Tx,
	principalID, subject, password, setBy string, mustChange bool) error {
	if err := CheckPasswordPolicy(password, subject); err != nil {
		return err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		insert into local_credentials (principal_id, password_hash, set_by, must_change)
		values ($1, $2, $3, $4)
		on conflict (principal_id) do update set
			password_hash = excluded.password_hash,
			set_at = now(), set_by = excluded.set_by, must_change = excluded.must_change,
			failed_attempts = 0, locked_until = null`,
		principalID, hash, setBy, mustChange)
	if err != nil {
		return fmt.Errorf("storing the password: %w", err)
	}
	return nil
}

// ClearPassword takes the password away; the identity then signs in through
// the provider or not at all.
func (s *Store) ClearPassword(ctx context.Context, tx pgx.Tx, principalID string) (bool, error) {
	tag, err := tx.Exec(ctx, `delete from local_credentials where principal_id = $1`, principalID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// CredentialOf reads what a screen may say about an identity's password.
func (s *Store) CredentialOf(ctx context.Context, principalID string) (*Credential, error) {
	var credential Credential
	err := s.pool.QueryRow(ctx, `
		select set_at, set_by, must_change, locked_until, failed_attempts, last_used_at
		from local_credentials where principal_id = $1`, principalID).
		Scan(&credential.SetAt, &credential.SetBy, &credential.MustChange,
			&credential.LockedUntil, &credential.FailedSince, &credential.LastUsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		// No row is not an empty password: this identity has none.
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &credential, nil
}

// CredentialsOfMany reads the same for a page of identities, in one query.
func (s *Store) CredentialsOfMany(ctx context.Context, principalIDs []string) (map[string]Credential, error) {
	out := map[string]Credential{}
	if len(principalIDs) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `
		select principal_id, set_at, set_by, must_change, locked_until, failed_attempts, last_used_at
		from local_credentials where principal_id = any($1)`, principalIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var credential Credential
		if err := rows.Scan(&id, &credential.SetAt, &credential.SetBy, &credential.MustChange,
			&credential.LockedUntil, &credential.FailedSince, &credential.LastUsedAt); err != nil {
			return nil, err
		}
		out[id] = credential
	}
	return out, rows.Err()
}

// LocalSignIn is a password sign-in that succeeded.
type LocalSignIn struct {
	Principal  *Principal
	MustChange bool
}

// SignInWithPassword decides a password sign-in and records what it cost.
//
// The counting is the point. A wrong password raises the count and, at the
// tenth, locks the account for a quarter of an hour; a right one clears
// both. The work is done even for a name nobody has, so that the time an
// answer takes does not tell an attacker which names exist.
func (s *Store) SignInWithPassword(ctx context.Context, subject, password string) (*LocalSignIn, error) {
	var principalID string
	var hash string
	var mustChange bool
	var failed int
	var lockedUntil *time.Time
	err := s.pool.QueryRow(ctx, `
		select p.id, c.password_hash, c.must_change, c.failed_attempts, c.locked_until
		from principals p
		join local_credentials c on c.principal_id = p.id
		where lower(p.subject) = lower($1) and p.disabled_at is null`, subject).
		Scan(&principalID, &hash, &mustChange, &failed, &lockedUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		// Hash something anyway: an answer that comes back faster for a name
		// nobody has is a list of the names somebody does have.
		_ = VerifyPassword("$argon2id$v=19$m=65536,t=3,p=4$"+
			"AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", password)
		return nil, ErrNoSuchLocalIdentity
	}
	if err != nil {
		return nil, err
	}
	if lockedUntil != nil && time.Now().Before(*lockedUntil) {
		return nil, fmt.Errorf("%w: until %s", ErrAccountLocked, lockedUntil.UTC().Format(time.RFC3339))
	}

	if !VerifyPassword(hash, password) {
		failed++
		var until *time.Time
		if failed >= MaxFailedSignIns {
			moment := time.Now().Add(LockWindow)
			until = &moment
		}
		if _, err := s.pool.Exec(ctx, `
			update local_credentials set failed_attempts = $2, locked_until = $3
			where principal_id = $1`, principalID, failed, until); err != nil {
			return nil, err
		}
		if until != nil {
			return nil, fmt.Errorf("%w: until %s", ErrAccountLocked, until.UTC().Format(time.RFC3339))
		}
		return nil, ErrWrongPassword
	}

	if _, err := s.pool.Exec(ctx, `
		update local_credentials set failed_attempts = 0, locked_until = null, last_used_at = now()
		where principal_id = $1`, principalID); err != nil {
		return nil, err
	}
	principal, err := s.PrincipalByID(ctx, principalID)
	if err != nil {
		return nil, err
	}
	return &LocalSignIn{Principal: principal, MustChange: mustChange}, nil
}
