package authz

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ultherego/flotestro/internal/secrets"
)

// What the identity provider hands a session - a refresh token and an ID token -
// is a credential at the provider: whoever reads it out of the database can renew
// the session there. It is sealed under the installation's key like every other
// secret of the panel, and bound to the session and to which of the two it is, so
// a value moved to another row or into the other column does not open.

// sealedTokenPrefix marks a stored token as sealed. A value without it is one a
// session wrote before this existed; sessions are short, so those are read as they
// are until they end and never written again.
const sealedTokenPrefix = "sealed1:"

// ErrTokenUnreadable means a stored provider token carries the mark of a sealed
// one and does not open under the keys the panel holds.
var ErrTokenUnreadable = errors.New("a stored identity provider token does not open under the installation's keys")

// TokenSealer seals and opens the provider tokens of sessions.
type TokenSealer struct {
	keys secrets.KeyProvider
}

// NewTokenSealer builds a sealer over the installation's key provider.
func NewTokenSealer(keys secrets.KeyProvider) *TokenSealer { return &TokenSealer{keys: keys} }

func tokenAssociated(sessionID, kind string) []byte {
	return []byte("web_session|" + sessionID + "|" + kind)
}

// Seal returns the stored form of a token. An empty token stays empty.
func (t *TokenSealer) Seal(ctx context.Context, sessionID, kind, token string) (string, error) {
	if token == "" {
		return "", nil
	}
	envelope, err := secrets.Seal(ctx, t.keys, []byte(token), tokenAssociated(sessionID, kind))
	if err != nil {
		return "", fmt.Errorf("sealing a provider token: %w", err)
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", err
	}
	return sealedTokenPrefix + base64.RawStdEncoding.EncodeToString(encoded), nil
}

// Open returns the token of a stored form. A value that is not sealed is returned
// as it is: the session wrote it before the sealing existed.
func (t *TokenSealer) Open(ctx context.Context, sessionID, kind, stored string) (string, error) {
	if !strings.HasPrefix(stored, sealedTokenPrefix) {
		return stored, nil
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(stored, sealedTokenPrefix))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTokenUnreadable, err)
	}
	var envelope secrets.Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return "", fmt.Errorf("%w: %v", ErrTokenUnreadable, err)
	}
	value, err := envelope.Open(ctx, t.keys, tokenAssociated(sessionID, kind))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTokenUnreadable, err)
	}
	return string(value), nil
}
