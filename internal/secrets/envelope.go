package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// The envelope is how a value lies in the database since the second
// version of the store.
//
// Every version of every secret gets a random data key of its own; the
// value is sealed under that key, and the data key is wrapped by the
// installation's key encryption key through the provider. The provider is
// the only party that ever sees the key encryption key, so a rotation of
// it touches the wrapped data keys alone - never the values - and the
// value of one secret never shares a key with the value of another.
//
// A row written the first way still opens: its envelope version says so,
// and the key it was sealed under is registered with the provider under
// the name "legacy". Such a row is rewrapped in the background into the
// second form, so an installation upgrades without re-entering anything.

// EnvelopeVersion is the form new versions are written in.
const EnvelopeVersion = 2

// LegacyKeyID names, with the provider, the key an installation from
// before the envelope sealed its values under. The startup guard registers
// the old key file under this name, and the rows written the first way
// are opened with it until the rewrap reaches them.
const LegacyKeyID = "legacy"

// KeyProvider keeps the key encryption keys and wraps data keys with them.
//
// The interface is the seam between the store and the place the keys
// live. The built-in provider keeps them in files of the state directory;
// a vault or a hardware module can implement the same four methods later
// without the store noticing.
type KeyProvider interface {
	// ActiveKeyID names the key new envelopes are wrapped with.
	ActiveKeyID(ctx context.Context) (string, error)
	// Wrap seals a data key under the named key encryption key.
	Wrap(ctx context.Context, keyID string, dek []byte) ([]byte, error)
	// Unwrap opens a wrapped data key with the named key encryption key.
	// An unknown key is ErrKeyUnavailable.
	Unwrap(ctx context.Context, keyID string, wrapped []byte) ([]byte, error)
	// Health says whether the provider can serve: the active key is
	// there and readable.
	Health(ctx context.Context) error
}

// LegacyOpener is a provider that also holds the key the rows of the first
// form were sealed under. The built-in provider has it after adopting an
// installation from before the envelope; a provider without it cannot
// open such rows, and says so through the error rather than by guessing.
type LegacyOpener interface {
	LegacyCipher() (*Cipher, bool)
}

// ErrKeyUnavailable means the provider does not hold the key an envelope
// names. It is the error of a row written under a key that has since
// been removed, or of a store started without its key.
var ErrKeyUnavailable = errors.New("secrets_key_unavailable")

// Envelope is one sealed value together with what is needed to open it,
// except the key encryption key itself.
type Envelope struct {
	Version    int
	KeyID      string
	WrappedDEK []byte
	Nonce      []byte
	Ciphertext []byte
}

// AssociatedData renders what an envelope is bound to.
//
// The row and the kind of thing in it go into the authentication: a
// ciphertext moved to another secret, another version, or from a secret
// into the sentinel, does not open. The envelope version is part of it
// too, so a row cannot be re-labelled as the other form.
func AssociatedData(secretID string, version int, kind string, envelopeVersion int) []byte {
	return []byte(secretID + "|" + strconv.Itoa(version) + "|" + kind + "|" + strconv.Itoa(envelopeVersion))
}

// Seal encrypts a value under a fresh data key and wraps that key with the
// provider's active key.
func Seal(ctx context.Context, keys KeyProvider, value, associated []byte) (Envelope, error) {
	keyID, err := keys.ActiveKeyID(ctx)
	if err != nil {
		return Envelope{}, err
	}
	return SealWith(ctx, keys, keyID, value, associated)
}

// SealWith is Seal under a named key rather than the active one; the
// rotation uses it to test a key before switching to it.
func SealWith(ctx context.Context, keys KeyProvider, keyID string, value, associated []byte) (Envelope, error) {
	dek := make([]byte, KeyLength)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return Envelope{}, err
	}
	aead, err := dataKeyAEAD(dek)
	if err != nil {
		return Envelope{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Envelope{}, err
	}
	wrapped, err := keys.Wrap(ctx, keyID, dek)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{
		Version:    EnvelopeVersion,
		KeyID:      keyID,
		WrappedDEK: wrapped,
		Nonce:      nonce,
		Ciphertext: aead.Seal(nil, nonce, value, associated),
	}, nil
}

// Open returns the value of an envelope of the second form.
func (e Envelope) Open(ctx context.Context, keys KeyProvider, associated []byte) ([]byte, error) {
	if e.Version != EnvelopeVersion {
		return nil, fmt.Errorf("envelope version %d cannot be opened as version %d", e.Version, EnvelopeVersion)
	}
	if e.KeyID == "" || len(e.WrappedDEK) == 0 {
		return nil, fmt.Errorf("the envelope names no key")
	}
	dek, err := keys.Unwrap(ctx, e.KeyID, e.WrappedDEK)
	if err != nil {
		return nil, err
	}
	aead, err := dataKeyAEAD(dek)
	if err != nil {
		return nil, err
	}
	value, err := aead.Open(nil, e.Nonce, e.Ciphertext, associated)
	if err != nil {
		return nil, fmt.Errorf("the envelope does not open in this row: %w", err)
	}
	return value, nil
}

// Rewrap moves the envelope to another key encryption key. The value and
// its data key stay as they are: only the wrapping changes hands, which
// is what makes a rotation cheap enough to run over the whole store.
func (e Envelope) Rewrap(ctx context.Context, keys KeyProvider, toKeyID string) (Envelope, error) {
	if e.Version != EnvelopeVersion {
		return Envelope{}, fmt.Errorf("envelope version %d cannot be rewrapped", e.Version)
	}
	dek, err := keys.Unwrap(ctx, e.KeyID, e.WrappedDEK)
	if err != nil {
		return Envelope{}, err
	}
	wrapped, err := keys.Wrap(ctx, toKeyID, dek)
	if err != nil {
		return Envelope{}, err
	}
	moved := e
	moved.KeyID = toKeyID
	moved.WrappedDEK = wrapped
	return moved, nil
}

func dataKeyAEAD(dek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
