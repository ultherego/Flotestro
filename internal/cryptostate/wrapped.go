package cryptostate

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/ultherego/flotestro/internal/secrets"
)

// The private keys of an installation, as they lie in the database: each one
// wrapped with the key encryption key the deployment mounts, and named by what
// it is for.
//
// A row is worth nothing without the key encryption key, which is why the rows
// may travel with a dump and the key may not.

// What a wrapped key is for. The purpose is part of what the row is sealed
// against, so a key cannot be moved from one use to another by an update
// statement.
const (
	// PurposeSecrets seals the values of the secret store.
	PurposeSecrets = "secrets"
	// PurposeAgentCA is the private key of a certificate authority of the
	// fleet.
	PurposeAgentCA = "agent-ca"
	// PurposeHelperSigning signs the capabilities the root helper accepts.
	PurposeHelperSigning = "helper-signing"
)

// WrappedKeyVersion is the layout of the wrapping. It is counted apart from
// the envelope version of a secret: these are two floors of the same building,
// and one may move without the other.
const WrappedKeyVersion = 1

// CodeWrappedKeyUnreadable is the stable code of a row that does not open
// under the key encryption key the deployment holds, although the row says it
// was wrapped with it. The content was changed, or two keys share a name.
const CodeWrappedKeyUnreadable = "wrapped_key_unreadable"

// WrappedKey is one private key of the installation as the database holds it.
type WrappedKey struct {
	// KeyID is the name the key is known by elsewhere: the key id an
	// envelope names, the identifier of an authority, the name of the
	// helper's signer.
	KeyID   string
	Purpose string
	// KEKID names the key encryption key this row was wrapped with. A row
	// that names another key is refused rather than half-read.
	KEKID           string
	EnvelopeVersion int
	Nonce           []byte
	Ciphertext      []byte
	CreatedAt       time.Time
	// RetiredAt marks a key that wraps nothing new but is still needed to
	// open what it wrapped.
	RetiredAt *time.Time
}

// Retired says whether the key has been put out of use for new material.
func (w WrappedKey) Retired() bool { return w.RetiredAt != nil }

// KeyStore is what a database-sealed provider needs of the database. It is a
// seam of its own rather than part of Storage: the guard's table is exercised
// without a database, and the keys are a separate concern from the record that
// names them.
type KeyStore interface {
	// WrappedKeys returns every key of a purpose, retired ones included:
	// a retired key still opens what it sealed.
	WrappedKeys(ctx context.Context, purpose string) ([]WrappedKey, error)
	// PutWrappedKey writes a key that must not exist yet. A key id already
	// taken comes back as ErrKeyExists, so that a caller racing another
	// replica can read what is there and decide.
	PutWrappedKey(ctx context.Context, key WrappedKey) error
	// WrappedKey reads one key by name.
	WrappedKey(ctx context.Context, keyID string) (WrappedKey, error)
	// RetireWrappedKey marks a key as no longer wrapping anything new. A key
	// already retired keeps the moment it was retired at.
	RetireWrappedKey(ctx context.Context, keyID string) error
	// DeleteWrappedKey removes a key. It serves the cleanup of an
	// initialisation that could not record itself; a key that anything in the
	// database still names is not to be deleted.
	DeleteWrappedKey(ctx context.Context, keyID string) error
}

// ErrKeyExists means a key of that name is already in the database.
var ErrKeyExists = errors.New("a key of that name is already in the database")

// ErrWrappedKeyMissing means no row of that name.
var ErrWrappedKeyMissing = errors.New("no wrapped key of that name")

// wrappedKeyAAD binds a row to its place. Nothing here is secret; all of it
// has to be true for the row to open, so a key cannot be moved between names,
// purposes or installations, and a row from another deployment's database does
// not open here even if both were wrapped with the same key.
func wrappedKeyAAD(keyID, purpose, kekID string, version int) []byte {
	return []byte("flotestro-wrapped-key|" + strconv.Itoa(version) + "|" +
		kekID + "|" + purpose + "|" + keyID)
}

// Seal wraps key material for the database.
//
// The sealing is done here rather than through secrets.Cipher on purpose: that
// primitive opens a value with no associated data when the bound form fails, a
// kindness the first form of the store needed and key material must not have.
// Here the binding either holds or the row is refused.
func (k *KEK) Seal(keyID, purpose string, material []byte) (WrappedKey, error) {
	if err := ValidateKeyID(keyID); err != nil {
		return WrappedKey{}, err
	}
	if err := validatePurpose(purpose); err != nil {
		return WrappedKey{}, err
	}
	if len(material) == 0 {
		return WrappedKey{}, fmt.Errorf("the key %s has no material", keyID)
	}
	aead, err := k.aead()
	if err != nil {
		return WrappedKey{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return WrappedKey{}, err
	}
	associated := wrappedKeyAAD(keyID, purpose, k.id, WrappedKeyVersion)
	return WrappedKey{
		KeyID:           keyID,
		Purpose:         purpose,
		KEKID:           k.id,
		EnvelopeVersion: WrappedKeyVersion,
		Nonce:           nonce,
		Ciphertext:      aead.Seal(nil, nonce, material, associated),
	}, nil
}

// Open returns the material of a wrapped key.
//
// A row wrapped with another key encryption key is refused by name before
// anything is decrypted: "this installation holds a different key" and "the
// row is damaged" are different situations, and the operator fixes them
// differently.
func (k *KEK) Open(row WrappedKey) ([]byte, error) {
	if !k.Is(row.KEKID) {
		return nil, fatal(CodeKEKMismatch, fmt.Sprintf(
			"the key %s was wrapped with %s; this deployment holds %s",
			row.KeyID, row.KEKID, k.id), nil)
	}
	if row.EnvelopeVersion != WrappedKeyVersion {
		return nil, fatal(CodeWrappedKeyUnreadable, fmt.Sprintf(
			"the key %s is wrapped in form %d, which this panel does not read",
			row.KeyID, row.EnvelopeVersion), nil)
	}
	aead, err := k.aead()
	if err != nil {
		return nil, err
	}
	if len(row.Nonce) != aead.NonceSize() {
		return nil, fatal(CodeWrappedKeyUnreadable, fmt.Sprintf(
			"the key %s carries a nonce of %d bytes instead of %d",
			row.KeyID, len(row.Nonce), aead.NonceSize()), nil)
	}
	associated := wrappedKeyAAD(row.KeyID, row.Purpose, row.KEKID, row.EnvelopeVersion)
	material, err := aead.Open(nil, row.Nonce, row.Ciphertext, associated)
	if err != nil {
		return nil, fatal(CodeWrappedKeyUnreadable, fmt.Sprintf(
			"the key %s does not open under %s: the row or what it says about itself was changed",
			row.KeyID, k.id), nil)
	}
	return material, nil
}

// aead is the primitive over the key encryption key itself.
func (k *KEK) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(k.key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func validatePurpose(purpose string) error {
	switch purpose {
	case PurposeSecrets, PurposeAgentCA, PurposeHelperSigning:
		return nil
	}
	return fmt.Errorf("%q is not a purpose a key is kept for", purpose)
}

// sealSecretsKey wraps a key of the secret store, whose length is fixed.
func sealSecretsKey(kek *KEK, keyID string, material []byte) (WrappedKey, error) {
	if len(material) != secrets.KeyLength {
		return WrappedKey{}, fmt.Errorf("the key %s has %d bytes instead of %d",
			keyID, len(material), secrets.KeyLength)
	}
	return kek.Seal(keyID, PurposeSecrets, material)
}
