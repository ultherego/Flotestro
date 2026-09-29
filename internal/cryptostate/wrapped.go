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
// may travel with a dump and the key may not. The key alone is not enough
// either: a row also names the installation it belongs to, because the name of
// a key encryption key is derived from the key material and two deployments
// holding the same key would otherwise be indistinguishable to their rows.

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

// The layout of the wrapping. It is counted apart from the envelope version of
// a secret: these are two floors of the same building, and one may move
// without the other.
const (
	// WrappedKeyVersion is the form new rows are written in: the installation
	// is part of what the row is sealed against.
	WrappedKeyVersion = 2
	// wrappedKeyVersionUnbound is the first form, which named no installation.
	// Rows of it keep opening under their own associated data, so no
	// installation has to re-seal anything to start.
	wrappedKeyVersionUnbound = 1
)

// CodeWrappedKeyUnreadable is the stable code of a row this panel cannot make
// sense of: the content or what the row says about itself was changed, or the
// row is in a form this panel does not read. It is what is left after the row
// has been cleared of naming another key and another installation.
const CodeWrappedKeyUnreadable = "wrapped_key_unreadable"

// CodeKEKRotated is the stable code of a write refused because the
// installation has moved to another key encryption key since this replica
// loaded the one it holds: a rewrap finished elsewhere while this replica was
// running. It is kept apart from CodeKEKMismatch, which is a deployment given
// the wrong key, and from the two codes above, which are rows already written:
// here nothing was written, and the remedy is to restart this replica onto the
// key the record now names.
const CodeKEKRotated = "kek_rotated"

// CodeWrappedKeyInstallationMismatch is the stable code of a row that belongs
// to another installation. It is kept apart from CodeWrappedKeyUnreadable
// because the two are fixed differently: a damaged row is restored from a
// backup, a row of another installation is taken out of this database, and an
// operator who cannot tell them apart will try the first remedy on the second
// problem.
const CodeWrappedKeyInstallationMismatch = "wrapped_key_installation_mismatch"

// WrappedKey is one private key of the installation as the database holds it.
type WrappedKey struct {
	// KeyID is the name the key is known by elsewhere: the key id an
	// envelope names, the identifier of an authority, the name of the
	// helper's signer.
	KeyID   string
	Purpose string
	// KEKID names the key encryption key this row was wrapped with. A row
	// that names another key is refused rather than half-read.
	KEKID string
	// InstallationID names the installation the row belongs to. It is empty
	// on a row of the first form, which recorded none. From the second form
	// on it is part of what the row is sealed against, so it cannot be
	// rewritten to say this installation without the row ceasing to open.
	InstallationID  string
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
	// PutWrappedKeyUnderRecordedKEK writes a key that must not exist yet,
	// and only while the installation record still names the key encryption
	// key the row was sealed with. A key id already taken comes back as
	// ErrKeyExists, so that a caller racing another replica can read what is
	// there and decide; a record that has moved on comes back as
	// CodeKEKRotated and no row is written.
	//
	// The check and the insert are one transaction because a replica seals
	// with the key it loaded at start: a rewrap that finished in between
	// would leave this row wrapped with a key the rewrap has already been
	// past, and nothing would ever come back for it.
	PutWrappedKeyUnderRecordedKEK(ctx context.Context, key WrappedKey) error
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
// has to be true for the row to open, so a key cannot be moved between names
// or purposes by an update statement.
//
// The first form stopped at the key encryption key, and a key encryption key
// is not a place: kekID is a keyed digest of the material, so two
// installations that hold the same key produce the same name and a row of one
// opened verbatim in the other. From the second form on the installation is in
// here as well, which is what makes a row belong somewhere rather than merely
// to a key. Rows of the first form are not re-read under the new binding -
// they never had it - so they keep the associated data they were sealed with.
func wrappedKeyAAD(keyID, purpose, kekID, installationID string, version int) []byte {
	base := "flotestro-wrapped-key|" + strconv.Itoa(version) + "|" +
		kekID + "|" + purpose + "|" + keyID
	if version == wrappedKeyVersionUnbound {
		return []byte(base)
	}
	return []byte(base + "|" + installationID)
}

// Seal wraps key material for the database.
//
// The sealing is done here rather than through secrets.Cipher on purpose: that
// primitive opens a value with no associated data when the bound form fails, a
// kindness the first form of the store needed and key material must not have.
// Here the binding either holds or the row is refused.
func (k *InstallationKEK) Seal(keyID, purpose string, material []byte) (WrappedKey, error) {
	if k.installation == "" {
		return WrappedKey{}, fmt.Errorf(
			"the key %s cannot be wrapped: the key encryption key %s was not bound to an installation",
			keyID, k.id)
	}
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
	associated := wrappedKeyAAD(keyID, purpose, k.id, k.installation, WrappedKeyVersion)
	return WrappedKey{
		KeyID:           keyID,
		Purpose:         purpose,
		KEKID:           k.id,
		InstallationID:  k.installation,
		EnvelopeVersion: WrappedKeyVersion,
		Nonce:           nonce,
		Ciphertext:      aead.Seal(nil, nonce, material, associated),
	}, nil
}

// Open returns the material of a wrapped key.
//
// The three things that can be wrong with a row are told apart before anything
// is decrypted: this deployment holds a different key encryption key, the row
// belongs to another installation, or the row is in a form this panel does not
// read. Each is a different job for the operator, so each says so by name, and
// only what is left over is reported as damage.
//
// Which associated data a row is opened with is the row's own to say: a row of
// the first form is opened the way it was sealed. That is what lets a mixed
// set - some rows re-sealed, some not - be read by one panel during a rewrap.
func (k *InstallationKEK) Open(row WrappedKey) ([]byte, error) {
	if !k.Is(row.KEKID) {
		return nil, fatal(CodeKEKMismatch, fmt.Sprintf(
			"the key %s was wrapped with %s; this deployment holds %s",
			row.KeyID, row.KEKID, k.id), nil)
	}
	switch row.EnvelopeVersion {
	case wrappedKeyVersionUnbound:
		// The first form named no installation, so there is nothing to compare
		// and the row opens under the associated data it was sealed with.
	case WrappedKeyVersion:
		if row.InstallationID != k.installation {
			return nil, fatal(CodeWrappedKeyInstallationMismatch, fmt.Sprintf(
				"the key %s belongs to the installation %s and this panel is the installation %s: "+
					"the row was copied from another deployment's database",
				row.KeyID, wrappedKeyOwner(row.InstallationID), k.installation), nil)
		}
	default:
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
	associated := wrappedKeyAAD(row.KeyID, row.Purpose, row.KEKID, row.InstallationID, row.EnvelopeVersion)
	material, err := aead.Open(nil, row.Nonce, row.Ciphertext, associated)
	if err != nil {
		return nil, fatal(CodeWrappedKeyUnreadable, fmt.Sprintf(
			"the key %s does not open under %s: the row or what it says about itself was changed",
			row.KeyID, k.id), nil)
	}
	return material, nil
}

// wrappedKeyOwner names the installation of a row that claims the second form
// and carries none: a row edited by hand, which the refusal still has to be
// able to speak about.
func wrappedKeyOwner(installationID string) string {
	if installationID == "" {
		return "no installation at all"
	}
	return installationID
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
func sealSecretsKey(kek *InstallationKEK, keyID string, material []byte) (WrappedKey, error) {
	if len(material) != secrets.KeyLength {
		return WrappedKey{}, fmt.Errorf("the key %s has %d bytes instead of %d",
			keyID, len(material), secrets.KeyLength)
	}
	return kek.Seal(keyID, PurposeSecrets, material)
}
