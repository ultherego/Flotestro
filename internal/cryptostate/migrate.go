package cryptostate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/ultherego/flotestro/internal/pki"
)

// Moving the keys of an installation into the database, and back.
//
// The move is one step or none. An installation whose secret store reads from
// the database while its fleet CA still reads from one replica's disk is worse
// off than either arrangement alone: it is shared in a way that hides which
// machine it still depends on. So every key the replicas need equally travels
// together, and one key that cannot be sealed and read back again stops the
// whole migration.

// Material is one key as it was found outside the database, ready to become a
// row.
type Material struct {
	// KeyID is the name the key will answer to. For the secret store it is
	// the key id the envelopes already name; for an authority it is the
	// issuer identifier; for the helper's signer it is the name the hosts
	// pin.
	KeyID   string
	Purpose string
	// Source is where the key was read from. It goes into the report and
	// into the backup, so that an operator can put things back by hand.
	Source string
	// Bytes is what the row will hold: the raw key of the secret store,
	// or the PEM the subsystem writes and reads.
	Bytes []byte
	// RetiredAt carries a retirement across a rewrap. A key put out of use
	// must not come back into use because its wrapping changed.
	RetiredAt *time.Time
}

// Digest names the material without giving it away. The reports and the
// backup carry it so that a key put back by hand can be told from a key put
// back by accident.
func (m Material) Digest() string {
	sum := sha256.Sum256(m.Bytes)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// RetiredAuthority is the certificate of an authority withdrawn from signing.
// It carries no key - the key is destroyed at the handover - but the fleet
// still has to recognise the hosts it issued for until the last of them has
// renewed, so it travels with the installation like everything else.
type RetiredAuthority struct {
	Serial      string
	Certificate []byte
	// Source is the file it was read from, for the report and the backup.
	Source string
}

// Entry is one line of what a migration did or would do.
type Entry struct {
	KeyID   string
	Purpose string
	Source  string
	Digest  string
	// Action is what happened to this key: "import", "rewrap", "restore".
	Action string
}

// MigrationReport is what a migration did, in the order the keys were taken. It is
// printed by a dry run word for word as it will be printed by the run itself.
type MigrationReport struct {
	KEKID string
	// PreviousKEKID is set by a rewrap: the key the rows were sealed with
	// before.
	PreviousKEKID string
	Entries       []Entry
	At            time.Time
}

// ImportStore is what moving the keys needs of the database: the rows, and a
// way to write all of them and the record together or not at all.
type ImportStore interface {
	KeyStore
	// ImportKeys writes every key, every withdrawn certificate and the key
	// encryption key's name in one transaction. It refuses an installation
	// whose keys are already in the database: a second import would be a
	// second opinion about what the installation is.
	ImportKeys(ctx context.Context, kekID string, keys []WrappedKey, retired []RetiredAuthority) error
	// ReplaceKeys rewraps: every row and the record move from one key
	// encryption key to another together.
	ReplaceKeys(ctx context.Context, fromKEKID, toKEKID string, keys []WrappedKey) error
	// ForgetKeys takes the named keys out of the database and clears the
	// record, which is the last step of a revert - after the files are back.
	// The names are the keys the revert actually wrote: anything else wrapped
	// with the same key appeared while it ran, is in no file, and is a refusal
	// rather than a row to drop.
	ForgetKeys(ctx context.Context, kekID string, keyIDs []string) error
	// RetiredAuthorities returns the certificates withdrawn from signing.
	RetiredAuthorities(ctx context.Context) ([][]byte, error)
	KEKID(ctx context.Context) (string, error)
	Load(ctx context.Context) (*Record, error)
}

// Import moves the material into the database.
//
// Every key is sealed and then opened again before anything is written. The
// round trip costs nothing and answers the only question that matters at this
// moment: will this installation still be able to read its own keys once the
// files are gone.
func Import(ctx context.Context, store ImportStore, kek *KEK, materials []Material, retired []RetiredAuthority) (MigrationReport, error) {
	report := MigrationReport{KEKID: kek.ID(), At: time.Now().UTC()}
	if len(materials) == 0 {
		return report, fmt.Errorf("there is nothing to move: no key was found outside the database")
	}
	recorded, err := store.KEKID(ctx)
	if err != nil {
		return report, err
	}
	if recorded != "" {
		return report, fmt.Errorf(
			"the keys of this installation are already in the database, wrapped with %s", recorded)
	}
	rows, err := seal(kek, materials)
	if err != nil {
		return report, err
	}
	if err := store.ImportKeys(ctx, kek.ID(), rows, retired); err != nil {
		return report, err
	}
	report.Entries = append(entries(materials, "import"), retiredEntries(retired)...)
	return report, nil
}

// Rewrap moves every row from one key encryption key to another.
//
// The keys themselves do not change - what the envelopes name, what the hosts
// pinned and what the certificates were signed with all stay as they are. Only
// the wrapping moves, which is why this can be done with the panel running and
// why losing the old key afterwards costs nothing.
func Rewrap(ctx context.Context, store ImportStore, from, to *KEK) (MigrationReport, error) {
	report := MigrationReport{KEKID: to.ID(), PreviousKEKID: from.ID(), At: time.Now().UTC()}
	if from.Is(to.ID()) {
		return report, fmt.Errorf("the installation is already wrapped with %s", to.ID())
	}
	recorded, err := store.KEKID(ctx)
	if err != nil {
		return report, err
	}
	if recorded == "" {
		return report, fmt.Errorf("the keys of this installation are not in the database yet")
	}
	if !from.Is(recorded) {
		return report, fatal(CodeKEKMismatch, fmt.Sprintf(
			"the installation is wrapped with %s; the key given as the current one is %s",
			recorded, from.ID()), nil)
	}
	materials, err := open(ctx, store, from)
	if err != nil {
		return report, err
	}
	rows, err := seal(to, materials)
	if err != nil {
		return report, err
	}
	if err := store.ReplaceKeys(ctx, from.ID(), to.ID(), rows); err != nil {
		return report, err
	}
	report.Entries = entries(materials, "rewrap")
	return report, nil
}

// Export opens every key of the installation, so that a revert can write the
// files back before the rows are dropped. Nothing is written here: what to do
// with the material is the caller's, and it is the one thing in this package
// that leaves the process holding plain key material.
func Export(ctx context.Context, store ImportStore, kek *KEK) ([]Material, error) {
	recorded, err := store.KEKID(ctx)
	if err != nil {
		return nil, err
	}
	if recorded == "" {
		return nil, fmt.Errorf("the keys of this installation are not in the database")
	}
	if !kek.Is(recorded) {
		return nil, fatal(CodeKEKMismatch, fmt.Sprintf(
			"the installation is wrapped with %s; this deployment holds %s", recorded, kek.ID()), nil)
	}
	return open(ctx, store, kek)
}

// ExportRetired hands back the withdrawn certificates, so that a revert can
// put them next to the keys. An installation that has ever rotated its CA and
// loses them cuts off every host that has not yet renewed.
func ExportRetired(ctx context.Context, store ImportStore) ([]RetiredAuthority, error) {
	certificates, err := store.RetiredAuthorities(ctx)
	if err != nil {
		return nil, err
	}
	retired := make([]RetiredAuthority, 0, len(certificates))
	for _, certPEM := range certificates {
		serial, err := RetiredSerial(certPEM)
		if err != nil {
			return nil, err
		}
		retired = append(retired, RetiredAuthority{
			Serial: serial, Certificate: certPEM, Source: "the database",
		})
	}
	return retired, nil
}

// seal wraps every material and reads each one back. A key that seals but does
// not open is the accident this whole stage exists to prevent, and the place to
// find it is here, before a row is written.
func seal(kek *KEK, materials []Material) ([]WrappedKey, error) {
	seen := map[string]bool{}
	rows := make([]WrappedKey, 0, len(materials))
	for _, material := range materials {
		if seen[material.KeyID] {
			return nil, fmt.Errorf("two keys are called %s; an installation cannot hold both", material.KeyID)
		}
		seen[material.KeyID] = true
		row, err := kek.Seal(material.KeyID, material.Purpose, material.Bytes)
		if err != nil {
			return nil, fmt.Errorf("the key %s could not be wrapped: %w", material.KeyID, err)
		}
		row.RetiredAt = material.RetiredAt
		back, err := kek.Open(row)
		if err != nil {
			return nil, fmt.Errorf("the key %s could not be read back after wrapping: %w", material.KeyID, err)
		}
		if !bytes.Equal(back, material.Bytes) {
			return nil, fmt.Errorf("the key %s came back changed from its own wrapping", material.KeyID)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// open reads every key of the installation out of the database.
func open(ctx context.Context, store ImportStore, kek *KEK) ([]Material, error) {
	var materials []Material
	for _, purpose := range []string{PurposeSecrets, PurposeAgentCA, PurposeHelperSigning} {
		rows, err := store.WrappedKeys(ctx, purpose)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			material, err := kek.Open(row)
			if err != nil {
				return nil, err
			}
			materials = append(materials, Material{
				KeyID:     row.KeyID,
				Purpose:   row.Purpose,
				Source:    "the database",
				Bytes:     material,
				RetiredAt: row.RetiredAt,
			})
		}
	}
	if len(materials) == 0 {
		return nil, fmt.Errorf("the record names a key encryption key, but the installation holds no key")
	}
	sort.Slice(materials, func(i, j int) bool {
		if materials[i].Purpose != materials[j].Purpose {
			return materials[i].Purpose < materials[j].Purpose
		}
		return materials[i].KeyID < materials[j].KeyID
	})
	return materials, nil
}

// retiredEntries reports the withdrawn certificates beside the keys. They are
// public, so the digest is there to compare copies, not to hide anything.
func retiredEntries(retired []RetiredAuthority) []Entry {
	lines := make([]Entry, 0, len(retired))
	for _, authority := range retired {
		sum := sha256.Sum256(authority.Certificate)
		lines = append(lines, Entry{
			KeyID:   authority.Serial,
			Purpose: "retired-authority",
			Source:  authority.Source,
			Digest:  "sha256:" + hex.EncodeToString(sum[:]),
			Action:  "import",
		})
	}
	return lines
}

func entries(materials []Material, action string) []Entry {
	lines := make([]Entry, 0, len(materials))
	for _, material := range materials {
		lines = append(lines, Entry{
			KeyID:   material.KeyID,
			Purpose: material.Purpose,
			Source:  material.Source,
			Digest:  material.Digest(),
			Action:  action,
		})
	}
	return lines
}

// Preview is what a dry run reports: exactly what the run would do, without
// touching the database.
func Preview(ctx context.Context, store ImportStore, kek *KEK, materials []Material, retired []RetiredAuthority) (MigrationReport, error) {
	report := MigrationReport{KEKID: kek.ID(), At: time.Now().UTC()}
	recorded, err := store.KEKID(ctx)
	if err != nil {
		return report, err
	}
	if recorded != "" {
		return report, fmt.Errorf(
			"the keys of this installation are already in the database, wrapped with %s", recorded)
	}
	if _, err := seal(kek, materials); err != nil {
		return report, err
	}
	report.Entries = append(entries(materials, "import"), retiredEntries(retired)...)
	return report, nil
}

// RetiredSerial names a withdrawn certificate the way the state directory
// named its file: by the serial of the certificate itself, so that the same
// authority keeps the same name whichever side it is read from.
func RetiredSerial(certPEM []byte) (string, error) {
	cert, err := pki.ParseCertificatePEM(certPEM)
	if err != nil {
		return "", fmt.Errorf("a withdrawn authority: %w", err)
	}
	return cert.SerialNumber.String(), nil
}
