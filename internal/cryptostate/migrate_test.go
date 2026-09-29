package cryptostate

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/secrets"
)

// memoryStore is the database of a migration without a database: the rows and
// the one column of the record the migration touches.
type memoryStore struct {
	*memoryKeys
	kekID  string
	record *Record
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		memoryKeys: newMemoryKeys(),
		record:     &Record{InstallationID: "6283c373-ab8a-4527-ad96-9a59b46a9234", Revision: 4},
	}
}

func (m *memoryStore) KEKID(context.Context) (string, error) { return m.kekID, nil }

func (m *memoryStore) Load(context.Context) (*Record, error) {
	if m.record == nil {
		return nil, ErrNoRecord
	}
	return m.record, nil
}

func (m *memoryStore) ImportKeys(ctx context.Context, kekID string, keys []WrappedKey) error {
	if m.kekID != "" {
		return errors.New("already wrapped")
	}
	for _, key := range keys {
		if err := m.PutWrappedKey(ctx, key); err != nil {
			return err
		}
	}
	m.kekID = kekID
	return nil
}

func (m *memoryStore) ReplaceKeys(ctx context.Context, from, to string, keys []WrappedKey) error {
	if m.kekID != from {
		return errors.New("not wrapped with that key")
	}
	m.mu.Lock()
	m.rows = map[string]WrappedKey{}
	m.mu.Unlock()
	for _, key := range keys {
		if err := m.PutWrappedKey(ctx, key); err != nil {
			return err
		}
	}
	m.kekID = to
	return nil
}

func (m *memoryStore) ForgetKeys(_ context.Context, kekID string) error {
	if m.kekID != kekID {
		return errors.New("not wrapped with that key")
	}
	m.mu.Lock()
	m.rows = map[string]WrappedKey{}
	m.mu.Unlock()
	m.kekID = ""
	return nil
}

func (m *memoryStore) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rows)
}

func installationMaterial() []Material {
	return []Material{
		{KeyID: "legacy", Purpose: PurposeSecrets, Source: "secrets.key",
			Bytes: bytes.Repeat([]byte{1}, secrets.KeyLength)},
		{KeyID: "k-one", Purpose: PurposeSecrets, Source: "keys/k-one.key",
			Bytes: bytes.Repeat([]byte{2}, secrets.KeyLength)},
		{KeyID: "cf4a324d-ea01-5141-a3a4-032fdc10e703", Purpose: PurposeAgentCA, Source: "ca.key",
			Bytes: []byte("-----BEGIN EC PRIVATE KEY-----\nnot really\n-----END EC PRIVATE KEY-----\n")},
		{KeyID: "hs-0123456789abcdef", Purpose: PurposeHelperSigning, Source: "helper-signing.key",
			Bytes: []byte("-----BEGIN PRIVATE KEY-----\nnot really\n-----END PRIVATE KEY-----\n")},
	}
}

// The whole identity of the installation moves at once. An installation whose
// secret store reads from the database while its authority still reads from
// one replica's disk is shared in a way that hides what it still depends on,
// so there is one step and no half of one.
func TestTheKeysOfAnInstallationMoveTogetherOrNotAtAll(t *testing.T) {
	ctx := context.Background()
	kek := testKEK(t, testKEKHex)
	store := newMemoryStore()
	materials := installationMaterial()

	// A dry run says exactly what the run will say, and writes nothing.
	preview, err := Preview(ctx, store, kek, materials)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Entries) != len(materials) {
		t.Fatalf("the preview lists %d keys of %d", len(preview.Entries), len(materials))
	}
	if store.count() != 0 || store.kekID != "" {
		t.Fatal("the preview wrote to the database")
	}

	report, err := Import(ctx, store, kek, materials)
	if err != nil {
		t.Fatal(err)
	}
	if store.kekID != kek.ID() {
		t.Errorf("the record names %q", store.kekID)
	}
	if store.count() != len(materials) {
		t.Errorf("the database holds %d keys of %d", store.count(), len(materials))
	}
	for i, entry := range report.Entries {
		if entry.Digest != materials[i].Digest() || entry.Action != "import" {
			t.Errorf("the report line for %s is %+v", entry.KeyID, entry)
		}
		if entry.Digest == string(materials[i].Bytes) {
			t.Error("the report carries the key itself")
		}
	}

	// Every purpose came through, and every key opens again.
	back, err := Export(ctx, store, kek)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != len(materials) {
		t.Fatalf("the installation holds %d keys of %d", len(back), len(materials))
	}
	byID := map[string][]byte{}
	for _, material := range back {
		byID[material.KeyID] = material.Bytes
	}
	for _, material := range materials {
		if !bytes.Equal(byID[material.KeyID], material.Bytes) {
			t.Errorf("the key %s did not come back as it went in", material.KeyID)
		}
	}

	// A second import would be a second opinion about what the installation is.
	if _, err := Import(ctx, store, kek, materials); err == nil {
		t.Error("the keys were imported twice")
	}
	if _, err := Preview(ctx, store, kek, materials); err == nil {
		t.Error("a dry run of a migration that already happened said it would work")
	}
}

// What cannot be moved stops the move. The checks that can be made before a
// row is written are made there, so the database is never left holding part of
// an installation.
func TestAMigrationThatCannotBeCompletedWritesNothing(t *testing.T) {
	ctx := context.Background()
	kek := testKEK(t, testKEKHex)
	good := installationMaterial()

	for _, test := range []struct {
		name      string
		materials []Material
	}{
		{"nothing to move", nil},
		{"two keys under one name", append(good, Material{
			KeyID: "k-one", Purpose: PurposeSecrets, Source: "keys/k-one.key",
			Bytes: bytes.Repeat([]byte{9}, secrets.KeyLength)})},
		{"a key kept for no known purpose", append(good, Material{
			KeyID: "k-odd", Purpose: "whatever-was-lying-around", Source: "keys/k-odd.key",
			Bytes: bytes.Repeat([]byte{9}, secrets.KeyLength)})},
		{"a key with no material", append(good, Material{
			KeyID: "k-empty", Purpose: PurposeSecrets, Source: "keys/k-empty.key"})},
		{"a name that cannot be a key id", append(good, Material{
			KeyID: "Keys/../../etc/shadow", Purpose: PurposeSecrets, Source: "?",
			Bytes: bytes.Repeat([]byte{9}, secrets.KeyLength)})},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newMemoryStore()
			if _, err := Import(ctx, store, kek, test.materials); err == nil {
				t.Fatal("the migration went through")
			}
			if store.count() != 0 || store.kekID != "" {
				t.Errorf("the database holds %d keys and names %q", store.count(), store.kekID)
			}
		})
	}
}

// Changing the key encryption key changes nothing else: the keys keep their
// names and their material, so the envelopes, the certificates and the pins on
// the hosts are untouched. That is what makes a compromised wrapping key
// something an operator can answer within the hour.
func TestARewrapMovesTheWrappingAndNothingElse(t *testing.T) {
	ctx := context.Background()
	first := testKEK(t, testKEKHex)
	second := testKEK(t, otherKEKHex)
	store := newMemoryStore()
	materials := installationMaterial()
	if _, err := Import(ctx, store, first, materials); err != nil {
		t.Fatal(err)
	}
	// One key is out of use but still opens what it sealed.
	if err := store.RetireWrappedKey(ctx, "legacy"); err != nil {
		t.Fatal(err)
	}

	if _, err := Rewrap(ctx, store, first, first); err == nil {
		t.Error("the installation was rewrapped with the key it already has")
	}
	if _, err := Rewrap(ctx, store, second, first); !refusedWith(err, CodeKEKMismatch) {
		t.Errorf("a rewrap from the wrong key answered %v", err)
	}

	report, err := Rewrap(ctx, store, first, second)
	if err != nil {
		t.Fatal(err)
	}
	if report.PreviousKEKID != first.ID() || report.KEKID != second.ID() {
		t.Errorf("the report says %s -> %s", report.PreviousKEKID, report.KEKID)
	}
	if store.kekID != second.ID() {
		t.Errorf("the record names %q", store.kekID)
	}
	if _, err := Export(ctx, store, first); !refusedWith(err, CodeKEKMismatch) {
		t.Errorf("the old key still opens the installation: %v", err)
	}

	back, err := Export(ctx, store, second)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != len(materials) {
		t.Fatalf("the installation holds %d keys of %d", len(back), len(materials))
	}
	retired := 0
	for _, material := range back {
		if material.RetiredAt != nil {
			retired++
			if material.KeyID != "legacy" {
				t.Errorf("the key %s came out of the rewrap retired", material.KeyID)
			}
		}
	}
	if retired != 1 {
		t.Error("a key that was put out of use came back into use through the rewrap")
	}

	// A provider built over the rewrapped rows serves the same keys.
	provider, err := NewDBProvider(ctx, store, second)
	if err != nil {
		t.Fatal(err)
	}
	if ids := provider.KeyIDs(); len(ids) != 2 {
		t.Errorf("the secret store holds %v", ids)
	}
}

// A revert puts the installation back where it was. The rows go only after the
// material is in the caller's hands, so an interrupted revert leaves the keys
// in the database rather than nowhere.
func TestARevertHandsBackTheMaterialBeforeTheRowsGo(t *testing.T) {
	ctx := context.Background()
	kek := testKEK(t, testKEKHex)
	stranger := testKEK(t, otherKEKHex)
	store := newMemoryStore()
	materials := installationMaterial()
	if _, err := Import(ctx, store, kek, materials); err != nil {
		t.Fatal(err)
	}

	if _, err := Export(ctx, store, stranger); !refusedWith(err, CodeKEKMismatch) {
		t.Errorf("another deployment's key opened this installation: %v", err)
	}
	if store.count() != len(materials) {
		t.Error("a refused revert took rows away")
	}

	back, err := Export(ctx, store, kek)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != len(materials) {
		t.Fatalf("the revert hands back %d keys of %d", len(back), len(materials))
	}
	if err := store.ForgetKeys(ctx, stranger.ID()); err == nil {
		t.Error("the rows were dropped on the word of a key the installation is not wrapped with")
	}
	if err := store.ForgetKeys(ctx, kek.ID()); err != nil {
		t.Fatal(err)
	}
	if store.count() != 0 || store.kekID != "" {
		t.Error("the revert left the installation half in the database")
	}
	if _, err := Export(ctx, store, kek); err == nil {
		t.Error("an installation with no keys in the database exported some")
	}

	// And it can be moved in again afterwards, which is what makes the rollback
	// a rollback rather than a one-way door.
	now := time.Now()
	materials[0].RetiredAt = &now
	if _, err := Import(ctx, store, kek, materials); err != nil {
		t.Fatalf("the installation could not move back into the database: %v", err)
	}
}
