package cryptostate

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/secrets"
)

// memoryKeys is the database of wrapped keys without a database. It keeps the
// two columns of the installation record a write is judged against, because a
// row sealed with a replica's own key may only be written while the record
// still names that key.
type memoryKeys struct {
	mu   sync.Mutex
	rows map[string]WrappedKey
	// recordedKEK and recordedInstallation are what the record says. They
	// are empty until the first key is written, the way an installation
	// names no key encryption key until its keys move into the database.
	recordedKEK          string
	recordedInstallation string
}

func newMemoryKeys() *memoryKeys { return &memoryKeys{rows: map[string]WrappedKey{}} }

// recordNames moves the record, which is what a rewrap run against another
// replica does to this one.
func (m *memoryKeys) recordNames(kekID, installationID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recordedKEK, m.recordedInstallation = kekID, installationID
}

func (m *memoryKeys) WrappedKeys(_ context.Context, purpose string) ([]WrappedKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var keys []WrappedKey
	for _, row := range m.rows {
		if row.Purpose == purpose {
			keys = append(keys, row)
		}
	}
	return keys, nil
}

func (m *memoryKeys) WrappedKey(_ context.Context, keyID string) (WrappedKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.rows[keyID]
	if !ok {
		return WrappedKey{}, ErrWrappedKeyMissing
	}
	return row, nil
}

func (m *memoryKeys) PutWrappedKey(_ context.Context, key WrappedKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.insert(key)
}

// PutWrappedKeyUnderRecordedKEK refuses under the lock the way Postgres
// refuses inside the transaction: the record is read and the row written with
// nothing able to move the record in between.
func (m *memoryKeys) PutWrappedKeyUnderRecordedKEK(_ context.Context, key WrappedKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.recordedKEK == "" {
		m.recordedKEK, m.recordedInstallation = key.KEKID, key.InstallationID
	}
	if m.recordedInstallation != key.InstallationID {
		return fatal(CodeWrappedKeyInstallationMismatch, fmt.Sprintf(
			"the key %s was sealed for the installation %s and this database describes %s",
			key.KeyID, wrappedKeyOwner(key.InstallationID), m.recordedInstallation), nil)
	}
	if m.recordedKEK != key.KEKID {
		return fatal(CodeKEKRotated, fmt.Sprintf(
			"the key %s was sealed with %s and the installation is now wrapped with %s",
			key.KeyID, key.KEKID, m.recordedKEK), nil)
	}
	return m.insert(key)
}

func (m *memoryKeys) insert(key WrappedKey) error {
	if _, taken := m.rows[key.KeyID]; taken {
		return ErrKeyExists
	}
	key.CreatedAt = time.Now()
	m.rows[key.KeyID] = key
	return nil
}

func (m *memoryKeys) RetireWrappedKey(_ context.Context, keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.rows[keyID]
	if !ok {
		return ErrWrappedKeyMissing
	}
	if row.RetiredAt == nil {
		now := time.Now()
		row.RetiredAt = &now
		m.rows[keyID] = row
	}
	return nil
}

func (m *memoryKeys) DeleteWrappedKey(_ context.Context, keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rows[keyID]; !ok {
		return ErrWrappedKeyMissing
	}
	delete(m.rows, keyID)
	return nil
}

const testKEKHex = "3f1a9c0e5b7d2648a0c3e5f7091b2d4e6a8c0e2f4a6b8d0f1234567890abcdef"

// strangerKEKHex belongs to no installation here: it is the third key a test
// needs to show that two are not simply tried in turn.
const strangerKEKHex = "5c7e9a1b3d5f70921436587a9cbedf01234567890abcdef0fedcba9876543210"
const otherKEKHex = "8e2b4d6f0a1c3e5079b1d3f5a7c9e10b2d4f60718293a4b5c6d7e8f901234567"

// testInstallationID is the installation every test here belongs to, unless it
// is a test about two of them.
const testInstallationID = "6283c373-ab8a-4527-ad96-9a59b46a9234"

// otherInstallationID is a second deployment that mounts the very same key
// encryption key: the shape of the mistake the binding exists for.
const otherInstallationID = "b04f1d8c-7a29-4e31-9f60-1c5d2e3a4b57"

func testKEK(t *testing.T, hexKey string) *InstallationKEK {
	t.Helper()
	return unboundKEK(t, hexKey).For(testInstallationID)
}

func unboundKEK(t *testing.T, hexKey string) *KEK {
	t.Helper()
	kek, err := ParseKEK(hexKey, "test")
	if err != nil {
		t.Fatal(err)
	}
	return kek
}

// The move into the database must not change what the keys do. An installation
// seals a value while its keys are files, moves them, and has to open the same
// value afterwards - the wrapping of a data key is the same operation on both
// sides.
func TestAKeyOpensTheSameEnvelopesFromTheDatabaseAsFromTheDirectory(t *testing.T) {
	ctx := context.Background()
	local, err := NewLocalProvider(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := local.GenerateNamed(ctx, "k-one"); err != nil {
		t.Fatal(err)
	}
	local.SetActive("k-one")

	dek := bytes.Repeat([]byte{7}, secrets.KeyLength)
	wrapped, err := local.Wrap(ctx, "k-one", dek)
	if err != nil {
		t.Fatal(err)
	}

	// The material of the file becomes a row, which is what import-state does.
	material, err := secrets.ReadKeyFile(local.Dir() + "/k-one.key")
	if err != nil {
		t.Fatal(err)
	}
	kek := testKEK(t, testKEKHex)
	store := newMemoryKeys()
	db, err := NewDBProvider(ctx, store, kek)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Adopt(ctx, "k-one", material); err != nil {
		t.Fatal(err)
	}
	db.SetActive("k-one")

	opened, err := db.Unwrap(ctx, "k-one", wrapped)
	if err != nil {
		t.Fatalf("a data key wrapped before the move does not open after it: %v", err)
	}
	if !bytes.Equal(opened, dek) {
		t.Error("the data key came back changed")
	}
	if id, err := db.ActiveKeyID(ctx); err != nil || id != "k-one" {
		t.Errorf("the active key is %q, %v", id, err)
	}
	if db.Name() != DBProviderName {
		t.Errorf("the provider calls itself %q", db.Name())
	}
	if err := db.Health(ctx); err != nil {
		t.Errorf("a provider that just wrote its key is unhealthy: %v", err)
	}
}

// A database is copied more often than a key. Rows that arrived with somebody
// else's dump, or that were edited in place, must not open here, and the two
// cases have to be told apart: a different key encryption key is an operator's
// mistake about which deployment this is, a row that will not open is damage.
func TestRowsThatDoNotBelongToThisDeploymentAreRefused(t *testing.T) {
	ctx := context.Background()
	kek := testKEK(t, testKEKHex)
	stranger := testKEK(t, otherKEKHex)
	material := bytes.Repeat([]byte{3}, secrets.KeyLength)

	sealed, err := sealSecretsKey(kek, "k-one", material)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		row  func(WrappedKey) WrappedKey
		code string
	}{
		{"as it was written", func(row WrappedKey) WrappedKey { return row }, ""},
		{"wrapped with the key of another deployment", func(row WrappedKey) WrappedKey {
			other, err := sealSecretsKey(stranger, "k-one", material)
			if err != nil {
				t.Fatal(err)
			}
			return other
		}, CodeKEKMismatch},
		{"the row says a key encryption key it was not wrapped with", func(row WrappedKey) WrappedKey {
			row.KEKID = stranger.ID()
			return row
		}, CodeKEKMismatch},
		{"renamed", func(row WrappedKey) WrappedKey {
			row.KeyID = "k-two"
			return row
		}, CodeWrappedKeyUnreadable},
		{"moved to another purpose", func(row WrappedKey) WrappedKey {
			row.Purpose = PurposeHelperSigning
			return row
		}, CodeWrappedKeyUnreadable},
		{"the ciphertext changed", func(row WrappedKey) WrappedKey {
			row.Ciphertext = append([]byte(nil), row.Ciphertext...)
			row.Ciphertext[0] ^= 0xff
			return row
		}, CodeWrappedKeyUnreadable},
		{"the nonce changed", func(row WrappedKey) WrappedKey {
			row.Nonce = append([]byte(nil), row.Nonce...)
			row.Nonce[0] ^= 0xff
			return row
		}, CodeWrappedKeyUnreadable},
		{"a nonce of the wrong length", func(row WrappedKey) WrappedKey {
			row.Nonce = row.Nonce[:len(row.Nonce)-1]
			return row
		}, CodeWrappedKeyUnreadable},
		{"a form this panel does not read", func(row WrappedKey) WrappedKey {
			row.EnvelopeVersion = WrappedKeyVersion + 1
			return row
		}, CodeWrappedKeyUnreadable},
		{"moved to another installation", func(row WrappedKey) WrappedKey {
			row.InstallationID = otherInstallationID
			return row
		}, CodeWrappedKeyInstallationMismatch},
		{"the installation taken off the row", func(row WrappedKey) WrappedKey {
			row.InstallationID = ""
			return row
		}, CodeWrappedKeyInstallationMismatch},
	} {
		t.Run(test.name, func(t *testing.T) {
			row := test.row(sealed)
			opened, err := kek.Open(row)
			if test.code == "" {
				if err != nil {
					t.Fatalf("the row was refused: %v", err)
				}
				if !bytes.Equal(opened, material) {
					t.Error("the key came back changed")
				}
				return
			}
			if err == nil {
				t.Fatal("the row opened")
			}
			var fatal *FatalError
			if !errors.As(err, &fatal) || fatal.Code != test.code {
				t.Errorf("the refusal is %v, expected %s", err, test.code)
			}

			// And a provider built over such a row refuses to start at all, rather
			// than serving the keys it happens to be able to read. A row moved to
			// another purpose is not among the keys of the secret store at all: it
			// is missing rather than unreadable, and the guard answers for that
			// where it compares the live secrets with the keys the provider holds.
			if row.Purpose != PurposeSecrets {
				return
			}
			store := newMemoryKeys()
			store.rows[row.KeyID] = row
			if _, err := NewDBProvider(ctx, store, kek); err == nil {
				t.Error("the provider started over a key it cannot open")
			}
		})
	}
}

// Two replicas of one installation start against one database. Both may reach
// for the same key at once; the one that arrives second has to take what is
// there rather than write a second key under the same name.
func TestASecondReplicaTakesTheKeyThatIsAlreadyThere(t *testing.T) {
	ctx := context.Background()
	kek := testKEK(t, testKEKHex)
	store := newMemoryKeys()

	first, err := NewDBProvider(ctx, store, kek)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewDBProvider(ctx, store, kek)
	if err != nil {
		t.Fatal(err)
	}
	material := bytes.Repeat([]byte{5}, secrets.KeyLength)
	if err := first.Adopt(ctx, "legacy", material); err != nil {
		t.Fatal(err)
	}
	// The second replica read the table before the row existed, so its own adopt
	// races the insert and loses it.
	if err := second.Adopt(ctx, "legacy", material); err != nil {
		t.Fatalf("the same key under the same name was refused: %v", err)
	}
	if got := len(store.rows); got != 1 {
		t.Errorf("the database holds %d rows for one key", got)
	}
	if _, ok := second.LegacyCipher(); !ok {
		t.Error("the replica that lost the race does not hold the key")
	}

	// Different material under a taken name is a collision, and is refused on
	// both sides of the race.
	other := bytes.Repeat([]byte{6}, secrets.KeyLength)
	if err := second.Adopt(ctx, "legacy", other); err == nil {
		t.Error("a second key was adopted under a name that is taken")
	}
	third, err := NewDBProvider(ctx, store, kek)
	if err != nil {
		t.Fatal(err)
	}
	if err := third.Adopt(ctx, "legacy", other); err == nil ||
		!strings.Contains(err.Error(), "different material") {
		t.Errorf("a replica that had read the row answered %v", err)
	}

	// A key this instance has not seen is looked for again before it is called
	// missing.
	if err := second.RequireKey(ctx, "k-elsewhere"); err == nil {
		t.Error("a key nobody wrote was found")
	}
	if err := first.GenerateNamed(ctx, "k-elsewhere"); err != nil {
		t.Fatal(err)
	}
	if err := second.RequireKey(ctx, "k-elsewhere"); err != nil {
		t.Errorf("a key another replica wrote is missing here: %v", err)
	}
}

// A key that was put out of use still opens what it sealed; it just stops
// sealing anything new. The provider has to say that plainly rather than hand
// the store a key the installation has retired.
func TestARetiredKeyOpensWhatItSealedAndSealsNothingNew(t *testing.T) {
	ctx := context.Background()
	kek := testKEK(t, testKEKHex)
	store := newMemoryKeys()
	provider, err := NewDBProvider(ctx, store, kek)
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.GenerateNamed(ctx, "k-old"); err != nil {
		t.Fatal(err)
	}
	dek := bytes.Repeat([]byte{9}, secrets.KeyLength)
	wrapped, err := provider.Wrap(ctx, "k-old", dek)
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Retire(ctx, "k-old"); err != nil {
		t.Fatal(err)
	}
	opened, err := provider.Unwrap(ctx, "k-old", wrapped)
	if err != nil || !bytes.Equal(opened, dek) {
		t.Errorf("a retired key stopped opening what it sealed: %v", err)
	}
	provider.SetActive("k-old")
	if _, err := provider.ActiveKeyID(ctx); !errors.Is(err, secrets.ErrKeyUnavailable) {
		t.Errorf("new material would be sealed under a retired key: %v", err)
	}

	// A replica that starts afterwards reads the same state out of the rows.
	fresh, err := NewDBProvider(ctx, store, kek)
	if err != nil {
		t.Fatal(err)
	}
	fresh.SetActive("k-old")
	if _, err := fresh.ActiveKeyID(ctx); !errors.Is(err, secrets.ErrKeyUnavailable) {
		t.Errorf("the retirement did not survive a restart: %v", err)
	}
	if ids := fresh.KeyIDs(); len(ids) != 1 || ids[0] != "k-old" {
		t.Errorf("the keys of the installation are %v", ids)
	}
}

// Health is what a running panel notices with. The row of the active key
// disappearing, or being rewritten under it, is the accident this answers.
func TestHealthNoticesTheActiveKeyChangingUnderTheRunningPanel(t *testing.T) {
	ctx := context.Background()
	kek := testKEK(t, testKEKHex)
	store := newMemoryKeys()
	provider, err := NewDBProvider(ctx, store, kek)
	if err != nil {
		t.Fatal(err)
	}
	id, err := provider.Generate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	provider.SetActive(id)
	if err := provider.Health(ctx); err != nil {
		t.Fatalf("a healthy provider reported %v", err)
	}

	replaced, err := sealSecretsKey(kek, id, bytes.Repeat([]byte{1}, secrets.KeyLength))
	if err != nil {
		t.Fatal(err)
	}
	store.rows[id] = replaced
	if err := provider.Health(ctx); err == nil {
		t.Error("the active key was replaced in the database and the panel called itself healthy")
	}

	delete(store.rows, id)
	if err := provider.Health(ctx); !errors.Is(err, secrets.ErrKeyUnavailable) {
		t.Errorf("a missing row answered %v", err)
	}

	// The cleanup of an initialisation that could not record itself takes the
	// row away with the key.
	if err := provider.Remove(ctx, id); err != nil {
		t.Fatal(err)
	}
	if provider.HasMaterial() {
		t.Error("the provider still holds a key it removed")
	}
}

// The provider will not start without a key encryption key, and says so with
// the code an operator can act on rather than with a panic somewhere later.
func TestAProviderWithoutAKeyEncryptionKeyDoesNotStart(t *testing.T) {
	if _, err := NewDBProvider(context.Background(), newMemoryKeys(), nil); !refusedWith(err, CodeKEKFileMissing) {
		t.Errorf("a provider without a key encryption key answered %v", err)
	}
}

// The whole point of binding the installation: kekID is a keyed digest of the
// key material, so two deployments that mount the same key encryption key give
// it the same name. Before the second form that was all a row said about where
// it came from, and a row lifted out of one database opened verbatim in the
// other.
func TestARowSealedForOneInstallationDoesNotOpenForAnotherHoldingTheSameKey(t *testing.T) {
	material := bytes.Repeat([]byte{7}, secrets.KeyLength)
	here := unboundKEK(t, testKEKHex).For(testInstallationID)
	there := unboundKEK(t, testKEKHex).For(otherInstallationID)

	// The fact the refusal rests on: one key, one name, two installations.
	if here.ID() != there.ID() {
		t.Fatalf("the same key material is named %s in one installation and %s in the other",
			here.ID(), there.ID())
	}

	row, err := sealSecretsKey(here, "k-one", material)
	if err != nil {
		t.Fatal(err)
	}
	if row.InstallationID != testInstallationID {
		t.Fatalf("the row names the installation %q", row.InstallationID)
	}
	if row.EnvelopeVersion != WrappedKeyVersion {
		t.Fatalf("a new row was written in form %d", row.EnvelopeVersion)
	}

	opened, err := there.Open(row)
	if err == nil {
		t.Fatalf("the row of another installation opened, giving back %d bytes", len(opened))
	}
	var refusal *FatalError
	if !errors.As(err, &refusal) || refusal.Code != CodeWrappedKeyInstallationMismatch {
		t.Fatalf("the refusal is %v, expected %s", err, CodeWrappedKeyInstallationMismatch)
	}
	// The operator has to be able to tell this from a damaged row, so the
	// refusal names both installations rather than saying the row is broken.
	if !strings.Contains(refusal.Reason, testInstallationID) ||
		!strings.Contains(refusal.Reason, otherInstallationID) {
		t.Errorf("the refusal does not name both installations: %s", refusal.Reason)
	}
	// And a panel does not start over such a row.
	store := newMemoryKeys()
	store.rows[row.KeyID] = row
	if _, err := NewDBProvider(context.Background(), store, there); err == nil {
		t.Error("the provider started over a key of another installation")
	}
}

// A key encryption key nobody bound to an installation seals nothing. It is a
// refusal and not a row written with an empty installation, which would be a
// row two deployments could both claim.
func TestAKeyEncryptionKeyThatNamesNoInstallationSealsNothing(t *testing.T) {
	unbound := unboundKEK(t, testKEKHex).For("")
	if _, err := unbound.Seal("k-one", PurposeSecrets, bytes.Repeat([]byte{1}, secrets.KeyLength)); err == nil {
		t.Fatal("a key bound to no installation wrapped a row")
	}
	if _, err := NewDBProvider(context.Background(), newMemoryKeys(), unbound); err == nil {
		t.Fatal("a provider started on a key bound to no installation")
	}
}

// sealFirstForm writes a row the way the panel wrote them before the
// installation was bound in: the same wrapping, the same associated data, and
// no installation on the row at all.
func sealFirstForm(t *testing.T, kek *InstallationKEK, keyID, purpose string, material []byte) WrappedKey {
	t.Helper()
	aead, err := kek.aead()
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatal(err)
	}
	associated := wrappedKeyAAD(keyID, purpose, kek.ID(), "", wrappedKeyVersionUnbound)
	return WrappedKey{
		KeyID:           keyID,
		Purpose:         purpose,
		KEKID:           kek.ID(),
		EnvelopeVersion: wrappedKeyVersionUnbound,
		Nonce:           nonce,
		Ciphertext:      aead.Seal(nil, nonce, material, associated),
	}
}

// The bytes of the first form are what every installation that has not
// rewrapped still has in its database. They are written down here because
// nothing else can notice them changing: a panel that computes them
// differently opens none of those rows, and finds out at the start after an
// upgrade.
func TestTheAssociatedDataOfTheFirstFormIsWhatItAlwaysWas(t *testing.T) {
	const expected = "flotestro-wrapped-key|1|kek-abc123|secrets|k-one"
	// The installation is passed and must make no difference: the first form
	// never carried one.
	for _, installation := range []string{"", testInstallationID, otherInstallationID} {
		got := string(wrappedKeyAAD("k-one", PurposeSecrets, "kek-abc123", installation, wrappedKeyVersionUnbound))
		if got != expected {
			t.Errorf("the first form binds %q, it always bound %q", got, expected)
		}
	}
}

// No installation has to re-seal anything to start: a row of the first form
// opens under the associated data it was sealed with, and the row's own form
// is what decides.
func TestARowOfTheFirstFormKeepsOpening(t *testing.T) {
	material := bytes.Repeat([]byte{9}, secrets.KeyLength)
	kek := testKEK(t, testKEKHex)
	row := sealFirstForm(t, kek, "k-old", PurposeSecrets, material)

	opened, err := kek.Open(row)
	if err != nil {
		t.Fatalf("a row of the first form was refused: %v", err)
	}
	if !bytes.Equal(opened, material) {
		t.Fatal("the key came back changed")
	}
	// It is honest about what it does not do: the first form bound no
	// installation, so it is the one thing the graft still works on, and a
	// rewrap is what closes it. A test that asserted otherwise would be
	// claiming a property the rows do not have.
	elsewhere := unboundKEK(t, testKEKHex).For(otherInstallationID)
	if _, err := elsewhere.Open(row); err != nil {
		t.Fatalf("a row of the first form stopped opening where it always did: %v", err)
	}
}

// A mixed set is allowed, and it has to be: a rewrap is what moves rows to the
// second form, and until one has run an installation holds only rows of the
// first. Requiring one form or the other would mean every installation had to
// rewrap before it could start again.
func TestAnInstallationOpensAMixedSetOfForms(t *testing.T) {
	ctx := context.Background()
	kek := testKEK(t, testKEKHex)
	store := newMemoryKeys()

	old := sealFirstForm(t, kek, "k-old", PurposeSecrets, bytes.Repeat([]byte{4}, secrets.KeyLength))
	store.rows[old.KeyID] = old
	fresh, err := sealSecretsKey(kek, "k-new", bytes.Repeat([]byte{5}, secrets.KeyLength))
	if err != nil {
		t.Fatal(err)
	}
	store.rows[fresh.KeyID] = fresh

	provider, err := NewDBProvider(ctx, store, kek)
	if err != nil {
		t.Fatalf("a set of both forms was refused: %v", err)
	}
	if ids := provider.KeyIDs(); len(ids) != 2 {
		t.Fatalf("the provider holds %v, expected both forms", ids)
	}
	// And the one row of the second form still refuses another installation,
	// so the mixed set costs nothing beyond what the first form already gave
	// away.
	elsewhere := unboundKEK(t, testKEKHex).For(otherInstallationID)
	if _, err := elsewhere.Open(fresh); err == nil {
		t.Error("the row of the second form opened for another installation")
	}
}

// rewrapInMemory does to the fake what crypto rewrap-kek does to the database:
// every row is opened under the old key, sealed under the new one, and the
// record moves with them.
func rewrapInMemory(t *testing.T, store *memoryKeys, from, to *InstallationKEK) {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	for id, row := range store.rows {
		material, err := from.Open(row)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := to.Seal(row.KeyID, row.Purpose, material)
		if err != nil {
			t.Fatal(err)
		}
		sealed.RetiredAt = row.RetiredAt
		store.rows[id] = sealed
	}
	store.recordedKEK, store.recordedInstallation = to.ID(), to.Installation()
}

// A replica seals with the key encryption key it loaded at its start. An
// operator rewrapping the installation from another replica moves every row
// and the record onto a new key, and this one notices nothing: the rewrap is
// over by the time it next makes a key, so no rewrap will ever come back for
// the row it would write. Every restart and every other replica would then
// refuse that row with kek_mismatch - the one key of the installation nobody
// can open - so the write is refused instead, and nothing is written.
func TestAKeyIsNotWrittenUnderAKeyEncryptionKeyTheInstallationHasLeft(t *testing.T) {
	ctx := context.Background()
	held := testKEK(t, testKEKHex)
	store := newMemoryKeys()
	replica, err := NewDBProvider(ctx, store, held)
	if err != nil {
		t.Fatal(err)
	}
	if err := replica.GenerateNamed(ctx, "k-one"); err != nil {
		t.Fatal(err)
	}

	// The rewrap, run against another replica of the same installation.
	rotated := testKEK(t, otherKEKHex)
	rewrapInMemory(t, store, held, rotated)

	for _, write := range []struct {
		name string
		id   string
		do   func(id string) error
	}{
		{"a key made", "k-two", func(id string) error { return replica.GenerateNamed(ctx, id) }},
		{"a key adopted", "k-three", func(id string) error {
			return replica.Adopt(ctx, id, bytes.Repeat([]byte{7}, secrets.KeyLength))
		}},
	} {
		err := write.do(write.id)
		if !refusedWith(err, CodeKEKRotated) {
			t.Errorf("%s after the rewrap answered %v, expected %s", write.name, err, CodeKEKRotated)
		}
		if _, err := store.WrappedKey(ctx, write.id); !errors.Is(err, ErrWrappedKeyMissing) {
			t.Errorf("%s after the rewrap left a row behind: %v", write.name, err)
		}
	}

	// The refusal does not teach this instance the new key: which of the
	// mounted keys a panel uses is decided once, at a start, and an instance
	// that changed it while running would leave the authorities it has already
	// handed out on the key before.
	if replica.KEKID() != held.ID() {
		t.Errorf("the instance moved itself to %s", replica.KEKID())
	}
	// It is already unfit to serve, which is what brings the restart: the row
	// of its active key no longer opens under the key it holds.
	replica.SetActive("k-one")
	if err := replica.Health(ctx); err == nil {
		t.Error("an instance left behind by a rewrap reported itself healthy")
	}

	// And the restart is the recovery: an instance started on the key the
	// record now names writes the key that was refused.
	restarted, err := NewDBProvider(ctx, store, rotated)
	if err != nil {
		t.Fatalf("an instance started on the key the record names was refused: %v", err)
	}
	if err := restarted.GenerateNamed(ctx, "k-two"); err != nil {
		t.Fatalf("the key was still refused after the restart: %v", err)
	}
	row, err := store.WrappedKey(ctx, "k-two")
	if err != nil {
		t.Fatal(err)
	}
	if row.KEKID != rotated.ID() {
		t.Errorf("the key was written under %s and the record names %s", row.KEKID, rotated.ID())
	}
}

// The two things that can be wrong with the record under a write are told
// apart: a key encryption key the installation has moved on from is this
// replica's own staleness, a database describing another installation is a
// deployment pointed at the wrong place. They are fixed differently.
func TestAWriteIntoAnotherInstallationsDatabaseSaysWhichOfTheTwoItIs(t *testing.T) {
	ctx := context.Background()
	held := testKEK(t, testKEKHex)
	store := newMemoryKeys()
	replica, err := NewDBProvider(ctx, store, held)
	if err != nil {
		t.Fatal(err)
	}
	store.recordNames(held.ID(), otherInstallationID)
	err = replica.GenerateNamed(ctx, "k-one")
	if !refusedWith(err, CodeWrappedKeyInstallationMismatch) {
		t.Errorf("the write answered %v, expected %s", err, CodeWrappedKeyInstallationMismatch)
	}
	if _, err := store.WrappedKey(ctx, "k-one"); !errors.Is(err, ErrWrappedKeyMissing) {
		t.Errorf("a row was written into another installation's database: %v", err)
	}
}
