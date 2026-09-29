package cryptostate

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/secrets"
)

// memoryKeys is the database of wrapped keys without a database.
type memoryKeys struct {
	mu   sync.Mutex
	rows map[string]WrappedKey
}

func newMemoryKeys() *memoryKeys { return &memoryKeys{rows: map[string]WrappedKey{}} }

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

func testKEK(t *testing.T, hexKey string) *KEK {
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
