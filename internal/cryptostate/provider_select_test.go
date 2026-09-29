package cryptostate

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// recordedKeys is the database as the selection sees it: the rows of
// memoryKeys, plus the key encryption key the installation record names.
type recordedKeys struct {
	*memoryKeys
	id  string
	err error
}

func (r recordedKeys) KEKID(context.Context) (string, error) { return r.id, r.err }

// writeKEKFile mounts a key the way a deployment does: readable by nobody but
// its owner.
func writeKEKFile(t *testing.T, hexKey string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "flotestro-kek")
	if err := os.WriteFile(path, []byte(hexKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The mode is set after the write, because a umask would take the bits off
	// the other way round.
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	return path
}

func testLocalProvider(t *testing.T) *LocalSealedProvider {
	t.Helper()
	local, err := NewLocalProvider(filepath.Join(t.TempDir(), KeysDir), "")
	if err != nil {
		t.Fatal(err)
	}
	return local
}

// A deployment may mount the key long before anything is migrated, so an
// installation that records no key encryption key is not asked for one: its
// keys are the files it has always had, and the mounted secret is not even
// looked at.
func TestAnInstallationThatRecordsNoKeyEncryptionKeyKeepsItsKeysInTheStateDirectory(t *testing.T) {
	ctx := context.Background()
	unreadable := filepath.Join(t.TempDir(), "flotestro-kek")
	if err := os.WriteFile(unreadable, []byte("not a key at all\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		source recordedKeys
		file   string
	}{
		{"no record at all", recordedKeys{memoryKeys: newMemoryKeys(), err: ErrNoRecord}, unreadable},
		{"a record naming no key", recordedKeys{memoryKeys: newMemoryKeys()}, unreadable},
		{"no file where the key would be", recordedKeys{memoryKeys: newMemoryKeys()}, filepath.Join(t.TempDir(), "absent")},
	} {
		t.Run(test.name, func(t *testing.T) {
			local := testLocalProvider(t)
			provider, err := SelectProvider(ctx, test.source, test.file, "", local)
			if err != nil {
				t.Fatalf("the start was refused: %v", err)
			}
			if provider != Provider(local) {
				t.Fatalf("the installation was given %s instead of its own keys", provider.Name())
			}
		})
	}
}

// Once the keys are rows, the key file is what opens them: starting without it
// is a refusal, not a fall back to the files in the state directory, which may
// still be lying there.
func TestARecordedKeyEncryptionKeyWithoutTheKeyFileRefusesTheStart(t *testing.T) {
	source := recordedKeys{memoryKeys: newMemoryKeys(), id: testKEK(t, testKEKHex).ID()}
	_, err := SelectProvider(context.Background(), source,
		filepath.Join(t.TempDir(), "absent"), "", testLocalProvider(t))
	if !refusedWith(err, CodeKEKFileMissing) {
		t.Fatalf("a start without the mounted key answered %v", err)
	}
}

// A key of another installation would open nothing, and the rows say so by
// name before anything is decrypted; the start says it here, where an operator
// still sees which key was expected.
func TestAKeyFileHoldingAnotherKeyRefusesTheStartAsAMismatch(t *testing.T) {
	source := recordedKeys{memoryKeys: newMemoryKeys(), id: testKEK(t, testKEKHex).ID()}
	_, err := SelectProvider(context.Background(), source,
		writeKEKFile(t, otherKEKHex), "", testLocalProvider(t))
	if !refusedWith(err, CodeKEKMismatch) {
		t.Fatalf("a start with the wrong key answered %v", err)
	}
}

// The recorded key and the mounted one agree: the installation reads its keys
// from the database, and the provider it gets is the one that opens the rows.
func TestTheRecordedKeyEncryptionKeyServesTheKeysFromTheDatabase(t *testing.T) {
	ctx := context.Background()
	kek := testKEK(t, testKEKHex)
	store := newMemoryKeys()
	seeded, err := NewDBProvider(ctx, store, kek)
	if err != nil {
		t.Fatal(err)
	}
	if err := seeded.GenerateNamed(ctx, "k-one"); err != nil {
		t.Fatal(err)
	}

	source := recordedKeys{memoryKeys: store, id: kek.ID()}
	provider, err := SelectProvider(ctx, source, writeKEKFile(t, testKEKHex), "", testLocalProvider(t))
	if err != nil {
		t.Fatalf("the start was refused: %v", err)
	}
	sealed, ok := provider.(*DBSealedProvider)
	if !ok {
		t.Fatalf("the installation was given %s", provider.Name())
	}
	if sealed.Name() != DBProviderName || sealed.KEKID() != kek.ID() {
		t.Fatalf("the provider is %s under %s", sealed.Name(), sealed.KEKID())
	}
	if err := sealed.RequireKey(ctx, "k-one"); err != nil {
		t.Fatalf("the key of the installation was not served: %v", err)
	}
}

// A rotation is the one moment an installation has two key encryption keys.
// Whichever of them the record names is the one this panel uses, so there is
// no order of the steps - rewrap first, move the file first - in which a
// restart leaves the panel unable to start.
func TestDuringARotationTheRecordSaysWhichOfTheTwoKeysIsUsed(t *testing.T) {
	ctx := context.Background()
	current := writeKEKFile(t, testKEKHex)
	next := writeKEKFile(t, otherKEKHex)

	// Before the rewrap: the rows are wrapped with the key in use, and the new
	// one lying beside it changes nothing.
	source := recordedKeys{memoryKeys: newMemoryKeys(), id: testKEK(t, testKEKHex).ID()}
	provider, err := SelectProvider(ctx, source, current, next, testLocalProvider(t))
	if err != nil {
		t.Fatalf("a panel with the new key beside the old was refused: %v", err)
	}
	if sealed, ok := provider.(*DBSealedProvider); !ok || sealed.KEKID() != testKEK(t, testKEKHex).ID() {
		t.Error("the panel did not use the key the record names")
	}

	// After the rewrap and before the files are moved: the record names the new
	// key, which is beside the old one. The panel starts on it.
	moved := recordedKeys{memoryKeys: newMemoryKeys(), id: testKEK(t, otherKEKHex).ID()}
	provider, err = SelectProvider(ctx, moved, current, next, testLocalProvider(t))
	if err != nil {
		t.Fatalf("a panel restarted between the rewrap and the move was refused: %v", err)
	}
	if sealed, ok := provider.(*DBSealedProvider); !ok || sealed.KEKID() != testKEK(t, otherKEKHex).ID() {
		t.Error("the panel did not follow the record to the new key")
	}

	// It is not a fallback to whatever opens: a third key beside the one in use
	// is refused like any other stranger, and the refusal names the key in use.
	stranger := writeKEKFile(t, strangerKEKHex)
	_, err = SelectProvider(ctx, moved, current, stranger, testLocalProvider(t))
	if !refusedWith(err, CodeKEKMismatch) {
		t.Errorf("a key the record does not name answered %v", err)
	}

	// And a rotation that was never started leaves no file there, which is the
	// ordinary state and not a refusal.
	_, err = SelectProvider(ctx, source, current, filepath.Join(t.TempDir(), "absent"), testLocalProvider(t))
	if err != nil {
		t.Errorf("a panel with no rotation under way was refused: %v", err)
	}
}
