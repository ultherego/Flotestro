//go:build integration

package integration

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/cryptostate"
	"github.com/ultherego/flotestro/internal/secrets"
)

// The keys of an installation lie in the database wrapped with a key the
// database does not hold. This exercises that table against the real schema:
// what a replica writes, another replica reads, and the rules that keep two
// keys from wearing one name are the database's, not the caller's.
func TestTheKeysOfTheInstallationLieInTheDatabaseWrappedWithAKeyItDoesNotHold(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store := cryptostate.NewPostgres(h.database(ctx))

	kek, err := cryptostate.ParseKEK(
		"3f1a9c0e5b7d2648a0c3e5f7091b2d4e6a8c0e2f4a6b8d0f1234567890abcdef", "test")
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := cryptostate.ParseKEK(
		"8e2b4d6f0a1c3e5079b1d3f5a7c9e10b2d4f60718293a4b5c6d7e8f901234567", "test")
	if err != nil {
		t.Fatal(err)
	}

	// Names of this test only, so that a panel running against the same
	// database is not disturbed by them.
	const keyID = "k-integration-wrapped"
	const otherID = "k-integration-second"
	cleanup := func() {
		_ = store.DeleteWrappedKey(context.WithoutCancel(ctx), keyID)
		_ = store.DeleteWrappedKey(context.WithoutCancel(ctx), otherID)
	}
	cleanup()
	t.Cleanup(cleanup)

	material := bytes.Repeat([]byte{0x2a}, secrets.KeyLength)
	row, err := kek.Seal(keyID, cryptostate.PurposeSecrets, material)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutWrappedKey(ctx, row); err != nil {
		t.Fatalf("the key could not be written: %v", err)
	}

	stored, err := store.WrappedKey(ctx, keyID)
	if err != nil {
		t.Fatalf("the key could not be read back: %v", err)
	}
	if stored.KEKID != kek.ID() || stored.Purpose != cryptostate.PurposeSecrets {
		t.Errorf("the row came back as %s/%s", stored.KEKID, stored.Purpose)
	}
	if stored.CreatedAt.IsZero() || stored.RetiredAt != nil {
		t.Errorf("a key just written is %v and retired at %v", stored.CreatedAt, stored.RetiredAt)
	}
	opened, err := kek.Open(stored)
	if err != nil || !bytes.Equal(opened, material) {
		t.Fatalf("the key did not survive the database: %v", err)
	}

	// The key encryption key is the whole of the protection: whoever holds the
	// rows and not the key holds nothing.
	if _, err := stranger.Open(stored); err == nil {
		t.Error("a row opened under a key encryption key it was not wrapped with")
	}

	// The name is the database's to refuse, not the caller's to check first.
	second, err := kek.Seal(keyID, cryptostate.PurposeSecrets, bytes.Repeat([]byte{1}, secrets.KeyLength))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutWrappedKey(ctx, second); !errors.Is(err, cryptostate.ErrKeyExists) {
		t.Errorf("a second key under the same name answered %v", err)
	}

	// Retiring says the key seals nothing new; it does not take it away, and
	// saying it twice does not move the moment it happened.
	if err := store.RetireWrappedKey(ctx, keyID); err != nil {
		t.Fatal(err)
	}
	retired, err := store.WrappedKey(ctx, keyID)
	if err != nil || retired.RetiredAt == nil {
		t.Fatalf("the key was not retired: %v", err)
	}
	if err := store.RetireWrappedKey(ctx, keyID); err != nil {
		t.Fatal(err)
	}
	again, err := store.WrappedKey(ctx, keyID)
	if err != nil {
		t.Fatal(err)
	}
	if !again.RetiredAt.Equal(*retired.RetiredAt) {
		t.Error("retiring a key twice moved the moment it was retired at")
	}

	// A provider reads every key of its purpose, retired ones included: a
	// retired key still opens what it sealed.
	live, err := kek.Seal(otherID, cryptostate.PurposeSecrets, bytes.Repeat([]byte{3}, secrets.KeyLength))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutWrappedKey(ctx, live); err != nil {
		t.Fatal(err)
	}
	keys, err := store.WrappedKeys(ctx, cryptostate.PurposeSecrets)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, key := range keys {
		found[key.KeyID] = true
		if _, err := kek.Open(key); err != nil && key.KEKID == kek.ID() {
			t.Errorf("the key %s does not open: %v", key.KeyID, err)
		}
	}
	if !found[keyID] || !found[otherID] {
		t.Errorf("the keys of the installation are %v", found)
	}

	// The other purposes are separate sets; a helper signing key is not among
	// the keys of the secret store.
	if _, err := store.WrappedKeys(ctx, cryptostate.PurposeHelperSigning); err != nil {
		t.Errorf("the helper signing keys could not be read: %v", err)
	}

	// Anything else is refused by the database rather than stored and found
	// unusable later.
	nonsense := live
	nonsense.KeyID = "k-integration-nonsense"
	nonsense.Purpose = "whatever-the-caller-felt-like"
	if err := store.PutWrappedKey(ctx, nonsense); err == nil {
		_ = store.DeleteWrappedKey(context.WithoutCancel(ctx), nonsense.KeyID)
		t.Error("a key kept for no known purpose was written")
	}

	if err := store.DeleteWrappedKey(ctx, keyID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.WrappedKey(ctx, keyID); !errors.Is(err, cryptostate.ErrWrappedKeyMissing) {
		t.Errorf("a deleted key answered %v", err)
	}
	if err := store.DeleteWrappedKey(ctx, keyID); !errors.Is(err, cryptostate.ErrWrappedKeyMissing) {
		t.Errorf("deleting a key twice answered %v", err)
	}
}

// The installation record says which key encryption key its rows are wrapped
// with, and an installation that has not moved its keys yet says nothing.
func TestTheRecordNamesTheKeyEncryptionKeyOrSaysNothingYet(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool := h.database(ctx)
	store := cryptostate.NewPostgres(pool)

	before, err := store.KEKID(ctx)
	if err != nil {
		t.Fatalf("the recorded key encryption key could not be read: %v", err)
	}
	if before != "" {
		// This installation has moved its keys into the database, and the panel
		// running against it would refuse to start on a record naming a key
		// nobody holds. What the column says is then checked and not changed.
		if !strings.HasPrefix(before, "kek-") || len(before) != 20 {
			t.Errorf("the record names the key encryption key %q, which is not the shape of one", before)
		}
		var rows int
		if err := pool.QueryRow(ctx, `select count(*) from crypto_wrapped_keys`).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		if rows == 0 {
			t.Error("the record names a key encryption key and the installation holds no wrapped key")
		}
		return
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(context.WithoutCancel(ctx),
			`update crypto_installation_state set kek_id = null where singleton`)
	})
	if err := store.SetKEKID(ctx, "kek-0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	after, err := store.KEKID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after != "kek-0123456789abcdef" {
		t.Errorf("the record names %q", after)
	}
}
