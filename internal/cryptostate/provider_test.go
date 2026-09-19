package cryptostate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ultherego/flotestro/internal/secrets"
)

// The built-in provider keeps every key as a file of its own, unreadable
// by anyone but the service, and finds them again at the next start.
func TestTheLocalProviderKeepsKeysAsFiles(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), KeysDir)
	provider, err := NewLocalProvider(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if provider.HasMaterial() {
		t.Fatal("an empty directory holds material")
	}
	id, err := provider.Generate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateKeyID(id); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, id+".key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %04o", info.Mode().Perm())
	}
	provider.SetActive(id)
	if err := provider.Health(ctx); err != nil {
		t.Fatal(err)
	}

	envelope, err := secrets.Seal(ctx, provider, []byte("value"), []byte("row"))
	if err != nil {
		t.Fatal(err)
	}
	// A second process reads the same directory and opens the envelope.
	reloaded, err := NewLocalProvider(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.KeyIDs(); len(got) != 1 || got[0] != id {
		t.Fatalf("keys after the reload = %v", got)
	}
	reloaded.SetActive(id)
	if value, err := envelope.Open(ctx, reloaded, []byte("row")); err != nil || string(value) != "value" {
		t.Fatalf("open after the reload: %q, %v", value, err)
	}
	// A wrapped key under another name does not unwrap: the name is part
	// of what the wrapping authenticates.
	if err := reloaded.GenerateNamed(ctx, "k-other"); err != nil {
		t.Fatal(err)
	}
	if _, err := reloaded.Unwrap(ctx, "k-other", envelope.WrappedDEK); err == nil {
		t.Error("a wrapped key unwrapped under another key")
	}
	if err := reloaded.GenerateNamed(ctx, "k-other"); err == nil {
		t.Error("a key was generated over an existing one")
	}

	// The file of the active key removed from under a running panel is
	// caught by the health check.
	if err := os.Remove(filepath.Join(dir, id+".key")); err != nil {
		t.Fatal(err)
	}
	if err := reloaded.Health(ctx); !errors.Is(err, secrets.ErrKeyUnavailable) {
		t.Errorf("health with the key file gone = %v", err)
	}
}

// Adopting the same material under the same name twice is fine; different
// material under a taken name is refused.
func TestAdoptionIsRepeatableAndRefusesDifferentMaterial(t *testing.T) {
	ctx := context.Background()
	provider, err := NewLocalProvider(filepath.Join(t.TempDir(), KeysDir), "")
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, secrets.KeyLength)
	for i := range key {
		key[i] = byte(i)
	}
	if err := provider.Adopt(ctx, secrets.LegacyKeyID, key); err != nil {
		t.Fatal(err)
	}
	if err := provider.Adopt(ctx, secrets.LegacyKeyID, key); err != nil {
		t.Fatalf("the same material again: %v", err)
	}
	other := append([]byte(nil), key...)
	other[0] ^= 0xff
	if err := provider.Adopt(ctx, secrets.LegacyKeyID, other); err == nil {
		t.Fatal("different material was adopted under a taken name")
	}
	if _, ok := provider.LegacyCipher(); !ok {
		t.Fatal("the legacy key is not offered for the rows of the first form")
	}
	if err := provider.Adopt(ctx, "Not A Key", key); err == nil {
		t.Fatal("an invalid key name was accepted")
	}
}

// A key may come from a systemd credential rather than a file of the state
// directory; it is read, registered under the credential's name and never
// written.
func TestAKeyMayComeFromASystemdCredential(t *testing.T) {
	ctx := context.Background()
	credentials := t.TempDir()
	key := make([]byte, secrets.KeyLength)
	for i := range key {
		key[i] = byte(255 - i)
	}
	if err := os.WriteFile(filepath.Join(credentials, "k-cred"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", credentials)
	dir := filepath.Join(t.TempDir(), KeysDir)
	provider, err := NewLocalProvider(dir, "k-cred")
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.RequireKey(ctx, "k-cred"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "k-cred.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the credential was copied into the state directory")
	}
	provider.SetActive("k-cred")
	if err := provider.Health(ctx); err != nil {
		t.Fatal(err)
	}
	// Without the directory systemd passes, the setting is a misconfiguration.
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if _, err := NewLocalProvider(dir, "k-cred"); err == nil {
		t.Fatal("a credential without a credentials directory was accepted")
	}
}
