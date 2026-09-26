package helpercap

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newStore(t *testing.T) TrustStore {
	t.Helper()
	dir := t.TempDir()
	return TrustStore{Dir: filepath.Join(dir, "trust.d"), HostIDPath: filepath.Join(dir, "host-id")}
}

func newSigner(t *testing.T) *Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return NewSignerFromKey(private)
}

// The first bundle on a host without keys is taken on trust and writes the
// host identity and the keys; the same bundle again changes nothing.
func TestFirstBundleBootstrapsTheKeyring(t *testing.T) {
	store := newStore(t)
	signer := newSigner(t)
	now := time.Unix(1_800_000_000, 0)

	update, err := store.Apply(signer.TrustBundle("host-1", now))
	if err != nil {
		t.Fatal(err)
	}
	if !update.Bootstrap || !update.Changed || update.HostID != "host-1" ||
		len(update.KeyIDs) != 1 || update.KeyIDs[0] != signer.KeyID() {
		t.Fatalf("bootstrap = %+v", update)
	}
	hostID, err := store.HostID()
	if err != nil || hostID != "host-1" {
		t.Fatalf("host id = %q, %v", hostID, err)
	}
	ring, skipped, err := store.Keyring()
	if err != nil || len(skipped) != 0 {
		t.Fatalf("keyring: %v, skipped %v", err, skipped)
	}
	if _, ok := ring.Lookup(signer.KeyID()); !ok {
		t.Fatal("the key was not written")
	}
	again, err := store.Apply(signer.TrustBundle("host-1", now))
	if err != nil {
		t.Fatal(err)
	}
	if again.Changed || again.Bootstrap {
		t.Errorf("the repeated bundle changed something: %+v", again)
	}
}

// Once a keyring exists, a bundle signed by a stranger is refused, a damaged
// one is refused, and a bundle for another host is refused unless the panel
// that is trusted signed it.
func TestLaterBundlesMustBeSignedByATrustedKey(t *testing.T) {
	store := newStore(t)
	signer := newSigner(t)
	now := time.Unix(1_800_000_000, 0)
	if _, err := store.Apply(signer.TrustBundle("host-1", now)); err != nil {
		t.Fatal(err)
	}

	stranger := newSigner(t)
	_, err := store.Apply(stranger.TrustBundle("host-1", now))
	if CodeOf(err) != ErrorTrustUntrusted {
		t.Fatalf("a stranger's bundle: %v", err)
	}
	ring, _, _ := store.Keyring()
	if _, ok := ring.Lookup(stranger.KeyID()); ok {
		t.Fatal("the stranger's key was written")
	}

	damaged := signer.TrustBundle("host-1", now)
	damaged.Keys[0].PublicKey[0] ^= 1
	if _, err := store.Apply(damaged); CodeOf(err) != ErrorTrustInvalid {
		t.Fatalf("a damaged bundle: %v", err)
	}
	renamed := signer.TrustBundle("host-1", now)
	renamed.HostId = "host-2"
	if _, err := store.Apply(renamed); CodeOf(err) != ErrorTrustUntrusted {
		t.Fatalf("a bundle altered after signing: %v", err)
	}

	// The trusted panel may move the identity: a re-enrollment.
	moved, err := store.Apply(signer.TrustBundle("host-2", now))
	if err != nil || moved.HostID != "host-2" || !moved.Changed {
		t.Fatalf("a re-enrollment signed by the trusted key: %+v, %v", moved, err)
	}
}

// A rotation: the bundle signed by the retired key introduces the new key; a
// bundle with the new key alone, signed by the new key, retires the old one.
func TestRotationOverlapsTwoKeys(t *testing.T) {
	store := newStore(t)
	old := newSigner(t)
	now := time.Unix(1_800_000_000, 0)
	if _, err := store.Apply(old.TrustBundle("host-1", now)); err != nil {
		t.Fatal(err)
	}

	fresh := newSigner(t)
	fresh.previous = old
	overlap, err := store.Apply(fresh.TrustBundle("host-1", now))
	if err != nil {
		t.Fatalf("the overlap bundle: %v", err)
	}
	if len(overlap.KeyIDs) != 2 {
		t.Fatalf("the overlap keyring = %v", overlap.KeyIDs)
	}

	fresh.previous = nil
	retired, err := store.Apply(fresh.TrustBundle("host-1", now))
	if err != nil {
		t.Fatalf("the bundle after the rotation: %v", err)
	}
	if len(retired.KeyIDs) != 1 || retired.KeyIDs[0] != fresh.KeyID() {
		t.Fatalf("the keyring after the rotation = %v", retired.KeyIDs)
	}
	if _, err := os.Stat(filepath.Join(store.Dir, old.KeyID()+".pub")); !os.IsNotExist(err) {
		t.Error("the retired key file is still there")
	}
	// The retired key signs nothing any more.
	if _, err := store.Apply(old.TrustBundle("host-1", now)); CodeOf(err) != ErrorTrustUntrusted {
		t.Errorf("the retired key was still trusted: %v", err)
	}
}

// A host whose keys went away but whose identity stays is not taken back on
// trust: an emptied keyring must not be an opening for another panel.
func TestEmptyKeyringWithAnIdentityIsNotBootstrapped(t *testing.T) {
	store := newStore(t)
	if err := os.MkdirAll(filepath.Dir(store.HostIDPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.HostIDPath, []byte("host-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	signer := newSigner(t)
	for _, host := range []string{"host-2", "host-1"} {
		if _, err := store.Apply(signer.TrustBundle(host, time.Now())); CodeOf(err) != ErrorTrustUntrusted {
			t.Fatalf("a bootstrap of %s over an existing identity: %v", host, err)
		}
	}
	if err := os.Remove(store.HostIDPath); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(signer.TrustBundle("host-1", time.Now())); err != nil {
		t.Fatalf("a bootstrap after the identity was removed: %v", err)
	}
}

// A key file that is not a key, or a symbolic link, is skipped and named;
// the usable keys are still honoured.
func TestUnusableKeyFilesAreSkipped(t *testing.T) {
	store := newStore(t)
	signer := newSigner(t)
	if _, err := store.Apply(signer.TrustBundle("host-1", time.Now())); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.Dir, "junk.pub"), []byte("not a key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/hostname", filepath.Join(store.Dir, "link.pub")); err != nil {
		t.Fatal(err)
	}
	ring, skipped, err := store.Keyring()
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) != 2 {
		t.Errorf("skipped = %v", skipped)
	}
	if _, ok := ring.Lookup(signer.KeyID()); !ok {
		t.Error("the good key was not honoured")
	}
}

// The signing key file: generated once with mode 0600, read back with the
// same identifier, and the retired key beside it loaded for the overlap.
func TestSignerKeyFileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "helper-signing.key")
	first, created, err := LoadOrGenerateSigner(path)
	if err != nil || !created {
		t.Fatalf("generate: %v, created %v", err, created)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v, %v", info.Mode(), err)
	}
	second, created, err := LoadOrGenerateSigner(path)
	if err != nil || created || second.KeyID() != first.KeyID() {
		t.Fatalf("load: %v, created %v, id %s vs %s", err, created, second.KeyID(), first.KeyID())
	}
	if len(second.TrustedKeys()) != 1 {
		t.Fatalf("trusted keys = %d", len(second.TrustedKeys()))
	}

	// A rotation: the active key becomes the previous one.
	if err := os.Rename(path, previousKeyPath(path)); err != nil {
		t.Fatal(err)
	}
	rotated, created, err := LoadOrGenerateSigner(path)
	if err != nil || !created {
		t.Fatalf("rotate: %v, created %v", err, created)
	}
	if rotated.KeyID() == first.KeyID() || rotated.previous == nil || rotated.previous.KeyID() != first.KeyID() {
		t.Fatalf("the rotation did not keep the previous key: %s, previous %v", rotated.KeyID(), rotated.previous)
	}
	bundle := rotated.TrustBundle("host-1", time.Now())
	if bundle.GetSignedByKeyId() != first.KeyID() || len(bundle.GetKeys()) != 2 {
		t.Errorf("the overlap bundle is signed by %s with %d keys", bundle.GetSignedByKeyId(), len(bundle.GetKeys()))
	}
	capability, _, err := rotated.Issue(Mint{HostID: "h", TaskID: "t", ActionType: "unit.restart", PayloadSHA256: make([]byte, 32)})
	if err != nil || capability.GetKeyId() != rotated.KeyID() {
		t.Errorf("capabilities are signed by %s, want the active key %s (%v)", capability.GetKeyId(), rotated.KeyID(), err)
	}
}

// The replay store forgets a nonce only once its capability is long past.
func TestReplayStoreSweepsExpiredRecords(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "replay")
	store, err := OpenReplayStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Unix(1_800_000_000, 0)
	store.now = func() time.Time { return now }
	nonce := make([]byte, NonceSize)
	nonce[0] = 7
	if _, err := store.Reserve(nonce, now.Add(time.Minute).Unix(), "task-1", "digest-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reserve(nonce, now.Add(time.Minute).Unix(), "task-2", "digest-1"); CodeOf(err) != ErrorCapabilityReplay {
		t.Fatalf("a second task consumed the nonce: %v", err)
	}
	if _, err := store.Reserve(nonce[:16], now.Unix(), "task-1", "digest-1"); CodeOf(err) != ErrorInvalidNonce {
		t.Fatalf("a short nonce: %v", err)
	}
	// Two records for one reservation: the nonce belongs to a task and a life
	// of the helper, and the request under it has a state of its own.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatalf("records = %d", len(entries))
	}
	now = now.Add(2 * time.Minute)
	store.Sweep()
	entries, _ = os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("the expired record was kept")
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("the replay directory has mode %v", info.Mode())
	}
}
