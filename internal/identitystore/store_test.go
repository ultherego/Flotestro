package identitystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ultherego/flotestro/internal/pki"
)

const testHost = "3f2a9c1e-0000-4000-8000-000000000001"

// generation wystawia komplet materialu przez to samo CA, ktorego uzywa panel.
func generation(t *testing.T, ca *pki.CA, hostID string) Generation {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: hostID}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	wydany, err := ca.SignAgentCSR(csrPEM, hostID)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return Generation{
		KeyPEM:         pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		CertificatePEM: wydany.PEM,
		TrustPEM:       ca.PEM,
	}
}

func storeWithIdentity(t *testing.T) (*Store, *pki.CA, string) {
	t.Helper()
	caDir := t.TempDir()
	ca, err := pki.EnsureCA(caDir)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	store := New(stateDir)
	if _, err := store.Commit(generation(t, ca, testHost)); err != nil {
		t.Fatalf("first generation: %v", err)
	}
	return store, ca, stateDir
}

func TestACommitGivesACompleteIdentity(t *testing.T) {
	store, _, _ := storeWithIdentity(t)
	identity, err := store.Current()
	if err != nil {
		t.Fatalf("reading the identity: %v", err)
	}
	if identity.HostID != testHost {
		t.Fatalf("host_id = %q", identity.HostID)
	}
	// The private key must not be readable by anyone but its owner.
	info, err := os.Stat(filepath.Join(identity.Dir, KeyName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key permissions = %04o", info.Mode().Perm())
	}
}

func TestARenewalLeavesThePreviousGeneration(t *testing.T) {
	store, ca, _ := storeWithIdentity(t)
	first, err := store.Current()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(generation(t, ca, testHost)); err != nil {
		t.Fatalf("second generation: %v", err)
	}
	second, err := store.Current()
	if err != nil {
		t.Fatal(err)
	}
	if second.Dir == first.Dir {
		t.Fatal("the renewal did not change the generation")
	}
	// The previous one stays: when the new one turns out to be bad, there has to be something to go back to.
	previous, err := store.Previous()
	if err != nil {
		t.Fatalf("no previous generation: %v", err)
	}
	if previous.Dir != first.Dir {
		t.Fatalf("previous = %s, want %s", previous.Dir, first.Dir)
	}
}

func TestOldGenerationsAreCleanedUp(t *testing.T) {
	store, ca, _ := storeWithIdentity(t)
	for i := 0; i < 3; i++ {
		if _, err := store.Commit(generation(t, ca, testHost)); err != nil {
			t.Fatalf("generation %d: %v", i, err)
		}
	}
	names, err := store.generations()
	if err != nil {
		t.Fatal(err)
	}
	// The private key is not to lie on disk longer than it is needed.
	if len(names) != GenerationsKept {
		t.Fatalf("generations on disk = %d (%v)", len(names), names)
	}
	if _, err := store.Current(); err != nil {
		t.Fatalf("the current one after cleaning: %v", err)
	}
}

// TestAnInterruptedWriteDoesNotDestroyTheIdentity replays the failure points
// from the document.
//
// Each of them once ended with a host that has the key of one pair and the
// certificate of another - that is, a host to be recovered by hand.
func TestAnInterruptedWriteDoesNotDestroyTheIdentity(t *testing.T) {
	store, ca, _ := storeWithIdentity(t)
	first, err := store.Current()
	if err != nil {
		t.Fatal(err)
	}
	generations := filepath.Join(store.Dir(), GenerationsDir)

	t.Run("interrupted after writing the key", func(t *testing.T) {
		halfWritten, err := os.MkdirTemp(generations, newPrefix)
		if err != nil {
			t.Fatal(err)
		}
		newOne := generation(t, ca, testHost)
		if err := os.WriteFile(filepath.Join(halfWritten, KeyName), newOne.KeyPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		current, err := store.Current()
		if err != nil || current.Dir != first.Dir {
			t.Fatalf("current = %+v, error = %v", current, err)
		}
		if err := store.Clean(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(halfWritten); !os.IsNotExist(err) {
			t.Fatal("a half-written generation stayed on disk")
		}
	})

	t.Run("interrupted before the switch", func(t *testing.T) {
		newOne := generation(t, ca, testHost)
		serial, err := serialNumber(newOne.CertificatePEM)
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(generations, serial)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for name, data := range map[string][]byte{
			KeyName: newOne.KeyPEM, CertificateName: newOne.CertificatePEM,
			TrustName: newOne.TrustPEM,
		} {
			if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		// The generation lies complete, but nobody switched to it: the host
		// is to keep running on the previous one.
		current, err := store.Current()
		if err != nil || current.Dir != first.Dir {
			t.Fatalf("current = %+v, error = %v", current, err)
		}
		_ = os.RemoveAll(dir)
	})

	t.Run("interrupted after creating the temporary symlink", func(t *testing.T) {
		next := filepath.Join(store.Dir(), nextName)
		if err := os.Symlink(filepath.Join(GenerationsDir, "no-such-one"), next); err != nil {
			t.Fatal(err)
		}
		current, err := store.Current()
		if err != nil || current.Dir != first.Dir {
			t.Fatalf("current = %+v, error = %v", current, err)
		}
		if err := store.Clean(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(next); !os.IsNotExist(err) {
			t.Fatal("the temporary symlink stayed after the cleanup")
		}
	})
}

func TestAMismatchedPairIsRejected(t *testing.T) {
	store, ca, _ := storeWithIdentity(t)
	first, err := store.Current()
	if err != nil {
		t.Fatal(err)
	}
	pierwszaGeneracja := generation(t, ca, testHost)
	drugaGeneracja := generation(t, ca, testHost)
	pomieszana := Generation{
		KeyPEM:         pierwszaGeneracja.KeyPEM,
		CertificatePEM: drugaGeneracja.CertificatePEM,
		TrustPEM:       ca.PEM,
	}
	if _, err := store.Commit(pomieszana); !errors.Is(err, ErrKeyPair) {
		t.Fatalf("blad = %v, chcemy %v", err, ErrKeyPair)
	}
	// Odrzucenie musi nastapic przed jakakolwiek zmiana: host zostaje na tym,
	// co dzialalo.
	current, err := store.Current()
	if err != nil || current.Dir != first.Dir {
		t.Fatalf("current = %+v, blad = %v", current, err)
	}
}

func TestACertificateFromAnotherCAIsRejected(t *testing.T) {
	store, _, _ := storeWithIdentity(t)
	obceCA, err := pki.EnsureCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	obca := generation(t, obceCA, testHost)
	nasze, err := store.Current()
	if err != nil {
		t.Fatal(err)
	}
	obca.TrustPEM = nasze.TrustPEM
	if _, err := store.Commit(obca); !errors.Is(err, ErrChain) {
		t.Fatalf("error = %v, want %v", err, ErrChain)
	}
}

func TestMigrationFromTheOldLayout(t *testing.T) {
	caDir := t.TempDir()
	ca, err := pki.EnsureCA(caDir)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	old := generation(t, ca, testHost)
	keyPath := filepath.Join(stateDir, "agent.key")
	certPath := filepath.Join(stateDir, "agent.pem")
	caPath := filepath.Join(stateDir, "ca.pem")
	for path, data := range map[string][]byte{
		keyPath: old.KeyPEM, certPath: old.CertificatePEM, caPath: old.TrustPEM,
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	store := New(stateDir)
	moved, err := store.Migrate(keyPath, certPath, caPath)
	if err != nil || !moved {
		t.Fatalf("migration = %v, error = %v", moved, err)
	}
	identity, err := store.Current()
	if err != nil || identity.HostID != testHost {
		t.Fatalf("the identity after migration = %+v, error = %v", identity, err)
	}
	// The originals stay: the previous version of the agent has something to
	// start from.
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("the old key disappeared: %v", err)
	}
	// A second migration does nothing - the identity is already in the store.
	again, err := store.Migrate(keyPath, certPath, caPath)
	if err != nil || again {
		t.Fatalf("the second migration = %v, error = %v", again, err)
	}
}
