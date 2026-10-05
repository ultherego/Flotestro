package cryptostate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/issuer"
	"github.com/ultherego/flotestro/internal/pki"
	"github.com/ultherego/flotestro/internal/secrets"
)

// memoryStorage is the database of the tests: one record, the facts the
// test sets, and a lock a second guard has to wait for.
type memoryStorage struct {
	mu       sync.Mutex
	lock     sync.Mutex
	record   *Record
	facts    Facts
	assigned map[string]string
	inserts  int
	// liveKeys are the keys the live secret versions were sealed with.
	liveKeys []string
}

func (m *memoryStorage) UpdateIfRevision(ctx context.Context, record Record, expected int64) error {
	m.mu.Lock()
	if m.record != nil && m.record.Revision != expected {
		m.mu.Unlock()
		return ErrRevisionMoved
	}
	m.mu.Unlock()
	return m.Update(ctx, record)
}

func (m *memoryStorage) LiveKeyIDs(context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.liveKeys...), nil
}

func (m *memoryStorage) Lock(context.Context) (func(), error) {
	m.lock.Lock()
	return m.lock.Unlock, nil
}

func (m *memoryStorage) Load(context.Context) (*Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.record == nil {
		return nil, ErrNoRecord
	}
	copied := *m.record
	return &copied, nil
}

func (m *memoryStorage) Insert(_ context.Context, record Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.record != nil {
		return errors.New("duplicate key value violates unique constraint")
	}
	record.InitializedAt = time.Now()
	record.UpdatedAt = record.InitializedAt
	record.Revision = 1
	m.record = &record
	m.inserts++
	return nil
}

func (m *memoryStorage) Update(_ context.Context, record Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.record == nil || m.record.InstallationID != record.InstallationID {
		return errors.New("the installation record is gone")
	}
	record.Revision = m.record.Revision + 1
	record.InitializedAt = m.record.InitializedAt
	record.UpdatedAt = time.Now()
	m.record = &record
	return nil
}

func (m *memoryStorage) Facts(context.Context) (Facts, error) { return m.facts, nil }

func (m *memoryStorage) AssignIssuer(_ context.Context, subject, serial, issuerID string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.assigned == nil {
		m.assigned = map[string]string{}
	}
	m.assigned[subject+" "+serial] = issuerID
	return 0, nil
}

// fakeProvider keeps its keys in memory and lets a test take one away.
type fakeProvider struct {
	mu     sync.Mutex
	active string
	keys   map[string]*secrets.Cipher
	raw    map[string][]byte
	// adopts counts the calls to Adopt, which is the one that keeps a key
	// where the installation will find it again.
	adopts int
}

func newFakeProvider() *fakeProvider {
	return &fakeProvider{keys: map[string]*secrets.Cipher{}, raw: map[string][]byte{}}
}

func (f *fakeProvider) Name() string { return "fake" }

func (f *fakeProvider) KeyIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	ids := make([]string, 0, len(f.keys))
	for id := range f.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (f *fakeProvider) HasMaterial() bool { return len(f.KeyIDs()) > 0 }

func (f *fakeProvider) RequireKey(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.keys[id]; !ok {
		return fmt.Errorf("%w: %s", secrets.ErrKeyUnavailable, id)
	}
	return nil
}

func (f *fakeProvider) Generate(ctx context.Context) (string, error) {
	id := fmt.Sprintf("k-%d", len(f.KeyIDs())+1)
	return id, f.GenerateNamed(ctx, id)
}

func (f *fakeProvider) GenerateNamed(ctx context.Context, id string) error {
	if err := f.RequireKey(ctx, id); err == nil {
		return fmt.Errorf("the key %s already exists", id)
	}
	key := make([]byte, secrets.KeyLength)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return err
	}
	return f.Adopt(ctx, id, key)
}

func (f *fakeProvider) Adopt(_ context.Context, id string, key []byte) error {
	f.mu.Lock()
	f.adopts++
	f.mu.Unlock()
	return f.keep(id, key)
}

// keep is what both Adopt and Offer do to this fake's maps.
func (f *fakeProvider) keep(id string, key []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if existing, ok := f.raw[id]; ok {
		if string(existing) != string(key) {
			return fmt.Errorf("the key %s already exists with different material", id)
		}
		return nil
	}
	cipher, err := secrets.NewCipher(key)
	if err != nil {
		return err
	}
	f.keys[id] = cipher
	f.raw[id] = key
	return nil
}

// Offer keeps the key in the maps and nothing else, and - unlike Adopt - does
// not count. The real providers differ in that Adopt writes a file or a row;
// what a test here can hold them to is that a start which refuses never got as
// far as Adopt.
func (f *fakeProvider) Offer(id string, key []byte) error {
	return f.keep(id, key)
}

func (f *fakeProvider) SetActive(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.active = id
}

func (f *fakeProvider) ActiveKeyID(context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.active == "" {
		return "", errors.New("no active key")
	}
	return f.active, nil
}

func (f *fakeProvider) Wrap(_ context.Context, id string, dek []byte) ([]byte, error) {
	f.mu.Lock()
	cipher, ok := f.keys[id]
	f.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", secrets.ErrKeyUnavailable, id)
	}
	nonce, ciphertext, err := cipher.Encrypt(dek, id, 0)
	if err != nil {
		return nil, err
	}
	return append(nonce, ciphertext...), nil
}

func (f *fakeProvider) Unwrap(_ context.Context, id string, wrapped []byte) ([]byte, error) {
	f.mu.Lock()
	cipher, ok := f.keys[id]
	f.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", secrets.ErrKeyUnavailable, id)
	}
	size := cipher.NonceSize()
	return cipher.Decrypt(wrapped[:size], wrapped[size:], id, 0)
}

func (f *fakeProvider) Health(ctx context.Context) error {
	id, err := f.ActiveKeyID(ctx)
	if err != nil {
		return err
	}
	return f.RequireKey(ctx, id)
}

func (f *fakeProvider) LegacyCipher() (*secrets.Cipher, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cipher, ok := f.keys[secrets.LegacyKeyID]
	return cipher, ok
}

// forget takes a key away, as a deleted file would.
func (f *fakeProvider) forget(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.keys, id)
	delete(f.raw, id)
}

// replace puts different material under a name: a key of the right size
// that is not the installation's.
func (f *fakeProvider) replace(t *testing.T, id string) {
	t.Helper()
	f.forget(id)
	if err := f.GenerateNamed(context.Background(), id); err != nil {
		t.Fatal(err)
	}
}

type lab struct {
	storage  *memoryStorage
	provider *fakeProvider
	dir      string
	legacy   string
	// probe stands in for the secret store's answer about the key an
	// adoption is about to trust. Nil is the shape of every case that is
	// not about the store, and skips the question.
	probe func(context.Context, secrets.KeyProvider) error
}

func newLab(t *testing.T) *lab {
	t.Helper()
	dir := t.TempDir()
	return &lab{
		storage: &memoryStorage{}, provider: newFakeProvider(),
		dir: dir, legacy: filepath.Join(dir, "secrets.key"),
	}
}

func (l *lab) options() Options {
	return Options{Storage: l.storage, Provider: l.provider, CADir: l.dir, LegacyKeyPath: l.legacy,
		SecretProbe: l.probe}
}

func (l *lab) open(t *testing.T) *Runtime {
	t.Helper()
	runtime, err := Open(context.Background(), l.options())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return runtime
}

func (l *lab) openFatal(t *testing.T, code string) *FatalError {
	t.Helper()
	_, err := Open(context.Background(), l.options())
	var fatal *FatalError
	if !errors.As(err, &fatal) {
		t.Fatalf("open = %v, want a fatal %s", err, code)
	}
	if fatal.Code != code {
		t.Fatalf("open failed with %s (%s), want %s", fatal.Code, fatal.Reason, code)
	}
	return fatal
}

// The first row of the startup table: no record, an empty database and no
// files.
func TestAnEmptyInstallationIsInitialised(t *testing.T) {
	l := newLab(t)
	runtime := l.open(t)
	record := runtime.Record()
	if record.InstallationID == "" || record.ActiveKeyID == "" || record.IssuerID == "" {
		t.Fatalf("record = %+v", record)
	}
	if !runtime.Report(context.Background()).Initialised {
		t.Error("the first start did not report itself as an initialisation")
	}
	if len(l.provider.KeyIDs()) != 1 || l.provider.KeyIDs()[0] != record.ActiveKeyID {
		t.Errorf("keys = %v, active = %s", l.provider.KeyIDs(), record.ActiveKeyID)
	}
	ca, err := pki.Open(l.dir)
	if err != nil {
		t.Fatal(err)
	}
	if ca.IssuerID() != record.IssuerID || ca.FingerprintHex() != record.IssuerFingerprint {
		t.Error("the record does not name the CA on disk")
	}
	if l.storage.assigned[ca.Certificate.Subject.CommonName+" "+ca.Certificate.SerialNumber.String()] != ca.IssuerID() {
		t.Error("the certificates of the CA were not assigned its issuer id")
	}

	// The second row: the record and the key are there; the self-test
	// passes and the panel starts without making anything.
	again := l.open(t)
	if again.Record().InstallationID != record.InstallationID {
		t.Fatal("the second start made another installation")
	}
	if l.storage.inserts != 1 || len(l.provider.KeyIDs()) != 1 {
		t.Fatalf("the second start made material: inserts = %d, keys = %v", l.storage.inserts, l.provider.KeyIDs())
	}
	if report := again.Report(context.Background()); report.Err != nil || report.Initialised || report.ActiveKeyID == "" {
		t.Errorf("report = %+v", report)
	}
}

// The third row: the record names a key that is gone. No key is made in its
// place; the start stops with the code and the installation stays as it is.
func TestAMissingSecretsKeyStopsTheStart(t *testing.T) {
	l := newLab(t)
	record := l.open(t).Record()
	l.provider.forget(record.ActiveKeyID)

	fatal := l.openFatal(t, CodeSecretsKeyUnavailable)
	if !errors.Is(fatal, secrets.ErrKeyUnavailable) {
		t.Errorf("the fatal does not carry the key error: %v", fatal)
	}
	if l.provider.HasMaterial() {
		t.Fatal("a key was made in place of the missing one")
	}
	if l.storage.record == nil || l.storage.record.InstallationID != record.InstallationID {
		t.Fatal("the record was touched")
	}
}

// A key of the right size under the right name that is not the
// installation's fails the self-test: the sentinel does not open.
func TestAForeignKeyFailsTheSelfTest(t *testing.T) {
	l := newLab(t)
	record := l.open(t).Record()
	l.provider.replace(t, record.ActiveKeyID)
	fatal := l.openFatal(t, CodeSecretsKeyUnavailable)
	if fatal.Reason == "" {
		t.Error("the fatal names no reason")
	}
}

// The fourth and fifth rows: the CA certificate without its key, and CA
// material that does not fit together.
func TestBrokenCAMaterialStopsTheStart(t *testing.T) {
	t.Run("certificate without key", func(t *testing.T) {
		l := newLab(t)
		l.open(t)
		if err := os.Remove(filepath.Join(l.dir, "ca.key")); err != nil {
			t.Fatal(err)
		}
		l.openFatal(t, CodeIssuerKeyUnavailable)
		if _, err := os.Stat(filepath.Join(l.dir, "ca.key")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("a CA key was made in place of the missing one")
		}
	})
	t.Run("key without certificate", func(t *testing.T) {
		l := newLab(t)
		l.open(t)
		if err := os.Remove(filepath.Join(l.dir, "ca.pem")); err != nil {
			t.Fatal(err)
		}
		l.openFatal(t, CodePKIStateMismatch)
	})
	t.Run("mismatched pair", func(t *testing.T) {
		l := newLab(t)
		l.open(t)
		other := t.TempDir()
		if _, err := pki.Init(other); err != nil {
			t.Fatal(err)
		}
		key, err := os.ReadFile(filepath.Join(other, "ca.key"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(l.dir, "ca.key"), key, 0o600); err != nil {
			t.Fatal(err)
		}
		l.openFatal(t, CodePKIStateMismatch)
	})
	t.Run("another CA in place of the recorded one", func(t *testing.T) {
		l := newLab(t)
		l.open(t)
		other := t.TempDir()
		if _, err := pki.Init(other); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"ca.key", "ca.pem"} {
			data, err := os.ReadFile(filepath.Join(other, name))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(l.dir, name), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		l.openFatal(t, CodePKIStateMismatch)
	})
	t.Run("no CA at all with a recorded one", func(t *testing.T) {
		l := newLab(t)
		l.open(t)
		for _, name := range []string{"ca.key", "ca.pem"} {
			if err := os.Remove(filepath.Join(l.dir, name)); err != nil {
				t.Fatal(err)
			}
		}
		l.openFatal(t, CodeIssuerKeyUnavailable)
		if pki.HasAnyMaterial(l.dir) {
			t.Fatal("a CA was made for an installation that lost its own")
		}
	})
}

// PKI-01 of the document: data in the database and no key to open it with is a
// fatal start, not a fresh key.
func TestSecretsWithoutAnyKeyStopTheStart(t *testing.T) {
	l := newLab(t)
	if _, err := pki.Init(l.dir); err != nil {
		t.Fatal(err)
	}
	l.storage.facts = Facts{SecretVersions: 3, Hosts: 2, Certificates: 2}
	l.openFatal(t, CodeSecretsKeyUnavailable)
	if l.provider.HasMaterial() {
		t.Fatal("a key was made for secrets it cannot open")
	}
	if l.storage.record != nil {
		t.Fatal("a record was written for an installation that cannot be opened")
	}
}

// The upgrade of an installation from before the record: the old key file and
// the CA are there, the database is full.
func TestAnExistingInstallationIsAdopted(t *testing.T) {
	l := newLab(t)
	if _, err := pki.Init(l.dir); err != nil {
		t.Fatal(err)
	}
	old, err := secrets.InitCipher(l.legacy)
	if err != nil {
		t.Fatal(err)
	}
	nonce, ciphertext, err := old.Encrypt([]byte("old value"), "secret-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	l.storage.facts = Facts{SecretVersions: 1, Hosts: 4, Certificates: 4}
	before, err := pki.Open(l.dir)
	if err != nil {
		t.Fatal(err)
	}

	runtime := l.open(t)
	record := runtime.Record()
	if record.ActiveKeyID != secrets.LegacyKeyID {
		t.Fatalf("active key after the adoption = %s", record.ActiveKeyID)
	}
	if record.IssuerID != before.IssuerID() {
		t.Fatal("the adoption did not record the existing CA")
	}
	if report := runtime.Report(context.Background()); !report.Adopted || report.Err != nil {
		t.Errorf("report = %+v", report)
	}
	legacy, ok := l.provider.LegacyCipher()
	if !ok {
		t.Fatal("the legacy key is not registered")
	}
	if value, err := legacy.Decrypt(nonce, ciphertext, "secret-a", 1); err != nil || string(value) != "old value" {
		t.Fatalf("a value sealed the old way: %q, %v", value, err)
	}
	// A new envelope goes under the same key, and the second start verifies
	// rather than adopts again.
	if _, err := secrets.Seal(context.Background(), l.provider, []byte("new"), nil); err != nil {
		t.Fatal(err)
	}
	again := l.open(t)
	if again.Record().InstallationID != record.InstallationID || l.storage.inserts != 1 {
		t.Fatal("the second start after the adoption made another installation")
	}
}

// A database that knows a fleet next to a state directory without a CA is a
// restore that forgot the directory; the start stops rather than making a CA
// the fleet does not trust.
func TestAFleetWithoutItsCAIsAmbiguous(t *testing.T) {
	l := newLab(t)
	l.storage.facts = Facts{Hosts: 5, Certificates: 5}
	l.openFatal(t, CodeStateAmbiguous)
	if pki.HasAnyMaterial(l.dir) {
		t.Fatal("a CA was made for a fleet that trusts another")
	}
	// Several keys and no record: nothing says which is active.
	m := newLab(t)
	if err := m.provider.GenerateNamed(context.Background(), "k-a"); err != nil {
		t.Fatal(err)
	}
	if err := m.provider.GenerateNamed(context.Background(), "k-b"); err != nil {
		t.Fatal(err)
	}
	m.openFatal(t, CodeStateAmbiguous)
}

// An initialisation that wrote its key and died before the record leaves one
// key and an empty database: the next start takes that key rather than
// stopping or making another.
func TestASingleKeyWithoutARecordIsTakenOver(t *testing.T) {
	l := newLab(t)
	if err := l.provider.GenerateNamed(context.Background(), "k-only"); err != nil {
		t.Fatal(err)
	}
	runtime := l.open(t)
	if runtime.Record().ActiveKeyID != "k-only" || len(l.provider.KeyIDs()) != 1 {
		t.Fatalf("active = %s, keys = %v", runtime.Record().ActiveKeyID, l.provider.KeyIDs())
	}
}

// The last row: two panels of one installation start at once. The lock
// lets one initialise; the other waits and reads what the first wrote.
func TestTwoPanelsDoNotMakeTwoInstallations(t *testing.T) {
	l := newLab(t)
	var wg sync.WaitGroup
	results := make([]string, 2)
	failures := make([]error, 2)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			runtime, err := Open(context.Background(), l.options())
			if err != nil {
				failures[i] = err
				return
			}
			results[i] = runtime.Record().InstallationID
		}(i)
	}
	wg.Wait()
	for _, err := range failures {
		if err != nil {
			t.Fatalf("a panel failed to start: %v", err)
		}
	}
	if results[0] != results[1] || results[0] == "" {
		t.Fatalf("installation ids = %v", results)
	}
	if l.storage.inserts != 1 || len(l.provider.KeyIDs()) != 1 {
		t.Fatalf("inserts = %d, keys = %v", l.storage.inserts, l.provider.KeyIDs())
	}
}

// A CA activation interrupted after the files and before the record: the
// record names a CA that is now retired, and it is caught up rather than
// reported as a mismatch.
func TestARecordBehindAnActivationIsCaughtUp(t *testing.T) {
	l := newLab(t)
	first := l.open(t)
	original := first.Record().IssuerID
	// The activation, without the hook: the files change, the record
	// does not.
	trust, err := pki.OpenTrust(l.dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.Prepare(); err != nil {
		t.Fatal(err)
	}
	if _, err := trust.Activate(); err != nil {
		t.Fatal(err)
	}
	again := l.open(t)
	if again.Record().IssuerID == original || again.Record().IssuerID != trust.Active().IssuerID() {
		t.Fatalf("issuer after the catch-up = %s, active = %s", again.Record().IssuerID, trust.Active().IssuerID())
	}
	if again.Record().Revision != 2 {
		t.Errorf("revision = %d, want 2", again.Record().Revision)
	}

	// With the hook in place the record follows the files at once.
	trust = again.Trust()
	if _, err := trust.Prepare(); err != nil {
		t.Fatal(err)
	}
	if _, err := trust.Activate(); err != nil {
		t.Fatal(err)
	}
	if again.Record().IssuerID != trust.Active().IssuerID() {
		t.Error("the activation hook did not move the record")
	}
	// Two revisions for the two steps: the preparation moves the record so the
	// other instances have a reason to read the store, and the handover moves
	// it again with the issuer that now signs.
	if l.open(t).Record().Revision != 4 {
		t.Error("the next start did not find the record current")
	}
}

// A rotation makes the new key, reseals the sentinel and moves the record;
// the old key stays. The same setting at the next start is a no-op.
func TestAKeyRotationIsResumableAndKeepsTheOldKey(t *testing.T) {
	l := newLab(t)
	first := l.open(t).Record()
	options := l.options()
	options.RotateTo = "k-next"
	rotated, err := Open(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	record := rotated.Record()
	if record.ActiveKeyID != "k-next" || record.Sentinel.KeyID != "k-next" {
		t.Fatalf("record after the rotation = %+v", record)
	}
	if err := l.provider.RequireKey(context.Background(), first.ActiveKeyID); err != nil {
		t.Fatal("the old key disappeared with the rotation")
	}
	if got, _ := l.provider.ActiveKeyID(context.Background()); got != "k-next" {
		t.Fatalf("the provider seals under %s", got)
	}
	// Again with the same setting: nothing changes.
	again, err := Open(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if again.Record().Revision != record.Revision {
		t.Error("a repeated rotation setting moved the record")
	}
	// Back to the legacy name is refused: the legacy key is the past.
	options.RotateTo = secrets.LegacyKeyID
	if _, err := Open(context.Background(), options); err == nil {
		t.Error("a rotation to the legacy key was accepted")
	}
}

// The start checked the active key and nothing else, so a key that live secret
// versions were sealed with and the provider no longer holds went unnoticed:
// the panel came up green, the status screen said a rewrap was running in the
// background - it could not - and the fault surfaced at the first read of that
// particular secret, which is the moment it must not.
func TestAKeyOfLiveSecretsThatTheProviderLostStopsTheStart(t *testing.T) {
	l := newLab(t)
	record := l.open(t).Record()

	// A secret still in use was sealed with a key of an earlier rotation.
	l.storage.mu.Lock()
	l.storage.liveKeys = []string{record.ActiveKeyID, "key-of-an-earlier-rotation"}
	l.storage.mu.Unlock()

	fatal := l.openFatal(t, CodeSecretsKeyUnavailable)
	if fatal.Reason == "" {
		t.Fatal("the refusal says nothing")
	}
	if !strings.Contains(fatal.Reason, "key-of-an-earlier-rotation") {
		t.Errorf("the refusal does not name the key nobody holds: %s", fatal.Reason)
	}

	// The same census with every key present is an ordinary start.
	l.storage.mu.Lock()
	l.storage.liveKeys = []string{record.ActiveKeyID}
	l.storage.mu.Unlock()
	if runtime := l.open(t); runtime == nil {
		t.Fatal("a start whose keys are all present was refused")
	}
}

// An authority activated on one instance used to leave every other instance
// signing with the old one, and rejecting the agents that had renewed against
// the new one: a documented maintenance action taking a site down. The state
// directory is shared, so keeping up is a matter of reading it.
func TestAnInstanceBroughtUpToTheRecordOfAnother(t *testing.T) {
	l := newLab(t)
	runtime := l.open(t)
	record := runtime.Record()

	// Another instance moved the record: a key rotation it also wrote the key
	// for, which this instance's provider holds because the material is shared.
	moved := record
	moved.ActiveKeyID = "key-of-the-other-instance"
	if err := l.provider.GenerateNamed(context.Background(), moved.ActiveKeyID); err != nil {
		t.Fatalf("the key of the other instance: %v", err)
	}
	sentinel, err := sealSentinel(context.Background(), l.provider, moved.ActiveKeyID, record.InstallationID)
	if err != nil {
		t.Fatalf("resealing the sentinel: %v", err)
	}
	moved.Sentinel = sentinel
	if err := l.storage.Update(context.Background(), moved); err != nil {
		t.Fatalf("the other instance's write: %v", err)
	}

	runtime.Reload(context.Background())
	if reason := runtime.Stale(); reason != "" {
		t.Fatalf("the instance reports itself behind: %s", reason)
	}
	if now := runtime.Record(); now.ActiveKeyID != moved.ActiveKeyID {
		t.Errorf("the instance still names the key %s", now.ActiveKeyID)
	}

	// A record naming a key this instance does not hold is what staleness is
	// for: it keeps working with what it has and says it is not fit to serve.
	unreachable := runtime.Record()
	unreachable.ActiveKeyID = "key-nobody-here-holds"
	if err := l.storage.Update(context.Background(), unreachable); err != nil {
		t.Fatal(err)
	}
	runtime.Reload(context.Background())
	if reason := runtime.Stale(); reason == "" {
		t.Error("an instance that could not catch up reports itself current")
	}
}

// A migration run beside a serving panel changes the record and not the
// process. The instance cannot pick up a provider at run time - it is what the
// panel was started with - so it says what it is and asks to be restarted,
// rather than reporting a state it is not in.
func TestAnInstanceDoesNotClaimAProviderItIsNotRunning(t *testing.T) {
	ctx := context.Background()
	l := newLab(t)
	runtime := l.open(t)
	storage := l.storage
	before := runtime.Report(ctx)
	if before.Provider != l.provider.Name() || before.RecordedProvider != "" || before.Stale != "" {
		t.Fatalf("a panel that just started reports %+v", before)
	}

	// Somebody runs crypto import-state against the same database.
	record, err := storage.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	record.Provider = DBProviderName
	record.Revision++
	if err := storage.Update(ctx, *record); err != nil {
		t.Fatal(err)
	}
	runtime.Reload(ctx)

	after := runtime.Report(ctx)
	if after.Provider != l.provider.Name() {
		t.Errorf("the instance reports the provider %q and runs %q", after.Provider, l.provider.Name())
	}
	if after.RecordedProvider != DBProviderName {
		t.Errorf("the instance does not say the record names %q", DBProviderName)
	}
	if after.Stale == "" {
		t.Error("the instance is behind the record and says nothing about it")
	}
	if !strings.Contains(after.Stale, "restarted") {
		t.Errorf("the reason does not say what to do: %q", after.Stale)
	}
}

// hostCSR is a certificate request of the kind an agent sends at a renewal.
func hostCSR(t *testing.T, hostID string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: hostID}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// Two instances over one installation: one hands signing over to a new
// authority and the other has to follow it.
//
// The reload used to open a second trust set and put it in the runtime's
// field. Nothing outside the runtime was looking there: the pool of the
// gateway, the issuer and the metrics are handed the object once at the start
// and hold it for the life of the process. The instance that did not perform
// the handover went back to ready while it went on signing with, and trusting,
// the authority the installation had withdrawn.
func TestTheInstanceThatDidNotRotateSignsWithTheAuthorityTheOtherOneActivated(t *testing.T) {
	ctx := context.Background()
	l := newLab(t)
	rotating := l.open(t)
	following := l.open(t)

	// What the rest of the panel is given at the start and never asks for again.
	held := following.Trust()
	certIssuer := issuer.FromTrust(held)
	withdrawn := held.Active().IssuerID()

	if _, err := rotating.Trust().Prepare(); err != nil {
		t.Fatal(err)
	}
	following.Reload(ctx)
	if pending, _ := held.Pending(); pending == nil {
		t.Fatal("the instance that did not prepare the authority does not know it, " +
			"so the hosts it serves get a bundle without it and would be cut off by the handover")
	}

	activated, err := rotating.Trust().Activate()
	if err != nil {
		t.Fatal(err)
	}
	following.Reload(ctx)
	if reason := following.Stale(); reason != "" {
		t.Fatalf("the instance reports itself behind the record: %s", reason)
	}
	if following.Trust() != held {
		t.Fatal("the reload swapped the trust set instead of refreshing the one everything holds")
	}
	if got := held.Active().FingerprintHex(); got != activated.Fingerprint {
		t.Fatalf("the instance signs with %s, the installation with %s", got, activated.Fingerprint)
	}
	if following.Record().IssuerID == withdrawn {
		t.Error("the record of the instance still names the authority that stepped down")
	}

	// The issuer follows, because it reads the signing authority per signature.
	issued, err := certIssuer.SignHost(ctx, hostCSR(t, "a-host"), "a-host")
	if err != nil {
		t.Fatal(err)
	}
	if issued.IssuerSerial != activated.Serial {
		t.Errorf("the certificate was issued by %s, the authority that signs is %s",
			issued.IssuerSerial, activated.Serial)
	}
	// And the pool the gateway verifies its clients against accepts it.
	block, _ := pem.Decode(issued.PEM)
	if block == nil {
		t.Fatal("the issued certificate carries no PEM block")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: held.Pool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("the pool of the instance rejects a certificate it has just issued: %v", err)
	}
}

// The activation hook of the fleet CA writes the installation record. It used
// to write the whole record out of the copy it held in memory, so a key
// rotation another replica had committed since the last read was put back to
// the old key and the old sentinel: the secrets sealed with one key and the
// record naming another (audit of 6c38561, CR-03).
func TestTheActivationHookDoesNotUndoAKeyRotation(t *testing.T) {
	l := newLab(t)
	runtime := l.open(t)

	// What this instance believes, and what the row says after another replica
	// rotated the key: a different active key and a different revision.
	before := runtime.record
	rotated := before
	rotated.ActiveKeyID = "rotated-by-another-replica"
	rotated.Revision = before.Revision + 7
	l.storage.mu.Lock()
	l.storage.record = &rotated
	l.storage.mu.Unlock()

	// The hook runs with the stale copy in hand.
	runtime.recordIssuer(context.Background(), runtime.trust.Active())

	after, err := l.storage.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if after.ActiveKeyID != rotated.ActiveKeyID {
		t.Fatalf("the active secrets key came back as %q; the other replica had set %q",
			after.ActiveKeyID, rotated.ActiveKeyID)
	}
	// And the hook did its own job: the authority that signs is recorded.
	if after.IssuerID != runtime.trust.Active().IssuerID() {
		t.Fatalf("the record names the issuer %q, and the authority that signs is %q",
			after.IssuerID, runtime.trust.Active().IssuerID())
	}
}

// An adoption trusts the key file with the data in the database, and until this
// check nothing compared the two: the sentinel that proves the key at every
// later start is sealed under this very key, here, now. A restore that brought
// the database and somebody else's secrets.key was adopted, the record was
// written, the sentinel was resealed, and every secret of the installation was
// unreadable with one line in the log to say so.
func TestAKeyThatDoesNotOpenTheFirstFormIsNotAdopted(t *testing.T) {
	l := newLab(t)
	if _, err := pki.Init(l.dir); err != nil {
		t.Fatal(err)
	}
	if _, err := secrets.InitCipher(l.legacy); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(l.legacy)
	if err != nil {
		t.Fatal(err)
	}
	l.storage.facts = Facts{SecretVersions: 3, Hosts: 4, Certificates: 4}
	l.probe = func(context.Context, secrets.KeyProvider) error {
		return fmt.Errorf("%w: secret-a version 1 does not open under the key offered for the first form",
			secrets.ErrFirstFormUnreadable)
	}

	fatal := l.openFatal(t, CodeSecretsKeyUnavailable)
	// The operator has to read which file is wrong and how much is behind it;
	// "the key is unavailable" sends them looking for a missing file.
	if !strings.Contains(fatal.Reason, l.legacy) {
		t.Errorf("the refusal does not name the key file: %s", fatal.Reason)
	}
	if !strings.Contains(fatal.Reason, "3 secret versions") {
		t.Errorf("the refusal does not say how many versions are behind it: %s", fatal.Reason)
	}
	if !errors.Is(fatal, secrets.ErrFirstFormUnreadable) {
		t.Errorf("the refusal does not carry what the store said: %v", fatal)
	}
	if l.storage.record != nil {
		t.Fatal("a record was written for an installation whose secrets the key does not open")
	}
	// The key was tried, not kept. A refusal that had already adopted left
	// keys/legacy.key holding the key it refused, and the next start - with the
	// right secrets.key restored - was refused for differing from it: the
	// repair of a refusal needed a file nobody had been told about.
	if l.provider.adopts != 0 {
		t.Fatalf("the refused start kept the key it refused (%d adoptions)", l.provider.adopts)
	}
	// Nothing is lost by the refusal: the ciphertexts are untouched because
	// they were never read for writing, and the key file is the one that was
	// there - so the right key, when it is found, still opens everything.
	after, err := os.ReadFile(l.legacy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("the refused start rewrote the key file")
	}

	// One step outside, from the legitimate side: the same installation whose
	// key does open its rows is adopted exactly as before. A check that
	// refused this would stop every upgrade from before the envelope.
	l.probe = func(context.Context, secrets.KeyProvider) error { return nil }
	runtime := l.open(t)
	if runtime.Record().ActiveKeyID != secrets.LegacyKeyID {
		t.Fatalf("active key after the adoption = %s", runtime.Record().ActiveKeyID)
	}
	if report := runtime.Report(context.Background()); !report.Adopted || report.Err != nil {
		t.Errorf("report = %+v", report)
	}
}
