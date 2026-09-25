package cryptostate

import (
	"context"
	"crypto/rand"
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
	return Options{Storage: l.storage, Provider: l.provider, CADir: l.dir, LegacyKeyPath: l.legacy}
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
	if l.open(t).Record().Revision != 3 {
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
