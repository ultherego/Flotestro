package cryptostate

import (
	"context"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/pki"
)

// memoryAuthorities is the authority half of the database without a database:
// the wrapped rows of memoryKeys, plus the withdrawn certificates that carry
// no key and therefore live apart from them.
type memoryAuthorities struct {
	*memoryKeys
	mu      sync.Mutex
	retired map[string][]byte
}

func newMemoryAuthorities() *memoryAuthorities {
	return &memoryAuthorities{memoryKeys: newMemoryKeys(), retired: map[string][]byte{}}
}

func (m *memoryAuthorities) ReplaceAuthority(ctx context.Context, row WrappedKey, remove []string) error {
	if err := m.DeleteAuthorities(ctx, remove); err != nil {
		return err
	}
	return m.PutWrappedKey(ctx, row)
}

func (m *memoryAuthorities) DeleteAuthorities(_ context.Context, keyIDs []string) error {
	m.memoryKeys.mu.Lock()
	defer m.memoryKeys.mu.Unlock()
	for _, id := range keyIDs {
		if row, ok := m.memoryKeys.rows[id]; ok && row.Purpose == PurposeAgentCA {
			delete(m.memoryKeys.rows, id)
		}
	}
	return nil
}

func (m *memoryAuthorities) RetiredAuthorities(_ context.Context) ([][]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	serials := make([]string, 0, len(m.retired))
	for serial := range m.retired {
		serials = append(serials, serial)
	}
	sort.Strings(serials)
	certificates := make([][]byte, 0, len(serials))
	for _, serial := range serials {
		certificates = append(certificates, m.retired[serial])
	}
	return certificates, nil
}

func (m *memoryAuthorities) PutRetiredAuthority(_ context.Context, serial string, certPEM []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.retired[serial] = append([]byte(nil), certPEM...)
	return nil
}

func (m *memoryAuthorities) DeleteRetiredAuthority(_ context.Context, serial string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.retired, serial)
	return nil
}

// dbTrust builds a trust set over the in-memory rows.
func dbTrust(t *testing.T, store *memoryAuthorities) *pki.Trust {
	t.Helper()
	trust, err := pki.EnsureTrustFrom(NewDBAuthorities(context.Background(), store, testKEK(t, testKEKHex)))
	if err != nil {
		t.Fatal(err)
	}
	return trust
}

// reopen reads the set again, as a restart or a second replica would.
func reopen(t *testing.T, store *memoryAuthorities) *pki.Trust {
	t.Helper()
	trust, err := pki.OpenTrustFrom(NewDBAuthorities(context.Background(), store, testKEK(t, testKEKHex)))
	if err != nil {
		t.Fatal(err)
	}
	return trust
}

func TestAnAuthorityWrittenToTheDatabaseIsTheOneTheNextStartSignsWith(t *testing.T) {
	store := newMemoryAuthorities()
	trust := dbTrust(t, store)
	created := trust.Active()

	back := reopen(t, store)
	if back.Active().FingerprintHex() != created.FingerprintHex() {
		t.Fatalf("another authority came back: %s instead of %s",
			back.Active().FingerprintHex(), created.FingerprintHex())
	}
	if err := back.Active().VerifyPair(); err != nil {
		t.Fatalf("the authority came back without a key that matches it: %v", err)
	}
	// The row is named by the issuer identifier, which is what the migration of
	// the keys into the database names it too.
	if _, err := store.WrappedKey(context.Background(), created.IssuerID()); err != nil {
		t.Fatalf("the authority is not in the database under its issuer identifier: %v", err)
	}
}

func TestAPreparedAuthorityIsToldFromTheSigningOneByItsBlockAndNotByAName(t *testing.T) {
	store := newMemoryAuthorities()
	trust := dbTrust(t, store)
	active := trust.Active().IssuerID()
	prepared, err := trust.Prepare()
	if err != nil {
		t.Fatal(err)
	}

	back := reopen(t, store)
	if back.Active().IssuerID() != active {
		t.Errorf("the prepared authority took over without an activation: %s", back.Active().IssuerID())
	}
	pending, preparedAt := back.Pending()
	if pending == nil {
		t.Fatal("the prepared authority did not come back as prepared")
	}
	if pending.FingerprintHex() != prepared.Fingerprint {
		t.Errorf("another authority came back as prepared: %s", pending.FingerprintHex())
	}
	if preparedAt.IsZero() {
		t.Error("the moment of preparation did not survive the move into the database")
	}

	// Both authorities are rows of one table, of one purpose, with nothing in
	// the row to say which is which: the block inside the bundle is what does.
	rows, err := store.WrappedKeys(context.Background(), PurposeAgentCA)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("the database holds %d authorities instead of two", len(rows))
	}
	blocks := 0
	for _, row := range rows {
		material, err := testKEK(t, testKEKHex).Open(row)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, at, err := AuthorityParts(material); err != nil {
			t.Fatal(err)
		} else if len(at) > 0 {
			blocks++
		}
	}
	if blocks != 1 {
		t.Errorf("%d of the two authorities carry a moment of preparation", blocks)
	}
}

func TestTheHandoverInTheDatabaseLeavesOneSigningAuthorityAndOneWithdrawn(t *testing.T) {
	store := newMemoryAuthorities()
	trust := dbTrust(t, store)
	previous := trust.Active()
	prepared, err := trust.Prepare()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.Activate(); err != nil {
		t.Fatal(err)
	}

	back := reopen(t, store)
	if back.Active().FingerprintHex() != prepared.Fingerprint {
		t.Errorf("after the handover another authority signs: %s", back.Active().FingerprintHex())
	}
	if pending, _ := back.Pending(); pending != nil {
		t.Error("after the handover an authority is still prepared to take over")
	}
	retired := back.Retired()
	if len(retired) != 1 || retired[0].FingerprintHex() != previous.FingerprintHex() {
		t.Fatalf("the authority that signed until now was not kept as withdrawn: %v", retired)
	}
	// The withdrawn one keeps no key: it has nothing left to sign.
	if retired[0].PrivateKey != nil {
		t.Error("a withdrawn authority came back with its private key")
	}
	if _, err := store.WrappedKey(context.Background(), previous.IssuerID()); err == nil {
		t.Error("the private key of the withdrawn authority is still a row of the database")
	}
	rows, err := store.WrappedKeys(context.Background(), PurposeAgentCA)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Errorf("the database holds %d authorities after the handover instead of one", len(rows))
	}
}

func TestAPreparedAuthorityIsAbandonedWithoutTouchingTheOneThatSigns(t *testing.T) {
	store := newMemoryAuthorities()
	trust := dbTrust(t, store)
	active := trust.Active().IssuerID()
	prepared, err := trust.Prepare()
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.Retire(prepared.Fingerprint, 0); err != nil {
		t.Fatal(err)
	}

	back := reopen(t, store)
	if pending, _ := back.Pending(); pending != nil {
		t.Error("the abandoned authority is still prepared to take over")
	}
	if back.Active().IssuerID() != active {
		t.Errorf("abandoning the prepared authority changed the one that signs: %s", back.Active().IssuerID())
	}
	rows, err := store.WrappedKeys(context.Background(), PurposeAgentCA)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Errorf("the database holds %d authorities after the abandonment instead of one", len(rows))
	}
}

func TestAWithdrawnAuthorityIsRemovedFromTheDatabaseOnlyWhenNoHostUsesIt(t *testing.T) {
	store := newMemoryAuthorities()
	trust := dbTrust(t, store)
	previous := trust.Active().FingerprintHex()
	if _, err := trust.Prepare(); err != nil {
		t.Fatal(err)
	}
	if _, err := trust.Activate(); err != nil {
		t.Fatal(err)
	}

	if err := trust.Retire(previous, 3); err == nil {
		t.Error("a withdrawn authority three hosts still use was removed")
	}
	if err := trust.Retire(previous, 0); err != nil {
		t.Fatal(err)
	}
	if left := reopen(t, store).Retired(); len(left) != 0 {
		t.Errorf("%d withdrawn authorities are still recognised", len(left))
	}
	// The one that signs is never removable, whatever the count says.
	if err := trust.Retire(trust.Active().FingerprintHex(), 0); err == nil {
		t.Error("the authority that signs new certificates was removed")
	}
}

func TestAnInstallationWithNoAuthorityInTheDatabaseIsNotOneWithAnEmptyOne(t *testing.T) {
	store := newMemoryAuthorities()
	_, err := pki.OpenTrustFrom(NewDBAuthorities(context.Background(), store, testKEK(t, testKEKHex)))
	if err == nil {
		t.Fatal("a database holding no authority opened as a trust set")
	}
	if !strings.Contains(err.Error(), pki.ErrNoMaterial.Error()) {
		t.Errorf("an empty database was refused for the wrong reason: %v", err)
	}
}

func TestAnAuthorityWrappedWithAnotherKeyIsRefusedRatherThanIgnored(t *testing.T) {
	store := newMemoryAuthorities()
	dbTrust(t, store)
	stranger := NewDBAuthorities(context.Background(), store, testKEK(t, otherKEKHex))
	if _, err := pki.OpenTrustFrom(stranger); err == nil {
		t.Fatal("an authority wrapped with another key encryption key opened")
	}
}

func TestTheMomentOfPreparationSurvivesARestartUnchanged(t *testing.T) {
	store := newMemoryAuthorities()
	trust := dbTrust(t, store)
	if _, err := trust.Prepare(); err != nil {
		t.Fatal(err)
	}
	_, first := reopen(t, store).Pending()
	time.Sleep(time.Millisecond)
	_, second := reopen(t, store).Pending()
	if !first.Equal(second) {
		t.Errorf("the moment of preparation moved between two starts: %s then %s", first, second)
	}
}

func TestTheHelperSigningKeyIsReadFromTheDatabaseAndNeverMadeThere(t *testing.T) {
	store := newMemoryAuthorities()
	kek := testKEK(t, testKEKHex)
	provider, err := NewDBProvider(context.Background(), store, kek)
	if err != nil {
		t.Fatal(err)
	}

	// An installation whose keys are rows and whose helper key is not one:
	// the hosts trust a signature this panel cannot make, and the start is
	// refused rather than a new key minted under them.
	if _, _, err := provider.HelperSigningKeys(context.Background()); err == nil {
		t.Fatal("a missing helper signing key was answered with something")
	}

	active := []byte("-----BEGIN PRIVATE KEY-----\nactive\n-----END PRIVATE KEY-----\n")
	previous := []byte("-----BEGIN PRIVATE KEY-----\nprevious\n-----END PRIVATE KEY-----\n")
	for _, key := range []struct {
		id       string
		material []byte
	}{
		{HelperKeyPrefix + "k1", active},
		{HelperPreviousPrefix + "k0", previous},
	} {
		row, err := kek.Seal(key.id, PurposeHelperSigning, key.material)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.PutWrappedKey(context.Background(), row); err != nil {
			t.Fatal(err)
		}
	}

	gotActive, gotPrevious, err := provider.HelperSigningKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// The name of the row is the only thing that says which key is in which
	// role, and "helper-previous-" begins with "helper-".
	if string(gotActive) != string(active) {
		t.Errorf("the key in the active role is %q", gotActive)
	}
	if string(gotPrevious) != string(previous) {
		t.Errorf("the key rotated from is %q", gotPrevious)
	}
}
