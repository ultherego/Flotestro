package cryptostate

import (
	"context"
	"errors"
	"fmt"
	"slices"
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
	// betweenReadAndWrite runs once, inside the next removal, so that a test
	// can put another replica's write exactly where the race is.
	betweenReadAndWrite func()
}

func newMemoryAuthorities() *memoryAuthorities {
	return &memoryAuthorities{memoryKeys: newMemoryKeys(), retired: map[string][]byte{}}
}

// ReplaceAuthority is guarded the way Postgres guards it: the row is sealed
// with the key one replica holds, the record has to still name that key, and
// the authorities have to be the ones the caller read before it decided.
func (m *memoryAuthorities) ReplaceAuthority(ctx context.Context, row WrappedKey, remove, seen []string) error {
	if err := m.authoritiesStillThese(seen); err != nil {
		return err
	}
	if err := m.drop(remove); err != nil {
		return err
	}
	return m.PutWrappedKeyUnderRecordedKEK(ctx, row)
}

// authoritiesStillThese answers the way the database does: the installation
// holds exactly the authorities the caller read, or the write is refused.
func (m *memoryAuthorities) authoritiesStillThese(seen []string) error {
	m.memoryKeys.mu.Lock()
	var now []string
	for id, row := range m.memoryKeys.rows {
		if row.Purpose == PurposeAgentCA {
			now = append(now, id)
		}
	}
	m.memoryKeys.mu.Unlock()
	sort.Strings(now)
	want := append([]string(nil), seen...)
	sort.Strings(want)
	if !slices.Equal(now, want) {
		return fmt.Errorf("%w: this instance read the authorities %v and the installation now holds %v",
			ErrRevisionMoved, want, now)
	}
	return nil
}

// DeleteAuthorities refuses the way Postgres refuses: the removal carries the
// set the caller read, and a set that has moved since is not dropped.
func (m *memoryAuthorities) DeleteAuthorities(_ context.Context, keyIDs, seen []string) error {
	// The hook stands for another replica writing between the read and this
	// write, which is the moment the condition exists for.
	if m.betweenReadAndWrite != nil {
		hook := m.betweenReadAndWrite
		m.betweenReadAndWrite = nil
		hook()
	}
	if err := m.authoritiesStillThese(seen); err != nil {
		return err
	}
	return m.drop(keyIDs)
}

// drop removes the rows without a condition, which is what the two writes do
// once their condition holds.
func (m *memoryAuthorities) drop(keyIDs []string) error {
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

// Abandoning a prepared authority read the set and then removed a row by name.
// Between the two, another replica may have activated that very authority -
// the name does not change at a handover - and the removal then took away the
// authority the whole fleet signs with (audit of 6c38561, CR-02).
func TestAbandoningAPreparedAuthorityDoesNotRemoveTheActivatedOne(t *testing.T) {
	store := newMemoryAuthorities()
	trust := dbTrust(t, store)
	prepared, err := trust.Prepare()
	if err != nil {
		t.Fatal(err)
	}

	// The other replica activates it exactly between the read and the write.
	var activated string
	store.betweenReadAndWrite = func() {
		second := reopen(t, store)
		if _, err := second.Activate(); err != nil {
			t.Errorf("the other replica could not activate: %v", err)
			return
		}
		activated = second.Active().IssuerID()
	}
	if err := trust.Retire(prepared.Fingerprint, 0); !errors.Is(err, ErrRevisionMoved) {
		t.Fatalf("abandoning an authority that was activated meanwhile answered %v", err)
	}
	if activated == "" {
		t.Fatal("the other replica never ran")
	}

	back := reopen(t, store)
	if back.Active().IssuerID() != activated {
		t.Fatalf("the installation signs with %s after the abandonment, not with the activated %s",
			back.Active().IssuerID(), activated)
	}
	if _, err := store.WrappedKey(context.Background(), activated); err != nil {
		t.Fatalf("the activated authority is no longer in the database: %v", err)
	}
}

// A rewrap opens every row, seals it with the new key encryption key and writes
// it back under the same name. An authority another replica activated in
// between keeps its name and changes its content, so a write conditional on
// the key encryption key alone put the previous state back: the activated
// authority became the prepared one again and the withdrawn one signed, with
// both operations reported as successful (audit of 6c38561, CR-02).
func TestARewrapDoesNotPutBackAnAuthorityAnotherReplicaActivated(t *testing.T) {
	ctx := context.Background()
	first := testKEK(t, testKEKHex)
	second := testKEK(t, otherKEKHex)

	store := newMemoryStore()
	// One set of rows, read as the authorities of the fleet and as the keys of
	// the installation: that is the one thing both writes touch.
	authorities := &memoryAuthorities{memoryKeys: store.memoryKeys, retired: map[string][]byte{}}
	trust := dbTrust(t, authorities)
	withdrawn := trust.Active().IssuerID()
	prepared, err := trust.Prepare()
	if err != nil {
		t.Fatal(err)
	}
	// The record names the key the rows are wrapped with, which the authorities
	// above wrote without going through a migration.
	store.kekID = first.ID()

	// The rewrap opens the set, and the other replica hands signing over before
	// the rewrap writes.
	store.betweenReadAndWrite = func() {
		if _, err := reopen(t, authorities).Activate(); err != nil {
			t.Errorf("the other replica could not activate: %v", err)
		}
	}
	if _, err := Rewrap(ctx, store, first, second); !errors.Is(err, ErrRevisionMoved) {
		t.Fatalf("the rewrap answered %v", err)
	}

	back := reopen(t, authorities)
	if got := back.Active().FingerprintHex(); got != prepared.Fingerprint {
		t.Fatalf("the installation signs with %s, not with the authority that was activated (%s)",
			got, prepared.Fingerprint)
	}
	if _, _, preparedAt, err := NewDBAuthorities(ctx, authorities, first).ReadPrepared(); err != nil ||
		!preparedAt.IsZero() {
		t.Fatalf("an authority is prepared again after the handover: %v, %v", preparedAt, err)
	}
	if _, err := store.WrappedKey(ctx, withdrawn); err == nil {
		t.Fatal("the withdrawn authority was written back as a key of the installation")
	}
	if store.kekID != first.ID() {
		t.Fatalf("the record names %s after the refused rewrap", store.kekID)
	}
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

// An authority is sealed with the key one replica holds, like any other row,
// so a replica left behind by a rewrap must not write one either. A CA nobody
// can open is a fleet that renews nothing.
func TestAnAuthorityIsNotWrittenUnderAKeyEncryptionKeyTheInstallationHasLeft(t *testing.T) {
	ctx := context.Background()
	store := newMemoryAuthorities()
	// The installation is wrapped with one key and this replica holds
	// another. It keeps no authority yet, so nothing it reads tells it so -
	// a set it can open is not the same as a set it may write to.
	store.recordNames(testKEK(t, otherKEKHex).ID(), testInstallationID)

	_, err := pki.EnsureTrustFrom(NewDBAuthorities(ctx, store, testKEK(t, testKEKHex)))
	if !refusedWith(err, CodeKEKRotated) {
		t.Errorf("the first authority of the fleet was answered %v, expected %s", err, CodeKEKRotated)
	}
	rows, err := store.WrappedKeys(ctx, PurposeAgentCA)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("the installation holds %d authorities nobody can open", len(rows))
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

// The authority of the installation is written with the condition the decision
// used: which authorities were there when the caller read them. Without it
// another replica could activate an authority between that read and this
// write, and this write would delete it and put its own in - the fleet signing
// with an authority nobody activated, and both writes reported as successes
// (audit of 6c38561, CR-02).
func TestWritingTheAuthorityCarriesWhatItRead(t *testing.T) {
	store := newMemoryAuthorities()
	dbTrust(t, store)

	rows, err := store.WrappedKeys(context.Background(), PurposeAgentCA)
	if err != nil || len(rows) != 1 {
		t.Fatalf("the installation holds %d authorities (%v)", len(rows), err)
	}
	first := rows[0]
	// Two further rows, which stand for the authorities two replicas would
	// write. What they hold does not matter here; which names are in the table
	// does.
	second, third := first, first
	second.KeyID, third.KeyID = "second-authority", "third-authority"

	ctx := context.Background()
	// A replica that read the first authority replaces it: the condition holds.
	if err := store.ReplaceAuthority(ctx, second, []string{first.KeyID}, []string{first.KeyID}); err != nil {
		t.Fatalf("a write that carried what it read was refused: %v", err)
	}
	// A second replica decided on the same reading, which is no longer true.
	err = store.ReplaceAuthority(ctx, third, []string{first.KeyID}, []string{first.KeyID})
	if !errors.Is(err, ErrRevisionMoved) {
		t.Fatalf("err = %v, expected the write to be refused", err)
	}
	// And what the first replica activated is still there.
	rows, err = store.WrappedKeys(ctx, PurposeAgentCA)
	if err != nil || len(rows) != 1 || rows[0].KeyID != second.KeyID {
		t.Fatalf("the installation now holds %+v (%v)", rows, err)
	}
	// Reading again is all it takes to go on: the condition is the read, not a
	// lock somebody has to hold.
	if err := store.ReplaceAuthority(ctx, third, []string{second.KeyID}, []string{second.KeyID}); err != nil {
		t.Fatalf("a write after reading the state again: %v", err)
	}
}
