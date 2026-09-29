//go:build integration

package integration

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/ultherego/flotestro/internal/cryptostate"
	"github.com/ultherego/flotestro/internal/pki"
)

// The fleet's certificate authorities against the real schema: what one
// replica writes, another reads, and the handover that must never leave the
// installation with two authorities that sign or none.
func TestTheAuthoritiesOfTheFleetLiveInTheDatabaseAndSurviveAHandover(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	store := cryptostate.NewPostgres(h.database(ctx))

	kek, err := cryptostate.ParseKEK(
		"3f1a9c0e5b7d2648a0c3e5f7091b2d4e6a8c0e2f4a6b8d0f1234567890abcdef", "test")
	if err != nil {
		t.Fatal(err)
	}

	// The authorities are the installation's own set, not a namespace a test
	// can borrow a corner of: a second one written here would be a second
	// authority claiming to sign. So this runs only against a database that
	// keeps none, which is every installation that has not moved its keys.
	existing, err := store.WrappedKeys(ctx, cryptostate.PurposeAgentCA)
	if err != nil {
		t.Fatalf("the authorities of the installation could not be read: %v", err)
	}
	if len(existing) > 0 {
		// It keeps its own set, so what can be checked is that set: exactly one
		// authority signs, at most one is prepared to take over, and every row
		// says which it is. A skip here would leave the arrangement this whole
		// stage produces unexamined by the suite that runs against it.
		theLiveSetIsCoherent(ctx, t, store, existing)
		t.Skipf("this installation keeps %d authorities in the database; its own set is not a test's to write to",
			len(existing))
	}

	authorities := cryptostate.NewDBAuthorities(ctx, store, kek)
	cleanup := func() {
		forget := context.WithoutCancel(ctx)
		rows, err := store.WrappedKeys(forget, cryptostate.PurposeAgentCA)
		if err != nil {
			return
		}
		names := make([]string, 0, len(rows))
		for _, row := range rows {
			names = append(names, row.KeyID)
		}
		_ = store.DeleteAuthorities(forget, names)
		for _, cert := range retiredSerials(forget, t, store) {
			_ = store.DeleteRetiredAuthority(forget, cert)
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	trust, err := pki.InitTrustFrom(authorities)
	if err != nil {
		t.Fatalf("the first authority of the installation was not created: %v", err)
	}
	first := trust.Active()

	// A second replica of the same deployment reads the same set, which is the
	// whole reason the keys were moved here.
	replica, err := pki.OpenTrustFrom(cryptostate.NewDBAuthorities(ctx, store, kek))
	if err != nil {
		t.Fatalf("a second replica could not read the authorities: %v", err)
	}
	if replica.Active().FingerprintHex() != first.FingerprintHex() {
		t.Fatalf("the second replica signs with %s and the first with %s",
			replica.Active().FingerprintHex(), first.FingerprintHex())
	}

	prepared, err := trust.Prepare()
	if err != nil {
		t.Fatalf("an authority could not be prepared: %v", err)
	}
	// The prepared one is told by the block it carries and by nothing else;
	// both are rows of one table under one purpose.
	afterPrepare, err := pki.OpenTrustFrom(cryptostate.NewDBAuthorities(ctx, store, kek))
	if err != nil {
		t.Fatal(err)
	}
	if afterPrepare.Active().FingerprintHex() != first.FingerprintHex() {
		t.Error("preparing an authority changed the one that signs")
	}
	pending, preparedAt := afterPrepare.Pending()
	if pending == nil || pending.FingerprintHex() != prepared.Fingerprint {
		t.Fatalf("the prepared authority did not come back: %v", pending)
	}
	if preparedAt.IsZero() {
		t.Error("the moment of preparation did not survive the database")
	}

	if _, err := trust.Activate(); err != nil {
		t.Fatalf("the handover failed: %v", err)
	}
	afterHandover, err := pki.OpenTrustFrom(cryptostate.NewDBAuthorities(ctx, store, kek))
	if err != nil {
		t.Fatal(err)
	}
	if afterHandover.Active().FingerprintHex() != prepared.Fingerprint {
		t.Errorf("after the handover %s signs", afterHandover.Active().FingerprintHex())
	}
	if still, _ := afterHandover.Pending(); still != nil {
		t.Error("after the handover an authority is still prepared to take over")
	}
	rows, err := store.WrappedKeys(ctx, cryptostate.PurposeAgentCA)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Errorf("the installation holds %d authorities after the handover instead of one", len(rows))
	}
	// The withdrawn authority keeps its certificate and loses its key: the
	// hosts it issued for are still recognised, and there is nothing left to
	// steal.
	retired := afterHandover.Retired()
	if len(retired) != 1 || retired[0].FingerprintHex() != first.FingerprintHex() {
		t.Fatalf("the authority that signed until now was not kept as withdrawn: %v", retired)
	}
	if retired[0].PrivateKey != nil {
		t.Error("a withdrawn authority came back with its private key")
	}
	if !bytes.Contains(afterHandover.Bundle(), retired[0].PEM) {
		t.Error("the withdrawn authority is not in the bundle the agents get")
	}

	if err := afterHandover.Retire(first.FingerprintHex(), 2); err == nil {
		t.Error("a withdrawn authority two hosts still use was removed")
	}
	if err := afterHandover.Retire(first.FingerprintHex(), 0); err != nil {
		t.Fatalf("a withdrawn authority nobody uses could not be removed: %v", err)
	}
	final, err := pki.OpenTrustFrom(cryptostate.NewDBAuthorities(ctx, store, kek))
	if err != nil {
		t.Fatal(err)
	}
	if left := final.Retired(); len(left) != 0 {
		t.Errorf("%d withdrawn authorities are still recognised", len(left))
	}
}

// retiredSerials names what the withdrawn table holds, for the cleanup.
func retiredSerials(ctx context.Context, t *testing.T, store *cryptostate.Postgres) []string {
	t.Helper()
	certificates, err := store.RetiredAuthorities(ctx)
	if err != nil {
		return nil
	}
	serials := make([]string, 0, len(certificates))
	for _, certPEM := range certificates {
		cert, err := pki.ParseCertificatePEM(certPEM)
		if err != nil {
			continue
		}
		serials = append(serials, cert.SerialNumber.String())
	}
	return serials
}

// theLiveSetIsCoherent checks the authorities a running installation keeps,
// without writing anything. The keys cannot be opened here - the key
// encryption key belongs to the deployment and not to the suite - so what is
// judged is the shape of the set: one signing authority, at most one prepared,
// every row named after the certificate it carries, and all of them wrapped
// with the one key the record names.
func theLiveSetIsCoherent(ctx context.Context, t *testing.T, store *cryptostate.Postgres, rows []cryptostate.WrappedKey) {
	t.Helper()
	recorded, err := store.KEKID(ctx)
	if err != nil {
		t.Fatalf("the recorded key encryption key could not be read: %v", err)
	}
	if recorded == "" {
		t.Fatal("the installation keeps authorities in the database and the record names no key encryption key")
	}
	record, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("the installation record could not be read: %v", err)
	}
	signing := 0
	for _, row := range rows {
		if row.KEKID != recorded {
			t.Errorf("the authority %s is wrapped with %s and the record names %s",
				row.KeyID, row.KEKID, recorded)
		}
		if row.Retired() {
			t.Errorf("the authority %s is marked retired; a withdrawn authority keeps no key at all",
				row.KeyID)
		}
		if row.KeyID == record.IssuerID {
			signing++
		}
	}
	if signing != 1 {
		t.Errorf("%d of the %d authorities is the one the record says signs (%s)",
			signing, len(rows), record.IssuerID)
	}
	if len(rows) > 2 {
		t.Errorf("the installation keeps %d authorities; one signs and at most one is prepared", len(rows))
	}
}
