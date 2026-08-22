package pki

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func liczCertyfikaty(t *testing.T, bundle []byte) int {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle) {
		t.Fatal("bundle nie zawiera certyfikatow")
	}
	return strings.Count(string(bundle), "BEGIN CERTIFICATE")
}

// TestWymianaJestDwufazowa pilnuje warunku, ktory chroni flote przed odcieciem.
// Nowe CA musi byc uznawane i rozsylane, zanim zacznie podpisywac: certyfikat
// serwera wystawiony CA, ktorego agent nie zna, konczy sie utrata lacznosci
// z cala flota przy najblizszym restarcie panelu.
func TestWymianaJestDwufazowa(t *testing.T) {
	dir := t.TempDir()
	trust, err := EnsureTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	pierwotne := trust.Active().Certificate.SerialNumber.String()

	if liczCertyfikaty(t, trust.Bundle()) != 1 {
		t.Fatal("swiezy zbior powinien miec dokladnie jedno CA")
	}

	przygotowane, err := trust.Prepare()
	if err != nil {
		t.Fatal(err)
	}
	if przygotowane.State != "pending" {
		t.Errorf("stan przygotowanego CA = %q", przygotowane.State)
	}
	// Przygotowane CA jest juz rozsylane i uznawane, ale nie podpisuje.
	if trust.Active().Certificate.SerialNumber.String() != pierwotne {
		t.Error("przygotowanie nie moze zmienic CA podpisujacego")
	}
	if liczCertyfikaty(t, trust.Bundle()) != 2 {
		t.Error("przygotowane CA musi trafic do bundla")
	}
	if _, err := trust.Prepare(); err == nil {
		t.Error("drugie przygotowanie przy oczekujacym CA powinno zostac odrzucone")
	}

	aktywne, err := trust.Activate()
	if err != nil {
		t.Fatal(err)
	}
	if aktywne.Serial != przygotowane.Serial {
		t.Errorf("podpisywanie przejelo CA %s, oczekiwano %s", aktywne.Serial, przygotowane.Serial)
	}
	// Poprzednie CA zostaje uznawane: certyfikaty agentow nim wydane sa wazne.
	if liczCertyfikaty(t, trust.Bundle()) != 2 {
		t.Error("po przejeciu zbior musi zawierac stare i nowe CA")
	}
	if _, err := trust.Activate(); err == nil {
		t.Error("przejecie bez przygotowanego CA powinno zostac odrzucone")
	}
}

func TestZbiorPrzezywaRestart(t *testing.T) {
	dir := t.TempDir()
	trust, err := EnsureTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	przygotowane, err := trust.Prepare()
	if err != nil {
		t.Fatal(err)
	}

	// Panel restartuje sie w trakcie wymiany; stan musi przetrwac.
	ponownie, err := EnsureTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	pending, przygotowaneO := ponownie.Pending()
	if pending == nil {
		t.Fatal("przygotowane CA nie przetrwalo restartu")
	}
	if pending.Certificate.SerialNumber.String() != przygotowane.Serial {
		t.Error("po restarcie oczekuje inne CA niz przygotowane")
	}
	if przygotowaneO.IsZero() {
		t.Error("chwila przygotowania nie przetrwala restartu")
	}
	if przygotowaneO.After(time.Now()) {
		t.Error("chwila przygotowania nie moze byc z przyszlosci")
	}

	if _, err := ponownie.Activate(); err != nil {
		t.Fatal(err)
	}
	poAktywacji, err := EnsureTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	if poAktywacji.Active().Certificate.SerialNumber.String() != przygotowane.Serial {
		t.Error("po restarcie podpisuje inne CA niz zatwierdzone")
	}
	if pending, _ := poAktywacji.Pending(); pending != nil {
		t.Error("po przejeciu nie moze zostac CA oczekujace")
	}
	if liczCertyfikaty(t, poAktywacji.Bundle()) != 2 {
		t.Error("wycofane CA musi zostac w zbiorze zaufania")
	}
}

// TestZnacznikPrzygotowaniaJestOdporny sprawdza zachowanie przy braku pliku
// ze znacznikiem. Panel ma wtedy przyjac wartosc bezpieczna, a nie odmowic
// startu ani uznac, ze flota zna juz nowe CA.
func TestZnacznikPrzygotowaniaJestOdporny(t *testing.T) {
	dir := t.TempDir()
	trust, err := EnsureTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.Prepare(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, pendingAtFile)); err != nil {
		t.Fatal(err)
	}

	przed := time.Now()
	odtworzone, err := EnsureTrust(dir)
	if err != nil {
		t.Fatalf("brak znacznika zatrzymal panel: %v", err)
	}
	_, przygotowaneO := odtworzone.Pending()
	if przygotowaneO.Before(przed.Add(-time.Minute)) {
		t.Errorf("przyjeto zbyt wczesna chwile przygotowania: %s", przygotowaneO)
	}
	// Znacznik ma zostac zapisany, zeby kolejny restart go nie przesuwal.
	if _, err := os.Stat(filepath.Join(dir, pendingAtFile)); err != nil {
		t.Error("znacznik nie zostal odtworzony na dysku")
	}
}

func TestWycofanieChroniHosty(t *testing.T) {
	dir := t.TempDir()
	trust, err := EnsureTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	aktywneOdcisk := trust.Authorities()[0].Fingerprint
	if _, err := trust.Prepare(); err != nil {
		t.Fatal(err)
	}
	if _, err := trust.Activate(); err != nil {
		t.Fatal(err)
	}

	var wycofane string
	for _, ca := range trust.Authorities() {
		if ca.State == "retired" {
			wycofane = ca.Fingerprint
		}
	}
	if wycofane == "" {
		t.Fatal("brak wycofanego CA po przejeciu")
	}

	// Dopoki hosty maja certyfikaty z tego CA, usuniecie go odcieloby je.
	if err := trust.Retire(wycofane, 3); err == nil {
		t.Error("wycofanie uzywanego CA powinno zostac odrzucone")
	}
	if err := trust.Retire(aktywneOdcisk, 0); err != nil {
		// aktywneOdcisk jest teraz wycofany, wiec usuniecie jest dozwolone.
		t.Errorf("nieuzywane CA powinno dac sie usunac: %v", err)
	}
	if liczCertyfikaty(t, trust.Bundle()) != 1 {
		t.Error("po usunieciu w zbiorze ma zostac samo CA podpisujace")
	}
	if err := trust.Retire(trust.Authorities()[0].Fingerprint, 0); err == nil {
		t.Error("nie wolno usunac CA, ktore podpisuje")
	}
}
