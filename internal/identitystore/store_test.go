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

const hostTestowy = "3f2a9c1e-0000-4000-8000-000000000001"

// generacja wystawia komplet materialu przez to samo CA, ktorego uzywa panel.
func generacja(t *testing.T, ca *pki.CA, hostID string) Generacja {
	t.Helper()
	klucz, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: hostID}}, klucz)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	wydany, err := ca.SignAgentCSR(csrPEM, hostID)
	if err != nil {
		t.Fatal(err)
	}
	kluczDER, err := x509.MarshalECPrivateKey(klucz)
	if err != nil {
		t.Fatal(err)
	}
	return Generacja{
		KluczPEM:      pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kluczDER}),
		CertyfikatPEM: wydany.PEM,
		ZaufaniePEM:   ca.PEM,
	}
}

func magazynZTozsamoscia(t *testing.T) (*Magazyn, *pki.CA, string) {
	t.Helper()
	katalogCA := t.TempDir()
	ca, err := pki.EnsureCA(katalogCA)
	if err != nil {
		t.Fatal(err)
	}
	stan := t.TempDir()
	magazyn := Nowy(stan)
	if _, err := magazyn.Zatwierdz(generacja(t, ca, hostTestowy)); err != nil {
		t.Fatalf("pierwsza generacja: %v", err)
	}
	return magazyn, ca, stan
}

func TestZatwierdzenieDajeKompletnaTozsamosc(t *testing.T) {
	magazyn, _, _ := magazynZTozsamoscia(t)
	tozsamosc, err := magazyn.Biezaca()
	if err != nil {
		t.Fatalf("odczyt tozsamosci: %v", err)
	}
	if tozsamosc.HostID != hostTestowy {
		t.Fatalf("host_id = %q", tozsamosc.HostID)
	}
	// Klucz prywatny nie moze byc czytelny dla nikogo poza wlascicielem.
	info, err := os.Stat(filepath.Join(tozsamosc.Katalog, NazwaKlucza))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("prawa klucza = %04o", info.Mode().Perm())
	}
}

func TestOdnowienieZostawiaPoprzedniaGeneracje(t *testing.T) {
	magazyn, ca, _ := magazynZTozsamoscia(t)
	pierwsza, err := magazyn.Biezaca()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := magazyn.Zatwierdz(generacja(t, ca, hostTestowy)); err != nil {
		t.Fatalf("druga generacja: %v", err)
	}
	druga, err := magazyn.Biezaca()
	if err != nil {
		t.Fatal(err)
	}
	if druga.Katalog == pierwsza.Katalog {
		t.Fatal("odnowienie nie zmienilo generacji")
	}
	// Poprzednia zostaje: gdy nowa okaze sie zla, musi byc do czego wrocic.
	poprzednia, err := magazyn.Poprzednia()
	if err != nil {
		t.Fatalf("brak poprzedniej generacji: %v", err)
	}
	if poprzednia.Katalog != pierwsza.Katalog {
		t.Fatalf("poprzednia = %s, chcemy %s", poprzednia.Katalog, pierwsza.Katalog)
	}
}

func TestStareGeneracjeSaSprzatane(t *testing.T) {
	magazyn, ca, _ := magazynZTozsamoscia(t)
	for i := 0; i < 3; i++ {
		if _, err := magazyn.Zatwierdz(generacja(t, ca, hostTestowy)); err != nil {
			t.Fatalf("generacja %d: %v", i, err)
		}
	}
	nazwy, err := magazyn.generacje()
	if err != nil {
		t.Fatal(err)
	}
	// Klucz prywatny nie ma lezec na dysku dluzej, niz jest potrzebny.
	if len(nazwy) != GeneracjiDoZachowania {
		t.Fatalf("generacji na dysku = %d (%v)", len(nazwy), nazwy)
	}
	if _, err := magazyn.Biezaca(); err != nil {
		t.Fatalf("biezaca po sprzataniu: %v", err)
	}
}

// TestPrzerwanieZapisuNieNiszczyTozsamosci odtwarza punkty awarii z dokumentu.
//
// Kazdy z nich kiedys konczyl sie hostem, ktory ma klucz z jednej pary
// i certyfikat z drugiej - czyli hostem do odzyskania recznie.
func TestPrzerwanieZapisuNieNiszczyTozsamosci(t *testing.T) {
	magazyn, ca, _ := magazynZTozsamoscia(t)
	pierwsza, err := magazyn.Biezaca()
	if err != nil {
		t.Fatal(err)
	}
	generacje := filepath.Join(magazyn.Katalog(), KatalogGeneracji)

	t.Run("przerwanie po zapisie klucza", func(t *testing.T) {
		polowiczna, err := os.MkdirTemp(generacje, przedrostekNowej)
		if err != nil {
			t.Fatal(err)
		}
		nowa := generacja(t, ca, hostTestowy)
		if err := os.WriteFile(filepath.Join(polowiczna, NazwaKlucza), nowa.KluczPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		biezaca, err := magazyn.Biezaca()
		if err != nil || biezaca.Katalog != pierwsza.Katalog {
			t.Fatalf("biezaca = %+v, blad = %v", biezaca, err)
		}
		if err := magazyn.Sprzataj(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(polowiczna); !os.IsNotExist(err) {
			t.Fatal("polowiczny zapis zostal na dysku")
		}
	})

	t.Run("przerwanie przed przelaczeniem", func(t *testing.T) {
		nowa := generacja(t, ca, hostTestowy)
		numer, err := numerSeryjny(nowa.CertyfikatPEM)
		if err != nil {
			t.Fatal(err)
		}
		katalog := filepath.Join(generacje, numer)
		if err := os.MkdirAll(katalog, 0o700); err != nil {
			t.Fatal(err)
		}
		for nazwa, dane := range map[string][]byte{
			NazwaKlucza: nowa.KluczPEM, NazwaCertyfikatu: nowa.CertyfikatPEM,
			NazwaZaufania: nowa.ZaufaniePEM,
		} {
			if err := os.WriteFile(filepath.Join(katalog, nazwa), dane, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		// Generacja lezy kompletna, ale nikt na nia nie przelaczyl: host ma
		// dzialac dalej na poprzedniej.
		biezaca, err := magazyn.Biezaca()
		if err != nil || biezaca.Katalog != pierwsza.Katalog {
			t.Fatalf("biezaca = %+v, blad = %v", biezaca, err)
		}
		_ = os.RemoveAll(katalog)
	})

	t.Run("przerwanie po utworzeniu dowiazania tymczasowego", func(t *testing.T) {
		nastepna := filepath.Join(magazyn.Katalog(), nazwaNastepnej)
		if err := os.Symlink(filepath.Join(KatalogGeneracji, "nie-ma-takiej"), nastepna); err != nil {
			t.Fatal(err)
		}
		biezaca, err := magazyn.Biezaca()
		if err != nil || biezaca.Katalog != pierwsza.Katalog {
			t.Fatalf("biezaca = %+v, blad = %v", biezaca, err)
		}
		if err := magazyn.Sprzataj(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(nastepna); !os.IsNotExist(err) {
			t.Fatal("tymczasowe dowiazanie zostalo po sprzataniu")
		}
	})
}

func TestNiepasujacaParaJestOdrzucana(t *testing.T) {
	magazyn, ca, _ := magazynZTozsamoscia(t)
	pierwsza, err := magazyn.Biezaca()
	if err != nil {
		t.Fatal(err)
	}
	pierwszaGeneracja := generacja(t, ca, hostTestowy)
	drugaGeneracja := generacja(t, ca, hostTestowy)
	pomieszana := Generacja{
		KluczPEM:      pierwszaGeneracja.KluczPEM,
		CertyfikatPEM: drugaGeneracja.CertyfikatPEM,
		ZaufaniePEM:   ca.PEM,
	}
	if _, err := magazyn.Zatwierdz(pomieszana); !errors.Is(err, ErrParaKluczy) {
		t.Fatalf("blad = %v, chcemy %v", err, ErrParaKluczy)
	}
	// Odrzucenie musi nastapic przed jakakolwiek zmiana: host zostaje na tym,
	// co dzialalo.
	biezaca, err := magazyn.Biezaca()
	if err != nil || biezaca.Katalog != pierwsza.Katalog {
		t.Fatalf("biezaca = %+v, blad = %v", biezaca, err)
	}
}

func TestCertyfikatObcegoCAJestOdrzucany(t *testing.T) {
	magazyn, _, _ := magazynZTozsamoscia(t)
	obceCA, err := pki.EnsureCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	obca := generacja(t, obceCA, hostTestowy)
	nasze, err := magazyn.Biezaca()
	if err != nil {
		t.Fatal(err)
	}
	obca.ZaufaniePEM = nasze.ZaufaniePEM
	if _, err := magazyn.Zatwierdz(obca); !errors.Is(err, ErrLancuch) {
		t.Fatalf("blad = %v, chcemy %v", err, ErrLancuch)
	}
}

func TestMigracjaZeStaregoUkladu(t *testing.T) {
	katalogCA := t.TempDir()
	ca, err := pki.EnsureCA(katalogCA)
	if err != nil {
		t.Fatal(err)
	}
	stan := t.TempDir()
	stara := generacja(t, ca, hostTestowy)
	kluczPath := filepath.Join(stan, "agent.key")
	certPath := filepath.Join(stan, "agent.pem")
	caPath := filepath.Join(stan, "ca.pem")
	for sciezka, dane := range map[string][]byte{
		kluczPath: stara.KluczPEM, certPath: stara.CertyfikatPEM, caPath: stara.ZaufaniePEM,
	} {
		if err := os.WriteFile(sciezka, dane, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	magazyn := Nowy(stan)
	przeniesiona, err := magazyn.Migruj(kluczPath, certPath, caPath)
	if err != nil || !przeniesiona {
		t.Fatalf("migracja = %v, blad = %v", przeniesiona, err)
	}
	tozsamosc, err := magazyn.Biezaca()
	if err != nil || tozsamosc.HostID != hostTestowy {
		t.Fatalf("tozsamosc po migracji = %+v, blad = %v", tozsamosc, err)
	}
	// Oryginaly zostaja: poprzednia wersja agenta ma z czego wystartowac.
	if _, err := os.Stat(kluczPath); err != nil {
		t.Fatalf("stary klucz zniknal: %v", err)
	}
	// Druga migracja jest bezczynna - tozsamosc jest juz w magazynie.
	ponowna, err := magazyn.Migruj(kluczPath, certPath, caPath)
	if err != nil || ponowna {
		t.Fatalf("ponowna migracja = %v, blad = %v", ponowna, err)
	}
}
