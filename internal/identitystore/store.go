// Package identitystore trzyma tozsamosc agenta jako niepodzielne generacje.
//
// Klucz, certyfikat i bundle zaufania sa jedna caloscia. Zapisane osobno,
// kazde swoim atomowym zapisem, daja okno, w ktorym host ma klucz z jednej
// pary i certyfikat z drugiej - i nie potrafi sie juz zalogowac do floty.
// Odzyskanie takiego hosta wymaga wejscia na niego recznie, wiec to jest ta
// awaria, ktorej caly ten pakiet ma nie dopuscic.
//
// Nowa generacja powstaje obok, jest sprawdzana i fsyncowana, a dopiero potem
// wskazuje ja atomowo podmieniany dowiazanie "current". Poprzednia zostaje na
// dysku: gdy nowa okaze sie zla, jest do czego wrocic.
package identitystore

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/pki"
)

// Nazwy plikow i katalogow magazynu.
const (
	KatalogTozsamosci = "identity"
	KatalogGeneracji  = "generations"
	NazwaBiezacej     = "current"
	nazwaNastepnej    = ".current-next"
	przedrostekNowej  = ".new-"

	NazwaKlucza      = "agent.key"
	NazwaCertyfikatu = "agent.pem"
	NazwaZaufania    = "trust-bundle.pem"
)

// GeneracjiDoZachowania mowi, ile generacji zostaje na dysku.
//
// Biezaca i jedna poprzednia: wiecej nie jest do niczego potrzebne, a kazda
// z nich to klucz prywatny, ktory lepiej, zeby nie lezal dluzej niz musi.
const GeneracjiDoZachowania = 2

// Bledy magazynu. Kody sa czescia kontraktu z operatorem - to one pokazuja
// sie na hoscie, ktory nie ma polaczenia z panelem.
var (
	ErrBrakTozsamosci = errors.New("identity_missing")
	ErrParaKluczy     = errors.New("key_pair")
	ErrZaufanie       = errors.New("trust_bundle_invalid")
	ErrLancuch        = errors.New("certificate_chain")
	ErrTozsamoscCert  = errors.New("identity_uri_missing")
)

// Generacja jest kompletem materialu kryptograficznego hosta.
type Generacja struct {
	KluczPEM      []byte
	CertyfikatPEM []byte
	ZaufaniePEM   []byte
}

// Tozsamosc jest wczytana generacja gotowa do uzycia w polaczeniu.
type Tozsamosc struct {
	HostID      string
	Certificate tls.Certificate
	CAPool      *x509.CertPool
	NotBefore   time.Time
	NotAfter    time.Time
	// Katalog wskazuje generacje, z ktorej pochodzi ta tozsamosc.
	Katalog string
	// ZaufaniePEM zostaje w pamieci, bo odnowienie musi zapisac komplet
	// nawet wtedy, gdy panel nie przyslal nowego bundla.
	ZaufaniePEM []byte
}

// Magazyn zarzadza katalogiem tozsamosci hosta.
type Magazyn struct {
	root string
}

// Nowy tworzy magazyn w katalogu stanu agenta.
func Nowy(katalogStanu string) *Magazyn {
	return &Magazyn{root: filepath.Join(katalogStanu, KatalogTozsamosci)}
}

// Katalog zwraca katalog tozsamosci.
func (m *Magazyn) Katalog() string { return m.root }

// Sprawdz weryfikuje generacje przed jakakolwiek zmiana na dysku.
//
// Kolejnosc ma znaczenie: najpierw para klucz-certyfikat, potem lancuch do
// bundla zaufania, na koncu tozsamosc w certyfikacie. Kazde z nich osobno
// oznacza cos innego dla operatora.
func Sprawdz(g Generacja) error {
	para, err := tls.X509KeyPair(g.CertyfikatPEM, g.KluczPEM)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrParaKluczy, err)
	}
	lisc, err := x509.ParseCertificate(para.Certificate[0])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrParaKluczy, err)
	}
	korzenie := x509.NewCertPool()
	if !korzenie.AppendCertsFromPEM(g.ZaufaniePEM) {
		return ErrZaufanie
	}
	if _, err := lisc.Verify(x509.VerifyOptions{
		Roots:       korzenie,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime: time.Now(),
	}); err != nil {
		return fmt.Errorf("%w: %v", ErrLancuch, err)
	}
	if _, err := pki.HostIDFromCert(lisc); err != nil {
		return fmt.Errorf("%w: %v", ErrTozsamoscCert, err)
	}
	return nil
}

// Zatwierdz zapisuje nowa generacje i przelacza na nia "current".
//
// Kolejnosc jest cala trescia tej funkcji: nic nie przelacza tozsamosci, zanim
// komplet nie lezy na dysku i nie przejdzie weryfikacji. Przerwanie w kazdym
// punkcie zostawia hosta na poprzedniej, dzialajacej generacji.
func (m *Magazyn) Zatwierdz(g Generacja) (*Tozsamosc, error) {
	if err := Sprawdz(g); err != nil {
		return nil, err
	}
	generacje := filepath.Join(m.root, KatalogGeneracji)
	if err := os.MkdirAll(generacje, 0o700); err != nil {
		return nil, err
	}

	tymczasowy, err := os.MkdirTemp(generacje, przedrostekNowej)
	if err != nil {
		return nil, err
	}
	zatwierdzona := false
	defer func() {
		if !zatwierdzona {
			_ = os.RemoveAll(tymczasowy)
		}
	}()
	if err := os.Chmod(tymczasowy, 0o700); err != nil {
		return nil, err
	}

	// Klucz jest czytelny wylacznie dla wlasciciela; certyfikat i bundle nie
	// sa tajne i moga byc czytane przez narzedzia diagnostyczne.
	if err := zapiszZSync(filepath.Join(tymczasowy, NazwaKlucza), g.KluczPEM, 0o600); err != nil {
		return nil, err
	}
	if err := zapiszZSync(filepath.Join(tymczasowy, NazwaCertyfikatu), g.CertyfikatPEM, 0o644); err != nil {
		return nil, err
	}
	if err := zapiszZSync(filepath.Join(tymczasowy, NazwaZaufania), g.ZaufaniePEM, 0o644); err != nil {
		return nil, err
	}
	if err := syncKatalog(tymczasowy); err != nil {
		return nil, err
	}

	numer, err := numerSeryjny(g.CertyfikatPEM)
	if err != nil {
		return nil, err
	}
	docelowy := filepath.Join(generacje, numer)
	// Ten sam numer seryjny znaczy ten sam certyfikat: zapis powtorzony po
	// przerwanym starcie ma dac ten sam wynik, a nie blad.
	if _, err := os.Stat(docelowy); err == nil {
		if err := os.RemoveAll(docelowy); err != nil {
			return nil, err
		}
	}
	if err := os.Rename(tymczasowy, docelowy); err != nil {
		return nil, err
	}
	zatwierdzona = true
	if err := syncKatalog(generacje); err != nil {
		return nil, err
	}

	if err := m.przelacz(numer); err != nil {
		return nil, err
	}
	if err := m.Sprzataj(); err != nil {
		return nil, err
	}
	return m.Biezaca()
}

// przelacz podmienia dowiazanie "current" jednym atomowym ruchem.
func (m *Magazyn) przelacz(numer string) error {
	nastepna := filepath.Join(m.root, nazwaNastepnej)
	_ = os.Remove(nastepna)
	if err := os.Symlink(filepath.Join(KatalogGeneracji, numer), nastepna); err != nil {
		return err
	}
	if err := os.Rename(nastepna, filepath.Join(m.root, NazwaBiezacej)); err != nil {
		_ = os.Remove(nastepna)
		return err
	}
	return syncKatalog(m.root)
}

// Biezaca wczytuje tozsamosc wskazywana przez "current".
//
// Dowiazanie rozwiazujemy do prawdziwego katalogu generacji: to on jest
// odpowiedzia na pytanie "z czego host teraz korzysta", a nie sciezka
// dowiazania, ktora jest zawsze ta sama.
func (m *Magazyn) Biezaca() (*Tozsamosc, error) {
	katalog, err := filepath.EvalSymlinks(filepath.Join(m.root, NazwaBiezacej))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBrakTozsamosci, err)
	}
	return wczytaj(katalog)
}

// Poprzednia wczytuje generacje sprzed biezacej.
//
// Zostaje na dysku po to, zeby bylo do czego wrocic, gdy nowa okaze sie zla -
// na przyklad gdy panel wyda certyfikat, ktorego sam potem nie uznaje.
func (m *Magazyn) Poprzednia() (*Tozsamosc, error) {
	biezaca, err := os.Readlink(filepath.Join(m.root, NazwaBiezacej))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBrakTozsamosci, err)
	}
	nazwy, err := m.generacje()
	if err != nil {
		return nil, err
	}
	aktualna := filepath.Base(biezaca)
	for i := len(nazwy) - 1; i >= 0; i-- {
		if nazwy[i] == aktualna {
			continue
		}
		return wczytaj(filepath.Join(m.root, KatalogGeneracji, nazwy[i]))
	}
	return nil, ErrBrakTozsamosci
}

// Sprzataj usuwa slady przerwanych zapisow i nadmiarowe generacje.
//
// Wolane przy starcie i po kazdym zatwierdzeniu: katalog tymczasowy, ktory
// zostal po awarii, i dowiazanie ".current-next" sa smieciami, a nie stanem.
func (m *Magazyn) Sprzataj() error {
	// Dowiazanie tymczasowe nigdy nie jest tozsamoscia hosta: albo zdazylo
	// zostac przemianowane na "current", albo nie istnieje.
	_ = os.Remove(filepath.Join(m.root, nazwaNastepnej))

	generacje := filepath.Join(m.root, KatalogGeneracji)
	wpisy, err := os.ReadDir(generacje)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, wpis := range wpisy {
		if strings.HasPrefix(wpis.Name(), przedrostekNowej) {
			_ = os.RemoveAll(filepath.Join(generacje, wpis.Name()))
		}
	}

	biezaca := ""
	if cel, err := os.Readlink(filepath.Join(m.root, NazwaBiezacej)); err == nil {
		biezaca = filepath.Base(cel)
	}
	nazwy, err := m.generacje()
	if err != nil {
		return err
	}
	// Kasujemy od najstarszych i nigdy biezacej: generacja, na ktorej host
	// wlasnie pracuje, nie jest nadmiarowa nawet wtedy, gdy jest najstarsza.
	doUsuniecia := len(nazwy) - GeneracjiDoZachowania
	for i := 0; i < len(nazwy) && doUsuniecia > 0; i++ {
		if nazwy[i] == biezaca {
			continue
		}
		if err := os.RemoveAll(filepath.Join(generacje, nazwy[i])); err != nil {
			return err
		}
		doUsuniecia--
	}
	return nil
}

// generacje zwraca nazwy generacji uporzadkowane od najstarszej.
func (m *Magazyn) generacje() ([]string, error) {
	wpisy, err := os.ReadDir(filepath.Join(m.root, KatalogGeneracji))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	type wpisGeneracji struct {
		nazwa string
		czas  time.Time
	}
	var zebrane []wpisGeneracji
	for _, wpis := range wpisy {
		if !wpis.IsDir() || strings.HasPrefix(wpis.Name(), przedrostekNowej) {
			continue
		}
		info, err := wpis.Info()
		if err != nil {
			continue
		}
		zebrane = append(zebrane, wpisGeneracji{nazwa: wpis.Name(), czas: info.ModTime()})
	}
	sort.Slice(zebrane, func(i, j int) bool {
		if zebrane[i].czas.Equal(zebrane[j].czas) {
			return zebrane[i].nazwa < zebrane[j].nazwa
		}
		return zebrane[i].czas.Before(zebrane[j].czas)
	})
	nazwy := make([]string, 0, len(zebrane))
	for _, wpis := range zebrane {
		nazwy = append(nazwy, wpis.nazwa)
	}
	return nazwy, nil
}

// wczytaj czyta komplet z katalogu generacji.
func wczytaj(katalog string) (*Tozsamosc, error) {
	kluczPEM, err := os.ReadFile(filepath.Join(katalog, NazwaKlucza))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBrakTozsamosci, err)
	}
	certPEM, err := os.ReadFile(filepath.Join(katalog, NazwaCertyfikatu))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBrakTozsamosci, err)
	}
	zaufaniePEM, err := os.ReadFile(filepath.Join(katalog, NazwaZaufania))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBrakTozsamosci, err)
	}

	para, err := tls.X509KeyPair(certPEM, kluczPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParaKluczy, err)
	}
	lisc, err := x509.ParseCertificate(para.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParaKluczy, err)
	}
	pula := x509.NewCertPool()
	if !pula.AppendCertsFromPEM(zaufaniePEM) {
		return nil, ErrZaufanie
	}
	hostID, err := pki.HostIDFromCert(lisc)
	if err != nil {
		// Starsze certyfikaty floty moga nie miec URI SAN. Nazwa wlasna jest
		// wtedy jedynym, co host o sobie wie - i lepsza niz odmowa startu.
		hostID = lisc.Subject.CommonName
	}
	para.Leaf = lisc
	return &Tozsamosc{
		HostID: hostID, Certificate: para, CAPool: pula,
		NotBefore: lisc.NotBefore, NotAfter: lisc.NotAfter,
		Katalog: katalog, ZaufaniePEM: zaufaniePEM,
	}, nil
}

// numerSeryjny nazywa generacje numerem seryjnym certyfikatu.
//
// Nazwa musi byc rozna dla roznych certyfikatow i taka sama dla powtorzonego
// zapisu tego samego - numer seryjny spelnia jedno i drugie.
func numerSeryjny(certPEM []byte) (string, error) {
	blok, _ := pem.Decode(certPEM)
	if blok == nil {
		return "", fmt.Errorf("%w: certyfikat nie jest poprawnym PEM", ErrParaKluczy)
	}
	cert, err := x509.ParseCertificate(blok.Bytes)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrParaKluczy, err)
	}
	return cert.SerialNumber.Text(16), nil
}

// zapiszZSync zapisuje plik i wymusza jego trwalosc.
func zapiszZSync(sciezka string, dane []byte, tryb os.FileMode) error {
	plik, err := os.OpenFile(sciezka, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, tryb)
	if err != nil {
		return err
	}
	if _, err := plik.Write(dane); err != nil {
		plik.Close()
		return err
	}
	if err := plik.Sync(); err != nil {
		plik.Close()
		return err
	}
	return plik.Close()
}

// syncKatalog wymusza trwalosc samej zmiany nazw w katalogu.
func syncKatalog(sciezka string) error {
	katalog, err := os.Open(sciezka)
	if err != nil {
		return err
	}
	defer katalog.Close()
	return katalog.Sync()
}

// Migruj przenosi tozsamosc ze starego ukladu plikow do generacji.
//
// Host postawiony przed wprowadzeniem magazynu ma klucz, certyfikat i bundle
// luzem w katalogu stanu. Przeniesienie ich w calosc jest jednorazowe i nie
// kasuje oryginalow: gdyby cos poszlo nie tak, poprzednia wersja agenta ma
// z czego wystartowac.
//
// Zwraca true, gdy migracja naprawde sie odbyla.
func (m *Magazyn) Migruj(kluczPath, certPath, zaufaniePath string) (bool, error) {
	if _, err := os.Lstat(filepath.Join(m.root, NazwaBiezacej)); err == nil {
		return false, nil
	}
	kluczPEM, err := os.ReadFile(kluczPath)
	if err != nil {
		return false, nil
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return false, nil
	}
	zaufaniePEM, err := os.ReadFile(zaufaniePath)
	if err != nil {
		return false, nil
	}
	if err := os.MkdirAll(m.root, 0o700); err != nil {
		return false, err
	}
	if _, err := m.Zatwierdz(Generacja{
		KluczPEM: kluczPEM, CertyfikatPEM: certPEM, ZaufaniePEM: zaufaniePEM,
	}); err != nil {
		// Tozsamosc, ktorej nie da sie zweryfikowac, nie jest tozsamoscia do
		// przeniesienia: host musi przejsc enrollment jeszcze raz.
		return false, err
	}
	return true, nil
}
