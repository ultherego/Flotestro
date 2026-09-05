package certificates

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	filesmodul "github.com/ultherego/flotestro/internal/modules/files"
)

// Prawa domyslne. Certyfikat jest jawny i musi go przeczytac usluga; klucz
// nie jest jawny i nie moze go przeczytac nikt poza wlascicielem.
const (
	TrybCertyfikatu = "0644"
	TrybKlucza      = "0600"
)

// OknoSondy ogranicza czekanie na odpowiedz uslugi po przeladowaniu.
const OknoSondy = 10 * time.Second

// Wdrozenie opisuje jedna podmiane certyfikatu na hoscie.
//
// Klucz jest w tej strukturze jako bajty i tylko tutaj: przychodzi z magazynu
// tuz przed operacja, zyje w pamieci procesu przez czas jej trwania i nie
// trafia ani do wyniku, ani do dziennika, ani do zadnego pliku poza tym,
// ktory ma powstac.
type Wdrozenie struct {
	Path       string
	KeyPath    string
	Certyfikat []byte
	Klucz      []byte
	Owner      string
	Group      string
	Mode       string
	KeyMode    string
	Jednostka  string
	Cel        string
}

// Sprawdz weryfikuje material przed podmiana.
//
// Kolejnosc pytan jest tu cala trescia: certyfikat, ktory nie pasuje do
// klucza, zatrzyma usluge dopiero przy starcie - juz po tym, jak stary plik
// przestanie istniec. Dlatego wszystko, co da sie sprawdzic bez dotykania
// dysku, sprawdzamy przed pierwszym zapisem.
func Sprawdz(wdrozenie Wdrozenie, teraz time.Time) ([]*x509.Certificate, error) {
	if err := WalidujSciezke(wdrozenie.Path); err != nil {
		return nil, err
	}
	if wdrozenie.KeyPath != "" {
		if err := WalidujSciezke(wdrozenie.KeyPath); err != nil {
			return nil, err
		}
	}
	if err := WalidujJednostke(wdrozenie.Jednostka); err != nil {
		return nil, err
	}
	if err := WalidujCel(wdrozenie.Cel); err != nil {
		return nil, err
	}

	certy, err := ParsujPEM(wdrozenie.Certyfikat)
	if err != nil {
		return nil, err
	}
	if err := SprawdzTerminy(certy[0], teraz); err != nil {
		return nil, err
	}
	if err := SprawdzLancuch(certy); err != nil {
		return nil, err
	}
	if len(wdrozenie.Klucz) > 0 {
		if wdrozenie.KeyPath == "" {
			return nil, errors.New("klucz przyszedl z magazynu, ale zlecenie nie mowi, gdzie go zapisac")
		}
		if err := DopasujKlucz(certy[0], wdrozenie.Klucz); err != nil {
			return nil, err
		}
	}
	// Sonda ma sprawdzic ten certyfikat, a nie dowolny. Nazwa celu spoza
	// certyfikatu oznacza, ze test i tak nie potwierdzilby wdrozenia.
	if wdrozenie.Cel != "" {
		if gospodarz, _, err := net.SplitHostPort(wdrozenie.Cel); err == nil {
			if net.ParseIP(gospodarz) == nil && !Obejmuje(certy[0], gospodarz) {
				return nil, fmt.Errorf("certyfikat nie obejmuje nazwy %q, wiec sonda nie potwierdzi wdrozenia", gospodarz)
			}
		}
	}
	return certy, nil
}

// Kopia trzyma poprzednia zawartosc pliku na czas operacji.
//
// Kopia zyje w pamieci, a nie obok pliku: zapis starego klucza do drugiego
// pliku zostawilby na dysku klucz, ktorego nikt juz nie pilnuje - takze
// wtedy, gdy wdrozenie sie powiedzie.
type Kopia struct {
	Path     string
	Istnial  bool
	Tresc    []byte
	Tryb     os.FileMode
	UID, GID int
}

// Zapamietaj czyta plik, ktory za chwile zostanie podmieniony.
func Zapamietaj(sciezka string) (Kopia, error) {
	kopia := Kopia{Path: sciezka, Tryb: 0o644, UID: -1, GID: -1}
	if sciezka == "" {
		return kopia, nil
	}
	dane, err := CzytajPlik(sciezka)
	if errors.Is(err, os.ErrNotExist) {
		return kopia, nil
	}
	if err != nil {
		return kopia, err
	}
	info, err := os.Lstat(sciezka)
	if err != nil {
		return kopia, err
	}
	kopia.Istnial = true
	kopia.Tresc = dane
	kopia.Tryb = info.Mode().Perm()
	if uid, gid, ok := wlascicielPliku(info); ok {
		kopia.UID, kopia.GID = uid, gid
	}
	return kopia, nil
}

// Przywroc wraca do zapamietanej zawartosci pliku.
//
// Plik, ktorego przed operacja nie bylo, znika: powrot do stanu sprzed
// zmiany oznacza takze brak pliku, ktory zmiana stworzyla.
func (k Kopia) Przywroc() error {
	if k.Path == "" {
		return nil
	}
	if !k.Istnial {
		if err := os.Remove(k.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return filesmodul.ZapiszAtomowo(k.Path, k.Tresc, k.Tryb, k.UID, k.GID)
}

// Zapisz kladzie certyfikat i klucz na swoich miejscach.
//
// Klucz idzie pierwszy: usluga przeladowana miedzy jednym zapisem a drugim
// zobaczy stary certyfikat z nowym kluczem albo nowy certyfikat ze starym
// kluczem, a tylko pierwsza z tych par nie konczy sie bledem uzgadniania.
func Zapisz(wdrozenie Wdrozenie, uid, gid int) error {
	if len(wdrozenie.Klucz) > 0 {
		tryb, err := filesmodul.WalidujTryb(wartoscAlbo(wdrozenie.KeyMode, TrybKlucza))
		if err != nil {
			return err
		}
		if tryb.Perm()&0o044 != 0 {
			return fmt.Errorf("prawa %q pozwalaja czytac klucz prywatny poza wlascicielem",
				wartoscAlbo(wdrozenie.KeyMode, TrybKlucza))
		}
		if err := filesmodul.ZapiszAtomowo(wdrozenie.KeyPath, wdrozenie.Klucz, tryb, uid, gid); err != nil {
			return err
		}
	}
	tryb, err := filesmodul.WalidujTryb(wartoscAlbo(wdrozenie.Mode, TrybCertyfikatu))
	if err != nil {
		return err
	}
	return filesmodul.ZapiszAtomowo(wdrozenie.Path, wdrozenie.Certyfikat, tryb, uid, gid)
}

func wartoscAlbo(wartosc, domyslna string) string {
	if wartosc == "" {
		return domyslna
	}
	return wartosc
}

// WynikSondy opisuje to, co usluga pokazuje po przeladowaniu.
type WynikSondy struct {
	Target            string `json:"target"`
	Reachable         bool   `json:"reachable"`
	FingerprintSHA256 string `json:"fingerprint_sha256,omitempty"`
	Subject           string `json:"subject,omitempty"`
	NotAfter          string `json:"not_after,omitempty"`
	Error             string `json:"error,omitempty"`
}

// Sonda pyta usluge, czym sie teraz przedstawia.
//
// Polaczenie nie sprawdza zaufania i nie powinno: pytanie brzmi "czy usluga
// podaje ten certyfikat, ktory wlasnie wdrozylismy", a nie "czy ten host
// ufa temu urzedowi". Weryfikacja lancucha wobec magazynu zaufania hosta
// odrzucalaby kazdy certyfikat z wlasnego CA - czyli wiekszosc tych, ktore
// panel wdraza.
func Sonda(ctx context.Context, cel string) WynikSondy {
	wynik := WynikSondy{Target: cel}
	if err := WalidujCel(cel); err != nil || cel == "" {
		if err != nil {
			wynik.Error = err.Error()
		}
		return wynik
	}
	gospodarz, _, _ := net.SplitHostPort(cel)
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: OknoSondy},
		Config: &tls.Config{
			// Nazwe podajemy, zeby serwer wybral wlasciwy certyfikat przy
			// SNI; weryfikacje robimy sami, porownujac odcisk.
			ServerName:         gospodarz,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	}
	polaczenie, err := dialer.DialContext(ctx, "tcp", cel)
	if err != nil {
		wynik.Error = err.Error()
		return wynik
	}
	defer polaczenie.Close()

	stan := polaczenie.(*tls.Conn).ConnectionState()
	if len(stan.PeerCertificates) == 0 {
		wynik.Error = "usluga nie przedstawila certyfikatu"
		return wynik
	}
	lisc := stan.PeerCertificates[0]
	wynik.Reachable = true
	wynik.FingerprintSHA256 = Odcisk(lisc)
	wynik.Subject = lisc.Subject.String()
	wynik.NotAfter = lisc.NotAfter.UTC().Format(time.RFC3339)
	return wynik
}

// Potwierdza mowi, czy usluga pokazuje dokladnie ten certyfikat.
func (w WynikSondy) Potwierdza(odcisk string) bool {
	return w.Reachable && w.FingerprintSHA256 == odcisk
}
