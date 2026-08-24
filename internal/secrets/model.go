// Package secrets przechowuje wartosci, ktore nie moga przejsc przez zadania.
//
// Zasada jest jedna i twarda: wartosc sekretu nie pojawia sie w zadaniu, w
// audycie ani w inwentarzu. Zadanie niesie odnosnik - nazwe i wersje - a host
// siega po tresc dopiero wtedy, gdy zaczyna operacje, na podstawie krotkiej
// dzierzawy wystawionej dla tego jednego zadania. Panel zapisuje fakt wydania,
// nigdy wydana wartosc.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Granice sekretu. Klucz prywatny miesci sie w kilku kilobajtach; wartosc
// wieksza niz to nie jest sekretem, tylko plikiem.
const (
	MaksymalnaWartosc = 64 << 10
	DlugoscKlucza     = 32
)

// OknoDzierzawy ogranicza czas miedzy wydaniem dzierzawy a pobraniem wartosci.
//
// Dzierzawa jest krotka celowo: powstaje w chwili dostarczenia zadania hostowi
// i ma wystarczyc na jego wykonanie, a nie na cokolwiek pozniej.
const OknoDzierzawy = 5 * time.Minute

var (
	// ErrNotFound oznacza sekret albo wersje, ktorej nie ma.
	ErrNotFound = errors.New("nie ma takiego sekretu")
	// ErrRetired oznacza sekret wycofany: istnieje w historii, ale nie da sie
	// go juz wydac.
	ErrRetired = errors.New("sekret zostal wycofany")
	// ErrNoLease oznacza pobranie bez waznej dzierzawy - albo dzierzawe juz
	// zuzyta. Jedno i drugie jest odmowa, a nie bledem technicznym.
	ErrNoLease = errors.New("brak waznej dzierzawy tego sekretu")
	// ErrDestroyed oznacza wersje, ktorej tresc zostala zniszczona.
	ErrDestroyed = errors.New("tresc tej wersji zostala zniszczona")
)

var nazwaSekretu = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,62}$`)

// WalidujNazwe sprawdza nazwe sekretu.
//
// Nazwa trafia do zadan, do audytu i do interfejsu, wiec musi byc krotka,
// jednoznaczna i bez znakow, ktore cokolwiek przesloniaja.
func WalidujNazwe(nazwa string) error {
	if !nazwaSekretu.MatchString(nazwa) {
		return fmt.Errorf("nazwa sekretu %q: dozwolone male litery, cyfry, kropka, myslnik i podkreslenie (2-63 znaki)", nazwa)
	}
	return nil
}

// WalidujWartosc sprawdza tresc sekretu.
func WalidujWartosc(wartosc []byte) error {
	if len(wartosc) == 0 {
		return errors.New("sekret bez wartosci nie jest sekretem")
	}
	if len(wartosc) > MaksymalnaWartosc {
		return fmt.Errorf("wartosc jest wieksza niz %d bajtow", MaksymalnaWartosc)
	}
	return nil
}

// Secret to metadane sekretu. Struktura nie ma pola na wartosc i nie moze go
// miec: to ona jedzie do interfejsu i do API.
type Secret struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	Description    string     `json:"description,omitempty"`
	CurrentVersion int        `json:"current_version"`
	CreatedBy      string     `json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	RetiredAt      *time.Time `json:"retired_at,omitempty"`
	Versions       []Wersja   `json:"versions,omitempty"`
}

// Wydawalny mowi, czy z sekretu da sie jeszcze wydac wartosc.
func (s Secret) Wydawalny() bool { return s.RetiredAt == nil && s.CurrentVersion > 0 }

// Wersja opisuje jedna wersje sekretu - bez jej tresci.
type Wersja struct {
	Version   int        `json:"version"`
	SizeBytes int        `json:"size_bytes"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	Destroyed *time.Time `json:"destroyed_at,omitempty"`
}

// Dzierzawa uprawnia jeden host do pobrania jednej wersji jednego sekretu
// w ramach jednego zadania.
type Dzierzawa struct {
	ID         string     `json:"id"`
	SecretID   string     `json:"secret_id"`
	SecretName string     `json:"secret_name"`
	Version    int        `json:"version"`
	JobID      string     `json:"job_id"`
	HostID     string     `json:"host_id"`
	IssuedAt   time.Time  `json:"issued_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RedeemedAt *time.Time `json:"redeemed_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// Wazna mowi, czy dzierzawa uprawnia do pobrania w danej chwili.
func (d Dzierzawa) Wazna(teraz time.Time) bool {
	return d.RedeemedAt == nil && d.RevokedAt == nil && teraz.Before(d.ExpiresAt)
}

// Szyfr chroni wartosci sekretow kluczem spoza bazy.
//
// Klucz lezy w pliku, a nie w bazie: kopia bazy bez tego pliku nie wystarcza,
// zeby odczytac cokolwiek. To jest cala roznica miedzy magazynem sekretow
// a kolumna z hasłami.
type Szyfr struct {
	aead cipher.AEAD
}

// OtworzSzyfr wczytuje klucz z pliku, a przy jego braku zaklada nowy.
//
// Zakladamy klucz sami, bo panel bez magazynu sekretow nie umie czesci
// operacji, a odmowa startu byla by gorsza niz brak. Za to mowimy wprost, ze
// bez kopii tego pliku sekretow nie da sie odzyskac.
func OtworzSzyfr(sciezka string) (*Szyfr, bool, error) {
	klucz, err := os.ReadFile(sciezka)
	utworzony := false
	switch {
	case err == nil:
		if len(klucz) != DlugoscKlucza {
			return nil, false, fmt.Errorf("klucz magazynu sekretow ma %d bajtow zamiast %d",
				len(klucz), DlugoscKlucza)
		}
	case errors.Is(err, os.ErrNotExist):
		klucz = make([]byte, DlugoscKlucza)
		if _, err := io.ReadFull(rand.Reader, klucz); err != nil {
			return nil, false, err
		}
		if err := os.MkdirAll(filepath.Dir(sciezka), 0o700); err != nil {
			return nil, false, err
		}
		if err := os.WriteFile(sciezka, klucz, 0o600); err != nil {
			return nil, false, err
		}
		utworzony = true
	default:
		return nil, false, err
	}

	blok, err := aes.NewCipher(klucz)
	if err != nil {
		return nil, false, err
	}
	aead, err := cipher.NewGCM(blok)
	if err != nil {
		return nil, false, err
	}
	return &Szyfr{aead: aead}, utworzony, nil
}

// Zaszyfruj zwraca nonce i szyfrogram.
func (s *Szyfr) Zaszyfruj(wartosc []byte) (nonce, szyfrogram []byte, err error) {
	nonce = make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return nonce, s.aead.Seal(nil, nonce, wartosc, nil), nil
}

// Odszyfruj zwraca wartosc sekretu.
func (s *Szyfr) Odszyfruj(nonce, szyfrogram []byte) ([]byte, error) {
	return s.aead.Open(nil, nonce, szyfrogram, nil)
}

// Odcisk liczy sume kontrolna wartosci.
//
// Odcisk sluzy hostowi do sprawdzenia, ze dostal to, co panel wydal. Nie jest
// zapisywany w bazie ani w audycie: dla krotkiej wartosci sam odcisk bywa
// wskazowka, a magazyn ma nie zostawiac wskazowek.
func Odcisk(wartosc []byte) string {
	suma := sha256.Sum256(wartosc)
	return hex.EncodeToString(suma[:])
}
