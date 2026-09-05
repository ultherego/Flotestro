// Package debian czyta tracker bezpieczenstwa Debiana.
//
// To jest zrodlo rozstrzygajace dla hostow Debiana: mowi, ktora wersja pakietu
// zrodlowego zawiera poprawke w danym wydaniu. Wersje te sa backportowane,
// wiec wedlug numeracji upstream wygladaja na podatne - i zaden zakres
// z feedu upstreamowego ich nie obejmuje.
package debian

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/vuln"
)

// Dostawca jest nazwa zrodla zapisywana przy kazdym ustaleniu.
const Dostawca = "debian"

// AdresDomyslny wskazuje pelny zrzut trackera.
const AdresDomyslny = "https://security-tracker.debian.org/tracker/data/json"

// MaksymalnyRozmiar ogranicza pobranie. Zrzut ma kilkadziesiat megabajtow;
// odpowiedz istotnie wieksza oznacza, ze pobieramy cos innego, niz myslimy.
const MaksymalnyRozmiar = 512 << 20

// ErrBezZmian oznacza feed, ktory sie nie zmienil od ostatniego pobrania.
var ErrBezZmian = fmt.Errorf("feed nie zmienil sie od ostatniego pobrania")

// Zrodlo pobiera i parsuje zrzut trackera.
type Zrodlo struct {
	URL    string
	Client *http.Client
}

// Nowe tworzy zrodlo.
func Nowe(adres string, limit time.Duration) *Zrodlo {
	if adres == "" {
		adres = AdresDomyslny
	}
	if limit <= 0 {
		limit = 10 * time.Minute
	}
	return &Zrodlo{URL: adres, Client: &http.Client{Timeout: limit}}
}

func (z *Zrodlo) Nazwa() string { return Dostawca }

// wpisWydania jest opisem jednego wydania w ustaleniu trackera.
type wpisWydania struct {
	Status       string `json:"status"`
	Urgency      string `json:"urgency"`
	FixedVersion string `json:"fixed_version"`
	// NoDSA oznacza podatnosc, ktorej producent nie zamierza naprawiac
	// w tym wydaniu. To nie to samo, co brak poprawki: to decyzja.
	NoDSA       string `json:"nodsa"`
	NoDSAReason string `json:"nodsa_reason"`
}

// wpisCVE jest jednym ustaleniem dla pakietu zrodlowego.
type wpisCVE struct {
	Description string                 `json:"description"`
	Scope       string                 `json:"scope"`
	Releases    map[string]wpisWydania `json:"releases"`
}

// Pobierz sciaga zrzut i zamienia go na ustalenia dla wskazanych wydan.
//
// Filtrujemy po wydaniach floty, bo pelny zrzut opisuje kilkanascie wydan
// i kilkaset tysiecy ustalen - a panel potrzebuje tych, ktore dotycza hostow,
// ktore naprawde ma.
func (z *Zrodlo) Pobierz(ctx context.Context, wydania []string,
	etag string) (vuln.Snapshot, []vuln.Advisory, error) {
	snapshot := vuln.Snapshot{Provider: Dostawca, Releases: wydania}

	zadanie, err := http.NewRequestWithContext(ctx, http.MethodGet, z.URL, nil)
	if err != nil {
		return snapshot, nil, err
	}
	// Warunkowe pobranie: zrzut zmienia sie kilka razy dziennie, a ma
	// kilkadziesiat megabajtow. Pobieranie go co cykl bez potrzeby jest
	// kosztem, ktory ponosi takze druga strona.
	if etag != "" {
		zadanie.Header.Set("If-None-Match", etag)
	}
	// Naglowka Accept-Encoding nie ustawiamy sami: gdy zrobi to klient,
	// biblioteka przestaje rozpakowywac odpowiedz i do parsera trafia
	// strumien gzip. Zostawiony bibliotece, kompresja dziala i jest
	// rozpakowywana przezroczyscie.
	zadanie.Header.Set("User-Agent", "flotestro-vuln/1")

	odpowiedz, err := z.Client.Do(zadanie)
	if err != nil {
		return snapshot, nil, err
	}
	defer odpowiedz.Body.Close()

	if odpowiedz.StatusCode == http.StatusNotModified {
		return snapshot, nil, ErrBezZmian
	}
	if odpowiedz.StatusCode != http.StatusOK {
		return snapshot, nil, fmt.Errorf("tracker odpowiedzial %s", odpowiedz.Status)
	}
	snapshot.ETag = odpowiedz.Header.Get("ETag")
	if zmodyfikowano := odpowiedz.Header.Get("Last-Modified"); zmodyfikowano != "" {
		if chwila, err := http.ParseTime(zmodyfikowano); err == nil {
			chwilaUTC := chwila.UTC()
			snapshot.SourceModifiedAt = &chwilaUTC
		}
	}

	ustalenia, err := Parsuj(io.LimitReader(odpowiedz.Body, MaksymalnyRozmiar), wydania)
	if err != nil {
		return snapshot, nil, err
	}
	snapshot.Digest = Odcisk(ustalenia)
	snapshot.AdvisoryCount = len(ustalenia)
	snapshot.FetchedAt = time.Now().UTC()
	return snapshot, ustalenia, nil
}

// Parsuj czyta zrzut strumieniowo i zwraca ustalenia dla wskazanych wydan.
//
// Strumieniowo, bo zrzut ma kilkadziesiat megabajtow: wczytany w calosci do
// pamieci kosztowalby wielokrotnosc tego rozmiaru po zdekodowaniu.
func Parsuj(zrodlo io.Reader, wydania []string) ([]vuln.Advisory, error) {
	interesujace := map[string]bool{}
	for _, wydanie := range wydania {
		interesujace[wydanie] = true
	}

	dekoder := json.NewDecoder(zrodlo)
	if _, err := dekoder.Token(); err != nil {
		return nil, fmt.Errorf("zrzut trackera: %w", err)
	}

	var ustalenia []vuln.Advisory
	for dekoder.More() {
		klucz, err := dekoder.Token()
		if err != nil {
			return nil, err
		}
		pakiet, ok := klucz.(string)
		if !ok {
			return nil, fmt.Errorf("zrzut trackera: nieoczekiwany klucz %v", klucz)
		}
		var wpisy map[string]wpisCVE
		if err := dekoder.Decode(&wpisy); err != nil {
			return nil, fmt.Errorf("pakiet %s: %w", pakiet, err)
		}
		for nazwaCVE, wpis := range wpisy {
			for wydanie, opis := range wpis.Releases {
				if !interesujace[wydanie] {
					continue
				}
				ustalenia = append(ustalenia, ustalenieZWpisu(pakiet, nazwaCVE, wydanie, opis, wpis))
			}
		}
	}
	sort.Slice(ustalenia, func(i, j int) bool {
		if ustalenia[i].SourcePackage != ustalenia[j].SourcePackage {
			return ustalenia[i].SourcePackage < ustalenia[j].SourcePackage
		}
		if ustalenia[i].Release != ustalenia[j].Release {
			return ustalenia[i].Release < ustalenia[j].Release
		}
		return ustalenia[i].AdvisoryID < ustalenia[j].AdvisoryID
	})
	return ustalenia, nil
}

// ustalenieZWpisu tlumaczy jeden wpis trackera na ustalenie panelu.
func ustalenieZWpisu(pakiet, nazwaCVE, wydanie string, opis wpisWydania, wpis wpisCVE) vuln.Advisory {
	ustalenie := vuln.Advisory{
		Provider: Dostawca, AdvisoryID: nazwaCVE, CVEIDs: []string{nazwaCVE},
		Distribution: "debian", Release: wydanie, SourcePackage: pakiet,
		VendorSeverity: Waga(opis.Urgency),
		Title:          skrocony(wpis.Description),
		URL:            "https://security-tracker.debian.org/tracker/" + nazwaCVE,
	}
	ustalenie.Status, ustalenie.FixedVersion = Status(opis)
	// Wersje i identyfikatory tez czyscimy: zrzut jest tekstem z zewnatrz,
	// a jeden bledny bajt nie moze przewrocic calego importu.
	ustalenie.FixedVersion = strings.ToValidUTF8(ustalenie.FixedVersion, "")
	ustalenie.SourcePackage = strings.ToValidUTF8(ustalenie.SourcePackage, "")
	ustalenie.AdvisoryID = strings.ToValidUTF8(ustalenie.AdvisoryID, "")
	return ustalenie
}

// Status tlumaczy stan wpisu trackera na stan ustalenia.
//
// Tracker ma trzy stany i jedna pulapke: "resolved" z wersja naprawiona "0"
// nie znaczy "naprawione w wersji zero", tylko "to wydanie nigdy nie bylo
// podatne". Potraktowanie tego jako wersji dawaloby podatnosc na kazdym
// hoscie, bo kazda wersja jest wieksza od zera.
func Status(opis wpisWydania) (string, string) {
	switch opis.Status {
	case "resolved":
		if opis.FixedVersion == "" || opis.FixedVersion == "0" {
			return vuln.StatusNieDotyczy, ""
		}
		return vuln.StatusNaprawione, opis.FixedVersion
	case "open":
		if opis.NoDSA != "" || opis.NoDSAReason != "" {
			// Producent rozstrzygnal, ze nie wyda poprawki w tym wydaniu.
			// To jest odpowiedz, a nie brak odpowiedzi - i host nadal jest
			// podatny.
			return vuln.StatusOdroczone, ""
		}
		return vuln.StatusOtwarte, ""
	case "undetermined":
		return vuln.StatusBadane, ""
	}
	return vuln.StatusBadane, ""
}

// Waga tlumaczy pilnosc trackera na wage producenta.
func Waga(urgency string) string {
	switch strings.ToLower(strings.TrimSpace(urgency)) {
	case "high", "high**":
		return "high"
	case "medium", "medium**":
		return "medium"
	case "low", "low**":
		return "low"
	case "unimportant":
		return "unimportant"
	case "end-of-life":
		return "end-of-life"
	}
	// "not yet assigned" nie jest waga: to brak wagi i tak ma zostac.
	return ""
}

// Odcisk liczy odcisk kanonicznej postaci ustalen.
//
// Kanonizacja jest jawna: te same dane musza dac ten sam odcisk, inaczej
// panel co pobranie zakladalby nowy snapshot i przeliczal cala flote.
func Odcisk(ustalenia []vuln.Advisory) string {
	suma := sha256.New()
	suma.Write([]byte("flotestro/vuln/debian/v1\n"))
	for _, ustalenie := range ustalenia {
		suma.Write([]byte(strings.Join([]string{
			ustalenie.SourcePackage, ustalenie.Release, ustalenie.AdvisoryID,
			ustalenie.Status, ustalenie.FixedVersion, ustalenie.VendorSeverity,
		}, "\x1f")))
		suma.Write([]byte{'\n'})
	}
	return hex.EncodeToString(suma.Sum(nil))
}

// skrocony przycina opis do 300 znakow, a nie bajtow.
//
// Ciecie po bajtach rozcina znak wielobajtowy na pol i zostawia sekwencje,
// ktorej nie da sie zapisac w bazie: caly import konczyl sie wtedy bledem
// kodowania, a panel zostawal bez feedu. Opisy trackera sa po angielsku, ale
// cytuja nazwy i znaki interpunkcyjne spoza ASCII.
func skrocony(opis string) string {
	opis = strings.ToValidUTF8(strings.TrimSpace(opis), "")
	znaki := []rune(opis)
	if len(znaki) > 300 {
		return string(znaki[:300])
	}
	return opis
}
