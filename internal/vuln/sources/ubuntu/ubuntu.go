// Package ubuntu czyta dane OVAL Canonical.
//
// To jest zrodlo rozstrzygajace dla hostow Ubuntu. Canonical publikuje osobny
// plik dla kazdego wydania, a w nim definicje per CVE: ktory pakiet zrodlowy
// jest podatny i w ktorej wersji zostal naprawiony. Wersje sa backportowane,
// wiec wedlug numeracji upstream wygladaja na podatne.
//
// Czego to zrodlo nie mowi i czego panel po nim nie udaje:
//
// Kieszen. Poprawka wydana w esm-apps albo esm-infra wymaga subskrypcji Ubuntu
// Pro, a plik zapisuje kieszen wylacznie w komentarzu kryterium. Panel
// traktuje ja jak kazda inna poprawke producenta: "producent wydal" to os
// vendor_fix, a "da sie wziac z repozytorium tego hosta" to osobna os, ktora
// bez metadanych repozytoriow zostaje nieustalona. Zadna z nich nie obiecuje
// wiecej, niz panel sprawdzil.
//
// Jadro. OVAL rozstrzyga jadro po wersji tej, ktora aktualnie dziala. Panel
// ocenia pakiety zainstalowane, wiec stare jadro lezace obok dzialajacego tez
// dostaje znalezisko. To jest swiadome: podatny plik na dysku jest podatny,
// a "czy dziala" to pytanie, na ktore ocena pakietow nie odpowiada.
package ubuntu

import (
	"compress/bzip2"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/vuln"
	"github.com/ultherego/flotestro/internal/vuln/version"
)

// Dostawca jest nazwa zrodla zapisywana przy kazdym ustaleniu.
const Dostawca = "ubuntu"

// AdresDomyslny wskazuje katalog z danymi OVAL.
const AdresDomyslny = "https://security-metadata.canonical.com/oval/"

// Limity pobrania. Plik jednego wydania ma kilkanascie megabajtow spakowany
// i okolo dwustu rozpakowany; odpowiedz istotnie wieksza oznacza, ze
// pobieramy cos innego, niz myslimy - albo ze ktos podstawil bombe.
const (
	MaksymalnyRozmiarSpakowany = 256 << 20
	MaksymalnyRozmiar          = 2 << 30
)

// ErrBezZmian oznacza feed, ktory sie nie zmienil od ostatniego pobrania.
var ErrBezZmian = fmt.Errorf("feed nie zmienil sie od ostatniego pobrania")

// Zrodlo pobiera i parsuje dane OVAL Canonical.
type Zrodlo struct {
	Baza   string
	Client *http.Client
}

// Nowe tworzy zrodlo.
func Nowe(adres string, limit time.Duration) *Zrodlo {
	if adres == "" {
		adres = AdresDomyslny
	}
	if !strings.HasSuffix(adres, "/") {
		adres += "/"
	}
	if limit <= 0 {
		limit = 10 * time.Minute
	}
	return &Zrodlo{Baza: adres, Client: &http.Client{Timeout: limit}}
}

func (z *Zrodlo) Nazwa() string { return Dostawca }

// Pobierz sciaga dane dla wskazanych wydan i skleja je w jeden snapshot.
//
// Canonical publikuje plik na wydanie, wiec pobranie jest tyle razy, ile
// wydan ma flota. Wydanie, ktorego Canonical nie publikuje, nie trafia do
// snapshotu - i dobrze: host takiego wydania ma dostac powod "wydanie spoza
// feedu", a nie ciche zero znalezisk.
func (z *Zrodlo) Pobierz(ctx context.Context, wydania []string,
	etag string) (vuln.Snapshot, []vuln.Advisory, error) {
	snapshot := vuln.Snapshot{Provider: Dostawca}
	lista := append([]string(nil), wydania...)
	sort.Strings(lista)

	znaczniki := ParsujZnaczniki(etag)
	nowe := map[string]string{}
	var ustalenia []vuln.Advisory
	var objete, bezZmian []string
	var najnowszy time.Time
	var zmienilo, pobralismy bool
	for _, wydanie := range lista {
		wynik, err := z.pobierzWydanie(ctx, wydanie, znaczniki[wydanie])
		if err != nil {
			return snapshot, nil, err
		}
		if wynik.brakWydania {
			continue
		}
		pobralismy = true
		if wynik.bezZmian {
			bezZmian = append(bezZmian, wydanie)
			nowe[wydanie] = znaczniki[wydanie]
			objete = append(objete, wydanie)
			continue
		}
		zmienilo = true
		ustalenia = append(ustalenia, wynik.ustalenia...)
		nowe[wydanie] = wynik.etag
		objete = append(objete, wydanie)
		if wynik.zmodyfikowano.After(najnowszy) {
			najnowszy = wynik.zmodyfikowano
		}
	}

	if !pobralismy {
		return snapshot, nil, fmt.Errorf("zadne z wydan %v nie ma danych OVAL", lista)
	}
	if !zmienilo {
		return snapshot, nil, ErrBezZmian
	}
	// Snapshot jest jeden i musi byc kompletny: wydania, ktore odpowiedzialy
	// "bez zmian", pobieramy jeszcze raz bezwarunkowo. Inaczej zapisalibysmy
	// snapshot bez ich ustalen i ich hosty wygladalyby na czyste.
	for _, wydanie := range bezZmian {
		wynik, err := z.pobierzWydanie(ctx, wydanie, "")
		if err != nil {
			return snapshot, nil, err
		}
		if wynik.brakWydania {
			continue
		}
		ustalenia = append(ustalenia, wynik.ustalenia...)
		nowe[wydanie] = wynik.etag
		if wynik.zmodyfikowano.After(najnowszy) {
			najnowszy = wynik.zmodyfikowano
		}
	}

	Uporzadkuj(ustalenia)
	snapshot.Releases = objete
	snapshot.ETag = ZlozZnaczniki(nowe)
	snapshot.Digest = Odcisk(ustalenia)
	snapshot.AdvisoryCount = len(ustalenia)
	snapshot.FetchedAt = time.Now().UTC()
	if !najnowszy.IsZero() {
		chwila := najnowszy.UTC()
		snapshot.SourceModifiedAt = &chwila
	}
	return snapshot, ustalenia, nil
}

// wynikWydania jest jednym pobraniem jednego pliku wydania.
type wynikWydania struct {
	ustalenia     []vuln.Advisory
	etag          string
	zmodyfikowano time.Time
	bezZmian      bool
	brakWydania   bool
}

// pobierzWydanie sciaga i parsuje plik jednego wydania.
func (z *Zrodlo) pobierzWydanie(ctx context.Context, wydanie, etag string) (wynikWydania, error) {
	var wynik wynikWydania
	adres := z.Baza + "com.ubuntu." + wydanie + ".cve.oval.xml.bz2"
	zadanie, err := http.NewRequestWithContext(ctx, http.MethodGet, adres, nil)
	if err != nil {
		return wynik, err
	}
	if etag != "" {
		zadanie.Header.Set("If-None-Match", etag)
	}
	zadanie.Header.Set("User-Agent", "flotestro-vuln/1")

	odpowiedz, err := z.Client.Do(zadanie)
	if err != nil {
		return wynik, err
	}
	defer odpowiedz.Body.Close()

	switch odpowiedz.StatusCode {
	case http.StatusNotModified:
		wynik.bezZmian = true
		return wynik, nil
	case http.StatusNotFound, http.StatusGone:
		// Canonical nie publikuje tego wydania. To nie jest blad pobrania:
		// to odpowiedz "tego wydania nie obejmujemy".
		wynik.brakWydania = true
		return wynik, nil
	case http.StatusOK:
	default:
		return wynik, fmt.Errorf("OVAL %s odpowiedzial %s", wydanie, odpowiedz.Status)
	}
	wynik.etag = odpowiedz.Header.Get("ETag")
	if zmodyfikowano := odpowiedz.Header.Get("Last-Modified"); zmodyfikowano != "" {
		if chwila, err := http.ParseTime(zmodyfikowano); err == nil {
			wynik.zmodyfikowano = chwila
		}
	}

	// Dwa liczniki, bo sa dwa rozmiary: spakowany chroni lacze, rozpakowany
	// chroni pamiec. Archiwum o kilku megabajtach potrafi rozpakowac sie do
	// gigabajtow, a strumien urwany w polowie wygladalby na komplet.
	spakowany := &licznikBajtow{zrodlo: io.LimitReader(odpowiedz.Body, MaksymalnyRozmiarSpakowany+1)}
	rozpakowany := &licznikBajtow{
		zrodlo: io.LimitReader(bzip2.NewReader(spakowany), MaksymalnyRozmiar+1),
	}
	ustalenia, err := Parsuj(rozpakowany, wydanie)
	if spakowany.przeczytane > MaksymalnyRozmiarSpakowany {
		return wynik, fmt.Errorf("dane OVAL %s przekraczaja %d bajtow po pobraniu",
			wydanie, MaksymalnyRozmiarSpakowany)
	}
	if rozpakowany.przeczytane > MaksymalnyRozmiar {
		return wynik, fmt.Errorf("dane OVAL %s przekraczaja %d bajtow po rozpakowaniu",
			wydanie, MaksymalnyRozmiar)
	}
	if err != nil {
		return wynik, fmt.Errorf("OVAL %s: %w", wydanie, err)
	}
	wynik.ustalenia = ustalenia
	return wynik, nil
}

// licznikBajtow liczy, ile naprawde przeczytano ze strumienia.
type licznikBajtow struct {
	zrodlo      io.Reader
	przeczytane int64
}

func (l *licznikBajtow) Read(bufor []byte) (int, error) {
	ile, err := l.zrodlo.Read(bufor)
	l.przeczytane += int64(ile)
	return ile, err
}

// Elementy dokumentu OVAL, ktore cokolwiek rozstrzygaja. Reszty nie czytamy:
// dokument opisuje takze testy rodziny systemu i wydania, a te panel zna
// z inwentarza hosta.
type definicja struct {
	Klasa    string   `xml:"class,attr"`
	Metadane metadane `xml:"metadata"`
	Kryteria kryteria `xml:"criteria"`
}

type metadane struct {
	Tytul     string     `xml:"title"`
	Opis      string     `xml:"description"`
	Odnosniki []odnosnik `xml:"reference"`
	Advisory  wpisPorady `xml:"advisory"`
}

type odnosnik struct {
	Zrodlo string `xml:"source,attr"`
	RefID  string `xml:"ref_id,attr"`
}

type wpisPorady struct {
	Waga string  `xml:"severity"`
	Data string  `xml:"public_date"`
	CVE  wpisCVE `xml:"cve"`
}

type wpisCVE struct {
	Priorytet string `xml:"priority,attr"`
}

// kryteria sa drzewem: definicja jadra ma kryteria zagniezdzone na kilka
// poziomow, po jednym na wariant jadra.
type kryteria struct {
	Kryteria  []kryteria  `xml:"criteria"`
	Kryterium []kryterium `xml:"criterion"`
}

type kryterium struct {
	TestRef string `xml:"test_ref,attr"`
}

type wpisTestu struct {
	ID        string       `xml:"id,attr"`
	Komentarz string       `xml:"comment,attr"`
	Stan      odnosnikStan `xml:"state"`
}

type odnosnikStan struct {
	Ref string `xml:"state_ref,attr"`
}

type wpisStanu struct {
	ID      string   `xml:"id,attr"`
	EVR     *wartosc `xml:"evr"`
	Wartosc *wartosc `xml:"value"`
}

type wartosc struct {
	Operacja string `xml:"operation,attr"`
	Tresc    string `xml:",chardata"`
}

// testKorelacji jest tym, co z testu OVAL zostaje po tlumaczeniu na jezyk
// panelu: czyj to pakiet i ktory stan mowi o wersji naprawionej.
type testKorelacji struct {
	pakiet string
	stan   string
	jadro  bool
}

// wpisDefinicji jest definicja po odchudzeniu.
//
// Definicje sa w dokumencie przed testami, wiec musimy je przetrzymac do
// konca pliku - a w calosci nie zmieszcza sie w pamieci panelu: same opisy
// jednego wydania to grubo ponad sto megabajtow, bo Canonical dokleja do
// kazdego instrukcje aktualizacji dla kilkudziesieciu wariantow jadra.
// Zostawiamy z definicji tylko to, co trafi do ustalenia.
type wpisDefinicji struct {
	cve   string
	waga  string
	data  string
	tytul string
	testy []string
}

// odchudz zostawia z definicji to, co panel naprawde zapisze.
func odchudz(wpis definicja) wpisDefinicji {
	wynik := wpisDefinicji{
		waga:  Waga(wpis.Metadane.Advisory.CVE.Priorytet, wpis.Metadane.Advisory.Waga),
		data:  strings.TrimSpace(wpis.Metadane.Advisory.Data),
		tytul: skrocony(bezInstrukcji(wpis.Metadane.Opis)),
		testy: zbierzTesty(wpis.Kryteria),
	}
	if wynik.tytul == "" {
		wynik.tytul = skrocony(wpis.Metadane.Tytul)
	}
	for _, odn := range wpis.Metadane.Odnosniki {
		if strings.EqualFold(odn.Zrodlo, "CVE") {
			wynik.cve = strings.ToValidUTF8(odn.RefID, "")
			break
		}
	}
	return wynik
}

// Parsuj czyta dane OVAL jednego wydania i zwraca ustalenia panelu.
//
// Strumieniowo, bo plik wydania ma po rozpakowaniu okolo dwustu megabajtow.
// Definicje sa w dokumencie przed testami i stanami, wiec zlaczenie robimy na
// koncu - trzymamy z definicji tylko to, co do niego potrzebne.
func Parsuj(zrodlo io.Reader, wydanie string) ([]vuln.Advisory, error) {
	dekoder := xml.NewDecoder(zrodlo)
	var definicje []wpisDefinicji
	testy := map[string]testKorelacji{}
	stany := map[string]string{}
	zamkniete := false

	for {
		token, err := dekoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch element := token.(type) {
		case xml.StartElement:
			switch element.Name.Local {
			case "definition":
				var wpis definicja
				if err := dekoder.DecodeElement(&wpis, &element); err != nil {
					return nil, err
				}
				if wpis.Klasa == "vulnerability" {
					definicje = append(definicje, odchudz(wpis))
				}
			case "dpkginfo_test", "variable_test":
				var wpis wpisTestu
				if err := dekoder.DecodeElement(&wpis, &element); err != nil {
					return nil, err
				}
				jadro := element.Name.Local == "variable_test"
				if jadro && !strings.Contains(wpis.Komentarz, "kernel") {
					continue
				}
				// Nazwa pakietu zrodlowego jest w komentarzu testu:
				// struktura OVAL niesie w obiekcie tylko pakiety binarne,
				// a Canonical prowadzi bezpieczenstwo po zrodle.
				pakiet := wCudzyslowie(wpis.Komentarz)
				if pakiet == "" {
					continue
				}
				testy[wpis.ID] = testKorelacji{pakiet: pakiet, stan: wpis.Stan.Ref, jadro: jadro}
			case "dpkginfo_state", "variable_state":
				var wpis wpisStanu
				if err := dekoder.DecodeElement(&wpis, &element); err != nil {
					return nil, err
				}
				if wersja := wersjaStanu(wpis); wersja != "" {
					stany[wpis.ID] = wersja
				}
			}
		case xml.EndElement:
			if element.Name.Local == "oval_definitions" {
				zamkniete = true
			}
		}
	}

	// Dokument urwany w polowie konczy sie po prostu brakiem kolejnego
	// tokenu. Bez tego sprawdzenia panel dostalby polowe danych jako komplet
	// i uznal brakujace ustalenia za nieistniejace.
	if !zamkniete {
		return nil, fmt.Errorf("dokument OVAL urwany przed zamknieciem")
	}

	ustalenia := zlacz(definicje, testy, stany, wydanie)
	// Dane, ktorych nie umiemy przeczytac, nie sa danymi pustymi. Gdyby
	// Canonical zmienil ksztalt dokumentu, panel ma powiedziec "blad", a nie
	// pokazac floty bez podatnosci.
	if len(definicje) > 0 && len(ustalenia) == 0 {
		return nil, fmt.Errorf("dokument OVAL ma %d definicji, z ktorych zadna nic nie ustala",
			len(definicje))
	}
	Uporzadkuj(ustalenia)
	return ustalenia, nil
}

// wersjaStanu wyciaga wersje naprawiona ze stanu OVAL.
//
// Rozumiemy wylacznie porownanie "mniejsza niz": tak Canonical zapisuje
// "naprawione od tej wersji". Innego operatora nie zgadujemy - stan, ktorego
// nie rozumiemy, zostaje bez wersji i pakiet wyjdzie jako podatny bez
// poprawki, a nie jako naprawiony.
func wersjaStanu(wpis wpisStanu) string {
	for _, pole := range []*wartosc{wpis.EVR, wpis.Wartosc} {
		if pole == nil || pole.Operacja != "less than" {
			continue
		}
		if wersja := strings.TrimSpace(pole.Tresc); wersja != "" {
			return strings.ToValidUTF8(wersja, "")
		}
	}
	return ""
}

// stanPakietu jest ustaleniem dla jednego pakietu zrodlowego w jednym CVE.
type stanPakietu struct {
	status string
	wersja string
}

// zlacz laczy definicje z testami i stanami w ustalenia panelu.
func zlacz(definicje []wpisDefinicji, testy map[string]testKorelacji,
	stany map[string]string, wydanie string) []vuln.Advisory {
	var ustalenia []vuln.Advisory
	for _, wpis := range definicje {
		if wpis.cve == "" {
			continue
		}

		pakiety := map[string]stanPakietu{}
		for _, ref := range wpis.testy {
			test, ok := testy[ref]
			if !ok {
				continue
			}
			wersja := stany[test.stan]
			// Kryterium jadra bez wersji nie mowi o podatnosci, tylko
			// o tym, ktory wariant jadra dziala.
			if test.jadro && wersja == "" {
				continue
			}
			status := vuln.StatusOtwarte
			if wersja != "" {
				status = vuln.StatusNaprawione
			}
			pakiety[test.pakiet] = polacz(pakiety[test.pakiet], stanPakietu{status, wersja})
		}

		for pakiet, stan := range pakiety {
			ustalenia = append(ustalenia, ustalenie(wpis, wydanie, pakiet, stan))
		}
	}
	return ustalenia
}

// polacz rozstrzyga dwa ustalenia o tym samym pakiecie w jednym CVE.
//
// Jedno CVE potrafi opisac ten sam pakiet w kilku kieszeniach: w glownej bez
// poprawki, w esm-apps z poprawka. Wygrywa poprawka - producent ja wydal.
// Gdy wersji jest kilka, bierzemy najnizsza: to od niej pakiet zawiera
// poprawke, wiec host z wersja wyzsza jest naprawiony w kazdej z kieszeni.
func polacz(poprzedni, nowy stanPakietu) stanPakietu {
	if poprzedni.status == "" {
		return nowy
	}
	if poprzedni.status != vuln.StatusNaprawione {
		return nowy
	}
	if nowy.status != vuln.StatusNaprawione {
		return poprzedni
	}
	if version.PorownajDeb(nowy.wersja, poprzedni.wersja) < 0 {
		return nowy
	}
	return poprzedni
}

// zbierzTesty schodzi po drzewie kryteriow i zbiera odnosniki do testow.
func zbierzTesty(drzewo kryteria) []string {
	var refy []string
	for _, wpis := range drzewo.Kryterium {
		if wpis.TestRef != "" {
			refy = append(refy, wpis.TestRef)
		}
	}
	for _, galaz := range drzewo.Kryteria {
		refy = append(refy, zbierzTesty(galaz)...)
	}
	return refy
}

// ustalenie sklada jedno ustalenie panelu.
func ustalenie(wpis wpisDefinicji, wydanie, pakiet string, stan stanPakietu) vuln.Advisory {
	wynik := vuln.Advisory{
		Provider: Dostawca, AdvisoryID: wpis.cve, CVEIDs: []string{wpis.cve},
		Distribution: "ubuntu", Release: wydanie,
		SourcePackage:  strings.ToValidUTF8(pakiet, ""),
		Status:         stan.status,
		FixedVersion:   stan.wersja,
		VendorSeverity: wpis.waga,
		Title:          wpis.tytul,
		URL:            "https://ubuntu.com/security/" + wpis.cve,
	}
	if chwila, err := time.Parse(time.RFC3339, wpis.data); err == nil {
		chwilaUTC := chwila.UTC()
		wynik.PublishedAt = &chwilaUTC
	}
	return wynik
}

// Waga tlumaczy priorytet Canonical na wage producenta.
//
// "untriaged" nie jest waga: to brak wagi i tak ma zostac. Producent, ktory
// jeszcze nie ocenil, nie powiedzial "nieistotne".
func Waga(priorytet, waga string) string {
	for _, kandydat := range []string{priorytet, waga} {
		switch strings.ToLower(strings.TrimSpace(kandydat)) {
		case "critical":
			return "critical"
		case "high":
			return "high"
		case "medium":
			return "medium"
		case "low":
			return "low"
		case "negligible":
			return "negligible"
		}
	}
	return ""
}

// Uporzadkuj ustawia ustalenia w kolejnosci niezaleznej od kolejnosci
// pobrania: odcisk musi byc ten sam dla tych samych danych.
func Uporzadkuj(ustalenia []vuln.Advisory) {
	sort.Slice(ustalenia, func(i, j int) bool {
		if ustalenia[i].SourcePackage != ustalenia[j].SourcePackage {
			return ustalenia[i].SourcePackage < ustalenia[j].SourcePackage
		}
		if ustalenia[i].Release != ustalenia[j].Release {
			return ustalenia[i].Release < ustalenia[j].Release
		}
		return ustalenia[i].AdvisoryID < ustalenia[j].AdvisoryID
	})
}

// Odcisk liczy odcisk kanonicznej postaci ustalen.
func Odcisk(ustalenia []vuln.Advisory) string {
	suma := sha256.New()
	suma.Write([]byte("flotestro/vuln/ubuntu/v1\n"))
	for _, ustalenie := range ustalenia {
		suma.Write([]byte(strings.Join([]string{
			ustalenie.SourcePackage, ustalenie.Release, ustalenie.AdvisoryID,
			ustalenie.Status, ustalenie.FixedVersion, ustalenie.VendorSeverity,
		}, "\x1f")))
		suma.Write([]byte{'\n'})
	}
	return hex.EncodeToString(suma.Sum(nil))
}

// ParsujZnaczniki czyta znaczniki ETag zapisane przy poprzednim snapshocie.
//
// Snapshot jest jeden, a plikow tyle, ile wydan - wiec w jednym polu siedzi
// mapa "wydanie=znacznik". Wpisu, ktory nie ma tego ksztaltu, nie zgadujemy:
// gorzej niz pobrac za duzo jest nie pobrac zmiany.
func ParsujZnaczniki(etag string) map[string]string {
	znaczniki := map[string]string{}
	for _, wpis := range strings.Fields(etag) {
		wydanie, znacznik, ok := strings.Cut(wpis, "=")
		if !ok || wydanie == "" || znacznik == "" {
			continue
		}
		znaczniki[wydanie] = znacznik
	}
	return znaczniki
}

// ZlozZnaczniki zapisuje znaczniki wydan w jednym polu snapshotu.
func ZlozZnaczniki(znaczniki map[string]string) string {
	wydania := make([]string, 0, len(znaczniki))
	for wydanie := range znaczniki {
		wydania = append(wydania, wydanie)
	}
	sort.Strings(wydania)
	wpisy := make([]string, 0, len(wydania))
	for _, wydanie := range wydania {
		znacznik := znaczniki[wydanie]
		// Znacznik ze spacja rozpadlby sie przy odczycie na dwa wpisy.
		// Pomijamy go: pobranie bezwarunkowe jest tanszym bledem niz
		// pobranie warunkowe z bledna wartoscia.
		if znacznik == "" || strings.ContainsAny(znacznik, " \t\n") {
			continue
		}
		wpisy = append(wpisy, wydanie+"="+znacznik)
	}
	return strings.Join(wpisy, " ")
}

// wCudzyslowie zwraca pierwszy tekst w apostrofach.
func wCudzyslowie(tekst string) string {
	poczatek := strings.Index(tekst, "'")
	if poczatek < 0 {
		return ""
	}
	reszta := tekst[poczatek+1:]
	koniec := strings.Index(reszta, "'")
	if koniec <= 0 {
		return ""
	}
	return strings.ToValidUTF8(reszta[:koniec], "")
}

// bezInstrukcji ucina z opisu instrukcje aktualizacji.
//
// Canonical doklada do opisu liste pakietow do zainstalowania - dla kazdego
// wariantu jadra osobno. To jest instrukcja, a nie opis podatnosci, i po
// przycieciu do trzystu znakow zostawalaby z niej sama polowa pierwszej
// komendy.
func bezInstrukcji(opis string) string {
	if ciecie := strings.Index(opis, "Update Instructions:"); ciecie >= 0 {
		opis = opis[:ciecie]
	}
	return opis
}

// skrocony przycina opis do 300 znakow, a nie bajtow.
func skrocony(opis string) string {
	opis = strings.ToValidUTF8(strings.TrimSpace(opis), "")
	znaki := []rune(opis)
	if len(znaki) > 300 {
		return string(znaki[:300])
	}
	return opis
}
