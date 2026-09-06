// Package redhat czyta dane CSAF/VEX Red Hata.
//
// To jest zrodlo rozstrzygajace dla hostow RHEL. Red Hat publikuje jeden
// dokument VEX na CVE i mowi w nim trzy rzeczy naraz: ktore produkty sa
// podatne, ktorych to nie dotyczy i w ktorej wersji pakietu jest poprawka.
//
// Czytamy wylacznie bazowy RHEL. Strumienie EUS, AUS i E4S maja wlasne
// wersje poprawek i przysluguja tylko czesci klientow, a produkty warstwowe
// (OpenShift, RHEM) to osobne dystrybucje pakietow. Ustalenie z takiego
// strumienia opisywaloby host, ktorego panel nie ma przed soba.
//
// AlmaLinux, Rocky i CentOS Stream nie sa tu obslugiwane celowo: ich pakiety
// maja wlasne numery wersji, wiec ustalenia Red Hata mowilyby o czym innym.
// Do czasu, az panel przeczyta ich wlasne zrodla, ich hosty maja dostawac
// powod "brak feedu" - to jest uczciwsza odpowiedz niz cudza ocena.
package redhat

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/vuln"
	"github.com/ultherego/flotestro/internal/vuln/version"
)

// Dostawca jest nazwa zrodla zapisywana przy kazdym ustaleniu.
const Dostawca = "redhat"

// Dystrybucja jest nazwa dystrybucji, dla ktorej te ustalenia obowiazuja.
const Dystrybucja = "rhel"

type naglowek struct {
	Title    string `json:"title"`
	Tracking struct {
		ID                 string `json:"id"`
		InitialReleaseDate string `json:"initial_release_date"`
	} `json:"tracking"`
	AggregateSeverity struct {
		Text string `json:"text"`
	} `json:"aggregate_severity"`
}

type galaz struct {
	Category string  `json:"category"`
	Name     string  `json:"name"`
	Product  produkt `json:"product"`
	Branches []galaz `json:"branches"`
}

type produkt struct {
	ProductID string `json:"product_id"`
	Helper    struct {
		CPE string `json:"cpe"`
	} `json:"product_identification_helper"`
}

type relacja struct {
	Category        string `json:"category"`
	FullProductName struct {
		ProductID string `json:"product_id"`
	} `json:"full_product_name"`
	ProductReference string `json:"product_reference"`
	RelatesTo        string `json:"relates_to_product_reference"`
}

// Ustalenia tlumaczy jeden dokument VEX na ustalenia panelu.
//
// Bierze wylacznie wskazane wydania bazowego RHEL-a. Filtr jest tu, a nie
// wyzej, z powodu rozmiaru: dokument CVE, ktory dotyka wszystkich produktow
// producenta, ma kilkadziesiat megabajtow i kilkaset tysiecy identyfikatorow.
// Wczytany w calosci do pamieci kosztowalby wielokrotnosc tego rozmiaru,
// wiec czytamy go strumieniowo i odrzucamy obce produkty od razu.
func Ustalenia(dokument []byte, wydania map[string]bool) ([]vuln.Advisory, error) {
	dekoder := json.NewDecoder(bytes.NewReader(dokument))
	otwarcie, err := dekoder.Token()
	if err != nil {
		return nil, fmt.Errorf("dokument VEX: %w", err)
	}
	if otwarcie != json.Delim('{') {
		return nil, fmt.Errorf("dokument VEX zaczyna sie od %v, a nie od obiektu", otwarcie)
	}

	var naglowekDokumentu naglowek
	produkty := map[string]string{}
	strumienie := map[string]string{}
	drzewoPrzeczytane := false
	var wynik []vuln.Advisory

	for dekoder.More() {
		token, err := dekoder.Token()
		if err != nil {
			return nil, err
		}
		klucz, _ := token.(string)
		switch klucz {
		case "document":
			if err := dekoder.Decode(&naglowekDokumentu); err != nil {
				return nil, fmt.Errorf("naglowek dokumentu: %w", err)
			}
		case "product_tree":
			if err := czytajDrzewo(dekoder, wydania, produkty, strumienie); err != nil {
				return nil, err
			}
			drzewoPrzeczytane = true
		case "vulnerabilities":
			// Drzewo produktow jest w dokumencie przed podatnosciami i tylko
			// ono mowi, ktorego wydania dotyczy identyfikator. Dokument
			// w innej kolejnosci odrzucamy, zamiast zgadywac.
			if !drzewoPrzeczytane {
				return nil, fmt.Errorf("dokument VEX ma podatnosci przed drzewem produktow")
			}
			zebrane, err := czytajPodatnosci(dekoder, naglowekDokumentu, produkty, strumienie)
			if err != nil {
				return nil, err
			}
			wynik = append(wynik, zebrane...)
		default:
			if err := pomin(dekoder); err != nil {
				return nil, err
			}
		}
	}
	if _, err := dekoder.Token(); err != nil {
		return nil, fmt.Errorf("dokument VEX urwany przed zamknieciem: %w", err)
	}
	return wynik, nil
}

// czytajDrzewo czyta drzewo produktow: ktory produkt jest ktorym wydaniem
// i ktory identyfikator zlozony nalezy do ktorego strumienia.
func czytajDrzewo(dekoder *json.Decoder, wydania map[string]bool,
	produkty, strumienie map[string]string) error {
	otwarcie, err := dekoder.Token()
	if err != nil {
		return err
	}
	if otwarcie != json.Delim('{') {
		return fmt.Errorf("drzewo produktow nie jest obiektem")
	}
	for dekoder.More() {
		token, err := dekoder.Token()
		if err != nil {
			return err
		}
		klucz, _ := token.(string)
		switch klucz {
		case "branches":
			// Galezi jest kilkaset i to one nios CPE - je czytamy w calosci.
			var galezie []galaz
			if err := dekoder.Decode(&galezie); err != nil {
				return fmt.Errorf("galezie produktow: %w", err)
			}
			for _, wpis := range galezie {
				zbierzWydania(wpis, wydania, produkty)
			}
		case "relationships":
			if err := czytajRelacje(dekoder, produkty, strumienie); err != nil {
				return err
			}
		default:
			if err := pomin(dekoder); err != nil {
				return err
			}
		}
	}
	// Zamkniecie obiektu drzewa.
	_, err = dekoder.Token()
	return err
}

// czytajRelacje wiaze pakiety z produktami, pomijajac obce produkty od razu.
//
// Relacji jest w duzym dokumencie kilkanascie tysiecy i wiekszosc dotyczy
// produktow warstwowych. Trzymanie ich wszystkich w pamieci po to, zeby je
// zaraz odrzucic, jest tym, czego panel nie moze sobie pozwolic.
func czytajRelacje(dekoder *json.Decoder, produkty, strumienie map[string]string) error {
	otwarcie, err := dekoder.Token()
	if err != nil {
		return err
	}
	if otwarcie != json.Delim('[') {
		return fmt.Errorf("relacje produktow nie sa lista")
	}
	for dekoder.More() {
		var wpis relacja
		if err := dekoder.Decode(&wpis); err != nil {
			return fmt.Errorf("relacja produktu: %w", err)
		}
		if wpis.FullProductName.ProductID == "" || wpis.RelatesTo == "" {
			continue
		}
		if produkty[wpis.RelatesTo] == "" {
			continue
		}
		strumienie[wpis.FullProductName.ProductID] = wpis.RelatesTo
	}
	_, err = dekoder.Token()
	return err
}

// czytajPodatnosci sklada ustalenia wszystkich podatnosci dokumentu.
func czytajPodatnosci(dekoder *json.Decoder, naglowekDokumentu naglowek,
	produkty, strumienie map[string]string) ([]vuln.Advisory, error) {
	otwarcie, err := dekoder.Token()
	if err != nil {
		return nil, err
	}
	if otwarcie != json.Delim('[') {
		return nil, fmt.Errorf("podatnosci nie sa lista")
	}
	waga := strings.ToLower(strings.TrimSpace(naglowekDokumentu.AggregateSeverity.Text))
	var wynik []vuln.Advisory
	for dekoder.More() {
		zebrane, err := czytajPodatnosc(dekoder, naglowekDokumentu, waga, produkty, strumienie)
		if err != nil {
			return nil, err
		}
		wynik = append(wynik, zebrane...)
	}
	if _, err := dekoder.Token(); err != nil {
		return nil, err
	}
	return wynik, nil
}

// stanProduktu jest jednym identyfikatorem produktu ze stanem, ktory
// producent mu przypisal.
type stanProduktu struct {
	id     string
	status string
}

// czytajPodatnosc sklada ustalenia jednej podatnosci.
//
// Klucze dokumentu ida alfabetycznie, wiec stany produktow przychodza przed
// naprawami i przed tytulem. Zbieramy najpierw stany - juz przefiltrowane do
// bazowego RHEL-a - a rozstrzygamy je dopiero, gdy caly obiekt jest odczytany.
func czytajPodatnosc(dekoder *json.Decoder, naglowekDokumentu naglowek, waga string,
	produkty, strumienie map[string]string) ([]vuln.Advisory, error) {
	otwarcie, err := dekoder.Token()
	if err != nil {
		return nil, err
	}
	if otwarcie != json.Delim('{') {
		return nil, fmt.Errorf("podatnosc nie jest obiektem")
	}

	var numerCVE, tytul, dataWydania string
	var stany []stanProduktu
	errata := map[string]string{}
	bezPlanu := map[string]bool{}

	for dekoder.More() {
		token, err := dekoder.Token()
		if err != nil {
			return nil, err
		}
		klucz, _ := token.(string)
		switch klucz {
		case "cve":
			if err := dekoder.Decode(&numerCVE); err != nil {
				return nil, err
			}
		case "title":
			if err := dekoder.Decode(&tytul); err != nil {
				return nil, err
			}
		case "release_date":
			if err := dekoder.Decode(&dataWydania); err != nil {
				return nil, err
			}
		case "product_status":
			zebrane, err := czytajStany(dekoder, produkty, strumienie)
			if err != nil {
				return nil, err
			}
			stany = append(stany, zebrane...)
		case "remediations":
			if err := czytajNaprawy(dekoder, produkty, strumienie, errata, bezPlanu); err != nil {
				return nil, err
			}
		default:
			if err := pomin(dekoder); err != nil {
				return nil, err
			}
		}
	}
	if _, err := dekoder.Token(); err != nil {
		return nil, err
	}

	numerCVE = strings.ToValidUTF8(strings.TrimSpace(numerCVE), "")
	if numerCVE == "" || len(stany) == 0 {
		return nil, nil
	}
	if tytul == "" {
		tytul = naglowekDokumentu.Title
	}
	return zloz(stany, numerCVE, skrocony(tytul), waga, dataWydania,
		naglowekDokumentu, produkty, strumienie, errata, bezPlanu), nil
}

// czytajStany czyta stany produktow, zostawiajac tylko bazowy RHEL.
func czytajStany(dekoder *json.Decoder, produkty, strumienie map[string]string) ([]stanProduktu, error) {
	otwarcie, err := dekoder.Token()
	if err != nil {
		return nil, err
	}
	if otwarcie != json.Delim('{') {
		return nil, fmt.Errorf("stany produktow nie sa obiektem")
	}
	var zebrane []stanProduktu
	for dekoder.More() {
		token, err := dekoder.Token()
		if err != nil {
			return nil, err
		}
		klucz, _ := token.(string)
		status := ""
		switch klucz {
		case "fixed":
			status = vuln.StatusNaprawione
		case "known_affected":
			status = vuln.StatusOtwarte
		case "under_investigation":
			status = vuln.StatusBadane
		}
		// Stanu "nie dotyczy" nie zapisujemy: korelator i tak nie robi z niego
		// znaleziska, a producent wymienia w nim tysiace pakietow na CVE.
		if status == "" {
			if err := pomin(dekoder); err != nil {
				return nil, err
			}
			continue
		}
		identyfikatory, err := czytajIdentyfikatory(dekoder, produkty, strumienie)
		if err != nil {
			return nil, err
		}
		for _, id := range identyfikatory {
			zebrane = append(zebrane, stanProduktu{id: id, status: status})
		}
	}
	_, err = dekoder.Token()
	return zebrane, err
}

// czytajIdentyfikatory czyta liste identyfikatorow produktow i zostawia te,
// ktore dotycza wydan branych pod uwage.
func czytajIdentyfikatory(dekoder *json.Decoder, produkty, strumienie map[string]string) ([]string, error) {
	otwarcie, err := dekoder.Token()
	if err != nil {
		return nil, err
	}
	if otwarcie != json.Delim('[') {
		return nil, fmt.Errorf("lista produktow nie jest lista")
	}
	var wynik []string
	for dekoder.More() {
		var id string
		if err := dekoder.Decode(&id); err != nil {
			return nil, err
		}
		if nasz(id, produkty, strumienie) {
			wynik = append(wynik, id)
		}
	}
	_, err = dekoder.Token()
	return wynik, err
}

// czytajNaprawy czyta naprawy, zostawiajac errate i decyzje "nie naprawimy".
func czytajNaprawy(dekoder *json.Decoder, produkty, strumienie map[string]string,
	errata map[string]string, bezPlanu map[string]bool) error {
	otwarcie, err := dekoder.Token()
	if err != nil {
		return err
	}
	if otwarcie != json.Delim('[') {
		return fmt.Errorf("naprawy nie sa lista")
	}
	for dekoder.More() {
		otwarcieNaprawy, err := dekoder.Token()
		if err != nil {
			return err
		}
		if otwarcieNaprawy != json.Delim('{') {
			return fmt.Errorf("naprawa nie jest obiektem")
		}
		var kategoria, adres string
		var identyfikatory []string
		for dekoder.More() {
			token, err := dekoder.Token()
			if err != nil {
				return err
			}
			klucz, _ := token.(string)
			switch klucz {
			case "category":
				if err := dekoder.Decode(&kategoria); err != nil {
					return err
				}
			case "url":
				if err := dekoder.Decode(&adres); err != nil {
					return err
				}
			case "product_ids":
				identyfikatory, err = czytajIdentyfikatory(dekoder, produkty, strumienie)
				if err != nil {
					return err
				}
			default:
				if err := pomin(dekoder); err != nil {
					return err
				}
			}
		}
		if _, err := dekoder.Token(); err != nil {
			return err
		}
		switch kategoria {
		case "vendor_fix":
			for _, id := range identyfikatory {
				errata[id] = adres
			}
		case "no_fix_planned":
			for _, id := range identyfikatory {
				bezPlanu[id] = true
			}
		}
	}
	_, err = dekoder.Token()
	return err
}

// nasz mowi, czy identyfikator produktu dotyczy wydania, ktore czytamy.
func nasz(id string, produkty, strumienie map[string]string) bool {
	if strumienie[id] != "" {
		return true
	}
	produktID, _, ok := strings.Cut(id, ":")
	return ok && produkty[produktID] != ""
}

// pomin przeskakuje wartosc, ktorej panel nie czyta.
//
// Same opisy i oceny CVSS to wiekszosc objetosci dokumentu, a nie wnosza nic
// do odpowiedzi "czy ten pakiet jest podatny".
func pomin(dekoder *json.Decoder) error {
	token, err := dekoder.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') && token != json.Delim('[') {
		return nil
	}
	poziom := 1
	for poziom > 0 {
		token, err := dekoder.Token()
		if err != nil {
			return err
		}
		switch token {
		case json.Delim('{'), json.Delim('['):
			poziom++
		case json.Delim('}'), json.Delim(']'):
			poziom--
		}
	}
	return nil
}

// klucz jednoznacznie wskazuje pakiet w wydaniu: po nim scalamy ustalenia
// z kilku strumieni tego samego wydania.
type klucz struct {
	wydanie string
	pakiet  string
}

// zloz rozstrzyga zebrane stany produktow w ustalenia panelu.
func zloz(stany []stanProduktu, numerCVE, tytul, waga, dataWydania string,
	naglowekDokumentu naglowek, produkty, strumienie map[string]string,
	errata map[string]string, bezPlanu map[string]bool) []vuln.Advisory {
	opublikowano := data(dataWydania, naglowekDokumentu.Tracking.InitialReleaseDate)
	zebrane := map[klucz]vuln.Advisory{}
	for _, stan := range stany {
		wydanie, pakiet, wersja, ok := rozbij(stan.id, produkty, strumienie)
		if !ok {
			continue
		}
		status := stan.status
		if status == vuln.StatusOtwarte && bezPlanu[stan.id] {
			// Producent rozstrzygnal, ze nie wyda poprawki. To jest
			// odpowiedz, a nie brak odpowiedzi - i host nadal jest podatny.
			status = vuln.StatusOdroczone
		}
		nowe := vuln.Advisory{
			Provider: Dostawca, AdvisoryID: numerCVE, CVEIDs: []string{numerCVE},
			Distribution: Dystrybucja, Release: wydanie,
			// Rodzina RPM koreluje po pakiecie binarnym: ustalenie Red Hata
			// mowi o konkretnej wersji do zainstalowania, a nie o zrodle.
			SourcePackage: pakiet, BinaryPackage: pakiet,
			FixedVersion: wersja, Status: status, VendorSeverity: waga,
			Title: tytul, URL: odnosnik(errata[stan.id], numerCVE),
			PublishedAt: opublikowano,
		}
		if numer := numerErraty(errata[stan.id]); numer != "" {
			nowe.AdvisoryID = numer
		}
		wpisz(zebrane, klucz{wydanie, pakiet}, nowe)
	}

	wynik := make([]vuln.Advisory, 0, len(zebrane))
	for _, ustalenie := range zebrane {
		wynik = append(wynik, ustalenie)
	}
	return wynik
}

// wpisz scala ustalenia o tym samym pakiecie w tym samym wydaniu.
//
// Jedno wydanie ma kilka strumieni (BaseOS, AppStream) i kilka architektur,
// a poprawka jest wydana w kazdym osobno - z tym samym numerem wersji, bo
// producent buduje ja raz. Wygrywa poprawka, a z kilku wersji ta najnizsza:
// od niej pakiet zawiera poprawke, wiec host z wersja wyzsza jest naprawiony.
func wpisz(zebrane map[klucz]vuln.Advisory, gdzie klucz, nowe vuln.Advisory) {
	poprzednie, jest := zebrane[gdzie]
	if !jest {
		zebrane[gdzie] = nowe
		return
	}
	if poprzednie.Status != vuln.StatusNaprawione {
		zebrane[gdzie] = nowe
		return
	}
	if nowe.Status != vuln.StatusNaprawione {
		return
	}
	if version.PorownajRPM(nowe.FixedVersion, poprzednie.FixedVersion) < 0 {
		zebrane[gdzie] = nowe
	}
}

// rozbij tlumaczy identyfikator produktu na wydanie, pakiet i wersje.
//
// Identyfikator ma dwie postacie: "produkt:pakiet" dla podatnosci bez
// poprawki i "strumien:NEVRA" dla wersji naprawionej.
//
// Architektury nie zapisujemy. Producent buduje poprawke raz i wydaje ja pod
// tym samym numerem dla kazdej architektury, wiec ustalenie na architekture
// bylo by tym samym zdaniem powiedzianym piec razy.
func rozbij(id string, produkty, strumienie map[string]string) (string, string, string, bool) {
	produktID, reszta, ok := strings.Cut(id, ":")
	if !ok || reszta == "" {
		return "", "", "", false
	}
	// Identyfikator zlozony wskazuje strumien przez relacje; prosty wskazuje
	// produkt wprost.
	odniesienie := produktID
	if cel, jest := strumienie[id]; jest {
		odniesienie = cel
	}
	wydanie := produkty[odniesienie]
	if wydanie == "" {
		return "", "", "", false
	}
	// Komponenty kontenerowe maja w nazwie sciezke obrazu, a nie pakiet
	// systemowy - panel nie ma ich na liscie pakietow hosta.
	if strings.Contains(reszta, "/") {
		return "", "", "", false
	}
	if !strings.Contains(reszta, ":") {
		return wydanie, strings.ToValidUTF8(reszta, ""), "", true
	}
	nazwa, arch, wersja, ok := RozbijNEVRA(reszta)
	if !ok || arch == "src" {
		// Pakiet zrodlowy nie jest zainstalowany na hoscie, wiec ustalenie
		// o nim nie ma czego dotyczyc.
		return "", "", "", false
	}
	return wydanie, nazwa, wersja, true
}

// RozbijNEVRA rozklada "nazwa-epoka:wersja-wydanie.arch" na czesci.
func RozbijNEVRA(nevra string) (string, string, string, bool) {
	kropka := strings.LastIndex(nevra, ".")
	if kropka <= 0 {
		return "", "", "", false
	}
	arch := nevra[kropka+1:]
	reszta := nevra[:kropka]

	dwukropek := strings.Index(reszta, ":")
	if dwukropek <= 0 {
		return "", "", "", false
	}
	lewa, prawa := reszta[:dwukropek], reszta[dwukropek+1:]
	mysnik := strings.LastIndex(lewa, "-")
	if mysnik <= 0 || prawa == "" {
		return "", "", "", false
	}
	nazwa, epoka := lewa[:mysnik], lewa[mysnik+1:]
	wersja := prawa
	// Epoke zapisujemy tak samo jak host: zero jest domyslne i nie nalezy
	// do numeru wersji.
	if epoka != "" && epoka != "0" {
		wersja = epoka + ":" + wersja
	}
	return strings.ToValidUTF8(nazwa, ""), strings.ToValidUTF8(arch, ""),
		strings.ToValidUTF8(wersja, ""), true
}

// zbierzWydania schodzi po drzewie produktow i zapisuje wydanie kazdego
// produktu, ktory jest bazowym RHEL-em z branych pod uwage wydan.
func zbierzWydania(wpis galaz, wydania map[string]bool, produkty map[string]string) {
	if wpis.Product.ProductID != "" {
		if wydanie := WydanieZCPE(wpis.Product.Helper.CPE); wydanie != "" {
			if len(wydania) == 0 || wydania[wydanie] {
				produkty[wpis.Product.ProductID] = wydanie
			}
		}
	}
	for _, galezie := range wpis.Branches {
		zbierzWydania(galezie, wydania, produkty)
	}
}

// WydanieZCPE zwraca wydanie bazowego RHEL-a albo puste, gdy CPE opisuje
// inny produkt.
//
// Bazowy RHEL ma w CPE "enterprise_linux". Strumienie rozszerzone
// (rhel_eus, rhel_aus, rhel_e4s, rhel_tus) maja wlasne nazwy i wlasne wersje
// poprawek - host, ktory ich nie kupil, nie moze byc nimi oceniany.
func WydanieZCPE(cpe string) string {
	czesci := strings.Split(cpe, ":")
	if len(czesci) < 5 {
		return ""
	}
	if czesci[2] != "redhat" || czesci[3] != "enterprise_linux" {
		return ""
	}
	wersja := czesci[4]
	if glowna, _, ok := strings.Cut(wersja, "."); ok {
		wersja = glowna
	}
	if wersja == "" {
		return ""
	}
	for _, znak := range wersja {
		if znak < '0' || znak > '9' {
			return ""
		}
	}
	return wersja
}

// numerErraty wyciaga identyfikator erraty z odnosnika producenta.
func numerErraty(url string) string {
	ciecie := strings.LastIndex(url, "/")
	if ciecie < 0 {
		return ""
	}
	numer := url[ciecie+1:]
	if !strings.HasPrefix(numer, "RHSA-") && !strings.HasPrefix(numer, "RHBA-") &&
		!strings.HasPrefix(numer, "RHEA-") {
		return ""
	}
	return strings.ToValidUTF8(numer, "")
}

// odnosnik wskazuje errate producenta, a gdy jej nie ma - strone CVE.
func odnosnik(errata, numerCVE string) string {
	if errata != "" {
		return strings.ToValidUTF8(errata, "")
	}
	return "https://access.redhat.com/security/cve/" + numerCVE
}

// skrocony przycina tytul do 300 znakow, a nie bajtow.
func skrocony(tytul string) string {
	tytul = strings.ToValidUTF8(strings.TrimSpace(tytul), "")
	znaki := []rune(tytul)
	if len(znaki) > 300 {
		return string(znaki[:300])
	}
	return tytul
}

// data czyta pierwsza czytelna date z podanych.
func data(kandydaci ...string) *time.Time {
	for _, kandydat := range kandydaci {
		chwila, err := time.Parse(time.RFC3339, strings.TrimSpace(kandydat))
		if err != nil {
			continue
		}
		chwilaUTC := chwila.UTC()
		return &chwilaUTC
	}
	return nil
}
