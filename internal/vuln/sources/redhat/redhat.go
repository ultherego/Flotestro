package redhat

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/ultherego/flotestro/internal/vuln"
)

// AdresDomyslny wskazuje katalog VEX Red Hata.
const AdresDomyslny = "https://security.access.redhat.com/data/csaf/v2/vex/"

// KatalogDomyslny jest miejscem, w ktorym panel trzyma odczytane ustalenia
// miedzy cyklami.
const KatalogDomyslny = "/var/lib/flotestro/vuln/redhat"

// Limity pobrania.
const (
	// MaksymalneArchiwum ogranicza pelne pobranie. Archiwum ma okolo
	// trzystu megabajtow; istotnie wieksze oznacza, ze pobieramy cos
	// innego, niz myslimy.
	MaksymalneArchiwum = 2 << 30
	// MaksymalnyPlik ogranicza pojedynczy dokument VEX. Dokumenty CVE,
	// ktore dotykaja wszystkich produktow producenta, maja po kilkadziesiat
	// megabajtow - i sa prawdziwe.
	MaksymalnyPlik = 256 << 20
	// MaksymalnieDokumentow ogranicza liczbe plikow w archiwum.
	MaksymalnieDokumentow = 500000
	// ZmianDoPelnegoPobrania mowi, powyzej ilu zmienionych plikow taniej
	// jest wziac cale archiwum niz dociagac je po jednym.
	ZmianDoPelnegoPobrania = 3000
)

// ErrBezZmian oznacza feed, ktory sie nie zmienil od ostatniego pobrania.
var ErrBezZmian = fmt.Errorf("feed nie zmienil sie od ostatniego pobrania")

// Zrodlo czyta dane CSAF/VEX Red Hata i trzyma je miedzy cyklami.
//
// To jedyne zrodlo panelu, ktore ma pamiec, i ma ja z koniecznosci: pelne
// dane to trzysta megabajtow archiwum i szescdziesiat kilka tysiecy plikow,
// a producent publikuje zmiany po kilkadziesiat dziennie. Pobieranie calosci
// co cykl byloby kosztem, ktory ponosi takze druga strona.
type Zrodlo struct {
	Baza    string
	Katalog string
	Client  *http.Client

	// zaladowane mowi, czy pamiec zrodla jest juz wypelniona. Zrodlo jest
	// wolane z jednej gorutyny harmonogramu, wiec nie ma tu zamka.
	zaladowane bool
	znacznik   time.Time
	archiwum   string
	// wydania mowi, dla ktorych wydan zapis zostal zbudowany. Dane sa
	// filtrowane przy czytaniu, wiec flota, ktora dostala nowe wydanie,
	// musi je odczytac od nowa - inaczej jej hosty wygladalyby na czyste.
	wydania map[string]bool
}

// Nowe tworzy zrodlo.
func Nowe(adres, katalog string, limit time.Duration) *Zrodlo {
	if adres == "" {
		adres = AdresDomyslny
	}
	if !strings.HasSuffix(adres, "/") {
		adres += "/"
	}
	if katalog == "" {
		katalog = KatalogDomyslny
	}
	if limit <= 0 {
		limit = 30 * time.Minute
	}
	return &Zrodlo{Baza: adres, Katalog: katalog, Client: &http.Client{Timeout: limit}}
}

func (z *Zrodlo) Nazwa() string { return Dostawca }

// Pobierz zwraca ustalenia dla wskazanych wydan bazowego RHEL-a.
func (z *Zrodlo) Pobierz(ctx context.Context, wydania []string,
	etag string) (vuln.Snapshot, []vuln.Advisory, error) {
	snapshot := vuln.Snapshot{Provider: Dostawca}

	chciane := map[string]bool{}
	for _, wydanie := range wydania {
		if wydanie != "" {
			chciane[wydanie] = true
		}
	}
	if len(chciane) == 0 {
		return snapshot, nil, fmt.Errorf("brak wydan do pobrania")
	}
	if !pokrywa(z.wydania, chciane) {
		z.wydania = chciane
		z.zaladowane = false
		z.znacznik = time.Time{}
	}

	pierwsze := !z.zaladowane
	pelne, err := z.zaladuj(ctx)
	if err != nil {
		return snapshot, nil, err
	}
	// Pelne pobranie w tym samym wywolaniu wyklucza drugie: inaczej
	// archiwum starsze niz prog zmian kazaloby sie pobierac w kolko.
	zmienionych, err := z.przyrost(ctx, !pelne)
	if err != nil {
		return snapshot, nil, err
	}
	if zmienionych == 0 && !pierwsze {
		return snapshot, nil, ErrBezZmian
	}
	if err := z.zapisz(); err != nil {
		return snapshot, nil, err
	}

	ustalenia, objete, err := z.zbierz()
	if err != nil {
		return snapshot, nil, err
	}

	Uporzadkuj(ustalenia)
	snapshot.Releases = przeciecie(objete, wydania)
	snapshot.Digest = Odcisk(ustalenia)
	snapshot.AdvisoryCount = len(ustalenia)
	snapshot.FetchedAt = time.Now().UTC()
	if !z.znacznik.IsZero() {
		chwila := z.znacznik.UTC()
		snapshot.SourceModifiedAt = &chwila
	}
	return snapshot, ustalenia, nil
}

// przeciecie zwraca wydania, ktore panel naprawde ma czym ocenic.
func przeciecie(objete map[string]bool, wydania []string) []string {
	var wynik []string
	for _, wydanie := range wydania {
		if objete[wydanie] {
			wynik = append(wynik, wydanie)
		}
	}
	sort.Strings(wynik)
	return wynik
}

// stanZrodla jest tym, co przezywa restart panelu.
type stanZrodla struct {
	Archiwum string    `json:"archiwum"`
	Znacznik time.Time `json:"znacznik"`
	// Wydania mowi, dla ktorych wydan zapisano ustalenia. Pamiec zbudowana
	// dla wezszego zbioru nie jest pamiecia niepelna - jest pamiecia o czym
	// innym, i trzeba ja zbudowac od nowa.
	Wydania []string `json:"wydania"`
}

// pokrywa mowi, czy pierwszy zbior wydan obejmuje drugi.
func pokrywa(mamy, chcemy map[string]bool) bool {
	if len(mamy) == 0 {
		return false
	}
	for wydanie := range chcemy {
		if !mamy[wydanie] {
			return false
		}
	}
	return true
}

// zbiorWydan zamienia liste wydan na zbior.
func zbiorWydan(wydania []string) map[string]bool {
	zbior := map[string]bool{}
	for _, wydanie := range wydania {
		if wydanie != "" {
			zbior[wydanie] = true
		}
	}
	return zbior
}

// listaWydan zamienia zbior wydan na uporzadkowana liste.
func listaWydan(zbior map[string]bool) []string {
	lista := make([]string, 0, len(zbior))
	for wydanie := range zbior {
		lista = append(lista, wydanie)
	}
	sort.Strings(lista)
	return lista
}

// zaladuj wypelnia pamiec zrodla: z dysku, a gdy go nie ma - z archiwum.
//
// Zwraca, czy siegnelo po pelne archiwum.
func (z *Zrodlo) zaladuj(ctx context.Context) (bool, error) {
	if z.zaladowane {
		return false, nil
	}
	if err := os.MkdirAll(z.katalogDokumentow(), 0o750); err != nil {
		return false, err
	}

	stan, err := z.wczytajStan()
	if err != nil {
		return false, err
	}
	if stan.Archiwum != "" && pokrywa(zbiorWydan(stan.Wydania), z.wydania) && z.maDokumenty() {
		z.archiwum, z.znacznik = stan.Archiwum, stan.Znacznik
		z.zaladowane = true
		return false, nil
	}
	if err := z.pelnePobranie(ctx); err != nil {
		return false, err
	}
	z.zaladowane = true
	return true, nil
}

// katalogDokumentow wskazuje miejsce na odczytane ustalenia.
func (z *Zrodlo) katalogDokumentow() string {
	return filepath.Join(z.Katalog, "dokumenty")
}

// maDokumenty mowi, czy na dysku sa jakiekolwiek odczytane ustalenia.
func (z *Zrodlo) maDokumenty() bool {
	wpisy, err := os.ReadDir(z.katalogDokumentow())
	return err == nil && len(wpisy) > 0
}

// pelnePobranie sciaga i rozpakowuje archiwum wszystkich dokumentow.
func (z *Zrodlo) pelnePobranie(ctx context.Context) error {
	nazwa, err := z.tekst(ctx, "archive_latest.txt")
	if err != nil {
		return fmt.Errorf("nazwa archiwum: %w", err)
	}
	nazwa = strings.TrimSpace(nazwa)
	if nazwa == "" || strings.ContainsAny(nazwa, "/\\") {
		return fmt.Errorf("archive_latest.txt wskazuje %q", nazwa)
	}

	// Archiwum jest z dnia, ktory ma w nazwie, a nie z dzisiaj. Znacznik
	// wziety z chwili pobrania kazalby uznac za odczytane wszystko, co
	// producent opublikowal od zlozenia archiwum - czyli przemilczec tydzien
	// zmian. Reszte dociaga przyrost.
	przed := DataArchiwum(nazwa)

	// Pelne pobranie zaczyna od czystego katalogu: dokument, ktory
	// producent wycofal, nie moze przezyc w zapisie jako ustalenie.
	if err := os.RemoveAll(z.katalogDokumentow()); err != nil {
		return err
	}
	if err := os.MkdirAll(z.katalogDokumentow(), 0o750); err != nil {
		return err
	}

	odpowiedz, err := z.pobierz(ctx, nazwa)
	if err != nil {
		return err
	}
	defer odpowiedz.Body.Close()

	licznik := &licznikBajtow{zrodlo: io.LimitReader(odpowiedz.Body, MaksymalneArchiwum+1)}
	rozpakowany, err := zstd.NewReader(licznik)
	if err != nil {
		return err
	}
	defer rozpakowany.Close()

	czytnik := tar.NewReader(rozpakowany)
	dokumentow := 0
	for {
		naglowek, err := czytnik.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("archiwum %s: %w", nazwa, err)
		}
		if naglowek.Typeflag != tar.TypeReg || !strings.HasSuffix(naglowek.Name, ".json") {
			continue
		}
		if naglowek.Size > MaksymalnyPlik {
			return fmt.Errorf("dokument %s ma %d bajtow", naglowek.Name, naglowek.Size)
		}
		dokumentow++
		if dokumentow > MaksymalnieDokumentow {
			return fmt.Errorf("archiwum ma wiecej niz %d dokumentow", MaksymalnieDokumentow)
		}
		tresc, err := io.ReadAll(io.LimitReader(czytnik, MaksymalnyPlik))
		if err != nil {
			return err
		}
		if err := z.przyjmij(sciezkaDokumentu(naglowek.Name), tresc); err != nil {
			return err
		}
	}
	if licznik.przeczytane > MaksymalneArchiwum {
		return fmt.Errorf("archiwum przekracza %d bajtow", MaksymalneArchiwum)
	}
	if dokumentow == 0 {
		return fmt.Errorf("archiwum %s nie ma ani jednego dokumentu", nazwa)
	}
	z.archiwum, z.znacznik = nazwa, przed
	return nil
}

// DataArchiwum czyta date ze nazwy archiwum ("csaf_vex_2026-08-30.tar.zst").
//
// Gdy nazwa jej nie niesie, zwracamy czas zerowy: wtedy przyrost przejdzie
// przez caly spis zmian, co jest droga, ale prawdziwa odpowiedzia.
func DataArchiwum(nazwa string) time.Time {
	for _, czesc := range strings.FieldsFunc(nazwa, func(znak rune) bool {
		return znak == '_' || znak == '.'
	}) {
		if chwila, err := time.Parse("2006-01-02", czesc); err == nil {
			return chwila.UTC()
		}
	}
	return time.Time{}
}

// przyrost dociaga pliki zmienione od ostatniego pobrania.
func (z *Zrodlo) przyrost(ctx context.Context, mozeArchiwum bool) (int, error) {
	zmiany, najnowszy, err := z.zmiany(ctx, "changes.csv")
	if err != nil {
		return 0, err
	}
	usuniete, _, err := z.zmiany(ctx, "deletions.csv")
	if err != nil {
		return 0, err
	}
	if len(zmiany) == 0 && len(usuniete) == 0 {
		return 0, nil
	}
	// Przy duzej liczbie zmian pobranie archiwum jest tansze dla obu stron
	// niz kilka tysiecy osobnych zadan.
	if len(zmiany) > ZmianDoPelnegoPobrania && mozeArchiwum {
		if err := z.pelnePobranie(ctx); err != nil {
			return 0, err
		}
		return len(zmiany), nil
	}

	for _, sciezka := range usuniete {
		if err := z.usun(sciezka); err != nil {
			return 0, err
		}
	}
	for _, sciezka := range zmiany {
		tresc, err := z.plik(ctx, sciezka)
		if err != nil {
			return 0, err
		}
		if tresc == nil {
			// Plik zniknal miedzy spisem a pobraniem: to nie jest blad,
			// to znaczy tyle, ze producent go wycofal.
			if err := z.usun(sciezka); err != nil {
				return 0, err
			}
			continue
		}
		if err := z.przyjmij(sciezka, tresc); err != nil {
			return 0, err
		}
	}
	if !najnowszy.IsZero() {
		z.znacznik = najnowszy
	}
	return len(zmiany) + len(usuniete), nil
}

// przyjmij tlumaczy jeden dokument i zapisuje jego ustalenia na dysku.
//
// Na dysku, a nie w pamieci: samych ustalen dla jednego wydania RHEL-a jest
// blisko miliona i trzymanie ich miedzy cyklami kosztowaloby panel kilkaset
// megabajtow tylko po to, zeby raz na dobe cos sie zmienilo.
func (z *Zrodlo) przyjmij(sciezka string, tresc []byte) error {
	ustalenia, err := Ustalenia(tresc, z.wydania)
	if err != nil {
		return fmt.Errorf("%s: %w", sciezka, err)
	}
	if len(ustalenia) == 0 {
		// Dokument, ktory nie mowi nic o bazowym RHEL-u, nie zajmuje
		// miejsca: takich jest wiekszosc.
		return z.usun(sciezka)
	}
	zapis, err := json.Marshal(ustalenia)
	if err != nil {
		return err
	}
	cel := filepath.Join(z.katalogDokumentow(), filepath.FromSlash(sciezka))
	if err := os.MkdirAll(filepath.Dir(cel), 0o750); err != nil {
		return err
	}
	return os.WriteFile(cel, zapis, 0o640)
}

// usun kasuje odczytane ustalenia jednego dokumentu.
func (z *Zrodlo) usun(sciezka string) error {
	err := os.Remove(filepath.Join(z.katalogDokumentow(), filepath.FromSlash(sciezka)))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// zbierz czyta z dysku wszystkie ustalenia i wydania, ktore opisuja.
func (z *Zrodlo) zbierz() ([]vuln.Advisory, map[string]bool, error) {
	objete := map[string]bool{}
	var wynik []vuln.Advisory
	lata, err := os.ReadDir(z.katalogDokumentow())
	if err != nil {
		return nil, nil, err
	}
	for _, rok := range lata {
		if !rok.IsDir() {
			continue
		}
		katalog := filepath.Join(z.katalogDokumentow(), rok.Name())
		pliki, err := os.ReadDir(katalog)
		if err != nil {
			return nil, nil, err
		}
		for _, plik := range pliki {
			tresc, err := os.ReadFile(filepath.Join(katalog, plik.Name()))
			if err != nil {
				return nil, nil, err
			}
			var ustalenia []vuln.Advisory
			if err := json.Unmarshal(tresc, &ustalenia); err != nil {
				// Uszkodzony zapis nie moze udawac kompletu: polowa danych
				// wyglada tak samo jak brak podatnosci.
				return nil, nil, fmt.Errorf("%s/%s: %w", rok.Name(), plik.Name(), err)
			}
			for _, ustalenie := range ustalenia {
				objete[ustalenie.Release] = true
			}
			wynik = append(wynik, ustalenia...)
		}
	}
	return wynik, objete, nil
}

// zmiany czyta spis zmienionych plikow nowszych niz znacznik zrodla.
func (z *Zrodlo) zmiany(ctx context.Context, nazwa string) ([]string, time.Time, error) {
	tresc, err := z.tekst(ctx, nazwa)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("%s: %w", nazwa, err)
	}
	return Zmiany(strings.NewReader(tresc), z.znacznik)
}

// Zmiany czyta spis "plik,data" i zwraca pliki nowsze niz znacznik.
func Zmiany(zrodlo io.Reader, po time.Time) ([]string, time.Time, error) {
	czytnik := csv.NewReader(zrodlo)
	czytnik.FieldsPerRecord = -1
	najnowszy := time.Time{}
	var pliki []string
	for {
		wiersz, err := czytnik.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, time.Time{}, err
		}
		if len(wiersz) < 2 {
			continue
		}
		chwila, err := time.Parse(time.RFC3339, strings.TrimSpace(wiersz[1]))
		if err != nil {
			continue
		}
		if chwila.After(najnowszy) {
			najnowszy = chwila.UTC()
		}
		if !po.IsZero() && !chwila.After(po) {
			continue
		}
		sciezka := sciezkaDokumentu(strings.TrimSpace(wiersz[0]))
		if sciezka == "" {
			continue
		}
		pliki = append(pliki, sciezka)
	}
	return pliki, najnowszy, nil
}

// sciezkaDokumentu sprowadza sciezke z archiwum albo spisu do postaci
// "rok/cve-....json".
//
// Nazwa przychodzi z zewnatrz, wiec nie przyjmujemy niczego, co nie wyglada
// dokladnie tak, jak dokument VEX: rok i plik CVE. Wszystko inne odrzucamy
// zamiast prostowac - sciezka, ktorej nie rozumiemy, nie jest sciezka, ktora
// wolno nam zgadywac.
func sciezkaDokumentu(nazwa string) string {
	nazwa = filepath.ToSlash(strings.TrimSpace(nazwa))
	czesci := strings.Split(nazwa, "/")
	if len(czesci) < 2 {
		return ""
	}
	rok, plik := czesci[len(czesci)-2], czesci[len(czesci)-1]
	if len(rok) != 4 || !sameCyfry(rok) {
		return ""
	}
	if !strings.HasPrefix(plik, "cve-") || !strings.HasSuffix(plik, ".json") {
		return ""
	}
	if strings.ContainsAny(plik, `\:`) || strings.Contains(plik, "..") {
		return ""
	}
	return rok + "/" + plik
}

// sameCyfry mowi, czy napis sklada sie wylacznie z cyfr.
func sameCyfry(napis string) bool {
	for _, znak := range napis {
		if znak < '0' || znak > '9' {
			return false
		}
	}
	return napis != ""
}

// plik pobiera jeden dokument VEX. Zwraca nil, gdy producent go wycofal.
func (z *Zrodlo) plik(ctx context.Context, sciezka string) ([]byte, error) {
	odpowiedz, err := z.pobierz(ctx, sciezka)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return nil, nil
		}
		return nil, err
	}
	defer odpowiedz.Body.Close()
	return io.ReadAll(io.LimitReader(odpowiedz.Body, MaksymalnyPlik))
}

// tekst pobiera maly plik pomocniczy.
func (z *Zrodlo) tekst(ctx context.Context, nazwa string) (string, error) {
	odpowiedz, err := z.pobierz(ctx, nazwa)
	if err != nil {
		return "", err
	}
	defer odpowiedz.Body.Close()
	tresc, err := io.ReadAll(io.LimitReader(odpowiedz.Body, MaksymalnyPlik))
	if err != nil {
		return "", err
	}
	return string(tresc), nil
}

// pobierz wykonuje zadanie do katalogu danych producenta.
func (z *Zrodlo) pobierz(ctx context.Context, nazwa string) (*http.Response, error) {
	zadanie, err := http.NewRequestWithContext(ctx, http.MethodGet, z.Baza+nazwa, nil)
	if err != nil {
		return nil, err
	}
	zadanie.Header.Set("User-Agent", "flotestro-vuln/1")
	odpowiedz, err := z.Client.Do(zadanie)
	if err != nil {
		return nil, err
	}
	if odpowiedz.StatusCode != http.StatusOK {
		odpowiedz.Body.Close()
		return nil, fmt.Errorf("%s odpowiedzial %s", nazwa, odpowiedz.Status)
	}
	return odpowiedz, nil
}

// wczytajStan czyta stan zapisany przy poprzednim pobraniu.
func (z *Zrodlo) wczytajStan() (stanZrodla, error) {
	var stan stanZrodla
	tresc, err := os.ReadFile(filepath.Join(z.Katalog, "stan.json"))
	if os.IsNotExist(err) {
		return stan, nil
	}
	if err != nil {
		return stan, err
	}
	if err := json.Unmarshal(tresc, &stan); err != nil {
		// Uszkodzony stan nie moze zablokowac zrodla: gorzej niz pobrac
		// wszystko jeszcze raz jest nie pobrac nic.
		return stanZrodla{}, nil
	}
	return stan, nil
}

// zapisz utrwala stan zrodla.
func (z *Zrodlo) zapisz() error {
	if err := os.MkdirAll(z.Katalog, 0o750); err != nil {
		return err
	}
	stan, err := json.Marshal(stanZrodla{
		Archiwum: z.archiwum, Znacznik: z.znacznik, Wydania: listaWydan(z.wydania),
	})
	if err != nil {
		return err
	}
	// Zapis stanu idzie przez plik tymczasowy i zmiane nazwy: przerwany
	// zapis nie moze zostawic panelu stanu, ktorego nie da sie odczytac.
	tymczasowy := filepath.Join(z.Katalog, "stan.json.tmp")
	if err := os.WriteFile(tymczasowy, stan, 0o640); err != nil {
		return err
	}
	return os.Rename(tymczasowy, filepath.Join(z.Katalog, "stan.json"))
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

// Uporzadkuj ustawia ustalenia w kolejnosci niezaleznej od kolejnosci
// odczytu: odcisk musi byc ten sam dla tych samych danych.
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
	suma.Write([]byte("flotestro/vuln/redhat/v1\n"))
	for _, ustalenie := range ustalenia {
		suma.Write([]byte(strings.Join([]string{
			ustalenie.SourcePackage, ustalenie.Release, ustalenie.AdvisoryID,
			ustalenie.Status, ustalenie.FixedVersion, ustalenie.VendorSeverity,
		}, "\x1f")))
		suma.Write([]byte{'\n'})
	}
	return hex.EncodeToString(suma.Sum(nil))
}
