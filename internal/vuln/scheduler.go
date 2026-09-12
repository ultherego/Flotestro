package vuln

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/hosts"
	"github.com/ultherego/flotestro/internal/inventory"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/opspec"
)

// Zrodlo jest adapterem trackera bezpieczenstwa jednej dystrybucji.
//
// Rozstrzyga producent: adapter tlumaczy jego jezyk na ustalenia panelu i nic
// wiecej. Wzbogacenie o CVSS czy opis upstreamowy moze przyjsc pozniej i nie
// ma prawa zmienic odpowiedzi "podatny / niepodatny".
type Zrodlo interface {
	Nazwa() string
	// Pobierz sciaga ustalenia dla wskazanych wydan. Zwraca ErrBezZmian, gdy
	// feed nie zmienil sie od pobrania opisanego etagiem.
	Pobierz(ctx context.Context, wydania []string, etag string) (Snapshot, []Advisory, error)
}

// ErrBezZmian oznacza feed bez zmian od ostatniego pobrania.
var ErrBezZmian = errors.New("feed nie zmienil sie od ostatniego pobrania")

// Ustawienia opisuja polityke korelatora.
type Ustawienia struct {
	// Interval mowi, jak czesto panel pyta trackery o zmiany.
	Interval time.Duration
	// MaxSnapshotAge jest wiekiem, powyzej ktorego dane uznajemy za
	// nieswieze. Nie zatrzymuje to oceny - dane sprzed doby sa lepsze niz ich
	// brak - ale musi byc widoczne obok wyniku.
	MaxSnapshotAge time.Duration
	// Debounce mowi, jak dlugo zbieramy prosby o przeliczenie hosta, zanim
	// je wykonamy. Host melduje liste pakietow i ustalenia osobno, a kilka
	// hostow potrafi odpowiedziec naraz - jedno przeliczenie dla calej
	// grupy kosztuje tyle, co jedno dla pierwszego z nich.
	Debounce time.Duration
	// MaxAdvisoryAge jest wiekiem, po ktorym panel prosi hosta o ponowny
	// odczyt metadanych jego repozytoriow.
	//
	// Osobny od wieku snapshotu, bo to osobne zrodlo i osobny cykl: producent
	// wydaje poprawki takze wtedy, gdy na hoscie nie zmienil sie ani jeden
	// pakiet. Panel wiazacy odswiezenie ustalen ze zmiana listy pakietow
	// odswiezalby je czasem nigdy.
	MaxAdvisoryAge time.Duration
}

// Domyslne zwraca ustawienia domyslne.
func Domyslne() Ustawienia {
	return Ustawienia{
		Interval: 30 * time.Minute, MaxSnapshotAge: 6 * time.Hour,
		MaxAdvisoryAge: 30 * time.Minute, Debounce: 15 * time.Second,
	}
}

// Harmonogram synchronizuje feedy i przelicza ocene floty.
type Harmonogram struct {
	store      *Store
	pakiety    *MagazynPakietow
	hosts      *hosts.Store
	inventory  *inventory.Store
	jobs       *jobs.Store
	zrodla     []Zrodlo
	ustawienia Ustawienia
	log        *slog.Logger
	// odswiezenia niosa hosty, ktore wlasnie przyslaly nowe dane. Ocena ma
	// nadazac za tym, co ja rozstrzyga: host, ktory odpowiedzial na prosbe
	// o odczyt, nie moze przez pol godziny widniec jako host bez odczytu.
	odswiezenia chan string
}

// NowyHarmonogram tworzy harmonogram korelatora.
func NowyHarmonogram(store *Store, pakiety *MagazynPakietow, hostStore *hosts.Store,
	inventoryStore *inventory.Store, jobStore *jobs.Store, zrodla []Zrodlo,
	ustawienia Ustawienia, log *slog.Logger) *Harmonogram {
	if ustawienia.Interval <= 0 {
		ustawienia.Interval = Domyslne().Interval
	}
	if ustawienia.MaxSnapshotAge <= 0 {
		ustawienia.MaxSnapshotAge = Domyslne().MaxSnapshotAge
	}
	if ustawienia.MaxAdvisoryAge <= 0 {
		ustawienia.MaxAdvisoryAge = Domyslne().MaxAdvisoryAge
	}
	if ustawienia.Debounce <= 0 {
		ustawienia.Debounce = Domyslne().Debounce
	}
	return &Harmonogram{
		store: store, pakiety: pakiety, hosts: hostStore, inventory: inventoryStore,
		jobs: jobStore, zrodla: zrodla, ustawienia: ustawienia, log: log,
		odswiezenia: make(chan string, 1024),
	}
}

// Odswiez prosi o przeliczenie oceny hosta poza kolejnoscia.
//
// Wolane przez gateway, gdy host przysle liste pakietow albo ustalenia swoich
// repozytoriow. Prosba jest tylko prosba: gdy kolejka jest pelna, host
// poczeka na zwykly cykl - to jest gorsze o kilkanascie minut, a nie
// o odpowiedz.
func (h *Harmonogram) Odswiez(hostID string) {
	if hostID == "" {
		return
	}
	select {
	case h.odswiezenia <- hostID:
	default:
		h.log.Debug("kolejka odswiezen oceny pelna", "host_id", hostID)
	}
}

// Run prowadzi synchronizacje i ocene do zamkniecia kontekstu.
func (h *Harmonogram) Run(ctx context.Context) {
	// Pierwszy przebieg od razu: panel po starcie nie moze przez pol godziny
	// pokazywac oceny sprzed restartu bez zaznaczenia, ze jest stara.
	h.Cykl(ctx)
	ticker := time.NewTicker(h.ustawienia.Interval)
	defer ticker.Stop()

	// Prosby o przeliczenie zbieramy przez chwile i wykonujemy razem. Host
	// odpowiada na liste pakietow i na ustalenia osobno, a odczyt ustalen
	// feedu dla jednego wydania to nawet milion wierszy - nie ma powodu
	// robic tego dwa razy pod rzad.
	czekajace := map[string]bool{}
	var zwloka *time.Timer
	var sygnal <-chan time.Time
	defer func() {
		if zwloka != nil {
			zwloka.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.Cykl(ctx)
		case hostID := <-h.odswiezenia:
			czekajace[hostID] = true
			if zwloka == nil {
				zwloka = time.NewTimer(h.ustawienia.Debounce)
				sygnal = zwloka.C
			}
		case <-sygnal:
			identyfikatory := make([]string, 0, len(czekajace))
			for hostID := range czekajace {
				identyfikatory = append(identyfikatory, hostID)
			}
			czekajace = map[string]bool{}
			zwloka, sygnal = nil, nil
			h.PrzeliczHosty(ctx, identyfikatory)
		}
	}
}

// PrzeliczHosty przelicza ocene wskazanych hostow.
func (h *Harmonogram) PrzeliczHosty(ctx context.Context, identyfikatory []string) {
	if len(identyfikatory) == 0 {
		return
	}
	opisy, err := h.opisyWskazanych(ctx, identyfikatory)
	if err != nil {
		h.log.Error("nie odczytano hostow do przeliczenia oceny", "err", err)
		return
	}
	h.Przelicz(ctx, opisy)
}

// opisyWskazanych zbiera to, czego ocena potrzebuje o wskazanych hostach.
func (h *Harmonogram) opisyWskazanych(ctx context.Context,
	identyfikatory []string) ([]OpisHosta, error) {
	fragmenty, err := h.inventory.FragmentyHostow(ctx, identyfikatory)
	if err != nil {
		return nil, err
	}
	opisy := make([]OpisHosta, 0, len(identyfikatory))
	for _, hostID := range identyfikatory {
		host, err := h.hosts.Get(ctx, hostID)
		if err != nil || host == nil {
			// Host skasowany miedzy prosba a przeliczeniem nie jest bledem
			// przegladu: po prostu go nie ma.
			continue
		}
		skrot := hosts.Summary{
			ID: host.ID, Hostname: host.Hostname,
			OSDistribution: host.OSDistribution, OSVersion: host.OSVersion,
		}
		opis := OpisHosta{ID: host.ID, Hostname: host.Hostname}
		opis.Distribution, opis.Release = dystrybucjaHosta(skrot, fragmenty[host.ID])
		opis.InventoryDigest, opis.InventoryReason = odciskZInwentarza(fragmenty[host.ID])
		opisy = append(opisy, opis)
	}
	return opisy, nil
}

// Cykl wykonuje jedno przejscie: synchronizacje feedow i ocene hostow.
func (h *Harmonogram) Cykl(ctx context.Context) {
	opisy, err := h.opisyHostow(ctx)
	if err != nil {
		h.log.Error("nie odczytano floty do oceny podatnosci", "err", err)
		return
	}
	h.Synchronizuj(ctx, opisy)
	h.Przelicz(ctx, opisy)
}

// OpisHosta jest tym, co panel wie o hoscie przed ocena.
type OpisHosta struct {
	ID           string
	Hostname     string
	Distribution string
	// Release jest nazwa wydania w jezyku producenta: codename dla Debiana
	// i Ubuntu, numer dla Fedory.
	Release string
	// InventoryDigest jest odciskiem listy pakietow zgloszonym przez hosta.
	InventoryDigest string
	InventoryReason string
}

// UstaleniaZHosta mowi, czy ustalenia dla tej dystrybucji czyta sie
// z metadanych repozytoriow hosta, a nie z centralnego feedu.
//
// Na razie wylacznie Fedora. Jej updateinfo niesie pelne ustalenia
// bezpieczenstwa razem z pakietami, wiec host czyta je z tego samego zrodla,
// z ktorego bierze poprawki.
//
// RHEL, AlmaLinux i Rocky maja updateinfo ubozsze albo niepelne, a ich
// rozstrzygajacym zrodlem sa CSAF/VEX producenta - i dopoki panel ich nie
// czyta, host tych dystrybucji zostaje z powodem "brak feedu". To jest
// uczciwsza odpowiedz niz ocena z metadanych, ktore nie opisuja wszystkiego.
func UstaleniaZHosta(dystrybucja string) bool {
	return strings.ToLower(dystrybucja) == "fedora"
}

// Dostawca zwraca nazwe trackera wlasciwego dla dystrybucji hosta.
//
// CentOS Stream, AlmaLinux i Rocky nie dostaja trackera Red Hata, choc
// pakiety maja te same nazwy: ich wersje sa wlasne (przebudowa dokleja swoj
// sufiks, Stream idzie przed RHEL-em), wiec ustalenie Red Hata mowiloby o
// czym innym. Do czasu, az panel przeczyta ich wlasne zrodla, ich hosty maja
// dostawac powod "brak feedu" - to jest uczciwsza odpowiedz niz cudza ocena.
func Dostawca(dystrybucja string) string {
	switch strings.ToLower(dystrybucja) {
	case "debian":
		return "debian"
	case "ubuntu":
		return "ubuntu"
	case "fedora":
		return "fedora"
	case "rhel":
		return "redhat"
	}
	return ""
}

// opisyHostow zbiera to, czego ocena potrzebuje o kazdym hoscie.
//
// Cala flote, strona po stronie. Lista dla UI ma limit i przy zbyt duzej
// wartosci cicho spada do stu pozycji - przeglad, ktory na tym polegal,
// ocenial sto hostow i milczal o reszcie. Host nieoceniony wyglada na ekranie
// tak samo jak host bez podatnosci, wiec cisza jest tu najgorsza odpowiedzia.
func (h *Harmonogram) opisyHostow(ctx context.Context) ([]OpisHosta, error) {
	var (
		opisy    []OpisHosta
		poNazwie string
		poID     string
	)
	for {
		strona, err := h.hosts.Sweep(ctx, poNazwie, poID, hosts.PageSize)
		if err != nil {
			return nil, err
		}
		if len(strona) == 0 {
			return opisy, nil
		}

		identyfikatory := make([]string, 0, len(strona))
		for _, host := range strona {
			identyfikatory = append(identyfikatory, host.ID)
		}
		// Fragmenty inwentarza bierzemy dla strony, a nie dla calej floty:
		// niosa pelne payloady modulow i w calosci nie zmieszcza sie w pamieci.
		fragmenty, err := h.inventory.FragmentyHostow(ctx, identyfikatory)
		if err != nil {
			return nil, err
		}
		for _, host := range strona {
			opis := OpisHosta{ID: host.ID, Hostname: host.Hostname}
			opis.Distribution, opis.Release = dystrybucjaHosta(host, fragmenty[host.ID])
			opis.InventoryDigest, opis.InventoryReason = odciskZInwentarza(fragmenty[host.ID])
			opisy = append(opisy, opis)
		}

		ostatni := strona[len(strona)-1]
		poNazwie, poID = ostatni.Hostname, ostatni.ID
		if len(strona) < hosts.PageSize {
			return opisy, nil
		}
	}
}

// dystrybucjaHosta ustala dystrybucje i wydanie w jezyku producenta.
func dystrybucjaHosta(host hosts.Summary, fragmenty []inventory.Fragment) (string, string) {
	dystrybucja := strings.ToLower(host.OSDistribution)
	wydanie := host.OSVersion

	// Trackery Debiana i Ubuntu mowia nazwami wydan, nie numerami. Nazwa
	// jest w inwentarzu, bo tylko host wie, jak nazywa sie jego wydanie.
	for _, fragment := range fragmenty {
		if fragment.Module != "system" || len(fragment.Payload) == 0 {
			continue
		}
		var tresc struct {
			OS struct {
				Distribution string `json:"distribution"`
				Version      string `json:"version"`
				Codename     string `json:"codename"`
			} `json:"os"`
		}
		if err := json.Unmarshal(fragment.Payload, &tresc); err != nil {
			continue
		}
		if tresc.OS.Distribution != "" {
			dystrybucja = strings.ToLower(tresc.OS.Distribution)
		}
		if tresc.OS.Codename != "" && (dystrybucja == "debian" || dystrybucja == "ubuntu") {
			wydanie = tresc.OS.Codename
		} else if tresc.OS.Version != "" {
			wydanie = tresc.OS.Version
		}
	}
	return dystrybucja, WydanieTrackera(dystrybucja, wydanie)
}

// WydanieTrackera sprowadza wydanie hosta do postaci, ktora zna tracker.
//
// Red Hat mowi o wydaniu glownym: host zglasza 9.4, a ustalenia dotycza
// dziewiatki. Bez tego kazdy host RHEL-a wychodzilby jako "wydanie spoza
// feedu". Debian, Ubuntu i Fedora nazywaja wydania tak samo jak ich hosty.
func WydanieTrackera(dystrybucja, wydanie string) string {
	if Dostawca(dystrybucja) != "redhat" {
		return wydanie
	}
	if glowne, _, ok := strings.Cut(wydanie, "."); ok {
		return glowne
	}
	return wydanie
}

// odciskZInwentarza czyta odcisk listy pakietow zgloszony przez hosta.
func odciskZInwentarza(fragmenty []inventory.Fragment) (string, string) {
	for _, fragment := range fragmenty {
		if fragment.Module != "packages" || len(fragment.Payload) == 0 {
			continue
		}
		var tresc struct {
			InstalledDigest string `json:"installed_digest"`
			InstalledReason string `json:"installed_unavailable_reason"`
		}
		if err := json.Unmarshal(fragment.Payload, &tresc); err != nil {
			continue
		}
		return tresc.InstalledDigest, tresc.InstalledReason
	}
	return "", ""
}

// Synchronizuj pobiera feedy dla wydan, ktore flota naprawde ma.
//
// Pobieramy tylko to, co dotyczy hostow w tej instalacji: pelny zrzut opisuje
// kilkanascie wydan i kilkaset tysiecy ustalen, a panel potrzebuje tych, na
// ktore ma czym odpowiedziec.
func (h *Harmonogram) Synchronizuj(ctx context.Context, opisy []OpisHosta) {
	wydania := map[string]map[string]bool{}
	for _, opis := range opisy {
		dostawca := Dostawca(opis.Distribution)
		if dostawca == "" || opis.Release == "" {
			continue
		}
		if wydania[dostawca] == nil {
			wydania[dostawca] = map[string]bool{}
		}
		wydania[dostawca][opis.Release] = true
	}

	for _, zrodlo := range h.zrodla {
		zbior := wydania[zrodlo.Nazwa()]
		if len(zbior) == 0 {
			// Nie pobieramy feedu dystrybucji, ktorej w tej instalacji nie ma.
			continue
		}
		lista := make([]string, 0, len(zbior))
		for wydanie := range zbior {
			lista = append(lista, wydanie)
		}

		etag := ""
		if poprzedni, err := h.store.AktywnySnapshot(ctx, zrodlo.Nazwa()); err == nil {
			// Etag ma sens tylko wtedy, gdy pytamy o ten sam zakres wydan:
			// inaczej "bez zmian" znaczyloby "bez zmian w innym zakresie".
			if tenSamZakres(poprzedni.Releases, lista) {
				etag = poprzedni.ETag
			}
		}

		snapshot, ustalenia, err := zrodlo.Pobierz(ctx, lista, etag)
		if errors.Is(err, ErrBezZmian) || (err != nil && strings.Contains(err.Error(), "nie zmienil sie")) {
			// "Bez zmian" jest potwierdzeniem, a nie brakiem odpowiedzi:
			// dane sa nadal te, ktore obowiazuja. Bez tego zapisu feed
			// zmieniajacy sie raz na dobe wygladalby na porzucony.
			if err := h.store.PotwierdzSnapshot(ctx, zrodlo.Nazwa()); err != nil {
				h.log.Error("nie odnotowano potwierdzenia feedu",
					"dostawca", zrodlo.Nazwa(), "err", err)
			}
			h.log.Debug("feed bez zmian", "dostawca", zrodlo.Nazwa())
			continue
		}
		if err != nil {
			// Nieudane pobranie nie zabiera panelowi poprzedniego snapshotu:
			// lepiej ocenic starszymi danymi i powiedziec, ze sa starsze.
			h.log.Error("nie pobrano feedu", "dostawca", zrodlo.Nazwa(), "err", err)
			_ = h.store.ZapiszBladPobrania(ctx, zrodlo.Nazwa(), err.Error())
			continue
		}
		if _, err := h.store.ZapiszSnapshot(ctx, snapshot, ustalenia); err != nil {
			h.log.Error("nie zapisano snapshotu feedu", "dostawca", zrodlo.Nazwa(), "err", err)
			continue
		}
		h.log.Info("snapshot feedu zapisany", "dostawca", zrodlo.Nazwa(),
			"ustalen", len(ustalenia), "wydania", lista, "odcisk", snapshot.Digest[:12])
	}
}

func tenSamZakres(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	zbior := map[string]bool{}
	for _, wpis := range a {
		zbior[wpis] = true
	}
	for _, wpis := range b {
		if !zbior[wpis] {
			return false
		}
	}
	return true
}

// Przelicz ocenia hosty aktywnym snapshotem ich dystrybucji.
//
// Przelicza tylko te, ktorych wejscie sie zmienilo. Ocena zalezy od trzech
// odciskow - snapshotu feedu, listy pakietow i zestawu ustalen hosta - oraz od
// tego, co przeszkadza w pelnym pokryciu. Gdy zadne z nich sie nie ruszylo,
// wynik bylby co do bajta ten sam, a koszt to odczyt kilkuset pakietow
// i przepisanie kilku tysiecy wierszy na host.
//
// Zostaje siatka bezpieczenstwa: ocena starsza niz dopuszczalny wiek feedu
// liczy sie od nowa bez wzgledu na odciski. Blad w rachunku "co sie zmienilo"
// ma kosztowac opoznienie, a nie ocene zamrozona na zawsze.
func (h *Harmonogram) Przelicz(ctx context.Context, opisy []OpisHosta) {
	snapshoty := map[string]Snapshot{}
	ustalenia := map[string]map[string][]Advisory{}
	teraz := time.Now().UTC()
	poprzednie := h.poprzednieStany(ctx, opisy)
	pominietych := 0

	for _, opis := range opisy {
		dostawca := Dostawca(opis.Distribution)
		snapshot, mamy := snapshoty[dostawca]
		if !mamy && dostawca != "" {
			if pobrany, err := h.store.AktywnySnapshot(ctx, dostawca); err == nil {
				snapshot = pobrany
			}
			snapshoty[dostawca] = snapshot
		}

		stanListy, err := h.pakiety.Stan(ctx, opis.ID)
		if err != nil {
			h.log.Error("nie odczytano stanu listy pakietow", "host_id", opis.ID, "err", err)
			continue
		}

		wejscie := Wejscie{
			HostID: opis.ID, Hostname: opis.Hostname,
			Distribution: opis.Distribution, Release: opis.Release,
			InventoryDigest: stanListy.Digest,
			BrakListy:       stanListy.Digest == "" || stanListy.PackageCount == 0,
			// Host zglasza inny odcisk niz ten, ktory panel ma u siebie:
			// ocena opisuje wtedy stan sprzed zmiany.
			ListaNieaktualna: opis.InventoryDigest != "" && stanListy.Digest != "" &&
				opis.InventoryDigest != stanListy.Digest,
		}

		// Dla Fedory zrodlem rozstrzygajacym sa metadane repozytoriow samego
		// hosta: to one mowia, ktora wersja zamyka ustalenie i czy lezy
		// w repozytorium, z ktorego ten host bierze pakiety.
		zestaw := map[string][]Advisory(nil)
		odswiezUstalenia := false
		if UstaleniaZHosta(opis.Distribution) {
			stanUstalen, err := h.pakiety.StanUstalenHosta(ctx, opis.ID)
			if err != nil {
				h.log.Error("nie odczytano stanu ustalen hosta", "host_id", opis.ID, "err", err)
				continue
			}
			zHosta, zebrane, err := h.pakiety.UstaleniaHosta(ctx, opis.ID)
			if err != nil {
				h.log.Error("nie odczytano ustalen hosta", "host_id", opis.ID, "err", err)
			}
			zestaw = zHosta
			wejscie.AdvisoryDigest = stanUstalen.Digest
			wejscie.AdvisoriesReason = stanUstalen.UnavailableReason
			switch {
			case wejscie.AdvisoriesReason != "":
				// Powod juz jest - odczyt sie nie udal albo go nie bylo.
				odswiezUstalenia = true
			case stanUstalen.CollectedAt == nil:
				wejscie.AdvisoriesReason = RodzajBrakUstalen
				odswiezUstalenia = true
			case teraz.Sub(*stanUstalen.CollectedAt) > h.ustawienia.MaxAdvisoryAge:
				// Producent wydaje poprawki takze wtedy, gdy na hoscie nie
				// zmienil sie ani jeden pakiet. Ustalenia maja wiec wlasny
				// cykl odswiezania, niezalezny od odcisku listy pakietow.
				wejscie.AdvisoriesReason = RodzajUstaleniaNieswieze
				odswiezUstalenia = true
			}

			// Snapshot jest tu wlasnoscia hosta: jego odciskiem jest odcisk
			// zestawu ustalen, a wiekiem - chwila odczytu metadanych.
			snapshot = Snapshot{
				Provider: dostawca, Digest: stanUstalen.Digest,
				Releases: []string{opis.Release}, AdvisoryCount: len(zHosta),
				FetchedAt: zebrane, Active: true,
			}
		} else {
			klucz := dostawca + "\x1f" + opis.Release
			if _, mamy := ustalenia[klucz]; !mamy && snapshot.ID != "" &&
				ObejmujeWydanie(snapshot, opis.Release) {
				pobrane, err := h.store.UstaleniaDlaWydania(ctx, snapshot.ID, opis.Distribution, opis.Release)
				if err != nil {
					h.log.Error("nie odczytano ustalen feedu", "dostawca", dostawca, "err", err)
				}
				ustalenia[klucz] = pobrane
			}
			zestaw = ustalenia[klucz]
		}

		// Zamowienie odczytu jest niezalezne od przeliczania: host bez listy
		// ma ja dostac tak samo wtedy, gdy jego ocena od cyklu sie nie
		// zmienila. Inaczej host raz pominiety nigdy by o nia nie poprosil.
		if wejscie.BrakListy || wejscie.ListaNieaktualna || odswiezUstalenia {
			h.poprosOOdczyt(ctx, opis, teraz)
		}

		if !h.doPrzeliczenia(poprzednie[opis.ID], wejscie, snapshot, teraz) {
			pominietych++
			continue
		}
		pakiety, err := h.pakiety.Pakiety(ctx, opis.ID)
		if err != nil {
			h.log.Error("nie odczytano listy pakietow", "host_id", opis.ID, "err", err)
			continue
		}
		wejscie.Packages = pakiety

		ocena := Ocen(wejscie, snapshot, zestaw, h.ustawienia.MaxSnapshotAge, teraz)
		if err := h.store.ZapiszUstalenia(ctx, opis.ID, ocena.Findings, ocena.Stan); err != nil {
			h.log.Error("nie zapisano oceny podatnosci", "host_id", opis.ID, "err", err)
			continue
		}
	}
	if pominietych > 0 {
		// Pominiecia mowimy glosno: cichy przeglad, ktory nic nie policzyl,
		// wyglada tak samo jak przeglad, ktory nic nie znalazl.
		h.log.Info("ocena podatnosci przeliczona", "hostow", len(opisy),
			"pominietych_bez_zmian", pominietych)
	}
}

// poprzednieStany czyta zapisane oceny hostow, strona po stronie.
func (h *Harmonogram) poprzednieStany(ctx context.Context, opisy []OpisHosta) map[string]StanHosta {
	wynik := map[string]StanHosta{}
	for poczatek := 0; poczatek < len(opisy); poczatek += hosts.PageSize {
		koniec := min(poczatek+hosts.PageSize, len(opisy))
		identyfikatory := make([]string, 0, koniec-poczatek)
		for _, opis := range opisy[poczatek:koniec] {
			identyfikatory = append(identyfikatory, opis.ID)
		}
		stany, err := h.store.StanyHostow(ctx, identyfikatory)
		if err != nil {
			// Bez poprzednich stanow przeliczamy wszystko. Kosztuje wiecej,
			// ale nie zostawia oceny zamrozonej na nieznanym wejsciu.
			h.log.Error("nie odczytano poprzednich ocen", "err", err)
			return map[string]StanHosta{}
		}
		for identyfikator, stan := range stany {
			wynik[identyfikator] = stan
		}
	}
	return wynik
}

// doPrzeliczenia mowi, czy ocene hosta trzeba policzyc od nowa.
//
// Wejsciem oceny sa trzy odciski i powod niepelnego pokrycia. Gdy zaden z nich
// sie nie zmienil, nowa ocena bylaby kopia poprzedniej - a jej policzenie
// kosztuje odczyt calej listy pakietow i przepisanie wszystkich znalezisk.
func (h *Harmonogram) doPrzeliczenia(poprzedni StanHosta, wejscie Wejscie,
	snapshot Snapshot, teraz time.Time) bool {
	if poprzedni.EvaluatedAt == nil {
		return true
	}
	// Siatka bezpieczenstwa: ocena, ktorej nikt nie ruszal dluzej niz wiek
	// dopuszczalny dla feedu, liczy sie od nowa bez wzgledu na odciski.
	if teraz.Sub(*poprzedni.EvaluatedAt) > h.ustawienia.MaxSnapshotAge {
		return true
	}
	if poprzedni.Distribution != wejscie.Distribution ||
		poprzedni.Release != wejscie.Release ||
		poprzedni.Provider != snapshot.Provider ||
		poprzedni.SnapshotDigest != snapshot.Digest ||
		poprzedni.InventoryDigest != wejscie.InventoryDigest ||
		poprzedni.AdvisoryDigest != wejscie.AdvisoryDigest {
		return true
	}
	// Powod pokrycia zalezy takze od czasu: feed swiezy o poranku bywa
	// nieswiezy wieczorem, a to zmienia wynik bez zmiany ani jednego odcisku.
	powod, _ := PowodPokrycia(wejscie, snapshot, h.ustawienia.MaxSnapshotAge, teraz)
	return powod != poprzedni.CoverageReason
}

// poprosOOdczyt zamawia u hosta pelna liste pakietow razem z ustaleniami
// producenta z metadanych jego repozytoriow.
//
// Zamawiamy ja sami, bo bez niej ocena tego hosta jest pusta - a pusta ocena
// wyglada jak host bez podatnosci.
func (h *Harmonogram) poprosOOdczyt(ctx context.Context, opis OpisHosta, teraz time.Time) {
	if h.jobs == nil || opis.InventoryReason != "" {
		return
	}
	tx, err := h.jobs.Pool().Begin(ctx)
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Klucz niesie kubelek czasu, a nie sam odcisk listy. Klucz oparty na
	// odcisku byl staly dopoki host sie nie zmienil - a zadanie, ktore raz sie
	// nie powiodlo, nigdy juz nie wracalo: kolejne cykle trafialy w ten sam
	// klucz i dostawaly to samo nieudane zlecenie. Kubelek zamyka to okno po
	// jednym interwale, a w jego obrebie nadal chroni przed powtorzeniem.
	kubelek := teraz.Truncate(h.ustawienia.Interval).UTC().Format(time.RFC3339)
	klucz := "vuln:packages:" + opis.ID + ":" + kubelek
	_, err = h.jobs.Create(ctx, tx, jobs.Spec{
		HostID:          opis.ID,
		Action:          opspec.ActionPackageList,
		IdempotencyKey:  klucz,
		RequiresApprova: false,
		CreatedBy:       "flotestro/vuln",
		Preconditions: jobs.Preconditions{
			RequiredCapabilities: []string{opspec.ActionPackageList.RequiredCapability()},
		},
	})
	if err != nil {
		return
	}
	if err := tx.Commit(ctx); err != nil {
		return
	}
	h.log.Info("zamowiono odczyt pakietow", "host_id", opis.ID,
		"odcisk_hosta", opis.InventoryDigest, "kubelek", kubelek)
}
