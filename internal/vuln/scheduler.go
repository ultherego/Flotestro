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
}

// Domyslne zwraca ustawienia domyslne.
func Domyslne() Ustawienia {
	return Ustawienia{Interval: 30 * time.Minute, MaxSnapshotAge: 6 * time.Hour}
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
	return &Harmonogram{
		store: store, pakiety: pakiety, hosts: hostStore, inventory: inventoryStore,
		jobs: jobStore, zrodla: zrodla, ustawienia: ustawienia, log: log,
	}
}

// Run prowadzi synchronizacje i ocene do zamkniecia kontekstu.
func (h *Harmonogram) Run(ctx context.Context) {
	// Pierwszy przebieg od razu: panel po starcie nie moze przez pol godziny
	// pokazywac oceny sprzed restartu bez zaznaczenia, ze jest stara.
	h.Cykl(ctx)
	ticker := time.NewTicker(h.ustawienia.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.Cykl(ctx)
		}
	}
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

// Dostawca zwraca nazwe trackera wlasciwego dla dystrybucji hosta.
func Dostawca(dystrybucja string) string {
	switch strings.ToLower(dystrybucja) {
	case "debian":
		return "debian"
	case "ubuntu":
		return "ubuntu"
	case "fedora":
		return "fedora"
	case "rhel", "centos", "almalinux", "rocky":
		return "redhat"
	}
	return ""
}

// opisyHostow zbiera to, czego ocena potrzebuje o kazdym hoscie.
func (h *Harmonogram) opisyHostow(ctx context.Context) ([]OpisHosta, error) {
	lista, err := h.hosts.List(ctx, hosts.ListFilter{Limit: 1000})
	if err != nil {
		return nil, err
	}
	identyfikatory := make([]string, 0, len(lista))
	for _, host := range lista {
		identyfikatory = append(identyfikatory, host.ID)
	}
	fragmenty, err := h.inventory.FragmentyHostow(ctx, identyfikatory)
	if err != nil {
		return nil, err
	}

	opisy := make([]OpisHosta, 0, len(lista))
	for _, host := range lista {
		opis := OpisHosta{ID: host.ID, Hostname: host.Hostname}
		opis.Distribution, opis.Release = dystrybucjaHosta(host, fragmenty[host.ID])
		opis.InventoryDigest, opis.InventoryReason = odciskZInwentarza(fragmenty[host.ID])
		opisy = append(opisy, opis)
	}
	return opisy, nil
}

// dystrybucjaHosta ustala dystrybucje i wydanie w jezyku producenta.
func dystrybucjaHosta(host hosts.Host, fragmenty []inventory.Fragment) (string, string) {
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
	return dystrybucja, wydanie
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
func (h *Harmonogram) Przelicz(ctx context.Context, opisy []OpisHosta) {
	snapshoty := map[string]Snapshot{}
	ustalenia := map[string]map[string][]Advisory{}
	teraz := time.Now().UTC()

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
		pakiety, err := h.pakiety.Pakiety(ctx, opis.ID)
		if err != nil {
			h.log.Error("nie odczytano listy pakietow", "host_id", opis.ID, "err", err)
			continue
		}

		wejscie := Wejscie{
			HostID: opis.ID, Hostname: opis.Hostname,
			Distribution: opis.Distribution, Release: opis.Release,
			Packages: pakiety, InventoryDigest: stanListy.Digest,
			BrakListy: len(pakiety) == 0,
			// Host zglasza inny odcisk niz ten, ktory panel ma u siebie:
			// ocena opisuje wtedy stan sprzed zmiany.
			ListaNieaktualna: opis.InventoryDigest != "" && stanListy.Digest != "" &&
				opis.InventoryDigest != stanListy.Digest,
		}

		klucz := dostawca + "\x1f" + opis.Release
		if _, mamy := ustalenia[klucz]; !mamy && snapshot.ID != "" &&
			ObejmujeWydanie(snapshot, opis.Release) {
			pobrane, err := h.store.UstaleniaDlaWydania(ctx, snapshot.ID, opis.Distribution, opis.Release)
			if err != nil {
				h.log.Error("nie odczytano ustalen feedu", "dostawca", dostawca, "err", err)
			}
			ustalenia[klucz] = pobrane
		}

		ocena := Ocen(wejscie, snapshot, ustalenia[klucz], h.ustawienia.MaxSnapshotAge, teraz)
		if err := h.store.ZapiszUstalenia(ctx, opis.ID, ocena.Findings, ocena.Stan); err != nil {
			h.log.Error("nie zapisano oceny podatnosci", "host_id", opis.ID, "err", err)
			continue
		}

		// Lista, ktorej panel nie ma albo ktora opisuje inny stan niz host,
		// jest powodem do zapytania hosta - a nie do milczenia.
		if wejscie.BrakListy || wejscie.ListaNieaktualna {
			h.poprosOListe(ctx, opis, stanListy)
		}
	}
}

// poprosOListe zamawia u hosta pelna liste pakietow.
//
// Zamawiamy ja sami, bo bez niej ocena tego hosta jest pusta - a pusta ocena
// wyglada jak host bez podatnosci.
func (h *Harmonogram) poprosOListe(ctx context.Context, opis OpisHosta, stan StanListy) {
	if h.jobs == nil || opis.InventoryReason != "" {
		return
	}
	tx, err := h.jobs.Pool().Begin(ctx)
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Klucz wiaze zlecenie z konkretnym odciskiem listy: dopoki host zglasza
	// ten sam stan, nie zamawiamy jej drugi raz.
	klucz := "vuln:packages:" + opis.ID + ":" + opis.InventoryDigest
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
	h.log.Info("zamowiono liste pakietow", "host_id", opis.ID,
		"odcisk_hosta", opis.InventoryDigest, "odcisk_panelu", stan.Digest)
}
