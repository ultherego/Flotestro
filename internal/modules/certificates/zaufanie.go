package certificates

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Magazyn zaufania hosta: katalog kotwic i narzedzie, ktore z nich sklada
// wiazke.
//
// Panel nie pisze do samej wiazki ani do katalogu dystrybucji: wiazka jest
// wynikiem, a nie zrodlem, i przepisana recznie wraca do poprzedniej postaci
// przy najblizszej aktualizacji pakietu. Zrodlem jest katalog kotwic lokalnych
// - jedyne miejsce, w ktorym administrator hosta dokłada wlasne urzedy.
const (
	AdapterDebian = "update-ca-certificates"
	AdapterRHEL   = "update-ca-trust"

	KatalogKotwicDebian = "/usr/local/share/ca-certificates"
	KatalogKotwicRHEL   = "/etc/pki/ca-trust/source/anchors"
	KatalogKotwicArch   = "/etc/ca-certificates/trust-source/anchors"

	SciezkaUpdateCACertificates = "/usr/sbin/update-ca-certificates"
	SciezkaUpdateCATrust        = "/usr/bin/update-ca-trust"

	// PrefiksKotwicy odroznia kotwice panelu od tych, ktore administrator
	// hosta polozyl tam sam. Panel nie usuwa cudzych urzedow.
	PrefiksKotwicy = "flotestro-"
)

var nazwaKotwicy = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Kotwica to urzad zaufany na hoscie.
//
// Klucza prywatnego tu nie ma i byc nie moze: kotwica jest materialem
// publicznym - to zaswiadczenie urzedu, a nie tozsamosc hosta.
type Kotwica struct {
	// ID jest nazwa, ktora panel nadal kotwicy. Plik na hoscie nazywa sie
	// od niej, wiec to po niej panel pozna swoja kotwice po restarcie.
	ID   string `json:"id"`
	Path string `json:"path"`
	// Managed odroznia kotwice panelu od urzedu polozonego tam recznie.
	Managed           bool       `json:"managed"`
	Subject           string     `json:"subject,omitempty"`
	Issuer            string     `json:"issuer,omitempty"`
	FingerprintSHA256 string     `json:"fingerprint_sha256,omitempty"`
	NotAfter          *time.Time `json:"not_after,omitempty"`
	IsCA              bool       `json:"is_ca"`
	// UnavailableReason opisuje plik, ktorego nie udalo sie odczytac.
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// MagazynZaufania opisuje, co host ma i czym to przelicza.
type MagazynZaufania struct {
	Adapter   string    `json:"adapter,omitempty"`
	Directory string    `json:"directory,omitempty"`
	Tool      string    `json:"tool,omitempty"`
	Anchors   []Kotwica `json:"anchors,omitempty"`
	// UnavailableReason mowi, dlaczego magazynu nie odczytano. Host bez
	// narzedzia i host z pustym katalogiem to dwie rozne odpowiedzi.
	UnavailableReason string    `json:"unavailable_reason,omitempty"`
	ObservedAt        time.Time `json:"observed_at"`
}

// WykryjMagazyn rozpoznaje magazyn zaufania hosta.
//
// Rozstrzyga narzedzie, a nie nazwa dystrybucji: ten sam pakiet bywa w roznych
// systemach, a panel ma dzialac takze tam, gdzie go nie znamy z nazwy.
func WykryjMagazyn(istnieje func(string) bool) MagazynZaufania {
	switch {
	case istnieje(SciezkaUpdateCACertificates) && istnieje(KatalogKotwicDebian):
		return MagazynZaufania{Adapter: AdapterDebian,
			Directory: KatalogKotwicDebian, Tool: SciezkaUpdateCACertificates}
	case istnieje(SciezkaUpdateCATrust) && istnieje(KatalogKotwicRHEL):
		return MagazynZaufania{Adapter: AdapterRHEL,
			Directory: KatalogKotwicRHEL, Tool: SciezkaUpdateCATrust}
	case istnieje(SciezkaUpdateCATrust) && istnieje(KatalogKotwicArch):
		return MagazynZaufania{Adapter: AdapterRHEL,
			Directory: KatalogKotwicArch, Tool: SciezkaUpdateCATrust}
	}
	return MagazynZaufania{
		UnavailableReason: "ten host nie ma katalogu kotwic ani narzedzia przeliczajacego magazyn zaufania",
	}
}

// SciezkaKotwicy sklada sciezke pliku kotwicy panelu.
//
// Rozszerzenie jest czescia umowy z narzedziem: update-ca-certificates bierze
// pod uwage wylacznie pliki ".crt", a update-ca-trust wylacznie ".pem".
// Kotwica z zla koncowka lezy w katalogu i nie robi nic.
func SciezkaKotwicy(magazyn MagazynZaufania, id string) string {
	if magazyn.Directory == "" || id == "" {
		return ""
	}
	koncowka := ".crt"
	if magazyn.Adapter == AdapterRHEL {
		koncowka = ".pem"
	}
	return path.Join(magazyn.Directory, PrefiksKotwicy+id+koncowka)
}

// WalidujKotwice sprawdza nazwe kotwicy.
func WalidujKotwice(id string) error {
	if !nazwaKotwicy.MatchString(id) {
		return fmt.Errorf("nieprawidlowa nazwa kotwicy %q", id)
	}
	return nil
}

// CzytajKotwice czyta katalog kotwic i opisuje to, co w nim lezy.
func CzytajKotwice(magazyn MagazynZaufania) MagazynZaufania {
	if magazyn.Directory == "" {
		return magazyn
	}
	wpisy, err := os.ReadDir(magazyn.Directory)
	if err != nil {
		magazyn.UnavailableReason = err.Error()
		return magazyn
	}
	for _, wpis := range wpisy {
		if wpis.IsDir() {
			continue
		}
		sciezka := path.Join(magazyn.Directory, wpis.Name())
		kotwica := Kotwica{
			Path:    sciezka,
			ID:      identyfikatorKotwicy(wpis.Name()),
			Managed: strings.HasPrefix(wpis.Name(), PrefiksKotwicy),
		}
		dane, err := CzytajPlik(sciezka)
		if err != nil {
			kotwica.UnavailableReason = err.Error()
			magazyn.Anchors = append(magazyn.Anchors, kotwica)
			continue
		}
		certy, err := ParsujPEM(dane)
		if err != nil {
			kotwica.UnavailableReason = err.Error()
			magazyn.Anchors = append(magazyn.Anchors, kotwica)
			continue
		}
		opis := Opisz(sciezka, certy)
		kotwica.Subject = opis.Subject
		kotwica.Issuer = opis.Issuer
		kotwica.FingerprintSHA256 = opis.FingerprintSHA256
		kotwica.NotAfter = opis.NotAfter
		kotwica.IsCA = opis.IsCA
		magazyn.Anchors = append(magazyn.Anchors, kotwica)
	}
	sort.Slice(magazyn.Anchors, func(i, j int) bool {
		return magazyn.Anchors[i].Path < magazyn.Anchors[j].Path
	})
	magazyn.ObservedAt = time.Now().UTC()
	return magazyn
}

// Kotwica zwraca kotwice panelu o danej nazwie.
func (m MagazynZaufania) Kotwica(id string) *Kotwica {
	for i := range m.Anchors {
		if m.Anchors[i].Managed && m.Anchors[i].ID == id {
			return &m.Anchors[i]
		}
	}
	return nil
}

func identyfikatorKotwicy(nazwa string) string {
	nazwa = strings.TrimSuffix(strings.TrimSuffix(nazwa, ".crt"), ".pem")
	return strings.TrimPrefix(nazwa, PrefiksKotwicy)
}

// PlanZaufania opisuje roznice miedzy kotwicami, ktore host ma, a zadanymi.
//
// Rotacja urzedu jest ciagiem stanow, a nie jedna zmiana: najpierw kazdy host
// ufa staremu i nowemu urzedowi naraz, potem dostaje nowy certyfikat liscia,
// i dopiero na koncu stary urzad znika. Plan opisuje jeden krok tego ciagu
// i mowi, czego host jeszcze nie jest gotow zrobic.
type PlanZaufania struct {
	Kind     string `json:"kind"`
	AnchorID string `json:"anchor_id"`
	Path     string `json:"path,omitempty"`
	Adapter  string `json:"adapter,omitempty"`
	// Action nazywa to, co by sie stalo: create, update, no_change, remove
	// albo remove_absent.
	Action string `json:"action"`

	// Stan zastany.
	Exists             bool       `json:"exists"`
	CurrentFingerprint string     `json:"current_fingerprint,omitempty"`
	CurrentNotAfter    *time.Time `json:"current_not_after,omitempty"`

	// Stan docelowy. Kotwica jest materialem publicznym, wiec plan opisuje ja
	// wprost - inaczej niz klucz prywatny liscia.
	DesiredSubject     string     `json:"desired_subject,omitempty"`
	DesiredFingerprint string     `json:"desired_fingerprint,omitempty"`
	DesiredNotAfter    *time.Time `json:"desired_not_after,omitempty"`

	// InUseBy wylicza certyfikaty hosta wystawione przez ta kotwice. Usuniecie
	// urzedu, ktory nadal cos podpisuje, zrywa zaufanie do dzialajacej uslugi.
	InUseBy []string `json:"in_use_by,omitempty"`

	Changes []string `json:"changes,omitempty"`
	Refusal string   `json:"refusal,omitempty"`

	PlanHash string `json:"plan_hash"`
}

// ZaplanujKotwice liczy roznice dla zalozenia albo podmiany kotwicy.
func ZaplanujKotwice(magazyn MagazynZaufania, id, material string, teraz time.Time) PlanZaufania {
	plan := PlanZaufania{Kind: RodzajZaufania, AnchorID: id, Adapter: magazyn.Adapter,
		Path: SciezkaKotwicy(magazyn, id)}
	if err := WalidujKotwice(id); err != nil {
		return plan.zOdmowa(err.Error())
	}
	if magazyn.UnavailableReason != "" {
		return plan.zOdmowa(magazyn.UnavailableReason)
	}
	certy, err := ParsujPEM([]byte(material))
	if err != nil {
		return plan.zOdmowa(err.Error())
	}
	// Kotwica, ktora nie jest urzedem, nie zacznie niczego podpisywac -
	// a wyglada w magazynie tak samo jak urzad.
	if !certy[0].IsCA {
		return plan.zOdmowa("material nie jest zaswiadczeniem urzedu (brak basicConstraints CA)")
	}
	if err := SprawdzTerminy(certy[0], teraz); err != nil {
		return plan.zOdmowa(err.Error())
	}
	koniec := certy[0].NotAfter.UTC()
	plan.DesiredSubject = certy[0].Subject.String()
	plan.DesiredFingerprint = Odcisk(certy[0])
	plan.DesiredNotAfter = &koniec

	obecna := magazyn.Kotwica(id)
	switch {
	case obecna == nil:
		plan.Action = PlanTworzy
		plan.Changes = []string{"host zacznie ufac urzedowi " + plan.DesiredSubject +
			" (wazny do " + koniec.Format(time.RFC3339) + ")"}
	case obecna.FingerprintSHA256 == plan.DesiredFingerprint:
		plan.opiszZastana(obecna)
		plan.Action = PlanBezZmian
	default:
		plan.opiszZastana(obecna)
		plan.Action = PlanZmienia
		plan.Changes = []string{"kotwica " + id + " z " + skrocony(obecna.FingerprintSHA256) +
			" na " + skrocony(plan.DesiredFingerprint)}
	}
	if plan.Action != PlanBezZmian {
		plan.Changes = append(plan.Changes, "magazyn zaufania zostanie przeliczony ("+magazyn.Tool+")")
	}
	plan.PlanHash = odciskPlanuZaufania(plan)
	return plan
}

// ZaplanujUsuniecieKotwicy liczy roznice dla wycofania zaufania.
//
// Certyfikaty hosta wystawione przez ta kotwice sa tu odmowa, a nie uwaga:
// usuniecie urzedu w chwili, gdy usluga nadal pokazuje jego certyfikat,
// zrywa zaufanie klientom, ktorzy niczego nie zmieniali.
func ZaplanujUsuniecieKotwicy(magazyn MagazynZaufania, id string,
	certyfikaty []Certyfikat) PlanZaufania {
	plan := PlanZaufania{Kind: RodzajZaufania, AnchorID: id, Adapter: magazyn.Adapter,
		Path: SciezkaKotwicy(magazyn, id)}
	if err := WalidujKotwice(id); err != nil {
		return plan.zOdmowa(err.Error())
	}
	if magazyn.UnavailableReason != "" {
		return plan.zOdmowa(magazyn.UnavailableReason)
	}
	obecna := magazyn.Kotwica(id)
	if obecna == nil {
		plan.Action = PlanJuzUsuniety
		plan.PlanHash = odciskPlanuZaufania(plan)
		return plan
	}
	plan.opiszZastana(obecna)
	for _, certyfikat := range certyfikaty {
		if certyfikat.Issuer != "" && certyfikat.Issuer == obecna.Subject {
			plan.InUseBy = append(plan.InUseBy, certyfikat.Path)
		}
	}
	sort.Strings(plan.InUseBy)
	if len(plan.InUseBy) > 0 {
		return plan.zOdmowa("urzad nadal podpisuje certyfikaty tego hosta: " +
			strings.Join(plan.InUseBy, ", "))
	}
	plan.Action = PlanUsuwa
	plan.Changes = []string{"host przestanie ufac urzedowi " + obecna.Subject,
		"magazyn zaufania zostanie przeliczony (" + magazyn.Tool + ")"}
	plan.PlanHash = odciskPlanuZaufania(plan)
	return plan
}

// Odmow wpisuje powod odmowy poznany po policzeniu roznic.
func (p *PlanZaufania) Odmow(powod string) {
	p.Refusal = powod
	p.PlanHash = odciskPlanuZaufania(*p)
}

func (p PlanZaufania) zOdmowa(powod string) PlanZaufania {
	p.Refusal = powod
	p.PlanHash = odciskPlanuZaufania(p)
	return p
}

func (p *PlanZaufania) opiszZastana(kotwica *Kotwica) {
	p.Exists = true
	p.Path = kotwica.Path
	p.CurrentFingerprint = kotwica.FingerprintSHA256
	p.CurrentNotAfter = kotwica.NotAfter
}

// odciskPlanuZaufania liczy odcisk planu poza samym odciskiem.
func odciskPlanuZaufania(plan PlanZaufania) string {
	bezOdcisku := plan
	bezOdcisku.PlanHash = ""
	zakodowany, err := json.Marshal(bezOdcisku)
	if err != nil {
		return ""
	}
	suma := sha256.Sum256(zakodowany)
	return hex.EncodeToString(suma[:])
}

// SkladajKotwice sprawdza material kotwicy przed zapisem na host.
func SkladajKotwice(material string, teraz time.Time) ([]byte, *x509.Certificate, error) {
	certy, err := ParsujPEM([]byte(material))
	if err != nil {
		return nil, nil, err
	}
	if !certy[0].IsCA {
		return nil, nil, fmt.Errorf("material nie jest zaswiadczeniem urzedu (brak basicConstraints CA)")
	}
	if err := SprawdzTerminy(certy[0], teraz); err != nil {
		return nil, nil, err
	}
	return []byte(material), certy[0], nil
}
