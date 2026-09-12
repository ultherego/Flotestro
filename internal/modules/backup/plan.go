package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Plan opisuje kopie, ktora powstanie na tym hoscie.
//
// To samo zlecenie na dwoch hostach jest dwiema roznymi kopiami: jeden ma
// wszystkie wskazane katalogi, drugi polowy nie ma wcale, trzeci nie ma
// jeszcze repozytorium. Zgoda operatora ma dotyczyc tego, co naprawde
// pojedzie z tego hosta - i ile go to bedzie kosztowac.
type Plan struct {
	ID         string `json:"id"`
	Tool       string `json:"tool"`
	Repository string `json:"repository,omitempty"`
	// Action nazywa to, co by sie stalo: run (kopia powstanie) albo verify.
	Action string `json:"action"`

	// Zakres danych: katalogi, ktore host naprawde ma, i te, ktorych nie ma.
	Paths        []string `json:"paths,omitempty"`
	MissingPaths []string `json:"missing_paths,omitempty"`
	// BytesOnHost jest suma rozmiarow plikow w zakresie. Nieznany rozmiar
	// zostaje brakiem wiedzy, a nie zerem.
	BytesOnHost *uint64 `json:"bytes_on_host,omitempty"`

	// Stan repozytorium przed kopia.
	RepositoryReady bool       `json:"repository_ready"`
	Snapshots       int        `json:"snapshots"`
	LastSuccessAt   *time.Time `json:"last_success_at,omitempty"`
	// WillInitialize mowi, ze kopia zalozy repozytorium.
	WillInitialize bool `json:"will_initialize,omitempty"`
	// Retention opisuje sprzatanie po kopii. Puste oznacza "nie sprzataj".
	Retention string `json:"retention,omitempty"`
	// Verified mowi, ze po kopii host sprawdzi repozytorium. Kopia bez
	// sprawdzenia nie jest tu sukcesem, wiec plan mowi o tym wprost.
	Verified bool `json:"verified"`
	ReadData bool `json:"read_data,omitempty"`

	Changes []string `json:"changes,omitempty"`
	// Refusal nazywa powod, dla ktorego kopia nie powstanie na tym hoscie:
	// brak narzedzia, nieodczytane repozytorium bez zgody na zalozenie,
	// brak wszystkich wskazanych katalogow.
	Refusal string `json:"refusal,omitempty"`

	PlanHash string `json:"plan_hash"`
}

// Nazwy dzialan planu.
const (
	PlanKopia       = "run"
	PlanSprawdzenie = "verify"
)

// Zaplanuj liczy plan kopii albo sprawdzenia wobec stanu repozytorium.
//
// Rozmiar zakresu liczy przekazana funkcja: modul nie chodzi po dysku sam,
// bo ta sama struktura sluzy testom i panelowi.
func Zaplanuj(stan Stan, zlecenie Definicja, sprawdzenie, readData bool,
	rozmiar func(string) (uint64, bool)) Plan {
	plan := Plan{
		ID: zlecenie.ID, Tool: zlecenie.Tool, Repository: zlecenie.Repository,
		Action: PlanKopia, Snapshots: len(stan.Snapshots),
		LastSuccessAt: stan.LastSuccessAt, ReadData: readData,
		// Kopia konczy sie sprawdzeniem repozytorium: kopia, ktorej nikt nie
		// sprawdzil, nie jest tu sukcesem.
		Verified: true,
	}
	if sprawdzenie {
		plan.Action = PlanSprawdzenie
	}
	if err := zlecenie.Waliduj(); err != nil {
		return plan.zOdmowa(err.Error())
	}

	plan.RepositoryReady = stan.UnavailableReason == ""
	if !plan.RepositoryReady {
		// Repozytorium nieodczytane i repozytorium puste to dwie rozne
		// odpowiedzi. Pierwsza pozwala zalozyc nowe tylko za jawna zgoda.
		if plan.Action == PlanSprawdzenie {
			return plan.zOdmowa("repozytorium nie odpowiedzialo: " + stan.UnavailableReason)
		}
		if !zlecenie.Initialize {
			return plan.zOdmowa("repozytorium nie odpowiedzialo (" + stan.UnavailableReason +
				"); zalozenie nowego wymaga jawnej zgody")
		}
		plan.WillInitialize = true
	}

	if plan.Action == PlanSprawdzenie {
		plan.Changes = []string{fmt.Sprintf("repozytorium z %d kopiami zostanie sprawdzone", plan.Snapshots)}
		if readData {
			plan.Changes = append(plan.Changes, "sprawdzenie odczyta dane, a nie sama strukture")
		}
		plan.PlanHash = odciskPlanuKopii(plan)
		return plan
	}

	var suma uint64
	var znanaSuma bool
	for _, sciezka := range zlecenie.Paths {
		if rozmiar == nil {
			plan.Paths = append(plan.Paths, sciezka)
			continue
		}
		bajty, jest := rozmiar(sciezka)
		if !jest {
			plan.MissingPaths = append(plan.MissingPaths, sciezka)
			continue
		}
		plan.Paths = append(plan.Paths, sciezka)
		suma += bajty
		znanaSuma = true
	}
	sort.Strings(plan.Paths)
	sort.Strings(plan.MissingPaths)
	if znanaSuma {
		kopia := suma
		plan.BytesOnHost = &kopia
	}
	// Kopia bez zadnego istniejacego katalogu zapisalaby pusty snapshot,
	// ktory wyglada jak backup, a nim nie jest.
	if len(plan.Paths) == 0 && zlecenie.Runbook == "" {
		return plan.zOdmowa("host nie ma zadnego z wskazanych katalogow")
	}

	plan.Retention = opisRetencji(zlecenie)
	if plan.WillInitialize {
		plan.Changes = append(plan.Changes, "repozytorium "+zlecenie.Repository+" zostanie zalozone")
	}
	plan.Changes = append(plan.Changes, "kopia obejmie "+strings.Join(plan.Paths, ", ")+
		rozmiarWZmianie(plan.BytesOnHost))
	if len(plan.MissingPaths) > 0 {
		plan.Changes = append(plan.Changes,
			"host nie ma: "+strings.Join(plan.MissingPaths, ", "))
	}
	if zlecenie.Runbook != "" {
		plan.Changes = append(plan.Changes, "przed kopia uruchomi sie runbook "+zlecenie.Runbook)
	}
	if plan.Retention != "" {
		plan.Changes = append(plan.Changes, "retencja: "+plan.Retention)
	}
	plan.Changes = append(plan.Changes, "po kopii host sprawdzi repozytorium")
	plan.PlanHash = odciskPlanuKopii(plan)
	return plan
}

// RozmiarSciezki liczy rozmiar zakresu na dysku hosta.
func RozmiarSciezki(sciezka string) (uint64, bool) {
	info, err := os.Lstat(sciezka)
	if err != nil {
		return 0, false
	}
	if !info.IsDir() {
		return uint64(info.Size()), true
	}
	var suma uint64
	wpisy, err := os.ReadDir(sciezka)
	if err != nil {
		// Katalog istnieje, ale nie da sie go policzyc: to nadal jest zakres
		// kopii, tylko o nieznanym rozmiarze.
		return 0, true
	}
	for _, wpis := range wpisy {
		info, err := wpis.Info()
		if err != nil {
			continue
		}
		if info.IsDir() {
			podsuma, _ := RozmiarSciezki(sciezka + "/" + wpis.Name())
			suma += podsuma
			continue
		}
		suma += uint64(info.Size())
	}
	return suma, true
}

// Odmow wpisuje powod odmowy poznany po policzeniu planu i liczy odcisk
// na nowo: plan z odmowa jest inna odpowiedzia niz plan bez niej.
func (p *Plan) Odmow(powod string) {
	p.Refusal = powod
	p.PlanHash = odciskPlanuKopii(*p)
}

func (p Plan) zOdmowa(powod string) Plan {
	p.Refusal = powod
	p.PlanHash = odciskPlanuKopii(p)
	return p
}

func opisRetencji(zlecenie Definicja) string {
	var czesci []string
	for _, para := range []struct {
		nazwa string
		ile   int
	}{
		{"ostatnich", zlecenie.KeepLast}, {"dziennych", zlecenie.KeepDaily},
		{"tygodniowych", zlecenie.KeepWeekly}, {"miesiecznych", zlecenie.KeepMonthly},
	} {
		if para.ile > 0 {
			czesci = append(czesci, fmt.Sprintf("%d %s", para.ile, para.nazwa))
		}
	}
	if len(czesci) == 0 {
		return ""
	}
	opis := "zostaje " + strings.Join(czesci, ", ")
	if zlecenie.Prune {
		opis += "; repozytorium zostanie przesprzatane"
	}
	return opis
}

func rozmiarWZmianie(bajty *uint64) string {
	if bajty == nil {
		return " (rozmiaru nie policzono)"
	}
	return fmt.Sprintf(" (%d MiB na dysku)", *bajty>>20)
}

// odciskPlanuKopii liczy odcisk planu poza samym odciskiem. Hasla
// repozytorium nie ma w planie, wiec nie ma go takze w odcisku.
func odciskPlanuKopii(plan Plan) string {
	bezOdcisku := plan
	bezOdcisku.PlanHash = ""
	zakodowany, err := json.Marshal(bezOdcisku)
	if err != nil {
		return ""
	}
	suma := sha256.Sum256(zakodowany)
	return hex.EncodeToString(suma[:])
}
