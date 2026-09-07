package docker

import (
	"context"
	"errors"
	"sort"
	"strings"
)

// Snapshot to pelny odczyt stanu kontenerow hosta.
type Snapshot struct {
	Summary    Summary     `json:"summary"`
	Containers []Container `json:"containers"`
	Images     []Image     `json:"images"`
	Networks   []Network   `json:"networks"`
	Volumes    []Volume    `json:"volumes"`
}

// Collect czyta stan silnika.
//
// Pelne listy sa pobierane na zadanie operatora, a podsumowanie trafia do
// inventory. Odpytywanie silnika przy kazdym heartbeacie obciazaloby host bez
// powodu: liczba kontenerow zmienia sie rzadziej niz co trzydziesci sekund,
// a operator i tak patrzy na te zakladke tylko wtedy, gdy jej potrzebuje.
func Collect(ctx context.Context, client *Client) Snapshot {
	if client == nil {
		return Snapshot{Summary: Summary{UnavailableReason: "brak adaptera silnika kontenerow"}}
	}

	snapshot := Snapshot{}
	engine, api, err := client.Version(ctx)
	if err != nil {
		// Silnik niedostepny to nie to samo co host bez kontenerow. Pusta
		// lista bez powodu wygladalaby jak porzadek na hoscie.
		snapshot.Summary.UnavailableReason = powodNiedostepnosci(err)
		return snapshot
	}
	snapshot.Summary.EngineVersion = engine
	snapshot.Summary.APIVersion = api

	kontenery, err := client.Containers(ctx, true)
	if err != nil {
		snapshot.Summary.UnavailableReason = powodNiedostepnosci(err)
		return snapshot
	}
	snapshot.Containers = kontenery

	// Stan zdrowia i licznik restartow wymagaja osobnego zapytania, wiec
	// pytamy tylko o kontenery, dla ktorych to znaczy cokolwiek. Zatrzymany
	// kontener nie ma zdrowia do sprawdzenia.
	for i := range snapshot.Containers {
		if snapshot.Containers[i].State != "running" && snapshot.Containers[i].State != "restarting" {
			continue
		}
		health, restarts, err := client.Inspect(ctx, snapshot.Containers[i].ID)
		if err != nil {
			continue
		}
		snapshot.Containers[i].Health = health
		snapshot.Containers[i].RestartCount = restarts
	}

	if obrazy, err := client.Images(ctx); err == nil {
		snapshot.Images = obrazy
	}
	if sieci, err := client.Networks(ctx); err == nil {
		snapshot.Networks = sieci
	}
	if wolumeny, err := client.Volumes(ctx); err == nil {
		snapshot.Volumes = wolumeny
	}

	powiazUzycie(&snapshot)
	snapshot.Summary = podsumuj(snapshot, snapshot.Summary)
	return snapshot
}

// powiazUzycie wypelnia uzycie sieci i wolumenow z listy kontenerow.
//
// Silnik nie odpowiada na to pytanie: w liscie sieci zwraca pusta mape
// kontenerow, a rozmiar i licznik odwolan wolumenu podaje dopiero przy
// osobnym rachunku miejsca. Bez tego wyliczenia kazda siec i kazdy wolumen
// wygladalyby na porzucone - a to one trafiaja pod sprzatanie.
//
// Liczy sie takze kontener zatrzymany: wolumen zatrzymanego kontenera nie
// jest wolumenem niczyim.
func powiazUzycie(snapshot *Snapshot) {
	poNazwie := map[string]int{}
	poID := map[string]int{}
	for i := range snapshot.Networks {
		poNazwie[snapshot.Networks[i].Name] = i
		poID[snapshot.Networks[i].ID] = i
	}
	wolumeny := map[string]int{}
	for i := range snapshot.Volumes {
		wolumeny[snapshot.Volumes[i].Name] = i
	}

	for _, kontener := range snapshot.Containers {
		for _, podlaczenie := range kontener.Networks {
			indeks, ok := poNazwie[podlaczenie.Name]
			if !ok {
				indeks, ok = poID[podlaczenie.ID]
			}
			if !ok {
				// Siec zniknela miedzy jednym zapytaniem a drugim. Kontener
				// mowi o niej prawde, ale nie ma jej do czego dopisac.
				continue
			}
			siec := &snapshot.Networks[indeks]
			siec.Containers = append(siec.Containers, NetworkMember{
				ID: kontener.ID, Name: kontener.Name, State: kontener.State,
				IPv4: podlaczenie.IPv4,
			})
			siec.InUse = true
		}
		for _, montowanie := range kontener.Mounts {
			if montowanie.Type != "volume" || montowanie.Name == "" {
				continue
			}
			indeks, ok := wolumeny[montowanie.Name]
			if !ok {
				continue
			}
			wolumen := &snapshot.Volumes[indeks]
			wolumen.UsedBy = append(wolumen.UsedBy, VolumeMount{
				ContainerID: kontener.ID, ContainerName: kontener.Name,
				State: kontener.State, Destination: montowanie.Destination,
				ReadOnly: montowanie.ReadOnly,
			})
			wolumen.InUse = true
		}
	}

	for i := range snapshot.Networks {
		sort.Slice(snapshot.Networks[i].Containers, func(a, b int) bool {
			return snapshot.Networks[i].Containers[a].Name < snapshot.Networks[i].Containers[b].Name
		})
	}
	for i := range snapshot.Volumes {
		sort.Slice(snapshot.Volumes[i].UsedBy, func(a, b int) bool {
			return snapshot.Volumes[i].UsedBy[a].ContainerName < snapshot.Volumes[i].UsedBy[b].ContainerName
		})
	}
}

// podsumuj liczy sygnaly decyzyjne. Podsumowanie nie jest metryka: mowi, czy
// cos wymaga uwagi operatora, a nie ile czego jest w kazdej chwili.
func podsumuj(snapshot Snapshot, podstawa Summary) Summary {
	podsumowanie := podstawa
	podsumowanie.Containers = len(snapshot.Containers)
	podsumowanie.Images = len(snapshot.Images)
	podsumowanie.Networks = len(snapshot.Networks)
	podsumowanie.Volumes = len(snapshot.Volumes)
	for _, siec := range snapshot.Networks {
		// Siec wbudowana nie jest kandydatem do sprzatania, wiec nie ma jej
		// w liczniku - inaczej kazdy host mialby trzy sieci "do usuniecia".
		if !siec.InUse && !siec.Predefined {
			podsumowanie.NetworksUnused++
		}
	}
	for _, wolumen := range snapshot.Volumes {
		if !wolumen.InUse {
			podsumowanie.VolumesUnused++
		}
	}

	projekty := map[string]*Project{}
	for _, kontener := range snapshot.Containers {
		switch kontener.State {
		case "running":
			podsumowanie.Running++
		case "paused":
			podsumowanie.Paused++
		default:
			podsumowanie.Stopped++
		}
		if kontener.Health == "unhealthy" {
			podsumowanie.Unhealthy++
		}
		// Kontener, ktory wstaje w kolko, jest sprawny w kazdej pojedynczej
		// chwili i mimo to zepsuty. Bez tego licznika nie widac tego wcale.
		if kontener.State == "restarting" || kontener.RestartCount >= progPetliRestartow {
			podsumowanie.RestartLooping++
		}
		if kontener.Compose == nil {
			continue
		}
		projekt := projekty[kontener.Compose.Project]
		if projekt == nil {
			projekt = &Project{
				Name:        kontener.Compose.Project,
				ConfigFiles: kontener.Compose.ConfigFiles,
				WorkingDir:  kontener.Compose.WorkingDir,
			}
			projekty[kontener.Compose.Project] = projekt
		}
		projekt.Total++
		if kontener.State == "running" {
			projekt.Running++
		}
		if kontener.Compose.Service != "" && !zawiera(projekt.Services, kontener.Compose.Service) {
			projekt.Services = append(projekt.Services, kontener.Compose.Service)
		}
	}

	for _, projekt := range projekty {
		sort.Strings(projekt.Services)
		podsumowanie.Projects = append(podsumowanie.Projects, *projekt)
	}
	sort.Slice(podsumowanie.Projects, func(i, j int) bool {
		return podsumowanie.Projects[i].Name < podsumowanie.Projects[j].Name
	})
	return podsumowanie
}

// progPetliRestartow oddziela kontener, ktory raz sie podniosl, od takiego,
// ktory wstaje w kolko. Wartosc jest celowo niska: operator ma zobaczyc
// problem, zanim urosnie do setek restartow.
const progPetliRestartow = 5

func zawiera(lista []string, wartosc string) bool {
	for _, pozycja := range lista {
		if pozycja == wartosc {
			return true
		}
	}
	return false
}

// powodNiedostepnosci tlumaczy blad na zdanie dla operatora.
func powodNiedostepnosci(err error) string {
	if errors.Is(err, ErrUnavailable) {
		return "silnik kontenerow nie odpowiada: " + skrocBlad(err)
	}
	return strings.TrimSpace(err.Error())
}
