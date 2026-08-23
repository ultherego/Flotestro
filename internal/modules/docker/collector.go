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

	snapshot.Summary = podsumuj(snapshot, snapshot.Summary)
	return snapshot
}

// podsumuj liczy sygnaly decyzyjne. Podsumowanie nie jest metryka: mowi, czy
// cos wymaga uwagi operatora, a nie ile czego jest w kazdej chwili.
func podsumuj(snapshot Snapshot, podstawa Summary) Summary {
	podsumowanie := podstawa
	podsumowanie.Containers = len(snapshot.Containers)
	podsumowanie.Images = len(snapshot.Images)
	podsumowanie.Networks = len(snapshot.Networks)
	podsumowanie.Volumes = len(snapshot.Volumes)

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
