package docker

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// Result opisuje wynik operacji na silniku kontenerow.
//
// Stan przed i po jest zapisywany zawsze, takze przy bledzie: bez tego
// operator nie wie, co zdazylo sie zmienic, zanim operacja padla.
type Result struct {
	Before *Container `json:"before,omitempty"`
	After  *Container `json:"after,omitempty"`
	// Removed wylicza obiekty, ktore zniknely. Sprzatanie ma powiedziec, co
	// dokladnie usunelo, a nie ile obiektow.
	Removed []string `json:"removed,omitempty"`
	// ReclaimedBytes jest sumaryczna wielkoscia odzyskanego miejsca. Brak
	// wartosci oznacza, ze silnik jej nie podal - zero znaczyloby, ze nic
	// nie odzyskano.
	ReclaimedBytes *int64 `json:"reclaimed_bytes,omitempty"`
	// ImageDigest wskazuje, co naprawde zostalo pobrane. Tag moze jutro
	// wskazywac inny obraz, digest nie.
	ImageDigest string `json:"image_digest,omitempty"`
}

// StartContainer uruchamia kontener.
func (c *Client) StartContainer(ctx context.Context, id string) error {
	return c.post(ctx, "/containers/"+id+"/start", nil)
}

// StopContainer zatrzymuje kontener, dajac mu czas na zamkniecie.
// Zero oznacza czas domyslny silnika, a nie natychmiastowe zabicie.
func (c *Client) StopContainer(ctx context.Context, id string, timeoutSeconds uint32) error {
	query := url.Values{}
	if timeoutSeconds > 0 {
		query.Set("t", strconv.FormatUint(uint64(timeoutSeconds), 10))
	}
	return c.post(ctx, "/containers/"+id+"/stop", query)
}

// RestartContainer przeladowuje kontener.
func (c *Client) RestartContainer(ctx context.Context, id string, timeoutSeconds uint32) error {
	query := url.Values{}
	if timeoutSeconds > 0 {
		query.Set("t", strconv.FormatUint(uint64(timeoutSeconds), 10))
	}
	return c.post(ctx, "/containers/"+id+"/restart", query)
}

// RemoveContainer usuwa kontener. Wolumeny znikaja tylko wtedy, gdy operator
// jawnie o to poprosil: wolumen przezywa kontener po to, zeby dane przezyly.
func (c *Client) RemoveContainer(ctx context.Context, id string, removeVolumes bool) error {
	query := url.Values{}
	if removeVolumes {
		query.Set("v", "1")
	}
	return c.call(ctx, http.MethodDelete, "/containers/"+id, query, nil)
}

// PullImage pobiera obraz i zwraca jego digest.
func (c *Client) PullImage(ctx context.Context, reference string) (string, error) {
	query := url.Values{}
	query.Set("fromImage", reference)
	// Silnik strumieniuje postep pobierania jako ciag obiektow JSON; tresci
	// nie potrzebujemy, wiec czytamy ja do konca i odrzucamy. Wazne jest, zeby
	// doczytac: zerwanie polaczenia w polowie przerywa pobieranie.
	if err := c.post(ctx, "/images/create", query); err != nil {
		return "", err
	}
	var szczegoly struct {
		ID          string   `json:"Id"`
		RepoDigests []string `json:"RepoDigests"`
	}
	if err := c.get(ctx, "/images/"+url.PathEscape(reference)+"/json", nil, &szczegoly); err != nil {
		// Obraz zostal pobrany; brak digestu nie uniewaznia operacji.
		return "", nil
	}
	if len(szczegoly.RepoDigests) > 0 {
		return szczegoly.RepoDigests[0], nil
	}
	return szczegoly.ID, nil
}

// RemoveImage usuwa obraz.
//
// Silnik zwraca liste warstw, ktore zniknely, ale nie ich rozmiar - odzyskane
// miejsce liczymy z rozmiarow zebranych przed usunieciem.
func (c *Client) RemoveImage(ctx context.Context, id string) error {
	return c.call(ctx, http.MethodDelete, "/images/"+url.PathEscape(id), nil, nil)
}

// RemoveVolume usuwa wolumen.
func (c *Client) RemoveVolume(ctx context.Context, name string) error {
	return c.call(ctx, http.MethodDelete, "/volumes/"+url.PathEscape(name), nil, nil)
}

// RemoveNetwork usuwa siec.
func (c *Client) RemoveNetwork(ctx context.Context, id string) error {
	return c.call(ctx, http.MethodDelete, "/networks/"+id, nil, nil)
}

// ContainerByID zwraca kontener o podanym identyfikatorze albo nil.
// Uzywane do zapisu stanu przed i po operacji.
func (c *Client) ContainerByID(ctx context.Context, id string) *Container {
	kontenery, err := c.Containers(ctx, true)
	if err != nil {
		return nil
	}
	for i := range kontenery {
		if kontenery[i].ID == id {
			kontener := kontenery[i]
			if health, restarts, err := c.Inspect(ctx, id); err == nil {
				kontener.Health = health
				kontener.RestartCount = restarts
			}
			return &kontener
		}
	}
	return nil
}

// post wykonuje operacje zmieniajaca stan silnika.
func (c *Client) post(ctx context.Context, path string, query url.Values) error {
	return c.call(ctx, http.MethodPost, path, query, nil)
}

// Sprzatanie usuwa wylacznie wskazane obiekty.
//
// Sprzatanie po filtrze usuwa to, co pasuje w chwili wykonania - a wiec takze
// obiekt utworzony po tym, jak operator obejrzal podglad. Lista jest wiec
// jawna: usuwamy dokladnie to, co zostalo pokazane.
func Prune(ctx context.Context, client *Client, images, volumes, networks []string) (Result, error) {
	wynik := Result{}
	var odzyskane int64
	var znaneRozmiary bool

	// Rozmiary sa liczone przed usunieciem: po fakcie nie ma juz czego mierzyc.
	rozmiary := map[string]int64{}
	if obrazy, err := client.Images(ctx); err == nil {
		for _, obraz := range obrazy {
			rozmiary[obraz.ID] = obraz.SizeBytes
		}
	}
	wolumeny := map[string]int64{}
	if lista, err := client.Volumes(ctx); err == nil {
		for _, wolumen := range lista {
			if wolumen.SizeBytes != nil {
				wolumeny[wolumen.Name] = *wolumen.SizeBytes
			}
		}
	}

	for _, id := range images {
		if err := client.RemoveImage(ctx, id); err != nil {
			return wynik, fmt.Errorf("obraz %s: %w", skrotID(id), err)
		}
		wynik.Removed = append(wynik.Removed, "image "+skrotID(id))
		if rozmiar, ok := rozmiary[id]; ok {
			odzyskane += rozmiar
			znaneRozmiary = true
		}
	}
	for _, nazwa := range volumes {
		if err := client.RemoveVolume(ctx, nazwa); err != nil {
			return wynik, fmt.Errorf("wolumen %s: %w", nazwa, err)
		}
		wynik.Removed = append(wynik.Removed, "volume "+nazwa)
		if rozmiar, ok := wolumeny[nazwa]; ok {
			odzyskane += rozmiar
			znaneRozmiary = true
		}
	}
	for _, id := range networks {
		if err := client.RemoveNetwork(ctx, id); err != nil {
			return wynik, fmt.Errorf("siec %s: %w", skrotID(id), err)
		}
		wynik.Removed = append(wynik.Removed, "network "+skrotID(id))
	}

	// Nieznane odzyskane miejsce zostaje nieznane. Zero znaczyloby, ze
	// sprzatanie niczego nie dalo.
	if znaneRozmiary {
		wynik.ReclaimedBytes = &odzyskane
	}
	return wynik, nil
}

// skrotID skraca identyfikator do dlugosci czytelnej w wyniku operacji.
func skrotID(id string) string {
	id = trimAlgorithm(id)
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func trimAlgorithm(id string) string {
	if len(id) > 7 && id[:7] == "sha256:" {
		return id[7:]
	}
	return id
}
