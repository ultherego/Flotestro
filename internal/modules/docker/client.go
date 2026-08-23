package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// SocketPaths to miejsca, w ktorych szukamy gniazda silnika.
var SocketPaths = []string{"/run/docker.sock", "/var/run/docker.sock"}

// apiVersion jest przypieta swiadomie. Bez przypiecia silnik odpowiada wersja
// domyslna, ktora zmienia sie z aktualizacja Dockera - a wtedy zmienia sie
// znaczenie pol, ktore czytamy, i nikt tego nie zauwaza.
const apiVersion = "v1.41"

// ErrUnavailable oznacza silnik, ktorego nie da sie odpytac.
var ErrUnavailable = errors.New("silnik kontenerow jest niedostepny")

// Client rozmawia z Engine API po gniezdzie unixowym.
//
// Klient nie przyjmuje dowolnej sciezki. Kazda operacja ma wlasna metode
// i wlasne parametry: przekazanie sciezki z zewnatrz oznaczaloby, ze przez
// helpera da sie wywolac dowolne API silnika, a to jest rownowazne rootowi.
type Client struct {
	http   *http.Client
	socket string
}

// New tworzy klienta dla pierwszego znalezionego gniazda.
func New() (*Client, error) {
	for _, path := range SocketPaths {
		info, err := os.Stat(path)
		if err != nil || info.Mode()&os.ModeSocket == 0 {
			continue
		}
		return NewAt(path), nil
	}
	return nil, fmt.Errorf("%w: brak gniazda silnika", ErrUnavailable)
}

// NewAt tworzy klienta dla wskazanego gniazda.
func NewAt(socket string) *Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &Client{
		socket: socket,
		http: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return dialer.DialContext(ctx, "unix", socket)
				},
				// Silnik jest lokalny; zadne z tych polaczen nie wychodzi
				// poza host, wiec pula moze byc mala.
				MaxIdleConns:    2,
				IdleConnTimeout: 30 * time.Second,
			},
		},
	}
}

// Version zwraca wersje silnika i wersje jego API.
func (c *Client) Version(ctx context.Context) (engine, api string, err error) {
	var wynik struct {
		Version    string `json:"Version"`
		APIVersion string `json:"ApiVersion"`
	}
	if err := c.get(ctx, "/version", nil, &wynik); err != nil {
		return "", "", err
	}
	return wynik.Version, wynik.APIVersion, nil
}

// get wykonuje zapytanie do sciezki zbudowanej w tym pakiecie. Sciezka nigdy
// nie pochodzi z zewnatrz modulu.
func (c *Client) get(ctx context.Context, path string, query url.Values, out any) error {
	return c.call(ctx, http.MethodGet, path, query, out)
}

func (c *Client) call(ctx context.Context, method, path string, query url.Values, out any) error {
	target := "http://docker/" + apiVersion + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrUnavailable, skrocBlad(err))
	}
	defer response.Body.Close()

	if response.StatusCode >= 400 {
		// Tresc bledu silnika bywa dluga; do wyniku trafia jej poczatek,
		// zeby komunikat pozostal czytelny.
		body, _ := io.ReadAll(io.LimitReader(response.Body, 512))
		return fmt.Errorf("silnik odpowiedzial %d: %s",
			response.StatusCode, strings.TrimSpace(string(body)))
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		return nil
	}
	// Odpowiedzi silnika bywaja duze: lista obrazow na hoscie budowlanym
	// potrafi miec megabajty. Limit chroni pamiec agenta i helpera.
	return json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(out)
}

// skrocBlad usuwa z komunikatu powtarzalny prefiks transportu HTTP, ktory nic
// nie wnosi dla operatora.
func skrocBlad(err error) string {
	tekst := err.Error()
	if index := strings.LastIndex(tekst, ": "); index > 0 && index+2 < len(tekst) {
		return tekst[index+2:]
	}
	return tekst
}

// Containers zwraca kontenery hosta. all obejmuje takze zatrzymane: kontener
// zatrzymany jest faktem o hoscie, a nie jego brakiem.
func (c *Client) Containers(ctx context.Context, all bool) ([]Container, error) {
	query := url.Values{}
	if all {
		query.Set("all", "1")
	}
	var surowe []struct {
		ID      string            `json:"Id"`
		Names   []string          `json:"Names"`
		Image   string            `json:"Image"`
		ImageID string            `json:"ImageID"`
		State   string            `json:"State"`
		Status  string            `json:"Status"`
		Created int64             `json:"Created"`
		Labels  map[string]string `json:"Labels"`
		Ports   []struct {
			IP          string `json:"IP"`
			PrivatePort uint16 `json:"PrivatePort"`
			PublicPort  uint16 `json:"PublicPort"`
			Type        string `json:"Type"`
		} `json:"Ports"`
		Mounts []struct {
			Type        string `json:"Type"`
			Name        string `json:"Name"`
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
			RW          bool   `json:"RW"`
		} `json:"Mounts"`
	}
	if err := c.get(ctx, "/containers/json", query, &surowe); err != nil {
		return nil, err
	}

	kontenery := make([]Container, 0, len(surowe))
	for _, wpis := range surowe {
		kontener := Container{
			ID:          wpis.ID,
			Name:        nazwaKontenera(wpis.Names),
			Image:       wpis.Image,
			ImageDigest: wpis.ImageID,
			State:       wpis.State,
			Status:      wpis.Status,
			CreatedAt:   time.Unix(wpis.Created, 0).UTC(),
			Labels:      etykietyBezSekretow(wpis.Labels),
			Compose:     przynaleznoscCompose(wpis.Labels),
		}
		for _, port := range wpis.Ports {
			kontener.Ports = append(kontener.Ports, Port{
				HostIP: port.IP, HostPort: port.PublicPort,
				ContainerPort: port.PrivatePort, Protocol: port.Type,
			})
		}
		for _, mount := range wpis.Mounts {
			kontener.Mounts = append(kontener.Mounts, Mount{
				Type: mount.Type, Name: mount.Name, Source: mount.Source,
				Destination: mount.Destination, ReadOnly: !mount.RW,
			})
		}
		kontenery = append(kontenery, kontener)
	}
	return kontenery, nil
}

// Inspect uzupelnia kontener o dane, ktorych lista nie podaje: stan zdrowia
// i licznik restartow. Odpytywane sa wylacznie kontenery, dla ktorych to ma
// znaczenie - pelny inspect calej listy przy kazdym cyklu obciazalby host.
func (c *Client) Inspect(ctx context.Context, id string) (health string, restarts int, err error) {
	var szczegoly struct {
		RestartCount int `json:"RestartCount"`
		State        struct {
			Health *struct {
				Status string `json:"Status"`
			} `json:"Health"`
		} `json:"State"`
	}
	if err := c.get(ctx, "/containers/"+id+"/json", nil, &szczegoly); err != nil {
		return "", 0, err
	}
	if szczegoly.State.Health != nil {
		health = szczegoly.State.Health.Status
	}
	return health, szczegoly.RestartCount, nil
}

// Images zwraca obrazy obecne na hoscie.
func (c *Client) Images(ctx context.Context) ([]Image, error) {
	var surowe []struct {
		ID         string   `json:"Id"`
		RepoTags   []string `json:"RepoTags"`
		RepoDig    []string `json:"RepoDigests"`
		Size       int64    `json:"Size"`
		Created    int64    `json:"Created"`
		Containers int64    `json:"Containers"`
	}
	if err := c.get(ctx, "/images/json", nil, &surowe); err != nil {
		return nil, err
	}
	obrazy := make([]Image, 0, len(surowe))
	for _, wpis := range surowe {
		obrazy = append(obrazy, Image{
			ID: wpis.ID, Tags: pomijajBezTagu(wpis.RepoTags), Digests: wpis.RepoDig,
			SizeBytes: wpis.Size, CreatedAt: time.Unix(wpis.Created, 0).UTC(),
			// Silnik zwraca -1, gdy liczby kontenerow nie policzono. Nieznane
			// uzycie nie moze wygladac jak obraz nieuzywany, bo to on trafia
			// pod sprzatanie.
			InUse: wpis.Containers != 0,
		})
	}
	return obrazy, nil
}

// Networks zwraca sieci Dockera.
func (c *Client) Networks(ctx context.Context) ([]Network, error) {
	var surowe []struct {
		ID     string `json:"Id"`
		Name   string `json:"Name"`
		Driver string `json:"Driver"`
		Scope  string `json:"Scope"`
		IPAM   struct {
			Config []struct {
				Subnet string `json:"Subnet"`
			} `json:"Config"`
		} `json:"IPAM"`
		Containers map[string]any `json:"Containers"`
	}
	if err := c.get(ctx, "/networks", nil, &surowe); err != nil {
		return nil, err
	}
	sieci := make([]Network, 0, len(surowe))
	for _, wpis := range surowe {
		siec := Network{
			ID: wpis.ID, Name: wpis.Name, Driver: wpis.Driver, Scope: wpis.Scope,
			InUse: len(wpis.Containers) > 0,
		}
		for _, config := range wpis.IPAM.Config {
			if config.Subnet != "" {
				siec.Subnets = append(siec.Subnets, config.Subnet)
			}
		}
		sieci = append(sieci, siec)
	}
	return sieci, nil
}

// Volumes zwraca wolumeny Dockera.
func (c *Client) Volumes(ctx context.Context) ([]Volume, error) {
	var odpowiedz struct {
		Volumes []struct {
			Name       string `json:"Name"`
			Driver     string `json:"Driver"`
			Mountpoint string `json:"Mountpoint"`
			UsageData  *struct {
				Size     int64 `json:"Size"`
				RefCount int64 `json:"RefCount"`
			} `json:"UsageData"`
		} `json:"Volumes"`
	}
	if err := c.get(ctx, "/volumes", nil, &odpowiedz); err != nil {
		return nil, err
	}
	wolumeny := make([]Volume, 0, len(odpowiedz.Volumes))
	for _, wpis := range odpowiedz.Volumes {
		wolumen := Volume{Name: wpis.Name, Driver: wpis.Driver, Mountpoint: wpis.Mountpoint}
		if wpis.UsageData != nil {
			// Rozmiar -1 oznacza, ze silnik go nie liczyl. Zapisanie go jako
			// zera sugerowaloby pusty wolumen gotowy do skasowania.
			if wpis.UsageData.Size >= 0 {
				rozmiar := wpis.UsageData.Size
				wolumen.SizeBytes = &rozmiar
			}
			wolumen.InUse = wpis.UsageData.RefCount > 0
		}
		wolumeny = append(wolumeny, wolumen)
	}
	return wolumeny, nil
}

// nazwaKontenera bierze pierwsza nazwe i obcina wiodacy ukosnik, ktory silnik
// dokleja do kazdej.
func nazwaKontenera(nazwy []string) string {
	if len(nazwy) == 0 {
		return ""
	}
	return strings.TrimPrefix(nazwy[0], "/")
}

func pomijajBezTagu(tagi []string) []string {
	var wynik []string
	for _, tag := range tagi {
		if tag != "<none>:<none>" && tag != "" {
			wynik = append(wynik, tag)
		}
	}
	return wynik
}

// przynaleznoscCompose czyta etykiety, ktorymi Compose oznacza swoje kontenery.
func przynaleznoscCompose(etykiety map[string]string) *ComposeMembership {
	projekt := etykiety["com.docker.compose.project"]
	if projekt == "" {
		return nil
	}
	return &ComposeMembership{
		Project:     projekt,
		Service:     etykiety["com.docker.compose.service"],
		ConfigFiles: etykiety["com.docker.compose.project.config_files"],
		WorkingDir:  etykiety["com.docker.compose.project.working_dir"],
	}
}

// etykietyBezSekretow odsiewa etykiety, ktore z nazwy niosa poswiadczenie.
//
// Silnik nie odroznia etykiety zwyklej od tajnej, wiec robimy to po nazwie.
// Wartosci zmiennych srodowiskowych nie zbieramy w ogole - to tam trafiaja
// hasla, a inventory jest trwale i widoczne szerzej niz sam host.
func etykietyBezSekretow(etykiety map[string]string) map[string]string {
	if len(etykiety) == 0 {
		return nil
	}
	wynik := make(map[string]string, len(etykiety))
	for klucz, wartosc := range etykiety {
		if wygladaNaSekret(klucz) {
			wynik[klucz] = "[ukryte]"
			continue
		}
		wynik[klucz] = wartosc
	}
	return wynik
}

func wygladaNaSekret(klucz string) bool {
	male := strings.ToLower(klucz)
	for _, wzorzec := range []string{"secret", "password", "passwd", "token", "apikey", "api_key", "credential"} {
		if strings.Contains(male, wzorzec) {
			return true
		}
	}
	return false
}
