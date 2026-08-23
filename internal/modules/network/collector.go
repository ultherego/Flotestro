package network

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// surowyInterfejs odwzorowuje jeden wpis z "ip -j addr show".
type surowyInterfejs struct {
	Index     int      `json:"ifindex"`
	Name      string   `json:"ifname"`
	Flags     []string `json:"flags"`
	MTU       int      `json:"mtu"`
	OperState string   `json:"operstate"`
	LinkType  string   `json:"link_type"`
	Address   string   `json:"address"`
	LinkInfo  struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
	AddrInfo []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
		Scope     string `json:"scope"`
		Protocol  string `json:"protocol"`
		Dynamic   bool   `json:"dynamic"`
		ValidLife *int64 `json:"valid_life_time"`
	} `json:"addr_info"`
}

// surowaTrasa odwzorowuje jeden wpis z "ip -j route show".
type surowaTrasa struct {
	Dst      string `json:"dst"`
	Gateway  string `json:"gateway"`
	Dev      string `json:"dev"`
	PrefSrc  string `json:"prefsrc"`
	Protocol string `json:"protocol"`
	Scope    string `json:"scope"`
	Metric   int    `json:"metric"`
	Table    string `json:"table"`
}

// zycieNieskonczone to wartosc, ktora jadro podaje dla adresu bez czasu zycia.
const zycieNieskonczone = 4294967295

// ParsujInterfejsy czyta wyjscie "ip -j addr show".
func ParsujInterfejsy(wyjscie string) ([]Interface, error) {
	var surowe []surowyInterfejs
	if err := json.Unmarshal([]byte(wyjscie), &surowe); err != nil {
		return nil, fmt.Errorf("odczyt interfejsow: %w", err)
	}
	interfejsy := make([]Interface, 0, len(surowe))
	for _, wpis := range surowe {
		interfejs := Interface{
			Name:      wpis.Name,
			Index:     wpis.Index,
			Kind:      rodzaj(wpis),
			MAC:       wpis.Address,
			MTU:       wpis.MTU,
			OperState: strings.ToLower(wpis.OperState),
		}
		for _, adres := range wpis.AddrInfo {
			// Adres bez prefiksu nie mowi, jaka siec host uwaza za lokalna.
			interfejs.Addresses = append(interfejs.Addresses, Address{
				Family:  adres.Family,
				Address: adres.Local + "/" + strconv.Itoa(adres.PrefixLen),
				Scope:   adres.Scope,
				Source:  adres.Protocol,
				// Adres dynamiczny ma skonczony czas zycia. Ten sam adres
				// jutro moze nalezec do kogos innego.
				Permanent: !adres.Dynamic &&
					(adres.ValidLife == nil || *adres.ValidLife == zycieNieskonczone),
			})
		}
		interfejsy = append(interfejsy, interfejs)
	}
	return interfejsy, nil
}

// rodzaj nazywa typ interfejsu. Jadro podaje go tylko dla wirtualnych, wiec
// brak informacji oznacza interfejs fizyczny albo loopback.
func rodzaj(wpis surowyInterfejs) string {
	if wpis.LinkInfo.Kind != "" {
		return wpis.LinkInfo.Kind
	}
	if wpis.Name == "lo" {
		return "loopback"
	}
	if wpis.LinkType == "ether" {
		return "ethernet"
	}
	return wpis.LinkType
}

// ParsujTrasy czyta wyjscie "ip -j route show".
func ParsujTrasy(wyjscie, rodzina string) ([]Route, error) {
	var surowe []surowaTrasa
	if err := json.Unmarshal([]byte(wyjscie), &surowe); err != nil {
		return nil, fmt.Errorf("odczyt tras: %w", err)
	}
	trasy := make([]Route, 0, len(surowe))
	for _, wpis := range surowe {
		trasy = append(trasy, Route{
			Destination: wpis.Dst,
			Gateway:     wpis.Gateway,
			Interface:   wpis.Dev,
			Source:      wpis.PrefSrc,
			Protocol:    wpis.Protocol,
			Scope:       wpis.Scope,
			Metric:      wpis.Metric,
			Table:       wpis.Table,
			Family:      rodzina,
		})
	}
	return trasy, nil
}

// UzupelnijZSys dopisuje to, czego "ip" nie podaje: predkosc lacza i nazwe
// sterownika. Odczyt z /sys jest tani i nie wymaga uruchamiania procesu.
func UzupelnijZSys(katalog string, interfejsy []Interface) {
	for i := range interfejsy {
		sciezka := filepath.Join(katalog, interfejsy[i].Name)
		if wartosc, ok := liczbaZPliku(filepath.Join(sciezka, "carrier")); ok {
			nosna := wartosc == 1
			interfejsy[i].Carrier = &nosna
		}
		// Predkosc jadro podaje tylko dla czesci sterownikow, a dla lacza
		// bez nosnej zwraca -1. Nieznana zostaje nieznana.
		if wartosc, ok := liczbaZPliku(filepath.Join(sciezka, "speed")); ok && wartosc > 0 {
			predkosc := int(wartosc)
			interfejsy[i].SpeedMbps = &predkosc
		}
		if cel, err := os.Readlink(filepath.Join(sciezka, "device", "driver")); err == nil {
			interfejsy[i].Driver = filepath.Base(cel)
		}
	}
}

func liczbaZPliku(sciezka string) (int64, bool) {
	dane, err := os.ReadFile(sciezka)
	if err != nil {
		return 0, false
	}
	wartosc, err := strconv.ParseInt(strings.TrimSpace(string(dane)), 10, 64)
	if err != nil {
		return 0, false
	}
	return wartosc, true
}

// OznaczKanalZarzadzania wskazuje interfejs i adres, ktorym host rozmawia
// z panelem.
//
// Adres bierze sie z faktycznego polaczenia agenta, a nie z pierwszej pozycji
// listy: host ma zwykle kilka adresow, a tylko jeden z nich jest tym, przez
// ktory panel go widzi. Pomylka w te strone konczy sie zmiana konfiguracji
// interfejsu, przez ktory wlasnie przyszlo polecenie.
func OznaczKanalZarzadzania(snapshot *Snapshot, adresLokalny string) {
	if adresLokalny == "" {
		return
	}
	adres := adresLokalny
	if host, _, err := net.SplitHostPort(adresLokalny); err == nil {
		adres = host
	}
	parsowany := net.ParseIP(adres)
	if parsowany == nil {
		return
	}
	for i := range snapshot.Interfaces {
		for _, przypisany := range snapshot.Interfaces[i].Addresses {
			wlasny, _, err := net.ParseCIDR(przypisany.Address)
			if err != nil || !wlasny.Equal(parsowany) {
				continue
			}
			snapshot.Interfaces[i].Management = true
			snapshot.ManagementInterface = snapshot.Interfaces[i].Name
			snapshot.ManagementAddress = przypisany.Address
			return
		}
	}
}
