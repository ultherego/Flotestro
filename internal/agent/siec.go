package agent

import (
	"context"
	"os/exec"
	"time"

	"github.com/ultherego/flotestro/internal/modules/network"
)

// sciezkiIP wylicza miejsca, w ktorych stoi narzedzie iproute2. Sciezka jest
// stala, a nie szukana w PATH: agent uruchamia wylacznie znane binaria.
var sciezkiIP = []string{"/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"}

// ZbierzSiec czyta interfejsy i trasy hosta.
//
// Odczyt nie wymaga roota: tablice jadra sa czytelne dla kazdego. Zapis
// konfiguracji to osobna sprawa i idzie przez helpera.
func ZbierzSiec(ctx context.Context, adresZarzadzania string) network.Snapshot {
	snapshot := network.Snapshot{ObservedAt: time.Now().UTC()}

	sciezka := sciezkaIP()
	if sciezka == "" {
		snapshot.UnavailableReason = "this host has no iproute2 (ip) binary"
		return snapshot
	}

	// Flaga -d doklada linkinfo, a wiec rodzaj interfejsu. Bez niej most
	// dockera i veth wygladaja jak zwykle karty sieciowe, a host z kilkunastoma
	// interfejsami wirtualnymi staje sie nieczytelny.
	wyjscie, err := wyjscieIP(ctx, sciezka, "-j", "-d", "addr", "show")
	if err != nil {
		snapshot.UnavailableReason = "ip addr: " + err.Error()
		return snapshot
	}
	interfejsy, err := network.ParsujInterfejsy(wyjscie)
	if err != nil {
		snapshot.UnavailableReason = err.Error()
		return snapshot
	}
	network.UzupelnijZSys("/sys/class/net", interfejsy)
	snapshot.Interfaces = interfejsy

	// Obie rodziny sa czytane osobno, bo "ip route show" pokazuje domyslnie
	// tylko IPv4. Milczenie o trasach IPv6 wygladaloby jak ich brak.
	for _, rodzina := range []struct {
		flaga   string
		rodzina string
	}{{"-4", network.FamilyIPv4}, {"-6", network.FamilyIPv6}} {
		wyjscie, err := wyjscieIP(ctx, sciezka, "-j", rodzina.flaga, "route", "show")
		if err != nil {
			continue
		}
		if trasy, err := network.ParsujTrasy(wyjscie, rodzina.rodzina); err == nil {
			snapshot.Routes = append(snapshot.Routes, trasy...)
		}
	}

	network.OznaczKanalZarzadzania(&snapshot, adresZarzadzania)
	snapshot.WriteAdapter = network.WykryjAdapter(network.Istnieje)
	return snapshot
}

func sciezkaIP() string {
	for _, sciezka := range sciezkiIP {
		if network.Istnieje(sciezka) {
			return sciezka
		}
	}
	return ""
}

func wyjscieIP(ctx context.Context, sciezka string, argumenty ...string) (string, error) {
	callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(callCtx, sciezka, argumenty...)
	cmd.Env = []string{"LC_ALL=C", "LANG=C"}
	wyjscie, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(wyjscie), nil
}
