package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/ultherego/flotestro/internal/agent"
	"github.com/ultherego/flotestro/internal/agentconfig"
)

// poleceniaStanu odpowiada na pytanie "co ten agent w ogole robi".
func poleceniaStanu(argumenty []string, wyjscie, bledy io.Writer) int {
	sciezka, ok := sciezkaKonfiguracji("status", argumenty, bledy)
	if !ok {
		return 2
	}

	problemy := 0
	cfg, err := agentconfig.Wczytaj(sciezka)
	if err != nil {
		fmt.Fprintf(wyjscie, "Config:       BLAD (%s): %v\n", sciezka, err)
		// Bez konfiguracji nie wiemy nawet, gdzie szukac tozsamosci -
		// zgadywanie katalogu dalo by odpowiedz o cudzym stanie.
		return 1
	}
	fmt.Fprintf(wyjscie, "Config:       poprawny (%s)\n", sciezka)

	tozsamosc := agent.OdczytajTozsamosc(cfg.Agent.StateDir)
	switch {
	case !tozsamosc.Obecna:
		fmt.Fprintf(wyjscie, "Identity:     brak (%s)\n", tozsamosc.Blad)
		problemy++
	default:
		fmt.Fprintf(wyjscie, "Identity:     host/%s\n", tozsamosc.HostID)
		zostalo := time.Until(tozsamosc.NotAfter)
		switch {
		case tozsamosc.Wygasl:
			fmt.Fprintf(wyjscie, "Certificate:  WYGASL %s\n",
				tozsamosc.NotAfter.UTC().Format(time.RFC3339))
			problemy++
		default:
			fmt.Fprintf(wyjscie, "Certificate:  wazny do %s (%s)\n",
				tozsamosc.NotAfter.UTC().Format(time.RFC3339), zaokraglony(zostalo))
		}
	}

	stan, err := agent.OdczytajStan(cfg.Agent.StateDir)
	switch {
	case os.IsNotExist(err):
		// Brak pliku stanu nie jest awaria: agent moze byc dopiero co
		// zainstalowany i jeszcze nie mial ani jednej sesji.
		fmt.Fprintln(wyjscie, "Session:      brak zapisu - agent jeszcze nie nawiazal sesji")
	case err != nil:
		fmt.Fprintf(wyjscie, "Session:      nieznana (%v)\n", err)
	case stan.ConnectedAt != nil:
		fmt.Fprintf(wyjscie, "Session:      polaczona z %s od %s (%s)\n", stan.Gateway,
			stan.ConnectedAt.UTC().Format(time.RFC3339), zaokraglony(time.Since(*stan.ConnectedAt)))
	default:
		powod := stan.LastError
		if powod == "" {
			powod = "bez sesji"
		}
		kiedy := ""
		if stan.DisconnectedAt != nil {
			kiedy = " od " + stan.DisconnectedAt.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(wyjscie, "Session:      rozlaczona%s: %s\n", kiedy, powod)
		problemy++
	}
	if stan.LastInventoryAt != nil {
		fmt.Fprintf(wyjscie, "Inventory:    %s, rewizja %s\n",
			stan.LastInventoryAt.UTC().Format(time.RFC3339), skrot(stan.InventoryRevision))
	}

	if cfg.Agent.Mode == agentconfig.TrybOdczytu {
		// W trybie odczytu helper nie ma prawa dzialac: jego brak jest
		// wtedy odpowiedzia, a nie usterka.
		fmt.Fprintf(wyjscie, "Helper:       wylaczony (tryb %s)\n", cfg.Agent.Mode)
	} else if err := gniazdoDziala(cfg.Helper.Socket); err != nil {
		fmt.Fprintf(wyjscie, "Helper:       niedostepny (%v)\n", err)
		problemy++
	} else {
		fmt.Fprintf(wyjscie, "Helper:       gniazdo gotowe (%s)\n", cfg.Helper.Socket)
	}

	fmt.Fprintf(wyjscie, "Agent:        %s\n", wersja)
	if problemy > 0 {
		return 1
	}
	return 0
}

// gniazdoDziala sprawdza, czy da sie polaczyc z helperem.
func gniazdoDziala(sciezka string) error {
	info, err := os.Stat(sciezka)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s nie jest gniazdem", sciezka)
	}
	polaczenie, err := net.DialTimeout("unix", sciezka, 2*time.Second)
	if err != nil {
		return err
	}
	return polaczenie.Close()
}

// zaokraglony skraca czas do postaci czytelnej dla czlowieka.
func zaokraglony(czas time.Duration) string {
	if czas < 0 {
		czas = -czas
	}
	dni := int(czas.Hours()) / 24
	godziny := int(czas.Hours()) % 24
	if dni > 0 {
		return fmt.Sprintf("%dd %02dh", dni, godziny)
	}
	return czas.Round(time.Second).String()
}

// skrot przycina odcisk do postaci, ktora da sie porownac wzrokiem.
func skrot(wartosc string) string {
	if len(wartosc) > 12 {
		return wartosc[:12]
	}
	return wartosc
}
