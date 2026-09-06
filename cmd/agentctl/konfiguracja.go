package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ultherego/flotestro/internal/agentconfig"
)

// poleceniaKonfiguracji obsluguje "config validate" i "config show".
func poleceniaKonfiguracji(argumenty []string, wyjscie, bledy io.Writer) int {
	if len(argumenty) == 0 {
		fmt.Fprintln(bledy, "uzycie: agentctl config validate|show [--config PLIK]")
		return 2
	}
	switch argumenty[0] {
	case "validate":
		return sprawdzKonfiguracje(argumenty[1:], wyjscie, bledy, false)
	case "show":
		return sprawdzKonfiguracje(argumenty[1:], wyjscie, bledy, true)
	default:
		fmt.Fprintf(bledy, "nieznane polecenie config: %s\n", argumenty[0])
		return 2
	}
}

// sciezkaKonfiguracji czyta wspolna flage --config.
func sciezkaKonfiguracji(nazwa string, argumenty []string, bledy io.Writer) (string, bool) {
	zestaw := flag.NewFlagSet(nazwa, flag.ContinueOnError)
	zestaw.SetOutput(bledy)
	sciezka := zestaw.String("config", agentconfig.SciezkaDomyslna, "plik konfiguracji agenta")
	if err := zestaw.Parse(argumenty); err != nil {
		return "", false
	}
	return *sciezka, true
}

// sprawdzKonfiguracje czyta plik i mowi, co z nim jest nie tak.
//
// Kazdy blad ma swoj kod, a nie tylko opis: to on trafia do zgloszenia
// z hosta, ktory jeszcze nie rozmawia z panelem.
func sprawdzKonfiguracje(argumenty []string, wyjscie, bledy io.Writer, pokaz bool) int {
	sciezka, ok := sciezkaKonfiguracji("config", argumenty, bledy)
	if !ok {
		return 2
	}

	cfg, err := agentconfig.Wczytaj(sciezka)
	if err != nil {
		fmt.Fprintf(bledy, "config: %s\n  %v\n", sciezka, err)
		return 1
	}
	problemy := 0
	if err := cfg.SprawdzBootstrapCA(); err != nil {
		fmt.Fprintf(bledy, "bootstrap_ca_file: %v\n", err)
		problemy++
	}
	if err := prawaPliku(sciezka); err != nil {
		fmt.Fprintf(bledy, "prawa pliku: %v\n", err)
		problemy++
	}
	if problemy > 0 {
		return 1
	}

	fmt.Fprintf(wyjscie, "Config:       poprawny (%s)\n", sciezka)
	if !pokaz {
		return 0
	}
	fmt.Fprintf(wyjscie, "Enrollment:   %s\n", cfg.Connection.EnrollmentURL)
	for i, adres := range cfg.Connection.GatewayURLs {
		etykieta := "Gateway:     "
		if i > 0 {
			// Kolejne bramy sa zapasowe: pokazujemy je pod pierwsza,
			// bez powtarzania etykiety.
			etykieta = "             "
		}
		fmt.Fprintf(wyjscie, "%s %s\n", etykieta, adres)
	}
	if cfg.Connection.BootstrapCA != "" {
		fmt.Fprintf(wyjscie, "Bootstrap CA: %s\n", cfg.Connection.BootstrapCA)
	}
	fmt.Fprintf(wyjscie, "Timeouts:     connect %s, reconnect %s-%s\n",
		cfg.Connection.ConnectTimeout, cfg.Connection.ReconnectMin, cfg.Connection.ReconnectMax)
	fmt.Fprintf(wyjscie, "Agent:        stan %s, inwentarz co %s, zadan %d, tryb %s\n",
		cfg.Agent.StateDir, cfg.Agent.InventoryInterval, cfg.Agent.MaxConcurrentTasks, cfg.Agent.Mode)
	fmt.Fprintf(wyjscie, "Helper:       %s\n", cfg.Helper.Socket)
	return 0
}

// prawaPliku pilnuje, ze konfiguracji nie moze podmienic kto popadnie.
//
// Plik wskazuje adres panelu i bundle CA, wiec prawo zapisu do niego jest
// prawem przekierowania hosta na cudzy panel.
func prawaPliku(sciezka string) error {
	info, err := os.Stat(sciezka)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s jest zapisywalny dla grupy albo innych (%04o)",
			sciezka, info.Mode().Perm())
	}
	return nil
}
