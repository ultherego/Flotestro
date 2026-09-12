package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/term"

	"github.com/ultherego/flotestro/internal/agent"
	"github.com/ultherego/flotestro/internal/agentconfig"
)

// poleceniaEnrollmentu przeprowadza jednorazowe przyjecie hosta do floty.
//
// Osobne polecenie, a nie skutek uboczny startu demona: enrollment jest
// jednorazowa decyzja operatora i wymaga sekretu, ktory nie ma prawa lezec
// w pliku srodowiska uslugi. Demon startuje dopiero wtedy, gdy tozsamosc juz
// jest - i wtedy nie potrzebuje zadnego tokenu.
func poleceniaEnrollmentu(argumenty []string, wejscie io.Reader, wyjscie, bledy io.Writer) int {
	zestaw := flag.NewFlagSet("enroll", flag.ContinueOnError)
	zestaw.SetOutput(bledy)
	sciezka := zestaw.String("config", agentconfig.DefaultPath, "plik konfiguracji agenta")
	plikTokenu := zestaw.String("token-file", "", "plik z tokenem enrollmentu")
	nazwa := zestaw.String("hostname", "", "nazwa hosta zglaszana do panelu")
	limit := zestaw.Duration("timeout", 2*time.Minute, "limit czasu na enrollment")
	if err := zestaw.Parse(argumenty); err != nil {
		return 2
	}

	cfg, err := agentconfig.Load(*sciezka)
	if err != nil {
		fmt.Fprintf(bledy, "config: %s\n  %v\n", *sciezka, err)
		return 1
	}
	if err := cfg.CheckBootstrapCA(); err != nil {
		fmt.Fprintf(bledy, "bootstrap_ca_file: %v\n", err)
		return 1
	}

	// Identity, ktora juz dziala, nie moze zostac zastapiona przy okazji.
	// Wymiana istniejacej tozsamosci jest osobna decyzja i idzie przez
	// zamowienie odtworzenia w panelu.
	stan := agent.OdczytajTozsamosc(cfg.Agent.StateDir)
	if stan.Obecna && !stan.Wygasl {
		fmt.Fprintf(bledy, "host jest juz zarejestrowany jako host/%s (certyfikat wazny do %s)\n",
			stan.HostID, stan.NotAfter.UTC().Format(time.RFC3339))
		fmt.Fprintln(bledy, "wymiane tozsamosci zamawia sie w panelu: POST /hosts/{id}/identity-recovery")
		return 1
	}

	token, err := odczytajToken(*plikTokenu, wejscie, bledy)
	if err != nil {
		fmt.Fprintf(bledy, "token enrollmentu: %v\n", err)
		return 1
	}
	defer wyczysc(token)
	if len(token) == 0 {
		fmt.Fprintln(bledy, "token enrollmentu jest pusty")
		return 1
	}

	ctx, anuluj := context.WithTimeout(context.Background(), *limit)
	defer anuluj()

	if *nazwa == "" {
		*nazwa, _ = os.Hostname()
	}
	tozsamosc, err := agent.EnsureIdentity(ctx, cfg.Agent.StateDir,
		cfg.Connection.EnrollmentURL, string(token), cfg.Connection.BootstrapCA)
	if err != nil {
		fmt.Fprintf(bledy, "enrollment nieudany: %v\n", err)
		return 1
	}

	fmt.Fprintf(wyjscie, "Zarejestrowany: host/%s\n", tozsamosc.HostID)
	fmt.Fprintf(wyjscie, "Certyfikat:     wazny do %s\n",
		tozsamosc.NotAfter.UTC().Format(time.RFC3339))
	fmt.Fprintln(wyjscie, "Uruchom usluge: systemctl start flotestro-agent.service")
	return 0
}

// odczytajToken pobiera token, nie zostawiajac go w argumentach ani
// w srodowisku procesu.
//
// Argument wiersza polecenia widzi kazdy uzytkownik hosta w liscie procesow,
// a zmienna srodowiskowa zostaje w pliku uslugi. Zostaje plik o zawezonych
// prawach, potok albo pytanie z wygaszonym echem.
func odczytajToken(sciezka string, wejscie io.Reader, bledy io.Writer) ([]byte, error) {
	if sciezka != "" {
		tresc, err := os.ReadFile(sciezka)
		if err != nil {
			return nil, err
		}
		return bytes.TrimSpace(tresc), nil
	}
	if plik, ok := wejscie.(*os.File); ok && term.IsTerminal(int(plik.Fd())) {
		fmt.Fprint(bledy, "Token enrollmentu: ")
		wartosc, err := term.ReadPassword(int(plik.Fd()))
		fmt.Fprintln(bledy)
		return bytes.TrimSpace(wartosc), err
	}
	tresc, err := io.ReadAll(io.LimitReader(wejscie, 4096))
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(tresc), nil
}

// wyczysc nadpisuje token w pamieci.
//
// Bez zludzen: runtime i jadro moga miec wlasne kopie, a jedyna prawdziwa
// ochrona to krotki termin waznosci, jedno uzycie i uniewaznienie po
// rejestracji. To jest sprzatniecie po sobie, a nie gwarancja.
func wyczysc(wartosc []byte) {
	for i := range wartosc {
		wartosc[i] = 0
	}
}
