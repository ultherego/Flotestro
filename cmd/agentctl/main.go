// Command agentctl obsluguje agenta Flotestro na hoscie.
//
// Narzedzie jest osobne od demona celowo. Operator, ktory stawia hosta albo
// szuka przyczyny ciszy, potrzebuje odpowiedzi natychmiast i bez panelu -
// a demon w tym czasie albo nie wstaje, albo wlasnie probuje sie polaczyc.
//
// Zadne polecenie nie zmienia stanu hosta poza jawnym poleceniem operatora
// i zadne nie wypisuje sekretow.
package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
)

func main() {
	os.Exit(uruchom(os.Args[1:], os.Stdout, os.Stderr))
}

func uruchom(argumenty []string, wyjscie, bledy io.Writer) int {
	if len(argumenty) == 0 {
		pomoc(bledy)
		return 2
	}
	switch argumenty[0] {
	case "config":
		return poleceniaKonfiguracji(argumenty[1:], wyjscie, bledy)
	case "status":
		return poleceniaStanu(argumenty[1:], wyjscie, bledy)
	case "diagnose":
		return poleceniaDiagnozy(argumenty[1:], wyjscie, bledy)
	case "version":
		fmt.Fprintf(wyjscie, "flotestro-agentctl %s (%s/%s, %s)\n",
			wersja, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return 0
	case "help", "-h", "--help":
		pomoc(wyjscie)
		return 0
	default:
		fmt.Fprintf(bledy, "nieznane polecenie: %s\n", argumenty[0])
		pomoc(bledy)
		return 2
	}
}

func pomoc(gdzie io.Writer) {
	fmt.Fprint(gdzie, `flotestro-agentctl - narzedzie hosta

  config validate [--config PLIK]   sprawdza plik konfiguracji i prawa do niego
  config show     [--config PLIK]   pokazuje ustawienia po uzupelnieniu domyslnych
  status          [--config PLIK]   tozsamosc, certyfikat, sesja i helper
  diagnose        [--config PLIK]   DNS, TCP, TLS, zegar, gniazdo i zdolnosci
  version                           wersja narzedzia

Kody wyjscia: 0 gotowe, 1 problem do naprawy, 2 blad uzycia.
`)
}
