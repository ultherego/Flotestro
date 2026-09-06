package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/ultherego/flotestro/internal/agent"
	"github.com/ultherego/flotestro/internal/agentconfig"
)

// poleceniaDiagnozy sprawdza droge od hosta do panelu krok po kroku.
//
// Kroki sa osobne celowo. "Nie dziala" nie jest odpowiedzia: co innego
// naprawia sie, gdy nie rozwiazuje sie nazwa, co innego gdy port jest
// zamkniety, a co innego gdy lancuch certyfikatow nie pasuje.
func poleceniaDiagnozy(argumenty []string, wyjscie, bledy io.Writer) int {
	sciezka, ok := sciezkaKonfiguracji("diagnose", argumenty, bledy)
	if !ok {
		return 2
	}
	ctx, anuluj := context.WithTimeout(context.Background(), 60*time.Second)
	defer anuluj()

	cfg, err := agentconfig.Wczytaj(sciezka)
	if err != nil {
		fmt.Fprintf(wyjscie, "config      BLAD  %s: %v\n", sciezka, err)
		return 1
	}
	fmt.Fprintf(wyjscie, "config      ok    %s\n", sciezka)

	problemy := 0
	tozsamosc := agent.OdczytajTozsamosc(cfg.Agent.StateDir)
	if tozsamosc.Obecna {
		fmt.Fprintf(wyjscie, "identity    ok    host/%s, certyfikat do %s\n",
			tozsamosc.HostID, tozsamosc.NotAfter.UTC().Format(time.RFC3339))
	} else {
		fmt.Fprintf(wyjscie, "identity    brak  %s\n", tozsamosc.Blad)
		problemy++
	}

	// Zaufanie sprawdzamy tym samym bundlem, ktorego uzywa agent. Bundle
	// systemowy powiedzialby co innego niz prawda o tej flocie.
	pula := pulaCA(cfg, tozsamosc)

	adresy := append([]string{cfg.Connection.EnrollmentURL}, cfg.Connection.GatewayURLs...)
	for _, adres := range adresy {
		problemy += sprawdzAdres(ctx, wyjscie, adres, pula, cfg.Connection.ConnectTimeout)
	}

	if cfg.Agent.Mode == agentconfig.TrybOdczytu {
		fmt.Fprintf(wyjscie, "helper      -     wylaczony (tryb %s)\n", cfg.Agent.Mode)
	} else if err := gniazdoDziala(cfg.Helper.Socket); err != nil {
		fmt.Fprintf(wyjscie, "helper      BLAD  %v\n", err)
		problemy++
	} else {
		fmt.Fprintf(wyjscie, "helper      ok    %s\n", cfg.Helper.Socket)
	}

	zdolnosci := agent.DetectCapabilities()
	dostepne := 0
	for _, zdolnosc := range zdolnosci {
		if zdolnosc.Available {
			dostepne++
		}
	}
	fmt.Fprintf(wyjscie, "capabilities ok   %d z %d dostepnych\n", dostepne, len(zdolnosci))

	if problemy > 0 {
		return 1
	}
	return 0
}

// pulaCA sklada zaufanie do sprawdzenia polaczenia.
func pulaCA(cfg agentconfig.Config, tozsamosc agent.StanTozsamosci) *x509.CertPool {
	pula := x509.NewCertPool()
	dodano := false
	for _, sciezka := range []string{tozsamosc.Sciezki.CA, cfg.Connection.BootstrapCA} {
		if sciezka == "" {
			continue
		}
		if tresc, err := os.ReadFile(sciezka); err == nil && pula.AppendCertsFromPEM(tresc) {
			dodano = true
		}
	}
	if !dodano {
		return nil
	}
	return pula
}

// sprawdzAdres przechodzi po kolei: nazwa, port, TLS i zegar.
func sprawdzAdres(ctx context.Context, wyjscie io.Writer, surowy string,
	pula *x509.CertPool, limit time.Duration) int {
	adres, err := url.Parse(surowy)
	if err != nil {
		fmt.Fprintf(wyjscie, "url         BLAD  %s: %v\n", surowy, err)
		return 1
	}
	host := adres.Hostname()
	port := adres.Port()
	if port == "" {
		port = "443"
	}

	adresy, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		fmt.Fprintf(wyjscie, "dns         BLAD  %s: %v\n", host, err)
		return 1
	}
	fmt.Fprintf(wyjscie, "dns         ok    %s -> %v\n", host, adresy)

	polaczenie, err := (&net.Dialer{Timeout: limit}).DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		fmt.Fprintf(wyjscie, "tcp         BLAD  %s:%s: %v\n", host, port, err)
		return 1
	}
	fmt.Fprintf(wyjscie, "tcp         ok    %s:%s\n", host, port)

	// Weryfikacji nie wylaczamy nawet w diagnostyce: pokazujemy blad
	// lancucha i oczekiwana nazwe, ale nie udajemy, ze polaczenie jest dobre.
	klient := tls.Client(polaczenie, &tls.Config{ServerName: host, RootCAs: pula, MinVersion: tls.VersionTLS12})
	defer klient.Close()
	if err := klient.HandshakeContext(ctx); err != nil {
		fmt.Fprintf(wyjscie, "tls         BLAD  %s: %v\n", host, err)
		return 1
	}
	stan := klient.ConnectionState()
	opis := "bez certyfikatu serwera"
	if len(stan.PeerCertificates) > 0 {
		serwer := stan.PeerCertificates[0]
		opis = fmt.Sprintf("%s, wazny do %s", serwer.Subject.CommonName,
			serwer.NotAfter.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(wyjscie, "tls         ok    %s (%s)\n", opis, wersjaTLS(stan.Version))
	return 0
}

func wersjaTLS(wersja uint16) string {
	switch wersja {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	}
	return fmt.Sprintf("0x%04x", wersja)
}
