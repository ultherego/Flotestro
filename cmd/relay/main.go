// Command flotestro-relay posredniczy miedzy agentami jednej lokalizacji
// a centrala.
//
// Relay jest opcjonalny. Ma sens tam, gdzie lokalizacja laczy sie z centrala
// przez WAN: utrzymuje jedno polaczenie w gore zamiast setek, buforuje wyniki
// na czas awarii lacza i nie przekazuje zadan, ktorym uplynal TTL.
//
// Kanonicznym zrodlem ustawien jest /etc/flotestro/relay.yaml. Relay jest
// osobna granica zaufania i ma osobny plik: wspolny z agentem znaczylby, ze
// jedno ustawienie opisuje dwie role o roznych uprawnieniach.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/http2"

	"github.com/ultherego/flotestro/internal/agent"
	"github.com/ultherego/flotestro/internal/config"
	"github.com/ultherego/flotestro/internal/relay"
	"github.com/ultherego/flotestro/internal/relayconfig"
)

// wersja jest stemplowana przy budowaniu wydania, tak samo jak w agencie.
var wersja = agent.Version

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := uruchom(os.Args[1:], log); err != nil {
		log.Error("relay zakonczony bledem", "err", err)
		os.Exit(1)
	}
}

func uruchom(args []string, log *slog.Logger) error {
	if len(args) == 0 {
		return fmt.Errorf("uzycie: flotestro-relay <run|enroll|config|version>")
	}
	switch args[0] {
	case "run":
		return polecenieRun(args[1:], log)
	case "enroll":
		return polecenieEnroll(args[1:], log)
	case "config":
		return polecenieConfig(args[1:])
	case "version":
		fmt.Printf("flotestro-relay %s\n", wersja)
		return nil
	default:
		return fmt.Errorf("nieznane polecenie %q", args[0])
	}
}

// polecenieConfig sprawdza plik konfiguracji i pokazuje, co z niego wynika.
//
// Relay stoi zwykle w lokalizacji bez operatora, wiec bledna konfiguracja ma
// byc widoczna przed startem uslugi, a nie w dzienniku po nieudanym starcie.
func polecenieConfig(args []string) error {
	zestaw := flag.NewFlagSet("config", flag.ContinueOnError)
	sciezka := zestaw.String("config", relayconfig.SciezkaDomyslna, "plik konfiguracji relaya")
	if err := zestaw.Parse(args); err != nil {
		return err
	}
	dzialanie := "validate"
	if zestaw.NArg() > 0 {
		dzialanie = zestaw.Arg(0)
	}
	cfg, err := relayconfig.Wczytaj(*sciezka)
	if err != nil {
		return err
	}
	switch dzialanie {
	case "validate":
		fmt.Printf("konfiguracja poprawna: %s\n", *sciezka)
		return nil
	case "show":
		fmt.Printf("nazwa:           %s\n", cfg.Relay.Name)
		fmt.Printf("site:            %s\n", cfg.Relay.Site)
		fmt.Printf("nasluch:         %s\n", cfg.Relay.Listen)
		fmt.Printf("nazwy sieciowe:  %s\n", strings.Join(cfg.Relay.AdvertisedNames, ", "))
		fmt.Printf("katalog stanu:   %s\n", cfg.Relay.StateDir)
		fmt.Printf("bufor (bajty):   %d\n", cfg.Bufor())
		fmt.Printf("enrollment:      %s\n", cfg.Upstream.EnrollmentURL)
		fmt.Printf("bramy:           %s\n", strings.Join(cfg.Upstream.GatewayURLs, ", "))
		return nil
	default:
		return fmt.Errorf("nieznane dzialanie %q; uzyj validate albo show", dzialanie)
	}
}

// polecenieEnroll rejestruje relay tokenem i konczy prace.
//
// Osobne polecenie, a nie krok startu uslugi: token jest sekretem
// jednorazowym i nie moze lezec w pliku, ktory przezywa restart. Rejestracja
// jest decyzja operatora i wykonuje sie raz.
func polecenieEnroll(args []string, log *slog.Logger) error {
	zestaw := flag.NewFlagSet("enroll", flag.ContinueOnError)
	sciezka := zestaw.String("config", relayconfig.SciezkaDomyslna, "plik konfiguracji relaya")
	tokenPlik := zestaw.String("token-file", "", "plik z tokenem enrollmentu")
	if err := zestaw.Parse(args); err != nil {
		return err
	}
	cfg, err := relayconfig.Wczytaj(*sciezka)
	if err != nil {
		return err
	}
	token, err := odczytajToken(*tokenPlik)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	tozsamosc, err := zarejestruj(ctx, cfg, token)
	if err != nil {
		return err
	}
	log.Info("relay zarejestrowany", "relay_id", tozsamosc.RelayID,
		"nazwa", cfg.Relay.Name, "wygasa", tozsamosc.NotAfter.Format(time.RFC3339))
	return nil
}

// odczytajToken bierze token z pliku albo ze standardowego wejscia.
//
// Tokenu nie przyjmujemy z argumentu wiersza polecen: argument widzi kazdy
// proces na maszynie, a token jest kluczem do tozsamosci calej lokalizacji.
func odczytajToken(plik string) (string, error) {
	if plik != "" {
		tresc, err := os.ReadFile(plik)
		if err != nil {
			return "", fmt.Errorf("token: %w", err)
		}
		return strings.TrimSpace(string(tresc)), nil
	}
	if token := strings.TrimSpace(config.Env("FLOTESTRO_ENROLLMENT_TOKEN", "")); token != "" {
		return token, nil
	}
	stan, err := os.Stdin.Stat()
	if err == nil && stan.Mode()&os.ModeCharDevice == 0 {
		tresc, err := os.ReadFile("/dev/stdin")
		if err == nil && strings.TrimSpace(string(tresc)) != "" {
			return strings.TrimSpace(string(tresc)), nil
		}
	}
	return "", errors.New("brak tokenu enrollmentu: podaj -token-file albo przekaz go potokiem")
}

// zarejestruj tworzy tozsamosc relaya na podstawie konfiguracji i tokenu.
func zarejestruj(ctx context.Context, cfg relayconfig.Config, token string) (relay.Tozsamosc, error) {
	tozsamosc, err := agent.EnsureIdentityFor(ctx, agent.IdentityRequest{
		StateDir:        cfg.Relay.StateDir,
		EnrollmentURL:   cfg.Upstream.EnrollmentURL,
		Token:           token,
		BootstrapCAPath: cfg.Upstream.BootstrapCA,
		MachineID:       cfg.Relay.Name,
		Hostname:        cfg.Relay.Name,
		Advertised:      strings.Join(cfg.Relay.AdvertisedNames, ","),
	})
	if err != nil {
		return relay.Tozsamosc{}, fmt.Errorf("tozsamosc relaya: %w", err)
	}
	return relay.Tozsamosc{
		RelayID:     tozsamosc.HostID,
		Certificate: tozsamosc.Certificate,
		CAPool:      tozsamosc.CAPool,
		NotAfter:    tozsamosc.NotAfter,
		ZaufaniePEM: tozsamosc.ZaufaniePEM,
	}, nil
}

// polecenieRun uruchamia relay na podstawie pliku konfiguracji.
func polecenieRun(args []string, log *slog.Logger) error {
	zestaw := flag.NewFlagSet("run", flag.ContinueOnError)
	sciezka := zestaw.String("config", relayconfig.SciezkaDomyslna, "plik konfiguracji relaya")
	if err := zestaw.Parse(args); err != nil {
		return err
	}
	cfg, err := relayconfig.Wczytaj(*sciezka)
	if err != nil {
		return err
	}
	log.Info("konfiguracja wczytana", "plik", *sciezka,
		"nazwa", cfg.Relay.Name, "bram", len(cfg.Upstream.GatewayURLs))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Relay bez tozsamosci nie wstaje. Jednostka ma warunek startu na plik
	// certyfikatu, wiec normalnie nie dojdzie tu bez rejestracji; komunikat
	// jest dla operatora, ktory uruchomil binarke recznie.
	tozsamosc, err := zarejestruj(ctx, cfg, "")
	if err != nil {
		return fmt.Errorf("%w; zarejestruj relay: flotestro-relay enroll", err)
	}
	log.Info("tozsamosc relaya gotowa", "relay_id", tozsamosc.RelayID,
		"nazwa", cfg.Relay.Name, "cert_not_after", tozsamosc.NotAfter.Format(time.RFC3339))

	zywa := relay.NowaZywa(tozsamosc)
	brama := cfg.Upstream.GatewayURLs[0]
	posrednik := relay.New(relay.Options{
		UpstreamURL:  brama,
		UpstreamURLs: cfg.Upstream.GatewayURLs,
		// Adres enrollmentu wlacza posredniczenie w rejestracji. W izolowanej
		// lokalizacji host nie widzi centrali i relay jest jedyna droga.
		EnrollmentURL: cfg.Upstream.EnrollmentURL,
		Identity:      tozsamosc.Certificate,
		TrustPool:     tozsamosc.CAPool,
		BufferBytes:   int(cfg.Bufor()),
		Log:           log,
	})
	// Host przed rejestracja nie ma certyfikatu, wiec uscisk nie moze go
	// zadac. Kazde RPC poza rejestracja sprawdza go z osobna.
	zywa.PosredniczyWRejestracji(cfg.Upstream.EnrollmentURL != "")

	// Agenci lacza sie do relaya tym samym protokolem co do centrali, wiec
	// wymagany jest certyfikat klienta wystawiony przez CA floty. Certyfikat
	// serwerowy pochodzi z zywej tozsamosci: odnowienie podmienia go bez
	// restartu, ktory zerwalby sesje calej lokalizacji naraz.
	server := &http.Server{
		Addr:    cfg.Relay.Listen,
		Handler: relay.WithClientCertificate(posrednik.Handler()),
		TLSConfig: &tls.Config{
			GetCertificate:     zywa.Certyfikat,
			GetConfigForClient: zywa.KonfiguracjaKlienta,
			ClientCAs:          tozsamosc.CAPool,
			MinVersion:         tls.VersionTLS13,
			NextProtos:         []string{"h2"},
		},
		ReadHeaderTimeout: 15 * time.Second,
	}
	if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
		return err
	}

	go relay.UtrzymujCertyfikat(ctx, zywa, relay.OpcjeOdnowienia{
		StateDir:   cfg.Relay.StateDir,
		GatewayURL: brama,
		Nazwy:      cfg.Relay.AdvertisedNames,
		Wersja:     wersja,
		Log:        log,
		PoOdnowieniu: func(nowa relay.Tozsamosc) {
			posrednik.OdswiezTozsamosc(nowa.Certificate, nowa.CAPool)
		},
	})

	// Po awarii lacza relay musi sam zauwazyc, ze centrala wrocila.
	go posrednik.WatchUpstream(ctx, 15*time.Second)
	go raportuj(ctx, posrednik, log)

	listener, err := net.Listen("tcp", cfg.Relay.Listen)
	if err != nil {
		return err
	}
	log.Info("relay nasluchuje", "adres", cfg.Relay.Listen,
		"centrala", posrednik.Brama(), "bram", len(cfg.Upstream.GatewayURLs),
		"bufor_bajtow", cfg.Bufor())

	errCh := make(chan error, 1)
	go func() { errCh <- server.ServeTLS(listener, "", "") }()

	select {
	case <-ctx.Done():
		zamkniecie, anuluj := context.WithTimeout(context.Background(), 10*time.Second)
		defer anuluj()
		return server.Shutdown(zamkniecie)
	case err := <-errCh:
		return err
	}
}

// raportuj oproznia bufor po powrocie lacza i pokazuje stan relaya.
// Zajetosc bufora jest sygnalem operacyjnym: rosnaca oznacza, ze lokalizacja
// pracuje, ale wyniki nie docieraja do centrali.
func raportuj(ctx context.Context, posrednik *relay.Relay, log *slog.Logger) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sesje, bufor, lacznosc := posrednik.Stats()
			log.Info("stan relaya", "sesje", sesje, "bufor_wiadomosci", bufor.Messages,
				"bufor_bajtow", bufor.Bytes, "odrzuconych", bufor.Dropped,
				"lacznosc_z_centrala", lacznosc)
		}
	}
}
