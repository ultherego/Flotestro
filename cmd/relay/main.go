// Command flotestro-relay posredniczy miedzy agentami jednej lokalizacji
// a centrala.
//
// Relay jest opcjonalny. Ma sens tam, gdzie lokalizacja laczy sie z centrala
// przez WAN: utrzymuje jedno polaczenie w gore zamiast setek, buforuje wyniki
// na czas awarii lacza i nie przekazuje zadan, ktorym uplynal TTL.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/net/http2"

	"github.com/ultherego/flotestro/internal/agent"
	"github.com/ultherego/flotestro/internal/config"
	"github.com/ultherego/flotestro/internal/relay"
)

func main() {
	stateDir := flag.String("state-dir",
		config.Env("FLOTESTRO_RELAY_STATE_DIR", "/var/lib/flotestro-relay"), "katalog stanu relaya")
	enrollmentURL := flag.String("enrollment-url",
		config.Env("FLOTESTRO_ENROLLMENT_URL", ""), "adres uslugi enrollmentu w centrali")
	upstreamURL := flag.String("gateway-url",
		config.Env("FLOTESTRO_GATEWAY_URL", ""), "adres bramy agentow w centrali")
	token := flag.String("enrollment-token",
		config.Env("FLOTESTRO_ENROLLMENT_TOKEN", ""), "token enrollmentu wystawiony dla relaya")
	name := flag.String("name", config.Env("FLOTESTRO_RELAY_NAME", ""), "nazwa relaya")
	listen := flag.String("listen", config.Env("FLOTESTRO_RELAY_LISTEN", ":8453"),
		"adres nasluchu dla agentow lokalizacji")
	advertised := flag.String("advertised", config.Env("FLOTESTRO_RELAY_ADVERTISED", ""),
		"adresy, pod ktorymi agenci widza relay (DNS albo IP, po przecinku)")
	caFile := flag.String("ca-file", config.Env("FLOTESTRO_CA_FILE", ""),
		"bundle CA floty uzywany przy pierwszym enrollmencie")
	bufferMB := flag.Int("buffer-mb", config.EnvInt("FLOTESTRO_RELAY_BUFFER_MB", 64),
		"limit bufora wynikow w megabajtach")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(*stateDir, *enrollmentURL, *upstreamURL, *token, *name, *listen,
		*advertised, *caFile, *bufferMB, log); err != nil {
		log.Error("relay zakonczony bledem", "err", err)
		os.Exit(1)
	}
}

func run(stateDir, enrollmentURL, upstreamURL, token, name, listen, advertised,
	caFile string, bufferMB int, log *slog.Logger) error {
	if upstreamURL == "" {
		return fmt.Errorf("brak adresu bramy centrali")
	}
	if name == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("nazwa relaya: %w", err)
		}
		name = hostname
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Tozsamosc relaya powstaje tak samo jak tozsamosc agenta: klucz prywatny
	// jest generowany lokalnie i nie opuszcza maszyny.
	identity, err := agent.EnsureIdentityFor(ctx, agent.IdentityRequest{
		StateDir:        stateDir,
		EnrollmentURL:   enrollmentURL,
		Token:           token,
		BootstrapCAPath: caFile,
		MachineID:       name,
		Hostname:        name,
		Advertised:      advertised,
	})
	if err != nil {
		return fmt.Errorf("tozsamosc relaya: %w", err)
	}
	log.Info("tozsamosc relaya gotowa",
		"relay_id", identity.HostID, "nazwa", name,
		"cert_not_after", identity.NotAfter.Format(time.RFC3339))

	posrednik := relay.New(relay.Options{
		UpstreamURL: upstreamURL,
		Identity:    identity.Certificate,
		TrustPool:   identity.CAPool,
		BufferBytes: bufferMB << 20,
		Log:         log,
	})

	// Agenci lacza sie do relaya tym samym protokolem co do centrali, wiec
	// wymagany jest certyfikat klienta wystawiony przez CA floty.
	server := &http.Server{
		Addr:    listen,
		Handler: relay.WithClientCertificate(posrednik.Handler()),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{identity.Certificate},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    identity.CAPool,
			MinVersion:   tls.VersionTLS13,
			NextProtos:   []string{"h2"},
		},
		ReadHeaderTimeout: 15 * time.Second,
	}
	if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
		return err
	}

	// Po awarii lacza relay musi sam zauwazyc, ze centrala wrocila.
	go posrednik.WatchUpstream(ctx, 15*time.Second)
	go raportuj(ctx, posrednik, log)

	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	log.Info("relay nasluchuje", "adres", listen, "centrala", upstreamURL,
		"bufor_mb", bufferMB)

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
