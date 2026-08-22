package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
)

// renewalThreshold mowi, kiedy zaczac odnawianie: gdy zostala mniej niz jedna
// trzecia okresu waznosci. Przy certyfikacie 30-dniowym daje to okolo dziesieciu
// dni na ponowienia, co jest zapasem na awarie centrali wymaganym przez
// dokument - a nie ostatnia godzina przed wygasnieciem.
const renewalThreshold = 1.0 / 3.0

// maxRenewalCheckInterval ogranicza odstep miedzy sprawdzeniami od gory.
// Odnowienie nie jest pilne co do minuty; czestsze sprawdzanie obciazaloby
// flote bez powodu.
const maxRenewalCheckInterval = 6 * time.Hour

// minRenewalCheckInterval chroni przed odpytywaniem w petli, gdyby certyfikat
// mial bardzo krotki termin.
const minRenewalCheckInterval = time.Minute

// checkInterval skaluje sprawdzanie do dlugosci zycia certyfikatu. Staly
// odstep szesciu godzin bylby bezuzyteczny przy certyfikacie godzinnym
// i niepotrzebnie czesty przy rocznym.
func checkInterval(notAfter, notBefore time.Time) time.Duration {
	total := notAfter.Sub(notBefore)
	if total <= 0 {
		return minRenewalCheckInterval
	}
	interval := total / 20
	if interval > maxRenewalCheckInterval {
		return maxRenewalCheckInterval
	}
	if interval < minRenewalCheckInterval {
		return minRenewalCheckInterval
	}
	return interval
}

// renewalRetryInterval obowiazuje po nieudanej probie. Centrala moze byc
// chwilowo niedostepna, a do wygasniecia zostaje jeszcze wiele dni.
const renewalRetryInterval = 30 * time.Minute

// RenewalOptions opisuje odnawianie certyfikatu agenta.
type RenewalOptions struct {
	StateDir   string
	GatewayURL string
	Log        *slog.Logger
	// OnRenewed jest wywolywane po zapisaniu nowego certyfikatu. Agent
	// przerywa wtedy sesje, zeby nastepna poszla juz nowa tozsamoscia.
	OnRenewed func()
}

// KeepCertificateFresh odnawia certyfikat agenta, zanim wygasnie.
//
// Bez tego cala flota przestaje sie laczyc w dniu wygasniecia certyfikatow,
// bo agent nie ma innej drogi powrotu niz ponowny enrollment tokenem, ktorego
// na hoscie juz nie ma.
func KeepCertificateFresh(ctx context.Context, identity *Identity, options RenewalOptions) {
	log := options.Log
	if log == nil {
		log = slog.Default()
	}
	timer := time.NewTimer(checkInterval(identity.NotAfter, leafNotBefore(identity)))
	defer timer.Stop()

	for {
		if needsRenewal(identity.NotAfter, leafNotBefore(identity)) {
			if err := renewCertificate(ctx, identity, options); err != nil {
				log.Warn("nie udalo sie odnowic certyfikatu agenta",
					"err", err, "wygasa", identity.NotAfter.Format(time.RFC3339))
				select {
				case <-ctx.Done():
					return
				case <-time.After(renewalRetryInterval):
					continue
				}
			}
			log.Info("certyfikat agenta odnowiony", "wygasa", identity.NotAfter.Format(time.RFC3339))
			if options.OnRenewed != nil {
				options.OnRenewed()
			}
		}

		// Odstep wynika z aktualnego certyfikatu, wiec po odnowieniu
		// dostosowuje sie do nowego terminu.
		timer.Reset(checkInterval(identity.NotAfter, leafNotBefore(identity)))
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}

// needsRenewal decyduje na podstawie pozostalej czesci okresu waznosci, a nie
// stalej liczby dni: krotszy certyfikat ma byc odnawiany czesciej.
func needsRenewal(notAfter, notBefore time.Time) bool {
	if notAfter.IsZero() {
		// Nieznany termin nie moze znaczyc "jeszcze dlugo". Proba odnowienia
		// jest tania, a brak wiedzy o waznosci jest sam w sobie powodem.
		return true
	}
	total := notAfter.Sub(notBefore)
	if total <= 0 {
		return true
	}
	return time.Until(notAfter) < time.Duration(float64(total)*renewalThreshold)
}

func leafNotBefore(identity *Identity) time.Time {
	if len(identity.Certificate.Certificate) == 0 {
		return time.Time{}
	}
	leaf, err := x509.ParseCertificate(identity.Certificate.Certificate[0])
	if err != nil {
		return time.Time{}
	}
	return leaf.NotBefore
}

// renewCertificate wymienia nowa pare kluczy na certyfikat i zapisuje ja
// atomowo. Stary material zostaje na dysku do chwili, w ktorej nowy jest
// kompletny: przerwanie w polowie nie moze zostawic hosta bez tozsamosci.
func renewCertificate(ctx context.Context, identity *Identity, options RenewalOptions) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		// Podmiot w CSR jest tylko wskazowka; tozsamosc nadaje control plane
		// na podstawie certyfikatu, ktorym agent sie uwierzytelnia.
		Subject: pkix.Name{CommonName: identity.HostID},
	}, key)
	if err != nil {
		return err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// Odnowienie idzie przez mTLS obecnym certyfikatem: to on jest dowodem
	// tozsamosci. Token enrollmentu nie bierze w tym udzialu.
	client := agentv1connect.NewAgentServiceClient(&http.Client{
		Timeout: 60 * time.Second,
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{identity.Certificate},
				RootCAs:      identity.CAPool,
				MinVersion:   tls.VersionTLS13,
			},
		},
	}, options.GatewayURL)

	response, err := client.RenewCertificate(ctx, connect.NewRequest(&agentv1.RenewCertificateRequest{
		CsrPem: csrPEM,
		Build:  &agentv1.AgentBuild{AgentVersion: Version},
	}))
	if err != nil {
		return fmt.Errorf("odnowienie odrzucone: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	p := paths(options.StateDir)
	if err := writeAtomic(p.Key, pem.EncodeToMemory(
		&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	if err := writeAtomic(p.Cert, response.Msg.GetCertificatePem(), 0o644); err != nil {
		return err
	}
	if bundle := response.Msg.GetCaBundlePem(); len(bundle) > 0 {
		if err := writeAtomic(p.CA, bundle, 0o644); err != nil {
			return err
		}
	}

	odnowiona, err := loadIdentity(p)
	if err != nil {
		return fmt.Errorf("nowy certyfikat nie daje sie wczytac: %w", err)
	}
	*identity = *odnowiona
	return nil
}

// writeAtomic zapisuje plik przez plik tymczasowy i zmiane nazwy. Przerwanie
// w polowie zapisu zostawiloby agenta z uszkodzonym kluczem, czyli bez drogi
// powrotu do floty.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	temporary := path + ".nowy"
	if err := os.WriteFile(temporary, data, mode); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	// Katalog musi trafic na dysk razem z plikiem, inaczej po awarii zasilania
	// zmiana nazwy moze zniknac, a plik tymczasowy zostac.
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}
