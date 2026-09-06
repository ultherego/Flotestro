package relay

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
	"math/big"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
	"github.com/ultherego/flotestro/internal/identitystore"
)

// progOdnowienia mowi, kiedy zaczac odnawianie: gdy zostala mniej niz jedna
// trzecia okresu waznosci. Certyfikat relaya zyje siedem dni, wiec zostaje
// okolo dwoch dni na ponowienia - a nie ostatnie godziny przed wygasnieciem,
// w ktorych awaria centrali odcina cala lokalizacje.
const progOdnowienia = 1.0 / 3.0

// Odstepy sprawdzania. Krotki czas zycia certyfikatu relaya wymaga czestszego
// zagladania niz u agenta, ale nie odpytywania w petli.
const (
	minOdstepSprawdzenia = time.Minute
	maxOdstepSprawdzenia = time.Hour
	odstepPoBledzie      = 10 * time.Minute
)

// Tozsamosc relaya wraz z materialem, ktory trzeba przelaczyc atomowo.
type Tozsamosc struct {
	RelayID     string
	Certificate tls.Certificate
	CAPool      *x509.CertPool
	NotAfter    time.Time
	ZaufaniePEM []byte
}

// Zywa tozsamosc trzyma biezacy material relaya i pozwala podmienic go
// w czasie pracy.
//
// Podmiana jest atomowa, bo listener relaya siega po certyfikat przy kazdym
// uscisku TLS. Odnowienie nie moze wymagac restartu procesu: restart zrywa
// sesje wszystkich agentow lokalizacji naraz, a odnowienie zdarza sie
// regularnie i samo z siebie nie jest zdarzeniem operacyjnym.
type Zywa struct {
	biezaca atomic.Pointer[Tozsamosc]
}

// NowaZywa tworzy uchwyt na biezaca tozsamosc relaya.
func NowaZywa(tozsamosc Tozsamosc) *Zywa {
	zywa := &Zywa{}
	zywa.biezaca.Store(&tozsamosc)
	return zywa
}

// Biezaca zwraca obecna tozsamosc.
func (z *Zywa) Biezaca() Tozsamosc { return *z.biezaca.Load() }

// Podmien wstawia nowa tozsamosc.
func (z *Zywa) Podmien(tozsamosc Tozsamosc) { z.biezaca.Store(&tozsamosc) }

// Certyfikat zwraca certyfikat serwerowy dla uscisku TLS z agentem.
func (z *Zywa) Certyfikat(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	tozsamosc := z.biezaca.Load()
	return &tozsamosc.Certificate, nil
}

// KonfiguracjaKlienta zwraca ustawienia uscisku dla agentow lokalizacji.
// Zbior zaufania jest czytany przy kazdym uscisku: po rotacji CA floty relay
// ma uznac nowe certyfikaty agentow bez restartu.
func (z *Zywa) KonfiguracjaKlienta(*tls.ClientHelloInfo) (*tls.Config, error) {
	tozsamosc := z.biezaca.Load()
	return &tls.Config{
		GetCertificate: z.Certyfikat,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      tozsamosc.CAPool,
		MinVersion:     tls.VersionTLS13,
		NextProtos:     []string{"h2"},
	}, nil
}

// OpcjeOdnowienia opisuje odnawianie certyfikatu relaya.
type OpcjeOdnowienia struct {
	StateDir   string
	GatewayURL string
	// Nazwy sa zyczeniem relaya. Centrala wystawia to, co ma w rejestrze;
	// wysylamy je, zeby rozjazd konfiguracji z rejestrem byl widoczny
	// w panelu, a nie dopiero w odrzuconych polaczeniach agentow.
	Nazwy  []string
	Wersja string
	Log    *slog.Logger
	// PoOdnowieniu jest wolane po podmianie tozsamosci. Relay odswieza
	// wtedy polaczenie do centrali, zeby szlo juz nowym certyfikatem.
	PoOdnowieniu func(Tozsamosc)
}

// UtrzymujCertyfikat odnawia certyfikat relaya, zanim wygasnie.
//
// Relay bez waznego certyfikatu nie jest tylko odciety sam: przestaje
// posredniczyc za cala lokalizacje. Dlatego odnawia sie wczesniej niz agent
// i probuje czesciej po bledzie.
func UtrzymujCertyfikat(ctx context.Context, zywa *Zywa, opcje OpcjeOdnowienia) {
	log := opcje.Log
	if log == nil {
		log = slog.Default()
	}
	timer := time.NewTimer(odstepSprawdzenia(zywa.Biezaca()))
	defer timer.Stop()

	for {
		if wymagaOdnowienia(zywa.Biezaca()) {
			odnowiona, err := odnow(ctx, zywa.Biezaca(), opcje)
			if err != nil {
				log.Warn("nie udalo sie odnowic certyfikatu relaya",
					"err", err, "wygasa", zywa.Biezaca().NotAfter.Format(time.RFC3339))
				select {
				case <-ctx.Done():
					return
				case <-time.After(odstepPoBledzie):
					continue
				}
			}
			// Podmiana najpierw, powiadomienie potem: nowe uscisci maja isc
			// nowym certyfikatem od pierwszej chwili, a nie od momentu, w
			// ktorym ktos skonczy obsluge zdarzenia.
			zywa.Podmien(odnowiona)
			log.Info("certyfikat relaya odnowiony",
				"relay_id", odnowiona.RelayID,
				"wygasa", odnowiona.NotAfter.Format(time.RFC3339))
			if opcje.PoOdnowieniu != nil {
				opcje.PoOdnowieniu(odnowiona)
			}
		}

		timer.Reset(odstepSprawdzenia(zywa.Biezaca()))
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}

// odstepSprawdzenia skaluje sprawdzanie do dlugosci zycia certyfikatu.
func odstepSprawdzenia(tozsamosc Tozsamosc) time.Duration {
	caly := tozsamosc.NotAfter.Sub(poczatek(tozsamosc))
	if caly <= 0 {
		return minOdstepSprawdzenia
	}
	odstep := caly / 40
	if odstep > maxOdstepSprawdzenia {
		return maxOdstepSprawdzenia
	}
	if odstep < minOdstepSprawdzenia {
		return minOdstepSprawdzenia
	}
	// Pelny jitter rozprasza relaye po awarii centrali. Bez niego wszystkie
	// wracaja w tej samej sekundzie i przewracaja ja ponownie.
	return odstep/2 + czasLosowy(odstep/2)
}

// wymagaOdnowienia decyduje na podstawie pozostalej czesci okresu waznosci.
func wymagaOdnowienia(tozsamosc Tozsamosc) bool {
	if tozsamosc.NotAfter.IsZero() {
		// Nieznany termin nie znaczy "jeszcze dlugo". Proba odnowienia jest
		// tania, a brak wiedzy o waznosci jest sam w sobie powodem.
		return true
	}
	caly := tozsamosc.NotAfter.Sub(poczatek(tozsamosc))
	if caly <= 0 {
		return true
	}
	return time.Until(tozsamosc.NotAfter) < time.Duration(float64(caly)*progOdnowienia)
}

func poczatek(tozsamosc Tozsamosc) time.Time {
	if len(tozsamosc.Certificate.Certificate) == 0 {
		return time.Time{}
	}
	lisc, err := x509.ParseCertificate(tozsamosc.Certificate.Certificate[0])
	if err != nil {
		return time.Time{}
	}
	return lisc.NotBefore
}

// odnow wymienia nowa pare kluczy na certyfikat i zapisuje ja atomowo.
func odnow(ctx context.Context, obecna Tozsamosc, opcje OpcjeOdnowienia) (Tozsamosc, error) {
	klucz, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Tozsamosc{}, err
	}
	dns, adresy := rozdzielNazwy(opcje.Nazwy)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: obecna.RelayID},
		DNSNames:    dns,
		IPAddresses: adresy,
	}, klucz)
	if err != nil {
		return Tozsamosc{}, err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// Odnowienie idzie przez mTLS obecnym certyfikatem: to on jest dowodem
	// tozsamosci relaya. Token enrollmentu nie bierze w tym udzialu.
	klient := agentv1connect.NewRelayServiceClient(&http.Client{
		Timeout: 60 * time.Second,
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{obecna.Certificate},
				RootCAs:      obecna.CAPool,
				MinVersion:   tls.VersionTLS13,
			},
		},
	}, opcje.GatewayURL)

	odpowiedz, err := klient.RenewCertificate(ctx,
		connect.NewRequest(&agentv1.RenewRelayCertificateRequest{
			CsrPem:          csrPEM,
			Build:           &agentv1.AgentBuild{AgentVersion: opcje.Wersja},
			AdvertisedNames: opcje.Nazwy,
		}))
	if err != nil {
		return Tozsamosc{}, fmt.Errorf("odnowienie odrzucone: %w", err)
	}

	kluczDER, err := x509.MarshalECPrivateKey(klucz)
	if err != nil {
		return Tozsamosc{}, err
	}
	// Bundle zaufania zmienia sie tylko przy rotacji CA floty. Gdy centrala
	// go nie przyslala, do generacji idzie ten, ktory obowiazuje: generacja
	// musi byc kompletem, a nie kluczem bez wskazania zaufania.
	bundle := odpowiedz.Msg.GetClientCaBundlePem()
	if len(bundle) == 0 {
		bundle = obecna.ZaufaniePEM
	}
	if len(bundle) == 0 {
		return Tozsamosc{}, fmt.Errorf("odnowienie bez bundla zaufania")
	}

	magazyn := identitystore.Nowy(opcje.StateDir)
	zapisana, err := magazyn.Zatwierdz(identitystore.Generacja{
		KluczPEM:      pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kluczDER}),
		CertyfikatPEM: odpowiedz.Msg.GetCertificatePem(),
		ZaufaniePEM:   bundle,
	})
	if err != nil {
		// Odrzucona generacja nie rusza tego, czym relay pracuje: lepiej
		// zostac na starym certyfikacie i sprobowac za chwile niz zostac
		// z polowa pary i odciac cala lokalizacje.
		return Tozsamosc{}, fmt.Errorf("nowa tozsamosc odrzucona: %w", err)
	}
	return Tozsamosc{
		RelayID:     zapisana.HostID,
		Certificate: zapisana.Certificate,
		CAPool:      zapisana.CAPool,
		NotAfter:    zapisana.NotAfter,
		ZaufaniePEM: zapisana.ZaufaniePEM,
	}, nil
}

// rozdzielNazwy dzieli nazwy sieciowe na adresy IP i nazwy DNS.
func rozdzielNazwy(nazwy []string) ([]string, []net.IP) {
	var dns []string
	var adresy []net.IP
	for _, nazwa := range nazwy {
		if adres := net.ParseIP(nazwa); adres != nil {
			adresy = append(adresy, adres)
			continue
		}
		dns = append(dns, nazwa)
	}
	return dns, adresy
}

// czasLosowy zwraca losowy odstep z przedzialu [0, gora).
func czasLosowy(gora time.Duration) time.Duration {
	if gora <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(gora)))
	if err != nil {
		return gora / 2
	}
	return time.Duration(n.Int64())
}
