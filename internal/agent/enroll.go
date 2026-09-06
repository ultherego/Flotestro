package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	"github.com/ultherego/flotestro/internal/buildinfo"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
	"github.com/ultherego/flotestro/internal/identitystore"
)

// Version jest wersja agenta raportowana do control plane.
//
// Zmienna, a nie stala: wydanie wpisuje tu numer pakietu przy budowaniu
// (-ldflags -X). Bez tego panel widzialby jedna wersje przez cale zycie
// floty i nie mialby jak sprawdzic, czy aktualizacja naprawde doszla.
var Version = buildinfo.Wersja

// Identity to material kryptograficzny hosta przechowywany lokalnie.
type Identity struct {
	HostID      string
	Certificate tls.Certificate
	CAPool      *x509.CertPool
	NotAfter    time.Time
	// ZaufaniePEM jest bundlem, ktory rozstrzyga o zaufaniu tej tozsamosci.
	// Trzymamy go w pamieci, bo odnowienie zapisuje cala generacje naraz -
	// takze wtedy, gdy panel nie przyslal nowego bundla.
	ZaufaniePEM []byte
}

// zTozsamosci tlumaczy generacje z magazynu na tozsamosc agenta.
func zTozsamosci(t *identitystore.Tozsamosc) *Identity {
	return &Identity{
		HostID: t.HostID, Certificate: t.Certificate, CAPool: t.CAPool,
		NotAfter: t.NotAfter, ZaufaniePEM: t.ZaufaniePEM,
	}
}

// IdentityPaths wskazuje pliki tozsamosci w katalogu stanu agenta.
type IdentityPaths struct {
	Key  string
	Cert string
	CA   string
}

func paths(stateDir string) IdentityPaths {
	return IdentityPaths{
		Key:  filepath.Join(stateDir, "agent.key"),
		Cert: filepath.Join(stateDir, "agent.pem"),
		CA:   filepath.Join(stateDir, "ca.pem"),
	}
}

// IdentityRequest opisuje tozsamosc zglaszana przy enrollmencie. Symulator
// podaje wartosci syntetyczne, agent na hoscie odczytuje je z systemu.
type IdentityRequest struct {
	StateDir        string
	EnrollmentURL   string
	Token           string
	BootstrapCAPath string
	MachineID       string
	Hostname        string
	// Advertised sa nazwami sieciowymi, pod ktorymi widac zglaszajacego sie.
	// Uzywa ich relay: musi wystapic takze jako serwer wobec agentow swojej
	// lokalizacji, a agent weryfikuje nazwe w certyfikacie.
	Advertised   string
	OSFamily     string
	OSVersion    string
	Architecture string
}

// EnsureIdentity wczytuje istniejaca tozsamosc albo przeprowadza enrollment.
// Klucz prywatny jest generowany lokalnie i nigdy nie opuszcza hosta.
func EnsureIdentity(ctx context.Context, stateDir, enrollmentURL, token, bootstrapCAPath string) (*Identity, error) {
	machineID, err := MachineID()
	if err != nil {
		return nil, fmt.Errorf("machine-id: %w", err)
	}
	hostname, _ := os.Hostname()
	osInfo := ReadOSInfo()
	return EnsureIdentityFor(ctx, IdentityRequest{
		StateDir:        stateDir,
		EnrollmentURL:   enrollmentURL,
		Token:           token,
		BootstrapCAPath: bootstrapCAPath,
		MachineID:       machineID,
		Hostname:        hostname,
		OSFamily:        osInfo.Family,
		OSVersion:       osInfo.Version,
		Architecture:    runtime.GOARCH,
	})
}

// EnsureIdentityFor przeprowadza enrollment dla podanej tozsamosci.
func EnsureIdentityFor(ctx context.Context, request IdentityRequest) (*Identity, error) {
	stateDir := request.StateDir
	enrollmentURL := request.EnrollmentURL
	token := request.Token
	bootstrapCAPath := request.BootstrapCAPath
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("katalog stanu: %w", err)
	}
	p := paths(stateDir)

	// Magazyn generacji jest zrodlem tozsamosci. Slady przerwanych zapisow
	// sprzatamy przy starcie: katalog tymczasowy po awarii nie jest stanem.
	magazyn := identitystore.Nowy(stateDir)
	if err := magazyn.Sprzataj(); err != nil {
		return nil, fmt.Errorf("porzadkowanie tozsamosci: %w", err)
	}
	if tozsamosc, err := magazyn.Biezaca(); err == nil && time.Now().Before(tozsamosc.NotAfter) {
		return zTozsamosci(tozsamosc), nil
	}
	// Host postawiony przed wprowadzeniem magazynu ma komplet luzem
	// w katalogu stanu. Przenosimy go raz, bez kasowania oryginalow.
	if przeniesiona, err := magazyn.Migruj(p.Key, p.Cert, p.CA); przeniesiona && err == nil {
		if tozsamosc, err := magazyn.Biezaca(); err == nil && time.Now().Before(tozsamosc.NotAfter) {
			return zTozsamosci(tozsamosc), nil
		}
	}

	caPEM, err := readCABundle(p.CA, bootstrapCAPath)
	if err != nil {
		return nil, err
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("bundle CA nie zawiera certyfikatu")
	}

	// Klucz tworzy magazyn, a nie ta funkcja: to on wie, czy klucz jest
	// plikiem, czy zostaje w ukladzie sprzetowym. Enrollment ma dzialac tak
	// samo w obu profilach.
	key, err := magazyn.NowyKlucz()
	if err != nil {
		return nil, err
	}
	machineID := request.MachineID
	if machineID == "" {
		return nil, fmt.Errorf("brak identyfikatora maszyny")
	}
	hostname := request.Hostname

	var dns []string
	var adresy []net.IP
	for _, nazwa := range strings.Split(request.Advertised, ",") {
		nazwa = strings.TrimSpace(nazwa)
		if nazwa == "" {
			continue
		}
		if adres := net.ParseIP(nazwa); adres != nil {
			adresy = append(adresy, adres)
			continue
		}
		dns = append(dns, nazwa)
	}
	// Podmiot w CSR jest tylko wskazowka; tozsamosc nadaje control plane.
	csrPEM, err := identitystore.Wniosek(key, machineID, dns, adresy)
	if err != nil {
		return nil, err
	}

	client := agentv1connect.NewEnrollmentServiceClient(&http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS12}},
	}, enrollmentURL)

	// Identyfikator proby przezywa restart agenta: gdy odpowiedz zginie
	// w sieci, ponowienie ma isc pod tym samym numerem i dostac ten sam
	// certyfikat zamiast odmowy "token zuzyty".
	numerProby, err := numerProbyEnrollmentu(stateDir)
	if err != nil {
		return nil, err
	}

	resp, err := client.Enroll(ctx, connect.NewRequest(&agentv1.EnrollRequest{
		EnrollmentToken: token,
		MachineId:       machineID,
		Hostname:        hostname,
		CsrPem:          csrPEM,
		ClientRequestId: numerProby,
		Build: &agentv1.AgentBuild{
			AgentVersion: Version,
			OsFamily:     request.OSFamily,
			OsVersion:    request.OSVersion,
			Architecture: request.Architecture,
		},
	}))
	if err != nil {
		return nil, fmt.Errorf("enrollment odrzucony: %w", err)
	}

	// Zapis idzie jedna generacja: klucz, certyfikat i bundle albo trafiaja
	// na dysk razem, albo nie trafia wcale.
	bundle := resp.Msg.GetCaBundlePem()
	if len(bundle) == 0 {
		bundle = caPEM
	}
	tozsamosc, err := magazyn.Zatwierdz(identitystore.Generacja{
		Klucz: key, CertyfikatPEM: resp.Msg.GetCertificatePem(), ZaufaniePEM: bundle,
	})
	if err != nil {
		return nil, fmt.Errorf("zapis tozsamosci: %w", err)
	}
	// Proba sie zamknela: nastepny enrollment jest nowa sprawa i idzie pod
	// nowym numerem.
	_ = os.Remove(filepath.Join(stateDir, plikProbyEnrollmentu))
	return zTozsamosci(tozsamosc), nil
}

// plikProbyEnrollmentu trzyma numer biezacej proby enrollmentu.
const plikProbyEnrollmentu = "enroll-request-id"

// numerProbyEnrollmentu zwraca staly numer proby, tworzac go przy pierwszym
// uzyciu.
//
// Numer musi przezyc restart agenta w trakcie enrollmentu: to on odroznia
// "ponow te sama probe" od "zacznij nowa". Nowy numer po kazdym restarcie
// zuzywalby token przy kazdej probie.
func numerProbyEnrollmentu(stateDir string) (string, error) {
	sciezka := filepath.Join(stateDir, plikProbyEnrollmentu)
	if zapisany, err := os.ReadFile(sciezka); err == nil {
		if numer, err := uuid.Parse(strings.TrimSpace(string(zapisany))); err == nil {
			return numer.String(), nil
		}
	}
	numer := uuid.NewString()
	if err := os.WriteFile(sciezka, []byte(numer+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("numer proby enrollmentu: %w", err)
	}
	return numer, nil
}

func readCABundle(statePath, bootstrapPath string) ([]byte, error) {
	if data, err := os.ReadFile(statePath); err == nil && len(data) > 0 {
		return data, nil
	}
	if bootstrapPath == "" {
		return nil, fmt.Errorf("brak bundla CA: podaj --ca-file przy pierwszym uruchomieniu")
	}
	data, err := os.ReadFile(bootstrapPath)
	if err != nil {
		return nil, fmt.Errorf("bundle CA: %w", err)
	}
	return data, nil
}

func loadIdentity(p IdentityPaths) (*Identity, error) {
	certPEM, err := os.ReadFile(p.Cert)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(p.Key)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(p.CA)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, err
	}
	if time.Now().After(leaf.NotAfter) {
		return nil, fmt.Errorf("certyfikat agenta wygasl %s", leaf.NotAfter.Format(time.RFC3339))
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("zapisany bundle CA jest nieprawidlowy")
	}
	certificate.Leaf = leaf
	return &Identity{
		HostID:      leaf.Subject.CommonName,
		Certificate: certificate,
		CAPool:      caPool,
		NotAfter:    leaf.NotAfter,
	}, nil
}
