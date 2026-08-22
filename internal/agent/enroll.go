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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"connectrpc.com/connect"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1/agentv1connect"
)

// Version jest wersja agenta raportowana do control plane.
const Version = "0.1.0"

// Identity to material kryptograficzny hosta przechowywany lokalnie.
type Identity struct {
	HostID      string
	Certificate tls.Certificate
	CAPool      *x509.CertPool
	NotAfter    time.Time
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

	if identity, err := loadIdentity(p); err == nil {
		return identity, nil
	}

	caPEM, err := readCABundle(p.CA, bootstrapCAPath)
	if err != nil {
		return nil, err
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("bundle CA nie zawiera certyfikatu")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	machineID := request.MachineID
	if machineID == "" {
		return nil, fmt.Errorf("brak identyfikatora maszyny")
	}
	hostname := request.Hostname

	wniosek := &x509.CertificateRequest{
		// Podmiot w CSR jest tylko wskazowka; tozsamosc nadaje control plane.
		Subject: pkix.Name{CommonName: machineID},
	}
	for _, nazwa := range strings.Split(request.Advertised, ",") {
		nazwa = strings.TrimSpace(nazwa)
		if nazwa == "" {
			continue
		}
		if adres := net.ParseIP(nazwa); adres != nil {
			wniosek.IPAddresses = append(wniosek.IPAddresses, adres)
			continue
		}
		wniosek.DNSNames = append(wniosek.DNSNames, nazwa)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, wniosek, key)
	if err != nil {
		return nil, err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	client := agentv1connect.NewEnrollmentServiceClient(&http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS12}},
	}, enrollmentURL)

	resp, err := client.Enroll(ctx, connect.NewRequest(&agentv1.EnrollRequest{
		EnrollmentToken: token,
		MachineId:       machineID,
		Hostname:        hostname,
		CsrPem:          csrPEM,
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

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(p.Key, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p.Cert, resp.Msg.GetCertificatePem(), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p.CA, resp.Msg.GetCaBundlePem(), 0o644); err != nil {
		return nil, err
	}
	return loadIdentity(p)
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
