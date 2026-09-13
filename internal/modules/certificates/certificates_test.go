package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// issue creates a key-certificate pair for tests.
func issue(t *testing.T, name string, issuer *x509.Certificate,
	issuerKey *ecdsa.PrivateKey, validity time.Duration, ca bool) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  ca,
		BasicConstraintsValid: true,
	}
	if !ca {
		template.DNSNames = []string{name}
		template.IPAddresses = []net.IP{net.ParseIP("10.10.10.10")}
	}
	parent, parentKey := template, key
	if issuer != nil {
		parent, parentKey = issuer, issuerKey
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func keyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	data, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("PKCS8 key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: data})
}

func TestDescribeReadsNamesAndDates(t *testing.T) {
	_, _, ca := issue(t, "Flotestro Test CA", nil, nil, 24*time.Hour, true)
	_ = ca
	cert, _, leaf := issue(t, "panel.flotestro.test", nil, nil, 48*time.Hour, false)

	certs, err := ParsePEM(leaf)
	if err != nil {
		t.Fatalf("ParsePEM: %v", err)
	}
	description := Describe("/etc/pki/tls/certs/panel.crt", certs)
	if description.FingerprintSHA256 != Fingerprint(cert) {
		t.Fatalf("the fingerprint %q does not match the certificate", description.FingerprintSHA256)
	}
	if description.KeyAlgorithm != "ECDSA" || description.KeyBits != 256 {
		t.Fatalf("key described as %s/%d", description.KeyAlgorithm, description.KeyBits)
	}
	if len(description.SANs) != 2 || description.SANs[0] != "panel.flotestro.test" {
		t.Fatalf("alternative names: %v", description.SANs)
	}
	if !description.SelfSigned {
		t.Fatal("a self-signed certificate was not recognised")
	}
	// The module gathers facts; judging the date belongs to the panel, so
	// the description holds no state beyond the date itself.
	if description.NotAfter.IsZero() {
		t.Fatal("no expiry date")
	}
}

func TestParsePEMSkipsKeyInFile(t *testing.T) {
	_, key, leaf := issue(t, "service.test", nil, nil, time.Hour, false)
	together := append(append([]byte{}, keyPEM(t, key)...), leaf...)
	certs, err := ParsePEM(together)
	if err != nil {
		t.Fatalf("ParsePEM: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected one certificate, got %d", len(certs))
	}
}

func TestMatchKeyRecognisesForeignKey(t *testing.T) {
	cert, key, _ := issue(t, "service.test", nil, nil, time.Hour, false)
	_, foreign, _ := issue(t, "other.test", nil, nil, time.Hour, false)

	if err := MatchKey(cert, keyPEM(t, key)); err != nil {
		t.Fatalf("own key rejected: %v", err)
	}
	err := MatchKey(cert, keyPEM(t, foreign))
	if err == nil {
		t.Fatal("a foreign key was accepted")
	}
	// The message must not carry the key content: this is the only place
	// in the module where the key is read at all.
	if strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Fatalf("the message carries the key content: %v", err)
	}
}

func TestCheckChainRejectsWrongOrder(t *testing.T) {
	ca, caKey, caPEM := issue(t, "Flotestro Test CA", nil, nil, 72*time.Hour, true)
	_, _, leafPEM := issue(t, "service.test", ca, caKey, 48*time.Hour, false)

	good, err := ParsePEM(append(append([]byte{}, leafPEM...), caPEM...))
	if err != nil {
		t.Fatalf("ParsePEM: %v", err)
	}
	if err := CheckChain(good); err != nil {
		t.Fatalf("a valid chain rejected: %v", err)
	}

	reversed, err := ParsePEM(append(append([]byte{}, caPEM...), leafPEM...))
	if err != nil {
		t.Fatalf("ParsePEM: %v", err)
	}
	if err := CheckChain(reversed); err == nil {
		t.Fatal("a chain in the wrong order was accepted")
	}
}

func TestCheckRejectsMaterialBeforeWrite(t *testing.T) {
	cert, key, leafPEM := issue(t, "service.test", nil, nil, 48*time.Hour, false)
	_, foreign, _ := issue(t, "other.test", nil, nil, time.Hour, false)
	_ = cert

	base := Deployment{
		Path: "/etc/pki/tls/certs/service.crt", KeyPath: "/etc/pki/tls/private/service.key",
		Certificate: leafPEM, Key: keyPEM(t, key),
	}
	if _, err := Check(base, time.Now()); err != nil {
		t.Fatalf("a valid deployment rejected: %v", err)
	}

	withForeignKey := base
	withForeignKey.Key = keyPEM(t, foreign)
	if _, err := Check(withForeignKey, time.Now()); err == nil {
		t.Fatal("a deployment with a foreign key was accepted")
	}

	expired := base
	if _, err := Check(expired, time.Now().Add(72*time.Hour)); err == nil {
		t.Fatal("an expired certificate was accepted")
	}

	// The probe is meant to confirm exactly this certificate: a target
	// outside its names means a test that would not confirm the deployment
	// anyway.
	foreignTarget := base
	foreignTarget.Target = "other.test:443"
	if _, err := Check(foreignTarget, time.Now()); err == nil {
		t.Fatal("a target outside the certificate was accepted")
	}

	ownTarget := base
	ownTarget.Target = "service.test:8443"
	if _, err := Check(ownTarget, time.Now()); err != nil {
		t.Fatalf("a target from the certificate rejected: %v", err)
	}
}

func TestValidatePathProtectsTrustStoreAndAgentIdentity(t *testing.T) {
	allowed := []string{
		"/etc/pki/tls/certs/service.crt",
		"/etc/ssl/private/service.key",
		"/etc/nginx/ssl/panel.pem",
		// Debian keeps the server certificate in the trust store directory:
		// a file lying there by itself makes nothing trusted.
		"/etc/ssl/certs/service.pem",
	}
	for _, p := range allowed {
		if err := ValidatePath(p); err != nil {
			t.Fatalf("path %s rejected: %v", p, err)
		}
	}
	forbidden := []string{
		"/etc/pki/ca-trust/source/anchors/foreign.crt",
		"/etc/ssl/certs/ca-certificates.crt",
		// A hash symlink is a trust store entry: a file under such a name
		// adds an authority, not a service certificate.
		"/etc/ssl/certs/3513523f.0",
		"/etc/pki/tls/certs/002c0b4f.1",
		"/etc/flotestro/agent/agent.crt",
		"/etc/pki/tls/certs/../../../root/.ssh/id_rsa",
		"etc/pki/tls/certs/service.crt",
		"/etc/shadow",
	}
	for _, p := range forbidden {
		if err := ValidatePath(p); err == nil {
			t.Fatalf("path %s was accepted", p)
		}
	}
}

func TestParseGetcertLinksRequestToFile(t *testing.T) {
	output := `Number of certificates and requests being tracked: 2.
Request ID '20250101120000':
	status: MONITORING
	stuck: no
	key pair storage: type=FILE,location='/etc/pki/tls/private/httpd.key'
	certificate: type=FILE,location='/etc/pki/tls/certs/httpd.crt'
	CA: IPA
	expires: 2026-12-01 10:00:00 UTC
	auto-renew: yes
Request ID '20250202130000':
	status: CA_UNREACHABLE
	key pair storage: type=FILE,location='/etc/pki/tls/private/ldap.key'
	certificate: type=FILE,location='/etc/pki/tls/certs/ldap.crt'
	CA: IPA
	auto-renew: no
`
	trackings := ParseGetcert(output)
	if len(trackings) != 2 {
		t.Fatalf("recognised %d requests: %v", len(trackings), trackings)
	}
	httpd, ok := trackings["/etc/pki/tls/certs/httpd.crt"]
	if !ok {
		t.Fatalf("no request for httpd: %v", trackings)
	}
	if httpd.Request != "20250101120000" || httpd.Status != "MONITORING" || httpd.CA != "IPA" {
		t.Fatalf("httpd request read as %+v", httpd)
	}
	if httpd.KeyPath != "/etc/pki/tls/private/httpd.key" {
		t.Fatalf("httpd key: %q", httpd.KeyPath)
	}
	if httpd.AutoRenew == nil || !*httpd.AutoRenew {
		t.Fatal("httpd auto-renew was not read")
	}
	if httpd.Expires == nil || httpd.Expires.Year() != 2026 {
		t.Fatalf("httpd expiry: %v", httpd.Expires)
	}
	ldap := trackings["/etc/pki/tls/certs/ldap.crt"]
	if ldap.AutoRenew == nil || *ldap.AutoRenew {
		t.Fatal("ldap auto-renew should be false, not no knowledge")
	}
}

func TestScanNoKnowledgeIsNotMissingFile(t *testing.T) {
	snapshot := Scan([]Target{{
		Path:    "/etc/pki/tls/certs/no-such-thing.crt",
		KeyPath: "/etc/pki/tls/private/no-such-thing.key",
	}})
	if len(snapshot.Certificates) != 1 {
		t.Fatalf("the scan returned %d items", len(snapshot.Certificates))
	}
	if snapshot.Certificates[0].UnavailableReason == "" {
		t.Fatal("a file that does not exist was not described with a reason")
	}
	// Key metadata is not visible without root: that is meant to be no
	// knowledge with a reason, not a quiet answer "there is no key".
	if _, missing := snapshot.Missing[FactKeyMetadata]; !missing {
		t.Fatalf("the missing key fact was not reported: %v", snapshot.Missing)
	}
	if snapshot.KeysKnown {
		t.Fatal("the key state was treated as known")
	}
}

func TestSupplementedInsertsTrackingAndKeys(t *testing.T) {
	snapshot := Snapshot{
		Certificates: []Certificate{{
			Path:    "/etc/pki/tls/certs/httpd.crt",
			Renewal: RenewalUnknown,
			Source:  SourceExternal,
			Key:     &KeyMetadata{Path: "/etc/pki/tls/private/httpd.key"},
		}, {
			Path:    "/etc/pki/tls/certs/manual.crt",
			Renewal: RenewalUnknown,
			Source:  SourceExternal,
		}},
		Missing: map[string]string{FactTracking: "requires root", FactKeyMetadata: "requires root"},
	}
	yes := true
	supplemented := snapshot.Supplemented(Supplement{
		Keys: map[string]KeyMetadata{
			"/etc/pki/tls/private/httpd.key": {Path: "/etc/pki/tls/private/httpd.key",
				Exists: true, Mode: "0600", Owner: "root"},
		},
		Tracking: map[string]Tracking{
			"/etc/pki/tls/certs/httpd.crt": {Request: "1", Status: "MONITORING", AutoRenew: &yes},
		},
		TrackingKnown: true,
	})

	if !supplemented.KeysKnown || !supplemented.TrackingKnown {
		t.Fatal("the helper facts were not recorded as known")
	}
	if len(supplemented.Missing) != 0 {
		t.Fatalf("gaps remained after the supplement: %v", supplemented.Missing)
	}
	if supplemented.Certificates[0].Renewal != RenewalTracked ||
		supplemented.Certificates[0].Source != SourceCertmonger {
		t.Fatalf("a certificate under certmonger care described as %+v", supplemented.Certificates[0])
	}
	if supplemented.Certificates[0].Key.Mode != "0600" {
		t.Fatalf("the key metadata was not inserted: %+v", supplemented.Certificates[0].Key)
	}
	// A file without a request is renewed manually - and that is a finding,
	// not no knowledge: the daemon answered that it does not watch it.
	if supplemented.Certificates[1].Renewal != RenewalManual {
		t.Fatalf("a file without a request described as %q", supplemented.Certificates[1].Renewal)
	}
}

func TestAddTrackedSkipsPathsOutsideScope(t *testing.T) {
	targets := AddTracked([]Target{{Path: "/etc/pki/tls/certs/known.crt"}}, map[string]Tracking{
		"/etc/pki/tls/certs/known.crt":  {Request: "1"},
		"/etc/pki/tls/certs/new.crt":    {Request: "2", KeyPath: "/etc/pki/tls/private/new.key"},
		"/etc/pki/ca-trust/foreign.crt": {Request: "3"},
	})
	if len(targets) != 2 {
		t.Fatalf("the scope has %d targets: %+v", len(targets), targets)
	}
	for _, target := range targets {
		if strings.HasPrefix(target.Path, "/etc/pki/ca-trust/") {
			t.Fatal("the trust store made it into the scan scope")
		}
	}
}

// A list cut off by the limit must say so: silence here looks like a host
// that has no more certificates, and it is a host nobody asked about the
// rest.
func TestScanReportsTruncatedList(t *testing.T) {
	targets := make([]Target, 0, MaxCertificates+5)
	for i := 0; i < MaxCertificates+5; i++ {
		targets = append(targets, Target{Path: fmt.Sprintf("/etc/ssl/certs/missing-%d.pem", i)})
	}
	snapshot := Scan(targets)
	if len(snapshot.Certificates) != MaxCertificates {
		t.Fatalf("%d targets described", len(snapshot.Certificates))
	}
	if snapshot.Truncated != 5 || snapshot.TruncatedReason == "" {
		t.Errorf("list truncation: %d, %q", snapshot.Truncated, snapshot.TruncatedReason)
	}

	short := Scan(targets[:2])
	if short.Truncated != 0 || short.TruncatedReason != "" {
		t.Errorf("a full list described as truncated: %+v", short)
	}
}
