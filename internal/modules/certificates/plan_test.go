package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testCertificate assembles a self-signed certificate in PEM.
func testCertificate(t *testing.T, name string, validFrom, validTo time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    validFrom,
		NotAfter:     validTo,
	}
	data, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: data}))
}

func TestCertificatePlanDistinguishesFoundState(t *testing.T) {
	now := time.Now()
	fresh := testCertificate(t, "panel.flotestro.test", now.Add(-time.Hour), now.Add(720*time.Hour))
	order := Order{
		Path: "/etc/ssl/certs/flotestro.pem", KeyPath: "/etc/ssl/private/flotestro.key",
		Certificate: fresh, KeySecret: "pki/panel#3", HasKey: true,
		Unit: "nginx.service", Target: "panel.flotestro.test:443",
	}

	creation := Compute(Certificate{}, order, now)
	if creation.Action != PlanCreate || creation.Refusal != "" || creation.Exists {
		t.Fatalf("a file that does not exist: %+v", creation)
	}
	if len(creation.Changes) != 4 || creation.DesiredFingerprint == "" {
		t.Errorf("changes: %v", creation.Changes)
	}
	// The private key has no right to appear in the plan or in the
	// fingerprint.
	if strings.Contains(strings.Join(creation.Changes, " "), "BEGIN") {
		t.Error("the plan carries key material")
	}

	current := Certificate{Path: order.Path, Subject: "CN=old",
		FingerprintSHA256: strings.Repeat("a", 64)}
	change := Compute(current, order, now)
	if change.Action != PlanUpdate || !strings.Contains(change.Changes[0], "certificate from aaaaaaaaaaaaaaaa to ") {
		t.Errorf("certificate replacement: %+v", change)
	}

	none := Compute(Certificate{Path: order.Path,
		FingerprintSHA256: creation.DesiredFingerprint}, order, now)
	if none.Action != PlanNoChange || len(none.Changes) != 0 {
		t.Errorf("the same certificate: %+v", none)
	}
	if creation.PlanHash == change.PlanHash || change.PlanHash == none.PlanHash {
		t.Error("plan fingerprints do not differ")
	}
}

func TestCertificatePlanRefusesMaterialAndTargetOutsideScope(t *testing.T) {
	now := time.Now()
	expired := testCertificate(t, "panel.flotestro.test", now.Add(-48*time.Hour), now.Add(-time.Hour))
	plan := Compute(Certificate{}, Order{
		Path: "/etc/ssl/certs/flotestro.pem", Certificate: expired}, now)
	if !strings.Contains(plan.Refusal, "expired") || plan.PlanHash == "" {
		t.Errorf("expired certificate: %+v", plan)
	}

	good := testCertificate(t, "panel.flotestro.test", now.Add(-time.Hour), now.Add(time.Hour))
	foreign := Compute(Certificate{}, Order{
		Path: "/etc/ssl/certs/flotestro.pem", Certificate: good,
		Target: "other.flotestro.test:443"}, now)
	if !strings.Contains(foreign.Refusal, "does not cover the name other.flotestro.test") {
		t.Errorf("target outside the scope: %+v", foreign)
	}

	noSecret := Compute(Certificate{}, Order{
		Path: "/etc/ssl/certs/flotestro.pem", KeyPath: "/etc/ssl/private/flotestro.key",
		Certificate: good}, now)
	if !strings.Contains(noSecret.Refusal, "secret store") {
		t.Errorf("key without a reference: %+v", noSecret)
	}
}

func TestCertificatePlanDistinguishesMissingFileFromUnread(t *testing.T) {
	now := time.Now()
	good := testCertificate(t, "panel.flotestro.test", now.Add(-time.Hour), now.Add(time.Hour))
	order := Order{Path: "/etc/ssl/certs/flotestro.pem", Certificate: good}

	missing := Compute(Certificate{Path: order.Path,
		UnavailableReason: "open /etc/ssl/certs/flotestro.pem: no such file or directory"},
		order, now)
	if missing.Action != PlanCreate || missing.Exists || missing.Refusal != "" {
		t.Errorf("a file that does not exist: %+v", missing)
	}

	unread := Compute(Certificate{Path: order.Path,
		UnavailableReason: "permission denied"}, order, now)
	if !strings.Contains(unread.Refusal, "the current certificate was not read") {
		t.Errorf("unread file: %+v", unread)
	}
}

func TestRenewalPlanLooksAtHostDaemon(t *testing.T) {
	now := time.Now()
	end := now.Add(240 * time.Hour)
	current := Certificate{Path: "/etc/pki/tls/certs/service.pem",
		FingerprintSHA256: strings.Repeat("d", 64), NotAfter: &end}
	monitoring := "MONITORING"
	tracking := &Tracking{Request: "20260101000000", Status: monitoring, CA: "IPA"}

	plan := ComputeRenewal(current, tracking, true, current.Path, "httpd.service", now)
	if plan.Refusal != "" || plan.Request != "20260101000000" || plan.PlanHash == "" {
		t.Fatalf("renewal plan: %+v", plan)
	}
	if plan.DaysToExpiry == nil || *plan.DaysToExpiry != 10 {
		t.Errorf("days to expiry: %v", plan.DaysToExpiry)
	}
	if len(plan.Changes) != 3 {
		t.Errorf("changes: %v", plan.Changes)
	}

	// Care that does not work is meant to be visible before approval, not
	// after.
	broken := *tracking
	broken.Status = "CA_UNREACHABLE"
	withVoice := ComputeRenewal(current, &broken, true, current.Path, "", now)
	if !strings.Contains(strings.Join(withVoice.Changes, ";"), "CA_UNREACHABLE") {
		t.Errorf("the request state did not reach the plan: %v", withVoice.Changes)
	}

	// A different request identifier is a different renewal: approval
	// cannot pass from one to the other.
	other := *tracking
	other.Request = "20260202000000"
	if ComputeRenewal(current, &other, true, current.Path, "httpd.service", now).PlanHash == plan.PlanHash {
		t.Error("the plan for a different request has the same fingerprint")
	}
}

func TestRenewalPlanRefusesWithoutDaemonAndWithoutRequest(t *testing.T) {
	now := time.Now()
	certPath := "/etc/pki/tls/certs/service.pem"
	noDaemon := ComputeRenewal(Certificate{}, nil, false, certPath, "", now)
	if !strings.Contains(noDaemon.Refusal, "has no certmonger") || noDaemon.PlanHash == "" {
		t.Errorf("host without the daemon: %+v", noDaemon)
	}
	noRequest := ComputeRenewal(Certificate{}, nil, true, certPath, "", now)
	if !strings.Contains(noRequest.Refusal, "does not track the file") {
		t.Errorf("file outside the daemon's care: %+v", noRequest)
	}
	badPath := ComputeRenewal(Certificate{}, nil, true, "/etc/passwd", "", now)
	if badPath.Refusal == "" {
		t.Error("a path outside the certificate directories passed without a refusal")
	}
}

// Three different plans of the module come back the same way, so the
// receiver must tell them apart without guessing from empty fields: a
// refused plan has everything empty but the reason and still names its
// kind.
func TestPlansNameTheirKind(t *testing.T) {
	now := time.Now()
	good := testCertificate(t, "panel.flotestro.test", now.Add(-time.Hour), now.Add(time.Hour))
	deployment := Compute(Certificate{}, Order{
		Path: "/etc/ssl/certs/flotestro.pem", Certificate: good}, now)
	if deployment.Kind != KindDeployment {
		t.Errorf("deployment plan: %q", deployment.Kind)
	}
	refused := Compute(Certificate{}, Order{Path: "/etc/passwd"}, now)
	if refused.Kind != KindDeployment || refused.Refusal == "" {
		t.Errorf("refused deployment plan: %+v", refused)
	}
	renewal := ComputeRenewal(Certificate{}, nil, false,
		"/etc/pki/tls/certs/service.pem", "", now)
	if renewal.Kind != KindRenewal {
		t.Errorf("renewal plan: %q", renewal.Kind)
	}
}
