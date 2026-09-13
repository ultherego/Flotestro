//go:build integration

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

const certificateReason = "integration test of the certificates module"

type certificateKeyView struct {
	Path          string `json:"path"`
	Exists        bool   `json:"exists"`
	Mode          string `json:"mode"`
	WorldReadable bool   `json:"world_readable"`
	Reason        string `json:"reason"`
}

type certificateView struct {
	Path              string              `json:"path"`
	Subject           string              `json:"subject"`
	FingerprintSHA256 string              `json:"fingerprint_sha256"`
	NotAfter          *time.Time          `json:"not_after"`
	Source            string              `json:"source"`
	Renewal           string              `json:"renewal"`
	Status            string              `json:"status"`
	DaysToExpiry      *int                `json:"days_to_expiry"`
	Watched           bool                `json:"watched"`
	Managed           bool                `json:"managed"`
	KeySecret         string              `json:"key_secret"`
	Key               *certificateKeyView `json:"key"`
	Reason            string              `json:"unavailable_reason"`
}

type certificateTargetView struct {
	ID        string `json:"id"`
	Path      string `json:"path"`
	KeyPath   string `json:"key_path"`
	KeySecret string `json:"key_secret"`
}

type certificateReportView struct {
	Certificates  []certificateView       `json:"certificates"`
	Targets       []certificateTargetView `json:"targets"`
	Status        string                  `json:"status"`
	TrackingKnown bool                    `json:"tracking_known"`
	KeysKnown     bool                    `json:"keys_known"`
	Stale         bool                    `json:"stale"`
}

// testPair issues a certificate and a key for one run.
func testPair(t *testing.T, name string, validity time.Duration) (certPEM, keyPEM, fingerprint string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	data, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("encoding the key: %v", err)
	}
	sum := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: data})),
		hex.EncodeToString(sum[:])
}

// TestCertificateDeploymentFromTheStore walks the full path of the module:
// watching a path, deploying a certificate with a key from the store and
// reading what really landed on the host.
func TestCertificateDeploymentFromTheStore(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")
	name := host.Hostname
	path := fmt.Sprintf("/etc/pki/tls/certs/flotestro-integration-%d.crt", time.Now().UnixNano())
	keyPath := strings.Replace(strings.Replace(path, "/certs/", "/private/", 1), ".crt", ".key", 1)

	certPEM, keyPEM, fingerprint := testPair(t, name, 40*24*time.Hour)
	secret := newSecret(t, h, keyPEM)

	// The watch scope is not an operation on the host: it changes what the
	// panel watches, not the machine state.
	var target certificateTargetView
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/certificates/targets", map[string]any{
		"path": path, "key_path": keyPath, "key_secret": secret.Name,
		"service": "integration",
	}, &target, http.StatusOK)
	t.Cleanup(func() {
		h.do(http.MethodDelete,
			"/api/v1/hosts/"+host.ID+"/certificates/targets?path="+path, nil, nil, 0)
		// The file stays on the host unless removed: the next runs fill the
		// target registry and push the certificates the host really has out
		// of the read.
		for _, toRemove := range []string{path, keyPath} {
			h.runOperation(host.ID, map[string]any{
				"action": "file.remove", "reason": certificateReason,
				"payload": map[string]any{"file": map[string]any{"path": toRemove}},
			}, 2*time.Minute)
		}
	})

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "certificate.deploy", "reason": certificateReason,
		"payload": map[string]any{"certificate": map[string]any{
			"path": path, "key_path": keyPath, "certificate": certPEM,
			"key_secret": map[string]any{"name": secret.Name},
		}},
	}, 3*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("the deployment ended in state %s: %+v", job.State, attempts)
	}

	report := hostCertificates(h, host.ID)
	deployed := findCertificate(t, report, path)
	if deployed.FingerprintSHA256 != fingerprint {
		t.Fatalf("the host holds a certificate with fingerprint %q, %q was deployed",
			deployed.FingerprintSHA256, fingerprint)
	}
	if !deployed.Managed || deployed.Source != "flotestro" {
		t.Errorf("a certificate deployed by the panel described as %+v", deployed)
	}
	if deployed.Status != "valid" || deployed.DaysToExpiry == nil || *deployed.DaysToExpiry < 30 {
		t.Errorf("expiry assessment = %s, days = %v", deployed.Status, deployed.DaysToExpiry)
	}
	// The private key must not be readable by anybody but the owner.
	if deployed.Key == nil || !deployed.Key.Exists {
		t.Fatalf("the panel does not know the key state: %+v", deployed.Key)
	}
	if deployed.Key.WorldReadable || deployed.Key.Mode != "0600" {
		t.Errorf("the key has mode %q (world_readable=%v)", deployed.Key.Mode, deployed.Key.WorldReadable)
	}
	// Certmonger answered that it does not track this file - that is a
	// finding, not missing knowledge.
	if !report.TrackingKnown || deployed.Renewal != "manual" {
		t.Errorf("renewal described as %q with tracking_known=%v",
			deployed.Renewal, report.TrackingKnown)
	}

	// The key value must be nowhere but the store.
	fragment := strings.Split(strings.TrimSpace(keyPEM), "\n")[1]
	assertValueAbsent(t, h, fragment)

	// A certificate with somebody else's key is rejected by the host before
	// the swap: what worked stays on disk.
	foreignCert, _, _ := testPair(t, name, 40*24*time.Hour)
	rejected, _ := h.runOperation(host.ID, map[string]any{
		"action": "certificate.deploy", "reason": certificateReason,
		"payload": map[string]any{"certificate": map[string]any{
			"path": path, "key_path": keyPath, "certificate": foreignCert,
			"key_secret": map[string]any{"name": secret.Name},
		}},
	}, 3*time.Minute)
	if rejected.State == "succeeded" {
		t.Fatal("a certificate not matching the key was deployed")
	}
	after := findCertificate(t, hostCertificates(h, host.ID), path)
	if after.FingerprintSHA256 != fingerprint {
		t.Fatalf("after the rejected deployment the host holds %q", after.FingerprintSHA256)
	}
}

// TestCertificateOutsideTheScopeFallsOutWhenOrdered guards the module
// boundary: the trust store and the agent identity are not service
// certificates.
func TestCertificateOutsideTheScopeFallsOutWhenOrdered(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	certPEM, _, _ := testPair(t, host.Hostname, 40*24*time.Hour)

	outside := []string{
		"/etc/pki/ca-trust/source/anchors/foreign.crt",
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/ssl/certs/3513523f.0",
		"/etc/flotestro/agent/agent.crt",
		"/etc/passwd",
	}
	for _, path := range outside {
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
			"action": "certificate.deploy", "reason": certificateReason,
			"payload": map[string]any{"certificate": map[string]any{
				"path": path, "certificate": certPEM,
			}},
		}, nil, http.StatusBadRequest)

		// The same rule binds the watch scope: a path the panel will not
		// write is not a path whose content it asks about either.
		h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/certificates/targets",
			map[string]any{"path": path}, nil, http.StatusBadRequest)
	}

	// Broken material falls out when ordered too, not after approval.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
		"action": "certificate.deploy", "reason": certificateReason,
		"payload": map[string]any{"certificate": map[string]any{
			"path": "/etc/ssl/private/flotestro-integration.crt", "certificate": "this is not PEM",
		}},
	}, nil, http.StatusBadRequest)
}

// TestCertificateScanDoesNotGuessTheState guards that missing knowledge has
// a reason, and an empty result does not pose as a host without
// certificates.
func TestCertificateScanDoesNotGuessTheState(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("debian")
	path := fmt.Sprintf("/etc/ssl/certs/flotestro-missing-%d.pem", time.Now().UnixNano())

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "certificate.scan",
		"payload": map[string]any{"certificate": map[string]any{
			"targets": []map[string]any{{"path": path}},
		}},
	}, 2*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("the scan ended in state %s: %+v", job.State, attempts)
	}

	report := hostCertificates(h, host.ID)
	missing := findCertificate(t, report, path)
	if missing.Reason == "" {
		t.Fatal("a file that does not exist was not described with a reason")
	}
	if missing.Status != "unknown" {
		t.Errorf("an unread file assessed as %q", missing.Status)
	}
	if missing.NotAfter != nil {
		t.Errorf("an unread file has the expiry %v", missing.NotAfter)
	}
	if !report.TrackingKnown {
		t.Error("it was not established what renews the certificates on this host")
	}
}

// TestRenewalWithoutTrackingRefuses guards the renewal boundary: the panel
// does not supply the certificate content, it only asks the host daemon -
// and a host without a request has nothing to renew and must say so
// outright.
func TestRenewalWithoutTrackingRefuses(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")
	path := fmt.Sprintf("/etc/pki/tls/certs/flotestro-untracked-%d.crt", time.Now().UnixNano())

	// A campaign renewing the same certificate across the fleet can point
	// only at the path: the certmonger request identifier differs on every
	// host. That is why the path is an allowed way of pointing here.
	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "certificate.renew", "reason": certificateReason,
		"payload": map[string]any{"certificate": map[string]any{"path": path}},
	}, 2*time.Minute)
	if job.State == "succeeded" {
		t.Fatal("a certificate nobody tracks was renewed")
	}
	if len(attempts) == 0 || !strings.Contains(attempts[len(attempts)-1].Message, "certmonger") {
		t.Fatalf("the refusal does not say what is missing: %+v", attempts)
	}

	// Without a request and without a path there is nothing to renew - and
	// that falls out already when ordered.
	h.do(http.MethodPost, "/api/v1/hosts/"+host.ID+"/operations", map[string]any{
		"action": "certificate.renew", "reason": certificateReason,
		"payload": map[string]any{"certificate": map[string]any{}},
	}, nil, http.StatusBadRequest)
}

// hostCertificates reads the certificates tab of a host.
func hostCertificates(h *harness, hostID string) certificateReportView {
	h.t.Helper()
	var report certificateReportView
	h.get("/api/v1/hosts/"+hostID+"/certificates", &report)
	return report
}

func findCertificate(t *testing.T, report certificateReportView, path string) certificateView {
	t.Helper()
	for _, certificate := range report.Certificates {
		if certificate.Path == path {
			return certificate
		}
	}
	t.Fatalf("the tab does not know the file %s: %+v", path, report.Certificates)
	return certificateView{}
}

// assertValueAbsent guards the property the store exists for: the key value
// must not appear in a job, the audit log or the inventory.
func assertValueAbsent(t *testing.T, h *harness, fragment string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool := h.database(ctx)
	pattern := "%" + fragment + "%"

	queries := map[string]string{
		"jobs":                    `select count(*) from jobs where payload::text like $1`,
		"job_attempts":            `select count(*) from job_attempts where coalesce(result_detail::text, '') || coalesce(message, '') like $1`,
		"audit_events":            `select count(*) from audit_events where detail::text like $1`,
		"host_module_inventory":   `select count(*) from host_module_inventory where payload::text like $1`,
		"certificate_deployments": `select count(*) from certificate_deployments where certificate like $1`,
	}
	for table, query := range queries {
		var count int
		if err := pool.QueryRow(ctx, query, pattern).Scan(&count); err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("the key value ended up in table %s (%d rows)", table, count)
		}
	}
}

// testAuthority issues an authority for one run of the rotation test.
func testAuthority(t *testing.T, name string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("authority key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(8760 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("authority: %v", err)
	}
	data, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("encoding the authority key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: data}))
}

// issuedPair is a service certificate signed by the given authority.
type issuedPair struct {
	certificate string
	key         string
	fingerprint string
}

func leafFromAuthority(t *testing.T, name, authorityPEM, authorityKeyPEM string) issuedPair {
	t.Helper()
	authorityBlock, _ := pem.Decode([]byte(authorityPEM))
	authority, err := x509.ParseCertificate(authorityBlock.Bytes)
	if err != nil {
		t.Fatalf("authority: %v", err)
	}
	keyBlock, _ := pem.Decode([]byte(authorityKeyPEM))
	authorityKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("authority key: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(720 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, authority, &key.PublicKey, authorityKey)
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	data, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("encoding the leaf key: %v", err)
	}
	sum := sha256.Sum256(der)
	return issuedPair{
		certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		key:         string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: data})),
		fingerprint: hex.EncodeToString(sum[:]),
	}
}

// TestFleetViewHasAnExpiryTimeline checks what the sorted list does not
// say: when the next wave of renewals comes. The list answers "what is on
// fire now", the timeline - "what to plan".
func TestFleetViewHasAnExpiryTimeline(t *testing.T) {
	h := newHarness(t)
	var view struct {
		Items []struct {
			DaysToExpiry *int `json:"days_to_expiry"`
		} `json:"items"`
		Timeline []struct {
			Reason string `json:"reason"`
			Count  int    `json:"count"`
		} `json:"timeline"`
	}
	h.get("/api/v1/certificates", &view)
	if len(view.Items) == 0 {
		t.Skip("the fleet reports no certificate at all")
	}
	if len(view.Timeline) == 0 {
		t.Fatal("the fleet view has no expiry timeline")
	}

	buckets := map[string]int{}
	sum := 0
	for _, bucket := range view.Timeline {
		buckets[bucket.Reason] = bucket.Count
		sum += bucket.Count
	}
	for _, name := range []string{"expired", "7 days", "30 days", "90 days", "later", "no expiry"} {
		if _, present := buckets[name]; !present {
			t.Errorf("the timeline has no bucket %q: %+v", name, view.Timeline)
		}
	}
	// Every certificate belongs to exactly one bucket. A timeline that does
	// not add up to the whole describes a different fleet than the list.
	if sum < len(view.Items) {
		t.Errorf("the timeline adds up to %d, there are at least %d certificates", sum, len(view.Items))
	}
	// A certificate without an expiry must not fall into the "later"
	// bucket: missing knowledge is not a distance in time.
	withoutExpiry := 0
	for _, item := range view.Items {
		if item.DaysToExpiry == nil {
			withoutExpiry++
		}
	}
	if withoutExpiry > 0 && buckets["no expiry"] == 0 {
		t.Errorf("the certificates without an expiry (%d) did not land in their own bucket", withoutExpiry)
	}
}

// TestPrivateKeyDoesNotReachTheHostJournal guards the property the secret
// store exists for in the first place - and which is not visible in the
// API: the key material passes through the agent and the helper at
// deployment, so one careless log line would leave it in the host journal
// forever.
func TestPrivateKeyDoesNotReachTheHostJournal(t *testing.T) {
	h := newHarness(t)
	host := h.hostByFamily("rhel")
	path := fmt.Sprintf("/etc/pki/tls/certs/flotestro-journal-%d.crt", time.Now().UnixNano())
	keyPath := strings.Replace(strings.Replace(path, "/certs/", "/private/", 1), ".crt", ".key", 1)

	certPEM, keyPEM, _ := testPair(t, host.Hostname, 40*24*time.Hour)
	secret := newSecret(t, h, keyPEM)
	t.Cleanup(func() {
		h.do(http.MethodDelete,
			"/api/v1/hosts/"+host.ID+"/certificates/targets?path="+path, nil, nil, 0)
		for _, toRemove := range []string{path, keyPath} {
			h.runOperation(host.ID, map[string]any{
				"action": "file.remove", "reason": certificateReason,
				"payload": map[string]any{"file": map[string]any{"path": toRemove}},
			}, 2*time.Minute)
		}
	})

	job, attempts := h.runOperation(host.ID, map[string]any{
		"action": "certificate.deploy", "reason": certificateReason,
		"payload": map[string]any{"certificate": map[string]any{
			"path": path, "key_path": keyPath, "certificate": certPEM,
			"key_secret": map[string]any{"name": secret.Name},
		}},
	}, 3*time.Minute)
	if job.State != "succeeded" {
		t.Fatalf("deployment: state = %s, %s", job.State, lastMessage(attempts))
	}

	// The journal is searched for a fragment of the key in the form it
	// passes through the panel in: one base64 line from the middle of the
	// material.
	fragment := strings.Split(strings.TrimSpace(keyPEM), "\n")[1]
	for _, unit := range []string{"flotestro-agent", "flotestro-helper"} {
		read, attempts := h.runOperation(host.ID, map[string]any{
			"action": "journal.read", "reason": certificateReason,
			"payload": map[string]any{"journal": map[string]any{
				"unit": unit + ".service", "lines": 400}},
		}, 2*time.Minute)
		if read.State != "succeeded" {
			t.Fatalf("reading the %s journal: state = %s, %s", unit, read.State,
				lastMessage(attempts))
		}
		for _, attempt := range attempts {
			if strings.Contains(attempt.Stdout, fragment) {
				t.Fatalf("the %s journal carries private key material", unit)
			}
			// The secret name alone in the journal is fine - it is a
			// reference, not a value. The value must not be there in any
			// form.
			if strings.Contains(attempt.Stdout, "BEGIN PRIVATE KEY") {
				t.Fatalf("the %s journal carries the key in PEM form", unit)
			}
		}
	}
}
