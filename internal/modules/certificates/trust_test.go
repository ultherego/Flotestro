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

// testAuthority assembles an authority certificate in PEM.
func testAuthority(t *testing.T, name string, validTo time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              validTo,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	data, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: data}))
}

func testStore() TrustStore {
	return TrustStore{Adapter: AdapterDebian,
		Directory: AnchorDirDebian, Tool: UpdateCACertificatesPath}
}

func TestAnchorPathDependsOnTool(t *testing.T) {
	debian := AnchorPath(testStore(), "lab-ca")
	if debian != "/usr/local/share/ca-certificates/flotestro-lab-ca.crt" {
		t.Errorf("path on debian = %q", debian)
	}
	rhel := AnchorPath(TrustStore{Adapter: AdapterRHEL,
		Directory: AnchorDirRHEL}, "lab-ca")
	if rhel != "/etc/pki/ca-trust/source/anchors/flotestro-lab-ca.pem" {
		t.Errorf("path on rhel = %q", rhel)
	}
	// The extension is part of the agreement with the tool, so it cannot
	// depend on the anchor name.
	if AnchorPath(TrustStore{}, "lab-ca") != "" {
		t.Error("a host without a store got an anchor path")
	}
	if err := ValidateAnchor("../etc/passwd"); err == nil {
		t.Error("a name with a path passed validation")
	}
}

func TestAnchorPlanDistinguishesFoundState(t *testing.T) {
	now := time.Now()
	material := testAuthority(t, "Flotestro Lab CA", now.Add(8760*time.Hour))

	fresh := ComputeAnchor(testStore(), "lab-ca", material, now)
	if fresh.Action != PlanCreate || fresh.Refusal != "" || len(fresh.Changes) != 2 {
		t.Fatalf("an anchor the host does not have: %+v", fresh)
	}

	store := testStore()
	store.Anchors = []Anchor{{
		ID: "lab-ca", Managed: true, Subject: fresh.DesiredSubject,
		Path: fresh.Path, FingerprintSHA256: fresh.DesiredFingerprint,
	}}
	none := ComputeAnchor(store, "lab-ca", material, now)
	if none.Action != PlanNoChange || len(none.Changes) != 0 || !none.Exists {
		t.Errorf("an anchor already trusted: %+v", none)
	}

	store.Anchors[0].FingerprintSHA256 = strings.Repeat("b", 64)
	replacement := ComputeAnchor(store, "lab-ca", material, now)
	if replacement.Action != PlanUpdate || !strings.Contains(replacement.Changes[0], "bbbbbbbbbbbbbbbb to ") {
		t.Errorf("anchor replacement: %+v", replacement)
	}
	if fresh.PlanHash == none.PlanHash || none.PlanHash == replacement.PlanHash {
		t.Error("plan fingerprints do not differ")
	}
}

func TestAnchorPlanRefusesMaterialThatIsNotAnAuthority(t *testing.T) {
	now := time.Now()
	leaf := testCertificate(t, "panel.flotestro.test", now.Add(-time.Hour), now.Add(time.Hour))
	plan := ComputeAnchor(testStore(), "lab-ca", leaf, now)
	if !strings.Contains(plan.Refusal, "not an authority certificate") {
		t.Errorf("a leaf as an anchor: %+v", plan)
	}
	expired := testAuthority(t, "Old CA", now.Add(-time.Hour))
	if p := ComputeAnchor(testStore(), "lab-ca", expired, now); p.Refusal == "" {
		t.Error("an expired authority passed without a refusal")
	}
	noStore := ComputeAnchor(TrustStore{UnavailableReason: "no tool"},
		"lab-ca", testAuthority(t, "CA", now.Add(time.Hour)), now)
	if noStore.Refusal != "no tool" || noStore.PlanHash == "" {
		t.Errorf("host without a store: %+v", noStore)
	}
}

// Removing an authority that still signs something breaks trust for
// clients that changed nothing. That is the rotation boundary: the old
// authority vanishes only when no host certificate comes from it any more.
func TestAnchorRemovalPlanLooksAtHostCertificates(t *testing.T) {
	store := testStore()
	store.Anchors = []Anchor{{ID: "lab-ca", Managed: true, Subject: "CN=Flotestro Lab CA",
		Path:              "/usr/local/share/ca-certificates/flotestro-lab-ca.crt",
		FingerprintSHA256: strings.Repeat("c", 64)}}

	inUse := ComputeAnchorRemoval(store, "lab-ca", []Certificate{
		{Path: "/etc/ssl/certs/service.pem", Issuer: "CN=Flotestro Lab CA"},
	})
	if !strings.Contains(inUse.Refusal, "still signs") || len(inUse.InUseBy) != 1 {
		t.Errorf("authority in use: %+v", inUse)
	}

	free := ComputeAnchorRemoval(store, "lab-ca", []Certificate{
		{Path: "/etc/ssl/certs/service.pem", Issuer: "CN=New CA"},
	})
	if free.Action != PlanRemove || free.Refusal != "" || len(free.Changes) != 2 {
		t.Errorf("authority without certificates: %+v", free)
	}

	missing := ComputeAnchorRemoval(testStore(), "lab-ca", nil)
	if missing.Action != PlanRemoveAbsent || missing.Refusal != "" {
		t.Errorf("an anchor that does not exist: %+v", missing)
	}
	if inUse.PlanHash == free.PlanHash || free.PlanHash == missing.PlanHash {
		t.Error("plan fingerprints do not differ")
	}
}

func TestDetectStoreDecidesByTool(t *testing.T) {
	debian := DetectStore(func(p string) bool {
		return p == UpdateCACertificatesPath || p == AnchorDirDebian
	})
	if debian.Adapter != AdapterDebian || debian.Directory != AnchorDirDebian {
		t.Errorf("debian: %+v", debian)
	}
	arch := DetectStore(func(p string) bool {
		return p == UpdateCATrustPath || p == AnchorDirArch
	})
	if arch.Adapter != AdapterRHEL || arch.Directory != AnchorDirArch {
		t.Errorf("arch: %+v", arch)
	}
	none := DetectStore(func(string) bool { return false })
	if none.UnavailableReason == "" || none.Adapter != "" {
		t.Errorf("host without a store: %+v", none)
	}
}

func TestTrustPlanNamesItsKind(t *testing.T) {
	now := time.Now()
	material := testAuthority(t, "Flotestro Lab CA", now.Add(8760*time.Hour))
	if p := ComputeAnchor(testStore(), "lab-ca", material, now); p.Kind != KindTrust {
		t.Errorf("trust plan: %q", p.Kind)
	}
	// A refused plan too: the kind cannot depend on how far the computation
	// got.
	if p := ComputeAnchor(testStore(), "../bad", material, now); p.Kind != KindTrust {
		t.Errorf("refused trust plan: %+v", p)
	}
	if p := ComputeAnchorRemoval(testStore(), "lab-ca", nil); p.Kind != KindTrust {
		t.Errorf("withdrawal plan: %q", p.Kind)
	}
}
