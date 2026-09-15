//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"
)

// cloneIdentity is what one first boot from the golden image ended with:
// the host the panel created and the certificate it issued.
type cloneIdentity struct {
	HostID      string
	MachineID   string
	Serial      string
	Fingerprint string
}

// enrollClone plays one first boot of a machine started from the image:
// a fresh key, a fresh machine id, the image's token. The host is deleted
// with the test the way the other synthetic hosts are.
func enrollClone(t *testing.T, h *harness, token, machine string) cloneIdentity {
	t.Helper()
	status, raw := h.enrollAttempt(t, token, machine, testCSR(t, machine))
	if status != http.StatusOK {
		t.Fatalf("the clone %s was refused: %d %s", machine, status, raw)
	}
	var result struct {
		HostID         string `json:"hostId"`
		CertificatePEM []byte `json:"certificatePem"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		if _, err := h.database(ctx).Exec(ctx,
			`delete from hosts where id = $1::uuid`, result.HostID); err != nil {
			t.Logf("the synthetic host %s was not cleaned up: %v", result.HostID, err)
		}
	})
	block, _ := pem.Decode(result.CertificatePEM)
	if block == nil {
		t.Fatalf("the answer for %s carries no PEM certificate", machine)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("the certificate of %s: %v", machine, err)
	}
	sum := sha256.Sum256(certificate.Raw)
	return cloneIdentity{
		HostID:      result.HostID,
		MachineID:   machine,
		Serial:      certificate.SerialNumber.String(),
		Fingerprint: hex.EncodeToString(sum[:]),
	}
}

// TestTwoClonesOfOneImageGetDistinctIdentities is the CI test the lifecycle
// document asks for next to the golden image procedure: two machines
// started from one image must end up as two hosts with two keys and two
// certificates, and a clone that kept the image's machine id must not
// become a second copy of the first.
//
// The image is stood in for by one batch order (max_uses 2) and the two
// first boots by two enrollments with fresh keys and different machine
// ids. The rule under test in the negative half is checkPurpose in
// internal/gateway/enrollment_service.go: a token of purpose "new" does
// not fit a machine id the panel already knows under an unretired host,
// whatever order it came with - the attempt is refused (HTTP 403, the same
// answer as every refused token), the reason duplicate_machine_id goes to
// the audit trail and to the certificate step of the order, and nothing
// is adopted or superseded: the first host keeps its row, its machine id
// and its certificate. The token is not used up either, because the
// refusal rolls the transaction back.
func TestTwoClonesOfOneImageGetDistinctIdentities(t *testing.T) {
	h := newHarness(t)

	// The image's order: one token, good for two machines. A batch order
	// is a step-up operation and carries a reason.
	var image orderView
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "golden image clone test", "reason": "golden image clone test",
		"site": "lab", "environment": "test", "max_uses": 2,
	}, &image, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/enrollment-requests/"+image.ID+"/revoke", nil, nil, 0)
	})

	first := enrollClone(t, h, image.Token, uniqueSubject("clone-a"))
	second := enrollClone(t, h, image.Token, uniqueSubject("clone-b"))

	if first.HostID == second.HostID {
		t.Fatalf("both clones became the host %s", first.HostID)
	}
	if first.Serial == second.Serial {
		t.Errorf("both clones hold the certificate serial %s", first.Serial)
	}
	if first.Fingerprint == second.Fingerprint {
		t.Errorf("both clones hold the certificate %s", first.Fingerprint)
	}

	// The panel's record of each host names the machine that enrolled and
	// the certificate it was given.
	for _, clone := range []cloneIdentity{first, second} {
		var view struct {
			ID             string `json:"id"`
			MachineID      string `json:"machine_id"`
			LifecycleState string `json:"lifecycle_state"`
		}
		h.get("/api/v1/hosts/"+clone.HostID, &view)
		if view.MachineID != clone.MachineID {
			t.Errorf("host %s is recorded for machine %q, enrolled as %q",
				clone.HostID, view.MachineID, clone.MachineID)
		}
		if view.LifecycleState != "active" {
			t.Errorf("host %s is %q after enrollment", clone.HostID, view.LifecycleState)
		}
		var trail struct {
			Items []struct {
				TargetID string `json:"target_id"`
				Detail   struct {
					CertSerial string `json:"cert_serial"`
					TokenID    string `json:"token_id"`
				} `json:"detail"`
			} `json:"items"`
		}
		h.get("/api/v1/audit?actor="+clone.MachineID+"&action=host.enroll&outcome=success", &trail)
		if len(trail.Items) != 1 {
			t.Fatalf("machine %s has %d successful enrollments in the trail, wanted 1",
				clone.MachineID, len(trail.Items))
		}
		if got := trail.Items[0]; got.TargetID != clone.HostID ||
			got.Detail.CertSerial != clone.Serial || got.Detail.TokenID != image.ID {
			t.Errorf("the enrollment of %s is recorded as %+v; wanted host %s, serial %s, order %s",
				clone.MachineID, got, clone.HostID, clone.Serial, image.ID)
		}
	}

	// The order counted both boots and closed itself on the last one.
	var used orderView
	h.get("/api/v1/enrollment-requests/"+image.ID, &used)
	if used.Uses != 2 || used.MaxUses != 2 {
		t.Errorf("the image's order has uses %d of %d, wanted 2 of 2", used.Uses, used.MaxUses)
	}
	if used.Status != "enrolled" {
		t.Errorf("the image's order is %q after its last use", used.Status)
	}

	// The negative half: a third machine from the image that kept the
	// first one's /etc/machine-id, with an order bound to that machine id
	// - the shape the Ansible role orders. The token fits the machine, the
	// purpose does not: the machine is already a host.
	var bound orderView
	h.do(http.MethodPost, "/api/v1/enrollment-requests", map[string]any{
		"description": "clone that kept its machine-id", "site": "lab", "environment": "test",
		"expected_machine_id": first.MachineID,
	}, &bound, http.StatusCreated)
	t.Cleanup(func() {
		h.do(http.MethodPost, "/api/v1/enrollment-requests/"+bound.ID+"/revoke", nil, nil, 0)
	})
	if bound.ExpectedMachineID != first.MachineID {
		t.Fatalf("the order was not bound to the machine: %+v", bound)
	}

	status, body := h.enrollAttempt(t, bound.Token, first.MachineID, testCSR(t, first.MachineID))
	if status != http.StatusForbidden {
		t.Fatalf("a clone with a known machine id was answered with %d: %s", status, body)
	}

	// Nothing was adopted: the first host is the same row with the same
	// machine id and the same certificate, and no other host carries that
	// machine id.
	var kept struct {
		ID             string `json:"id"`
		MachineID      string `json:"machine_id"`
		LifecycleState string `json:"lifecycle_state"`
	}
	h.get("/api/v1/hosts/"+first.HostID, &kept)
	if kept.MachineID != first.MachineID || kept.LifecycleState != "active" {
		t.Errorf("the first host changed under the refused clone: %+v", kept)
	}
	var trail struct {
		Items []struct {
			TargetID string `json:"target_id"`
			Detail   struct {
				CertSerial string `json:"cert_serial"`
			} `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/audit?actor="+first.MachineID+"&action=host.enroll&outcome=success", &trail)
	if len(trail.Items) != 1 || trail.Items[0].Detail.CertSerial != first.Serial {
		t.Errorf("the machine %s got another certificate: %+v", first.MachineID, trail.Items)
	}
	ctx := context.Background()
	var rows int
	if err := h.database(ctx).QueryRow(ctx,
		`select count(*) from hosts where machine_id = $1`, first.MachineID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Errorf("the machine %s is %d hosts, wanted 1", first.MachineID, rows)
	}

	// The refusal is named where the operator reads it: on the order, at
	// the certificate step (the token itself was fine), and in the trail
	// against the order. The token was not used up by the refusal.
	var refused orderView
	h.get("/api/v1/enrollment-requests/"+bound.ID, &refused)
	if refused.Uses != 0 {
		t.Errorf("the refused order counts %d uses, wanted 0", refused.Uses)
	}
	var certificate *stepView
	for i := range refused.Steps {
		if refused.Steps[i].Key == "certificate" {
			certificate = &refused.Steps[i]
		}
		if refused.Steps[i].Key == "token" && refused.Steps[i].ErrorCode != "" {
			t.Errorf("the refusal landed on the token step: %+v", refused.Steps[i])
		}
	}
	if certificate == nil {
		t.Fatalf("no certificate step: %+v", refused.Steps)
	}
	if certificate.ErrorCode != "duplicate_machine_id" {
		t.Errorf("certificate step error_code = %q, detail %q; wanted duplicate_machine_id",
			certificate.ErrorCode, certificate.Detail)
	}
	var denials struct {
		Items []struct {
			ActorID string `json:"actor_id"`
			Detail  struct {
				Reason  string `json:"reason"`
				Purpose string `json:"purpose"`
			} `json:"detail"`
		} `json:"items"`
	}
	h.get("/api/v1/audit?target_id="+bound.ID+"&action=host.enroll&outcome=denied", &denials)
	found := false
	for _, item := range denials.Items {
		if item.Detail.Reason == "duplicate_machine_id" && item.ActorID == first.MachineID {
			found = true
			if item.Detail.Purpose != "new" {
				t.Errorf("the refusal names the purpose %q, wanted new", item.Detail.Purpose)
			}
		}
	}
	if !found {
		t.Errorf("the trail of the order does not name the duplicate machine: %+v", denials.Items)
	}
}
