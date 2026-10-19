package agent

import (
	"os"
	"path/filepath"
	"testing"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/helpercap"
)

// A relay carries the acknowledgement of a result, so it can write one. The
// copy in the spool is the only durable record of work already done on the
// host, and it is freed by the panel's signature or not at all.

func trustedPanel(t *testing.T) (signer *helpercap.Signer, trustDir string) {
	t.Helper()
	signer, _, err := helpercap.LoadOrGenerateSigner(filepath.Join(t.TempDir(), "helper-signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	trustDir = t.TempDir()
	pem, err := helpercap.EncodePublicKeyPEM(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(trustDir, signer.KeyID()+".pub"), pem, 0o644); err != nil {
		t.Fatal(err)
	}
	return signer, trustDir
}

func deliveryWithOneAnswer(t *testing.T, trustDir string) *resultDelivery {
	t.Helper()
	spool := openResultSpool(t, t.TempDir(), ResultSpoolSize, ResultSpoolBytes)
	if err := spool.Enqueue(finishedTask("attempt-1")); err != nil {
		t.Fatal(err)
	}
	return &resultDelivery{
		spool: spool, send: func(*agentv1.AgentMessage) error { return nil }, log: quietLog(),
		acknowledged: true,
		verify:       resultAckVerifier("host-1", trustDir, quietLog()),
	}
}

func settledAck() *agentv1.TaskResultAck {
	return &agentv1.TaskResultAck{
		TaskId: "attempt-1", IdempotencyKey: "job:attempt-1", Status: agentv1.TaskResultAck_STATUS_SETTLED,
	}
}

func TestOnlyThePanelsSignatureFreesAnAnswer(t *testing.T) {
	signer, trustDir := trustedPanel(t)

	// What a relay can write with the identifiers it sees and no key.
	for name, forged := range map[string]func() *agentv1.TaskResultAck{
		"an unsigned acknowledgement": settledAck,
		"a signature of nothing": func() *agentv1.TaskResultAck {
			ack := settledAck()
			ack.KeyId, ack.Signature = signer.KeyID(), make([]byte, 64)
			return ack
		},
		"a genuine acknowledgement for another host": func() *agentv1.TaskResultAck {
			ack := settledAck()
			signer.SignResultAck("host-2", ack)
			return ack
		},
		"a genuine one with its status changed": func() *agentv1.TaskResultAck {
			ack := settledAck()
			signer.SignResultAck("host-1", ack)
			ack.Status = agentv1.TaskResultAck_STATUS_DUPLICATE
			return ack
		},
	} {
		d := deliveryWithOneAnswer(t, trustDir)
		d.acknowledge(forged())
		if d.spool.Len() != 1 {
			t.Errorf("%s freed the answer", name)
		}
	}

	d := deliveryWithOneAnswer(t, trustDir)
	ack := settledAck()
	signer.SignResultAck("host-1", ack)
	d.acknowledge(ack)
	if d.spool.Len() != 0 {
		t.Error("the panel's own acknowledgement did not free the answer")
	}
}

// Before the panel has handed the host a key there is nothing to check
// against; the host behaves as it did before the signature existed.
func TestAHostWithNoKeyOfThePanelTakesAcknowledgementsAsTheyCome(t *testing.T) {
	d := deliveryWithOneAnswer(t, t.TempDir())
	d.acknowledge(settledAck())
	if d.spool.Len() != 0 {
		t.Error("a host that holds no key kept an answer the panel took")
	}
}
