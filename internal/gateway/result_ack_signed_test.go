package gateway

import (
	"path/filepath"
	"testing"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/helpercap"
)

// Every acknowledgement of a result carries the panel's signature, for the host
// it goes to: a relay carries it and can write one of its own.
func TestEveryAcknowledgementOfAResultIsSignedForItsHost(t *testing.T) {
	signer, _, err := helpercap.LoadOrGenerateSigner(filepath.Join(t.TempDir(), "helper-signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	ring := helpercap.NewKeyring(signer.PublicKey())
	service := &AgentService{helperSigner: signer}
	session := NewSession("s", "host-1", "0.64.2", "boot", "127.0.0.1", 4)
	result := &agentv1.TaskResult{TaskId: "attempt-1", IdempotencyKey: "job:attempt-1"}

	for _, status := range []agentv1.TaskResultAck_Status{
		agentv1.TaskResultAck_STATUS_SETTLED,
		agentv1.TaskResultAck_STATUS_DUPLICATE,
		agentv1.TaskResultAck_STATUS_REJECTED_STALE,
	} {
		service.ackResult("host-1", session, result, status, "job_already_settled")
		ack := (<-session.outbound).GetTaskResultAck()
		if ack.GetStatus() != status {
			t.Fatalf("the status %v went out as %v", status, ack.GetStatus())
		}
		if err := helpercap.VerifyResultAck(ring, "host-1", ack); err != nil {
			t.Errorf("the acknowledgement %v is not the panel's: %v", status, err)
		}
		if err := helpercap.VerifyResultAck(ring, "host-2", ack); err == nil {
			t.Errorf("the acknowledgement %v would pass for another host", status)
		}
	}
}

// The acknowledgement says which content it was made for: the host compares it with
// the answer it holds.
func TestTheAcknowledgementCarriesTheDigestOfTheResultItAnswers(t *testing.T) {
	signer, _, err := helpercap.LoadOrGenerateSigner(filepath.Join(t.TempDir(), "helper-signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	ring := helpercap.NewKeyring(signer.PublicKey())
	service := &AgentService{helperSigner: signer}
	session := NewSession("s", "host-1", "0.64.2", "boot", "127.0.0.1", 4)
	result := &agentv1.TaskResult{TaskId: "attempt-1", IdempotencyKey: "job:attempt-1", Stdout: []byte("output")}

	service.ackResult("host-1", session, result, agentv1.TaskResultAck_STATUS_SETTLED, "")
	ack := (<-session.outbound).GetTaskResultAck()
	if string(ack.GetResultDigest()) != string(helpercap.ResultDigest(result)) || len(ack.GetResultDigest()) == 0 {
		t.Fatalf("the acknowledgement names the digest %x, the result has %x",
			ack.GetResultDigest(), helpercap.ResultDigest(result))
	}
	if err := helpercap.VerifyResultAck(ring, "host-1", ack); err != nil {
		t.Fatalf("the acknowledgement with its digest is not the panel's: %v", err)
	}
}
