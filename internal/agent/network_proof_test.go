package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// withPanel answers the proof the way a channel would and gives the previous
// answer back when the test ends.
func withPanel(t *testing.T, answer func(context.Context, string) (panelAck, error)) {
	t.Helper()
	previous := askPanel
	askPanel = answer
	t.Cleanup(func() { askPanel = previous })
}

// A channel that refuses the call is a channel the host cannot be managed
// through; the proof fails and the rescue plan stays armed.
func TestProofFailsWhenThePanelRefusesTheCall(t *testing.T) {
	withPanel(t, func(context.Context, string) (panelAck, error) {
		return panelAck{}, errors.New("connection refused")
	})
	proof := proveManagementChannel(context.Background(), "https://panel.example.com:8443", time.Now())
	if proof.Proved || proof.Attempts != 1 {
		t.Fatalf("proof = %+v", proof)
	}
	if !strings.Contains(proof.Reason, "connection refused") {
		t.Fatalf("reason = %q", proof.Reason)
	}
	if !strings.Contains(proof.summary(), "was not proved") {
		t.Fatalf("summary = %q", proof.summary())
	}
}

// A channel that carries an acknowledged call is the only thing that disarms
// the rescue plan.
func TestProofSucceedsOnlyOnAnAcknowledgedCall(t *testing.T) {
	answered := 0
	withPanel(t, func(_ context.Context, gatewayURL string) (panelAck, error) {
		answered++
		if gatewayURL != "https://panel.example.com:8443" {
			t.Fatalf("the proof went to %q", gatewayURL)
		}
		return panelAck{GatewayID: "gw-1", ServerTime: time.Date(2026, 9, 18, 8, 0, 0, 0, time.UTC)}, nil
	})
	proof := proveManagementChannel(context.Background(), "https://panel.example.com:8443", time.Now())
	if !proof.Proved || proof.GatewayID != "gw-1" || proof.Attempts != 1 || proof.Reason != "" {
		t.Fatalf("proof = %+v", proof)
	}
	if answered != 1 {
		t.Fatalf("the panel was called %d times", answered)
	}
	summary := proof.summary()
	if !strings.Contains(summary, "was proved") || !strings.Contains(summary, "gw-1") ||
		!strings.Contains(summary, "mTLS") {
		t.Fatalf("summary = %q", summary)
	}
}

// The case the old check called a success: the connection opens and nothing
// answers on it.
func TestAChannelThatOpensButNeverAcknowledgesFailsTheProof(t *testing.T) {
	withPanel(t, func(context.Context, string) (panelAck, error) {
		return panelAck{}, nil
	})
	proof := proveManagementChannel(context.Background(), "https://panel.example.com:8443", time.Now())
	if proof.Proved {
		t.Fatal("a call nobody acknowledged was taken for a proof")
	}
	if !strings.Contains(proof.Reason, "without acknowledging") {
		t.Fatalf("reason = %q", proof.Reason)
	}
}

// Without the address of the panel there is nothing to prove the channel
// against, and "it probably works" is not an answer that may disarm a rescue.
func TestProofFailsWithoutAnAddressOfThePanel(t *testing.T) {
	withPanel(t, func(context.Context, string) (panelAck, error) {
		t.Fatal("the proof called the panel without knowing its address")
		return panelAck{}, nil
	})
	proof := proveManagementChannel(context.Background(), "  ", time.Now())
	if proof.Proved || proof.Attempts != 0 || proof.Reason == "" {
		t.Fatalf("proof = %+v", proof)
	}
}

// An answer that carries only the time of the panel is still an
// acknowledgement: a gateway that does not name itself has answered anyway.
func TestAnAnswerWithoutAGatewayNameIsStillAnAcknowledgement(t *testing.T) {
	withPanel(t, func(context.Context, string) (panelAck, error) {
		return panelAck{ServerTime: time.Date(2026, 9, 18, 8, 0, 0, 0, time.UTC)}, nil
	})
	proof := proveManagementChannel(context.Background(), "https://panel.example.com:8443", time.Now())
	if !proof.Proved || !strings.Contains(proof.summary(), "the panel acknowledged") {
		t.Fatalf("proof = %+v, summary = %q", proof, proof.summary())
	}
}

// A context that ended stops the proof instead of hanging on it, and the
// reason says the task ran out rather than the channel being fine.
func TestProofStopsWithTheTask(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	withPanel(t, func(callCtx context.Context, _ string) (panelAck, error) {
		return panelAck{}, callCtx.Err()
	})
	proof := proveManagementChannel(ctx, "https://panel.example.com:8443", time.Now().Add(time.Minute))
	if proof.Proved || !strings.Contains(proof.Reason, "the task ended") {
		t.Fatalf("proof = %+v", proof)
	}
}

// waitForPanel is the same proof for the modules that need only the answer.
func TestWaitForPanelAnswersWithTheProof(t *testing.T) {
	withPanel(t, func(context.Context, string) (panelAck, error) {
		return panelAck{GatewayID: "gw-1"}, nil
	})
	if !waitForPanel(context.Background(), "https://panel.example.com:8443", time.Now()) {
		t.Fatal("an acknowledged call did not count as reaching the panel")
	}
	withPanel(t, func(context.Context, string) (panelAck, error) { return panelAck{}, nil })
	if waitForPanel(context.Background(), "https://panel.example.com:8443", time.Now()) {
		t.Fatal("a call nobody acknowledged counted as reaching the panel")
	}
}
