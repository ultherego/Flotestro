package agent

import (
	"context"
	"io"
	"log/slog"
	"testing"

	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
)

// TestPanikaZadaniaNieZabijaAgenta pilnuje bariery odpornosci. Blad w obsludze
// jednej operacji nie moze pozbawic hosta zarzadzania: control plane zobaczylby
// wtedy zerwana sesje zamiast informacji, co poszlo nie tak.
func TestPanikaZadaniaNieZabijaAgenta(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	task := &agentv1.TaskEnvelope{TaskId: "zadanie-1"}

	// Wykonawca z pustym dziennikiem panikuje przy pierwszym odwolaniu.
	pusty := &TaskExecutor{log: log}
	result := executeTask(context.Background(), pusty, task, log)
	if result == nil {
		t.Fatal("brak wyniku po panice")
	}
	if result.GetStatus() != agentv1.TaskResult_STATUS_FAILED {
		t.Errorf("status = %s, oczekiwano FAILED", result.GetStatus())
	}
	if result.GetErrorCode() != RejectInternalError {
		t.Errorf("kod bledu = %q", result.GetErrorCode())
	}
	if result.GetTaskId() != "zadanie-1" {
		t.Errorf("wynik nie wskazuje proby: %q", result.GetTaskId())
	}
}

// TestAgentBezWykonawcyOdrzucaZadanie sprawdza agenta, ktory z zalozenia nie
// wykonuje operacji. Odrzucenie jest odpowiedzia, a nie awaria.
func TestAgentBezWykonawcyOdrzucaZadanie(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	result := executeTask(context.Background(), nil,
		&agentv1.TaskEnvelope{TaskId: "zadanie-2"}, log)

	if result.GetStatus() != agentv1.TaskResult_STATUS_REJECTED {
		t.Errorf("status = %s, oczekiwano REJECTED", result.GetStatus())
	}
	if result.GetErrorCode() != RejectUnsupported {
		t.Errorf("kod bledu = %q, oczekiwano %q", result.GetErrorCode(), RejectUnsupported)
	}
}
