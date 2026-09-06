package gateway

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/opspec"
)

// rozstrzygnijAktualizacjeAgenta zamyka zadania wymiany agenta po jego
// powrocie.
//
// Agent, ktory wymienia sam siebie, nie ma jak odeslac wyniku: proces, ktory
// wykonywal zadanie, zostal zastapiony w polowie. Rozstrzyga wiec to, co
// panel widzi na wlasne oczy - wersja zgloszona przy nowym polaczeniu.
// Kod wyjscia menedzera pakietow moglby byc zerowy takze wtedy, gdy host
// nigdy nie wrocil.
func (s *AgentService) rozstrzygnijAktualizacjeAgenta(ctx context.Context,
	hostID, wersja string) {
	zadania, err := s.jobs.OtwarteZadaniaAkcji(ctx, hostID, string(opspec.ActionAgentUpgrade))
	if err != nil {
		s.log.Error("nie odczytano zadan wymiany agenta", "host_id", hostID, "err", err)
		return
	}
	for _, zadanie := range zadania {
		cel := wersjaDocelowa(zadanie.Payload)
		if cel == "" {
			continue
		}
		if cel != wersja {
			// Host wrocil, ale nie w tej wersji: transakcja przeszla i host
			// dziala, tylko nie tak, jak zlecono. To jest niepowodzenie
			// zadania, a nie awaria hosta.
			s.zamknijAktualizacje(ctx, hostID, zadanie, jobs.StateFailed, "agent_version_mismatch",
				fmt.Sprintf("host wrocil w wersji %s, oczekiwano %s", wersja, cel))
			continue
		}
		s.zamknijAktualizacje(ctx, hostID, zadanie, jobs.StateSucceeded, "",
			"agent wrocil w wersji "+wersja)
	}
}

// zamknijAktualizacje zapisuje wynik zadania wymiany agenta.
func (s *AgentService) zamknijAktualizacje(ctx context.Context, hostID string,
	zadanie jobs.OtwarteZadanie, stan jobs.State, kod, opis string) {
	status := "succeeded"
	if stan != jobs.StateSucceeded {
		status = "failed"
	}
	if _, err := s.jobs.RecordResult(ctx, zadanie.JobID, zadanie.AttemptID, jobs.Result{
		Status: status, ErrorCode: kod, Message: opis,
	}, stan); err != nil {
		s.log.Error("nie zapisano wyniku wymiany agenta",
			"host_id", hostID, "job_id", zadanie.JobID, "err", err)
		return
	}
	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorAgent, ActorID: hostID,
		Action: "agent.upgrade", TargetType: "job", TargetID: zadanie.JobID,
		Outcome: audit.OutcomeSuccess,
		Detail:  map[string]any{"state": string(stan), "message": opis},
	})
	s.log.Info("wymiana agenta rozstrzygnieta",
		"host_id", hostID, "job_id", zadanie.JobID, "stan", stan, "opis", opis)
}

// wersjaDocelowa czyta wersje z payloadu zadania.
func wersjaDocelowa(payload json.RawMessage) string {
	if len(payload) == 0 {
		return ""
	}
	var tresc opspec.Payload
	if err := json.Unmarshal(payload, &tresc); err != nil {
		return ""
	}
	if tresc.AgentUpgrade == nil {
		return ""
	}
	return tresc.AgentUpgrade.TargetVersion
}
