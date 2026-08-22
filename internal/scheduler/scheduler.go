// Package scheduler pobiera zatwierdzone zadania z kolejki i dostarcza je
// agentom. Nie podejmuje decyzji biznesowych poza limitami wykonania.
package scheduler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/gateway"
	agentv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/agent/v1"
	"github.com/ultherego/flotestro/internal/jobs"
	"github.com/ultherego/flotestro/internal/opspec"
)

// EnrollmentCredentials wystawia jednorazowe poswiadczenie dolaczenia hosta
// do domeny. Poswiadczenie powstaje w chwili wysylki i nie jest przechowywane
// w bazie razem z zadaniem.
type EnrollmentCredentials interface {
	EnsureHostWithOTP(ctx context.Context, fqdn string) (string, error)
}

// Options konfiguruje petle schedulera.
type Options struct {
	GatewayID string
	// Interval jest podstawowym odstepem miedzy przebiegami. Okresowy skan
	// gwarantuje postep nawet wtedy, gdy powiadomienie zaginie.
	Interval time.Duration
	// LeaseDuration musi byc dluzszy niz najdluzsza operacja, inaczej lease
	// wygasnie w trakcie poprawnego wykonania.
	LeaseDuration time.Duration
	// BatchSize ogranicza liczbe zadan pobieranych w jednym przebiegu.
	BatchSize int
	// SendTimeout ogranicza czekanie na przyjecie zadania przez sesje.
	SendTimeout time.Duration
}

// Scheduler laczy kolejke zadan z aktywnymi sesjami agentow.
type Scheduler struct {
	store       *jobs.Store
	registry    *gateway.Registry
	audit       *audit.Recorder
	credentials EnrollmentCredentials
	log         *slog.Logger
	options     Options
}

func New(store *jobs.Store, registry *gateway.Registry, recorder *audit.Recorder,
	credentials EnrollmentCredentials, log *slog.Logger, options Options) *Scheduler {
	if options.Interval <= 0 {
		options.Interval = 2 * time.Second
	}
	if options.LeaseDuration <= 0 {
		options.LeaseDuration = 5 * time.Minute
	}
	if options.BatchSize <= 0 {
		options.BatchSize = 32
	}
	if options.SendTimeout <= 0 {
		options.SendTimeout = 5 * time.Second
	}
	return &Scheduler{store: store, registry: registry, audit: recorder,
		credentials: credentials, log: log, options: options}
}

// Run utrzymuje petle dostarczania do zamkniecia kontekstu.
func (s *Scheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(s.options.Interval)
	defer ticker.Stop()

	housekeeping := time.NewTicker(30 * time.Second)
	defer housekeeping.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-housekeeping.C:
			s.housekeep(ctx)
		case <-ticker.C:
			s.dispatchOnce(ctx)
		}
	}
}

// housekeep zwraca do kolejki zadania po wygaslym lease i konczy zadania
// po TTL. Bez tego zadanie utracone razem z gatewayem zostaloby na zawsze.
func (s *Scheduler) housekeep(ctx context.Context) {
	if count, err := s.store.ReclaimExpiredLeases(ctx); err != nil {
		s.log.Error("nie odzyskano wygaslych lease", "err", err)
	} else if count > 0 {
		s.log.Warn("zadania wrocily do kolejki po wygasnieciu lease", "liczba", count)
	}
	if count, err := s.store.ExpireOverdue(ctx); err != nil {
		s.log.Error("nie oznaczono zadan po TTL", "err", err)
	} else if count > 0 {
		s.log.Info("zadania wygasly przed uruchomieniem", "liczba", count)
	}
}

func (s *Scheduler) dispatchOnce(ctx context.Context) {
	hosts := s.registry.ConnectedHosts()
	if len(hosts) == 0 {
		return
	}

	leased, err := s.store.Lease(ctx, s.options.GatewayID, hosts, s.options.BatchSize, s.options.LeaseDuration)
	if err != nil {
		s.log.Error("nie pobrano zadan z kolejki", "err", err)
		return
	}
	for _, item := range leased {
		s.deliver(ctx, item)
	}
}

func (s *Scheduler) deliver(ctx context.Context, item jobs.LeasedJob) {
	envelope, err := s.buildEnvelopeFor(ctx, item)
	if err != nil {
		s.log.Error("nie zbudowano koperty zadania", "job_id", item.Job.ID, "err", err)
		_ = s.store.ReleaseLease(ctx, item.Job.ID, item.AttemptID, "invalid_envelope")
		return
	}

	sessionID, err := s.registry.Dispatch(item.Job.HostID,
		&agentv1.ServerMessage{Payload: &agentv1.ServerMessage_Task{Task: envelope}},
		s.options.SendTimeout)
	if err != nil {
		// Host rozlaczyl sie miedzy pobraniem a wysylka. Zadanie wraca do
		// kolejki i zostanie dostarczone przy nastepnym polaczeniu.
		s.log.Info("nie dostarczono zadania, powrot do kolejki",
			"job_id", item.Job.ID, "host_id", item.Job.HostID, "powod", err)
		if releaseErr := s.store.ReleaseLease(ctx, item.Job.ID, item.AttemptID, err.Error()); releaseErr != nil {
			s.log.Error("nie zwrocono zadania do kolejki", "job_id", item.Job.ID, "err", releaseErr)
		}
		return
	}

	if err := s.store.MarkDispatched(ctx, item.Job.ID, item.AttemptID, sessionID); err != nil {
		s.log.Error("nie odnotowano dostarczenia", "job_id", item.Job.ID, "err", err)
		return
	}

	s.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: s.options.GatewayID,
		Action: "job.dispatch", TargetType: "job", TargetID: item.Job.ID,
		RequestID: item.Job.RequestID, Outcome: audit.OutcomeSuccess,
		Detail: map[string]any{
			"host_id": item.Job.HostID, "attempt": item.Attempt,
			"action_type": item.Job.ActionType, "session_id": sessionID,
		},
	})
	s.log.Info("zadanie dostarczone",
		"job_id", item.Job.ID, "host_id", item.Job.HostID,
		"action", item.Job.ActionType, "attempt", item.Attempt)
}

// buildEnvelopeFor buduje koperte i uzupelnia ja o poswiadczenia, ktore
// celowo nie sa przechowywane w bazie.
func (s *Scheduler) buildEnvelopeFor(ctx context.Context, item jobs.LeasedJob) (*agentv1.TaskEnvelope, error) {
	envelope, err := buildEnvelope(item)
	if err != nil {
		return nil, err
	}

	enroll, ok := envelope.GetAction().(*agentv1.TaskEnvelope_DomainEnroll)
	if !ok || enroll.DomainEnroll.GetPreflightOnly() {
		return envelope, nil
	}
	if s.credentials == nil {
		return nil, errUnknownAction("brak zrodla poswiadczen dolaczenia do domeny")
	}

	hostname := enroll.DomainEnroll.GetHostname()
	if hostname == "" {
		return nil, errUnknownAction("dolaczenie wymaga nazwy FQDN hosta")
	}
	// Haslo powstaje teraz i jest wazne do pierwszego uzycia; nie trafia
	// do bazy ani do audytu.
	password, err := s.credentials.EnsureHostWithOTP(ctx, hostname)
	if err != nil {
		return nil, err
	}
	enroll.DomainEnroll.OneTimePassword = password
	return envelope, nil
}

// buildEnvelope zamienia zadanie z bazy na koperte protokolu agenta.
// task_id wskazuje konkretna probe, a idempotency_key cala operacje - dzieki
// temu ponowne dostarczenie tej samej operacji zwraca poprzedni wynik.
func buildEnvelope(item jobs.LeasedJob) (*agentv1.TaskEnvelope, error) {
	var payload opspec.Payload
	if err := json.Unmarshal(item.Job.Payload, &payload); err != nil {
		return nil, err
	}
	var preconditions jobs.Preconditions
	if len(item.Job.Preconditions) > 0 {
		if err := json.Unmarshal(item.Job.Preconditions, &preconditions); err != nil {
			return nil, err
		}
	}
	hash, err := opspec.PayloadHash(opspec.ActionType(item.Job.ActionType),
		item.Job.ActionVersion, payload)
	if err != nil {
		return nil, err
	}

	envelope := &agentv1.TaskEnvelope{
		TaskId:         item.AttemptID,
		IdempotencyKey: item.Job.IdempotencyKey,
		CreatedAt:      timestamppb.New(item.Job.CreatedAt),
		ExpiresAt:      timestamppb.New(item.Job.ExpiresAt),
		PayloadHash:    hash,
		Preconditions: &agentv1.Preconditions{
			OsFamily:             preconditions.OSFamily,
			RequiredCapabilities: preconditions.RequiredCapabilities,
			ExpectedBootId:       preconditions.ExpectedBootID,
		},
		Limits: &agentv1.Limits{
			TimeoutSeconds: uint32(item.Job.TimeoutSeconds),
			MaxOutputBytes: uint32(item.Job.MaxOutputBytes),
		},
		ActorContext: &agentv1.ActorContext{
			ActorId:   item.Job.CreatedBy,
			RequestId: item.Job.RequestID,
			Approvals: approvalsOf(item.Job),
		},
	}
	if item.Job.CampaignID != nil {
		envelope.CampaignId = *item.Job.CampaignID
	}

	action := opspec.ActionType(item.Job.ActionType)
	switch action {
	case opspec.ActionPackagePlan:
		envelope.Action = &agentv1.TaskEnvelope_PackagePlan{
			PackagePlan: &agentv1.PackagePlan{
				RefreshMetadata: payload.PackagePlan.RefreshMetadata,
				OnlyPackages:    payload.PackagePlan.OnlyPackages,
				SecurityOnly:    payload.PackagePlan.SecurityOnly,
			},
		}

	case opspec.ActionPackageUpgrade:
		request := &agentv1.PackageUpgrade{
			Packages:     payload.PackageUpgrade.Packages,
			SecurityOnly: payload.PackageUpgrade.SecurityOnly,
		}
		if payload.PackageUpgrade.PlanHash != "" {
			hash, err := hex.DecodeString(payload.PackageUpgrade.PlanHash)
			if err != nil {
				return nil, fmt.Errorf("nieprawidlowy hash planu: %w", err)
			}
			request.PlanHash = hash
		}
		envelope.Action = &agentv1.TaskEnvelope_PackageUpgrade{PackageUpgrade: request}

	case opspec.ActionDomainEnroll, opspec.ActionDomainPreflight:
		envelope.Action = &agentv1.TaskEnvelope_DomainEnroll{
			DomainEnroll: &agentv1.DomainEnroll{
				Domain:        payload.DomainEnroll.Domain,
				Realm:         payload.DomainEnroll.Realm,
				Server:        payload.DomainEnroll.Server,
				Hostname:      payload.DomainEnroll.Hostname,
				PreflightOnly: action == opspec.ActionDomainPreflight,
			},
		}

	case opspec.ActionUnitStatus:
		envelope.Action = &agentv1.TaskEnvelope_ReadUnitStatus{
			ReadUnitStatus: &agentv1.ReadUnitStatus{Units: payload.UnitStatus.Units},
		}

	case opspec.ActionSystemReboot:
		envelope.Action = &agentv1.TaskEnvelope_SystemReboot{
			SystemReboot: &agentv1.SystemReboot{
				DelaySeconds: payload.Reboot.DelaySeconds,
				Reason:       payload.Reboot.Reason,
			},
		}

	case opspec.ActionReadJournal:
		request := &agentv1.ReadJournal{
			Unit:  payload.Journal.Unit,
			Lines: payload.Journal.Lines,
			Since: payload.Journal.Since,
		}
		if payload.Journal.MaxPriority != nil {
			request.MaxPriority = payload.Journal.MaxPriority
		}
		envelope.Action = &agentv1.TaskEnvelope_ReadJournal{ReadJournal: request}
	default:
		operation, ok := unitOperations[action]
		if !ok {
			return nil, errUnknownAction(item.Job.ActionType)
		}
		envelope.Action = &agentv1.TaskEnvelope_UnitAction{
			UnitAction: &agentv1.UnitAction{Unit: payload.Unit.Unit, Operation: operation},
		}
	}
	return envelope, nil
}

var unitOperations = map[opspec.ActionType]agentv1.UnitAction_Operation{
	opspec.ActionUnitStart:   agentv1.UnitAction_OPERATION_START,
	opspec.ActionUnitStop:    agentv1.UnitAction_OPERATION_STOP,
	opspec.ActionUnitRestart: agentv1.UnitAction_OPERATION_RESTART,
	opspec.ActionUnitReload:  agentv1.UnitAction_OPERATION_RELOAD,
}

func approvalsOf(job jobs.Job) []string {
	if job.ApprovedBy == "" {
		return nil
	}
	return []string{job.ApprovedBy}
}

type unknownActionError string

func (e unknownActionError) Error() string { return "nieznany typ operacji: " + string(e) }

func errUnknownAction(action string) error { return unknownActionError(action) }

// Jitter rozklada start pierwszej petli, zeby restart wielu replik nie
// wywolal jednoczesnego uderzenia w baze.
func Jitter(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(base)))
}
