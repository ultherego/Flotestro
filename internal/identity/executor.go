package identity

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/audit"
	"github.com/ultherego/flotestro/internal/authz"
	"github.com/ultherego/flotestro/internal/freeipa"
)

// SessionRevoker uniewaznia sesje panelu nalezace do tozsamosci.
type SessionRevoker interface {
	RevokeSessionsOf(ctx context.Context, principalID, reason string) (int64, error)
	ListPrincipals(ctx context.Context) ([]authz.Principal, error)
}

// Executor wykonuje zatwierdzone zmiany katalogu, faza po fazie.
type Executor struct {
	store     *Store
	directory *freeipa.Client
	sessions  SessionRevoker
	audit     *audit.Recorder
	log       *slog.Logger
	interval  time.Duration
}

func NewExecutor(store *Store, directory *freeipa.Client, sessions SessionRevoker,
	recorder *audit.Recorder, log *slog.Logger, interval time.Duration) *Executor {
	if interval <= 0 {
		interval = 3 * time.Second
	}
	return &Executor{store: store, directory: directory, sessions: sessions,
		audit: recorder, log: log, interval: interval}
}

// Run wykonuje zatwierdzone zmiany do zamkniecia kontekstu.
func (e *Executor) Run(ctx context.Context) {
	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.tick(ctx)
		}
	}
}

func (e *Executor) tick(ctx context.Context) {
	pending, err := e.store.Pending(ctx)
	if err != nil {
		e.log.Error("nie pobrano zmian katalogu", "err", err)
		return
	}
	for _, change := range pending {
		claimed, err := e.store.Claim(ctx, change.ID)
		if err != nil {
			e.log.Error("nie przejeto zmiany katalogu", "change_id", change.ID, "err", err)
			continue
		}
		if !claimed {
			continue
		}
		e.execute(ctx, change)
	}
}

// execute realizuje zmiane faza po fazie. Kazda faza ma wlasny wynik, bo
// czesciowy sukces nie moze byc przedstawiony jako powodzenie.
func (e *Executor) execute(ctx context.Context, change Change) {
	var payload Payload
	if err := json.Unmarshal(change.Payload, &payload); err != nil {
		e.finish(ctx, change, StateFailed, nil, "nieczytelny payload: "+err.Error())
		return
	}

	action := ActionType(change.ActionType)
	var phases []Phase

	switch action {
	case ActionUserCreate:
		phases = e.createUser(ctx, payload.User)
	case ActionUserDisable:
		phases = e.setUserAccess(ctx, payload.Reference, false)
	case ActionUserEnable:
		phases = e.setUserAccess(ctx, payload.Reference, true)
	case ActionGroupMembers:
		phases = e.changeGroupMembers(ctx, payload.Group)
	case ActionSSHKeys:
		phases = e.setSSHKeys(ctx, payload.SSHKeys)
	case ActionDNSRecordEnsure:
		phases = e.zapiszRekord(ctx, payload.DNS, true)
	case ActionDNSRecordRemove:
		phases = e.zapiszRekord(ctx, payload.DNS, false)
	default:
		e.finish(ctx, change, StateFailed, nil, "nieznany typ zmiany")
		return
	}

	state := StateFor(phases)
	message := ""
	if state == StatePartiallyApplied {
		// Ten stan istnieje po to, zeby nie ukryc faktu, ze czesc zmian
		// zostala zastosowana, a czesc nie.
		message = "czesc faz sie nie powiodla; katalog jest w stanie posrednim"
	}
	e.finish(ctx, change, state, phases, message)
}

// createUser tworzy konto, dodaje do grup i ustawia klucze. Kazdy krok jest
// osobna faza, bo katalog wykonuje je osobno i moga sie rozejsc.
func (e *Executor) createUser(ctx context.Context, spec *UserPayload) []Phase {
	var phases []Phase

	phase := startPhase("utworzenie konta")
	user, err := e.directory.CreateUser(ctx, freeipa.UserSpec{
		UID:       spec.UID,
		FirstName: spec.FirstName,
		LastName:  spec.LastName,
		Email:     spec.Email,
		Shell:     spec.Shell,
		SSHKeys:   spec.SSHKeys,
	})
	phases = append(phases, finishPhase(phase, err, describeUser(user)))
	if err != nil {
		// Bez konta kolejne fazy nie maja sensu.
		return phases
	}

	for _, group := range spec.Groups {
		phase := startPhase("dodanie do grupy " + group)
		err := e.directory.AddGroupMembers(ctx, group, []string{spec.UID})
		phases = append(phases, finishPhase(phase, err, ""))
	}
	return phases
}

// setUserAccess blokuje albo odblokowuje konto.
//
// Przy blokadzie kolejnosc jest istotna: najpierw lokalny znacznik odmowy
// i uniewaznienie sesji panelu, dopiero potem katalog. Odwrotna kolejnosc
// zostawialaby dzialajaca sesje na czas propagacji zmiany.
func (e *Executor) setUserAccess(ctx context.Context, ref *ReferencePayload, enable bool) []Phase {
	var phases []Phase

	if !enable {
		phase := startPhase("lokalny znacznik odmowy")
		count, err := e.store.SetLocalDeny(ctx, ref.UID, ref.Reason, true)
		phases = append(phases, finishPhase(phase, err,
			describeCount("oznaczono tozsamosci", count)))

		phase = startPhase("uniewaznienie sesji panelu")
		revoked, err := e.revokeSessions(ctx, ref.UID, ref.Reason)
		phases = append(phases, finishPhase(phase, err,
			describeCount("uniewazniono sesji", revoked)))
	}

	phase := startPhase("zmiana stanu konta w katalogu")
	err := e.directory.SetUserEnabled(ctx, ref.UID, enable)
	phases = append(phases, finishPhase(phase, err, ""))

	if enable && err == nil {
		phase := startPhase("zdjecie lokalnego znacznika odmowy")
		count, denyErr := e.store.SetLocalDeny(ctx, ref.UID, "", false)
		phases = append(phases, finishPhase(phase, denyErr,
			describeCount("odblokowano tozsamosci", count)))
	}
	return phases
}

// revokeSessions konczy sesje panelu nalezace do konta.
func (e *Executor) revokeSessions(ctx context.Context, subject, reason string) (int64, error) {
	principals, err := e.sessions.ListPrincipals(ctx)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, principal := range principals {
		if principal.Subject != subject {
			continue
		}
		revoked, err := e.sessions.RevokeSessionsOf(ctx, principal.ID,
			firstNonEmpty(reason, "konto zablokowane"))
		if err != nil {
			return total, err
		}
		total += revoked
	}
	return total, nil
}

func (e *Executor) changeGroupMembers(ctx context.Context, spec *GroupPayload) []Phase {
	var phases []Phase
	if len(spec.Add) > 0 {
		phase := startPhase("dodanie czlonkow do grupy " + spec.Group)
		err := e.directory.AddGroupMembers(ctx, spec.Group, spec.Add)
		phases = append(phases, finishPhase(phase, err, ""))
	}
	if len(spec.Remove) > 0 {
		phase := startPhase("usuniecie czlonkow z grupy " + spec.Group)
		err := e.directory.RemoveGroupMembers(ctx, spec.Group, spec.Remove)
		phases = append(phases, finishPhase(phase, err, ""))
	}
	return phases
}

func (e *Executor) setSSHKeys(ctx context.Context, spec *SSHKeysPayload) []Phase {
	phase := startPhase("ustawienie kluczy SSH konta " + spec.UID)
	err := e.directory.SetUserSSHKeys(ctx, spec.UID, spec.Keys)
	return []Phase{finishPhase(phase, err, "")}
}

// finish zapisuje wynik i odnotowuje go w audycie.
func (e *Executor) finish(ctx context.Context, change Change, state State,
	phases []Phase, message string) {
	if err := e.store.Finish(ctx, change.ID, state, phases, message); err != nil {
		e.log.Error("nie zapisano wyniku zmiany katalogu", "change_id", change.ID, "err", err)
	}

	outcome := audit.OutcomeSuccess
	if state != StateSucceeded {
		outcome = audit.OutcomeFailure
	}
	failedPhases := make([]string, 0)
	for _, phase := range phases {
		if phase.Status == "failed" {
			failedPhases = append(failedPhases, phase.Name+": "+phase.Message)
		}
	}
	e.audit.Record(ctx, audit.Event{
		ActorType: audit.ActorSystem, ActorID: "identity-executor",
		Action: "directory_change.execute", TargetType: "directory_change", TargetID: change.ID,
		RequestID: change.RequestID, Outcome: outcome,
		Detail: map[string]any{
			"action_type": change.ActionType, "state": string(state),
			"created_by": change.CreatedBy, "approved_by": change.ApprovedBy,
			"failed_phases": failedPhases, "message": message,
		},
	})

	logger := e.log.Info
	if state != StateSucceeded {
		logger = e.log.Warn
	}
	logger("zmiana katalogu zakonczona",
		"change_id", change.ID, "typ", change.ActionType, "stan", state,
		"faz", len(phases), "nieudanych", len(failedPhases))
}

func startPhase(name string) Phase {
	return Phase{Name: name, StartedAt: time.Now().UTC()}
}

func finishPhase(phase Phase, err error, message string) Phase {
	phase.FinishedAt = time.Now().UTC()
	if err != nil {
		phase.Status = "failed"
		phase.Message = err.Error()
		return phase
	}
	phase.Status = "succeeded"
	phase.Message = message
	return phase
}

func describeUser(user *freeipa.User) string {
	if user == nil {
		return ""
	}
	return "UID " + user.UIDNumber + ", GID " + user.GIDNumber
}

func describeCount(label string, count int64) string {
	if count == 0 {
		return label + ": 0"
	}
	return label + ": " + itoa(count)
}

func itoa(value int64) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// zapiszRekord dopisuje albo usuwa rekord i - gdy trzeba - jego odpowiednik
// odwrotny. Kazdy jest osobna faza, bo katalog wykonuje je osobno i moga sie
// rozejsc: rekord w przod bez rekordu wstecz jest czestym, cichym bledem.
func (e *Executor) zapiszRekord(ctx context.Context, spec *DNSRecordPayload, dopisanie bool) []Phase {
	var phases []Phase
	if spec == nil {
		return phases
	}
	opis := spec.Type + " " + spec.Name + "." + strings.TrimSuffix(spec.Zone, ".")

	glowny := freeipa.RecordSpec{
		Zone: strings.TrimSuffix(spec.Zone, "."), Name: spec.Name,
		Type: spec.Type, Value: spec.Value, TTL: spec.TTL,
	}
	phase := startPhase("rekord " + opis)
	var err error
	if dopisanie {
		_, err = e.directory.EnsureRecord(ctx, glowny)
	} else {
		err = e.directory.RemoveRecord(ctx, glowny)
	}
	phases = append(phases, finishPhase(phase, err, spec.Value))
	if err != nil || !spec.Reverse {
		return phases
	}

	// Strefa wskazana wprost nie moze zostawic nazwy policzonej dla /24:
	// wtedy PTR powstalby dla innego adresu niz ten w zleceniu.
	strefa, nazwa, err := freeipa.StrefaOdwrotna(spec.Value)
	if spec.ReverseZone != "" {
		strefa = strings.TrimSuffix(spec.ReverseZone, ".")
		nazwa, err = freeipa.NazwaWStrefie(spec.Value, strefa)
	}
	phase = startPhase("rekord odwrotny PTR " + nazwa + "." + strefa)
	if err == nil {
		// Cel PTR jest pelna nazwa rekordu w przod - takze wtedy, gdy
		// rekord stoi w korzeniu strefy i zapisuje sie jako "@".
		cel := freeipa.PelnaNazwa(spec.Zone, spec.Name) + "."
		odwrotny := freeipa.RecordSpec{
			Zone: strefa, Name: nazwa, Type: freeipa.RekordPTR, Value: cel, TTL: spec.TTL,
		}
		if dopisanie {
			_, err = e.directory.EnsureRecord(ctx, odwrotny)
		} else {
			err = e.directory.RemoveRecord(ctx, odwrotny)
		}
	}
	phases = append(phases, finishPhase(phase, err, ""))
	return phases
}
