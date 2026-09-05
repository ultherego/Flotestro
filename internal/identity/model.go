// Package identity realizuje zmiany w katalogu tozsamosci: plan, zatwierdzenie
// i wykonanie zlozone z faz. Utworzenie uzytkownika jest jedna transakcja
// biznesowa panelu, ale kilkoma operacjami katalogu.
package identity

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ultherego/flotestro/internal/freeipa"
)

// ActionType jest typem zmiany w katalogu.
type ActionType string

const (
	ActionUserCreate   ActionType = "identity.user.create"
	ActionUserDisable  ActionType = "identity.user.disable"
	ActionUserEnable   ActionType = "identity.user.enable"
	ActionGroupMembers ActionType = "identity.group.members"
	ActionSSHKeys      ActionType = "identity.sshkeys.set"
	// DNS katalogowy jest zmiana centralna, tak samo jak konto: dotyczy
	// calej sieci, a nie jednego hosta, i idzie jedna transakcja przez
	// connector katalogu - a nie przez agenta.
	ActionDNSRecordEnsure ActionType = "dns.record.ensure"
	ActionDNSRecordRemove ActionType = "dns.record.remove"
)

// State jest stanem zmiany.
type State string

const (
	StatePlanned          State = "planned"
	StateAwaitingApproval State = "awaiting_approval"
	StateRunning          State = "running"
	StateSucceeded        State = "succeeded"
	// StatePartiallyApplied oznacza zmiane, ktorej czesc faz sie powiodla.
	// Dokument zabrania przedstawiania takiego wyniku jako powodzenia.
	StatePartiallyApplied State = "partially_applied"
	StateFailed           State = "failed"
	StateCanceled         State = "canceled"
)

// Terminal mowi, czy stan jest koncowy.
func (s State) Terminal() bool {
	switch s {
	case StateSucceeded, StatePartiallyApplied, StateFailed, StateCanceled:
		return true
	default:
		return false
	}
}

// Payload jest suma typow zmian. Dokladnie jedno pole jest wypelnione.
type Payload struct {
	User      *UserPayload      `json:"user,omitempty"`
	Group     *GroupPayload     `json:"group,omitempty"`
	SSHKeys   *SSHKeysPayload   `json:"ssh_keys,omitempty"`
	Reference *ReferencePayload `json:"reference,omitempty"`
	DNS       *DNSRecordPayload `json:"dns,omitempty"`
}

// DNSRecordPayload opisuje rekord w strefie katalogu.
type DNSRecordPayload struct {
	Zone string `json:"zone"`
	Name string `json:"name"`
	Type string `json:"type"`
	// Value jest trescia rekordu: adres, nazwa albo tekst - zaleznie od typu.
	Value string `json:"value"`
	TTL   int    `json:"ttl,omitempty"`
	// Reverse jest zgoda na dopisanie rekordu odwrotnego. Rekord PTR jest
	// osobnym, widocznym elementem planu: to on decyduje, co odpowie
	// zapytanie o adres, a zapomnienie o nim jest najczestszym bledem przy
	// dopisywaniu hostow.
	Reverse bool `json:"reverse,omitempty"`
	// ReverseZone pozwala wskazac strefe odwrotna wprost. Puste oznacza
	// strefe wyliczona z adresu - a ta zaklada podzial na /24.
	ReverseZone string `json:"reverse_zone,omitempty"`
}

// UserPayload opisuje konto do utworzenia.
type UserPayload struct {
	UID       string   `json:"uid"`
	FirstName string   `json:"first_name,omitempty"`
	LastName  string   `json:"last_name"`
	Email     string   `json:"email,omitempty"`
	Shell     string   `json:"shell,omitempty"`
	Groups    []string `json:"groups,omitempty"`
	SSHKeys   []string `json:"ssh_keys,omitempty"`
}

// GroupPayload opisuje zmiane czlonkostwa.
type GroupPayload struct {
	Group  string   `json:"group"`
	Add    []string `json:"add,omitempty"`
	Remove []string `json:"remove,omitempty"`
}

// SSHKeysPayload ustawia komplet kluczy publicznych konta.
type SSHKeysPayload struct {
	UID  string   `json:"uid"`
	Keys []string `json:"keys"`
}

// ReferencePayload wskazuje istniejacy obiekt katalogu.
type ReferencePayload struct {
	UID    string `json:"uid"`
	Reason string `json:"reason,omitempty"`
}

// Validate sprawdza spojnosc typu zmiany z payloadem.
func Validate(action ActionType, payload Payload) error {
	switch action {
	case ActionUserCreate:
		if payload.User == nil {
			return fmt.Errorf("operacja %s wymaga payloadu user", action)
		}
		if payload.User.UID == "" || payload.User.LastName == "" {
			return fmt.Errorf("konto wymaga nazwy i nazwiska")
		}
	case ActionUserDisable, ActionUserEnable:
		if payload.Reference == nil || payload.Reference.UID == "" {
			return fmt.Errorf("operacja %s wymaga wskazania konta", action)
		}
	case ActionGroupMembers:
		if payload.Group == nil || payload.Group.Group == "" {
			return fmt.Errorf("operacja %s wymaga wskazania grupy", action)
		}
		if len(payload.Group.Add) == 0 && len(payload.Group.Remove) == 0 {
			return fmt.Errorf("zmiana czlonkostwa jest pusta")
		}
	case ActionSSHKeys:
		if payload.SSHKeys == nil || payload.SSHKeys.UID == "" {
			return fmt.Errorf("operacja %s wymaga wskazania konta", action)
		}
	case ActionDNSRecordEnsure, ActionDNSRecordRemove:
		if payload.DNS == nil {
			return fmt.Errorf("operacja %s wymaga payloadu dns", action)
		}
		// Sprawdzamy tym samym kodem, ktory zaraz wykona zapis: rekord
		// odrzucony przez katalog ma odpasc przy zlecaniu, a nie po
		// zatwierdzeniu.
		if err := (freeipa.RecordSpec{
			Zone: payload.DNS.Zone, Name: payload.DNS.Name, Type: payload.DNS.Type,
			Value: payload.DNS.Value, TTL: payload.DNS.TTL,
		}).Validate(); err != nil {
			return err
		}
		if payload.DNS.Reverse {
			if payload.DNS.Type != freeipa.RekordA && payload.DNS.Type != freeipa.RekordAAAA {
				return fmt.Errorf("rekord odwrotny ma sens wylacznie dla adresu")
			}
			if payload.DNS.ReverseZone == "" {
				if _, _, err := freeipa.StrefaOdwrotna(payload.DNS.Value); err != nil {
					return err
				}
			} else if _, err := freeipa.NazwaWStrefie(payload.DNS.Value, payload.DNS.ReverseZone); err != nil {
				// Strefa, ktora nie obejmuje tego adresu, dalaby rekord PTR
				// dla zupelnie innego hosta.
				return err
			}
		}
	default:
		return fmt.Errorf("nieznany typ zmiany %q", action)
	}
	return nil
}

// Permission zwraca uprawnienie wymagane do zlecenia zmiany.
func (a ActionType) Permission() string {
	switch a {
	case ActionUserCreate, ActionUserDisable, ActionUserEnable, ActionSSHKeys:
		return "identity.user.write"
	case ActionGroupMembers:
		return "identity.group.write"
	case ActionDNSRecordEnsure, ActionDNSRecordRemove:
		return "dns.directory.write"
	default:
		return "identity.policy.write"
	}
}

// Known sprawdza, czy typ zmiany jest obslugiwany.
func (a ActionType) Known() bool {
	switch a {
	case ActionUserCreate, ActionUserDisable, ActionUserEnable, ActionGroupMembers, ActionSSHKeys,
		ActionDNSRecordEnsure, ActionDNSRecordRemove:
		return true
	default:
		return false
	}
}

// PayloadHash liczy hash planu w postaci kanonicznej.
func PayloadHash(action ActionType, payload Payload) ([]byte, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(fmt.Appendf(nil, "%s\n%s", action, encoded))
	return sum[:], nil
}

// Plan opisuje wplyw zmiany, zanim cokolwiek sie wydarzy.
type Plan struct {
	Summary string `json:"summary"`
	// Steps to fazy, ktore zostana wykonane.
	Steps []string `json:"steps"`
	// AffectedUsers to konta dotkniete zmiana.
	AffectedUsers []string `json:"affected_users,omitempty"`
	// CurrentGroups i ResultingGroups pokazuja czlonkostwo przed i po.
	CurrentGroups   []string `json:"current_groups,omitempty"`
	ResultingGroups []string `json:"resulting_groups,omitempty"`
	// ReachableHosts i SudoRules pokazuja dostep wynikajacy z czlonkostwa.
	ReachableHosts []string `json:"reachable_hosts,omitempty"`
	SudoRules      []string `json:"sudo_rules,omitempty"`
	// Warnings opisuja skutki, ktore latwo przeoczyc.
	Warnings []string `json:"warnings,omitempty"`
	// Conflicts zatrzymuja wykonanie: katalog juz zawiera obiekt o tej nazwie.
	Conflicts []string `json:"conflicts,omitempty"`
}

// Blocked mowi, czy plan wyklucza wykonanie.
func (p Plan) Blocked() bool { return len(p.Conflicts) > 0 }

// Phase jest wynikiem jednej fazy wykonania.
type Phase struct {
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	Message    string    `json:"message,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

// Change jest widokiem zmiany zwracanym przez API.
type Change struct {
	ID               string          `json:"id"`
	ActionType       string          `json:"action_type"`
	Payload          json.RawMessage `json:"payload"`
	PayloadHash      string          `json:"payload_hash"`
	Plan             json.RawMessage `json:"plan"`
	State            State           `json:"state"`
	RequiresApproval bool            `json:"requires_approval"`
	ApprovedBy       string          `json:"approved_by,omitempty"`
	ApprovedAt       *time.Time      `json:"approved_at,omitempty"`
	CanceledBy       string          `json:"canceled_by,omitempty"`
	Phases           json.RawMessage `json:"phases"`
	ResultMessage    string          `json:"result_message,omitempty"`
	CreatedBy        string          `json:"created_by"`
	RequestID        string          `json:"request_id,omitempty"`
	StartedAt        *time.Time      `json:"started_at,omitempty"`
	FinishedAt       *time.Time      `json:"finished_at,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
}

// StateFor okresla stan koncowy na podstawie wynikow faz.
// Czesciowe powodzenie ma wlasny stan: przedstawienie go jako sukcesu
// ukrywaloby fakt, ze czesc zmian zostala zastosowana, a czesc nie.
func StateFor(phases []Phase) State {
	var succeeded, failed int
	for _, phase := range phases {
		switch phase.Status {
		case "succeeded":
			succeeded++
		case "failed":
			failed++
		}
	}
	switch {
	case failed == 0 && succeeded > 0:
		return StateSucceeded
	case failed > 0 && succeeded > 0:
		return StatePartiallyApplied
	default:
		return StateFailed
	}
}
