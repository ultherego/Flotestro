// Package remediation prowadzi plan naprawy przez kolejne kroki.
//
// Naprawa nie jest jedna operacja. Kroki ida po kolei, kazdy jest zwyklym
// zadaniem modulu, ktory za dana rzecz odpowiada, i kazdy moze sie nie udac.
// Plan jest tu po to, zeby bylo wiadomo, co juz poszlo, co czeka i dlaczego
// reszta nie ruszyla - bez tego zostaje garsc niepowiazanych zadan.
package remediation

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/ultherego/flotestro/internal/compliance"
	"github.com/ultherego/flotestro/internal/opspec"
)

// Stany planu.
const (
	StanWToku      = "running"
	StanUdany      = "succeeded"
	StanNieudany   = "failed"
	StanZatrzymany = "stopped"
)

// Stany kroku.
const (
	KrokOczekuje  = "pending"
	KrokWToku     = "running"
	KrokUdany     = "succeeded"
	KrokNieudany  = "failed"
	KrokPominiety = "skipped"
)

// OknoPowrotu ogranicza czekanie na host po kroku wymagajacym restartu.
//
// Restart konczy plan, ale plan konczy sie dopiero wtedy, gdy host wroci:
// wyslane polecenie nie jest jeszcze dzialajacym hostem.
const OknoPowrotu = 15 * time.Minute

// Krok to jeden etap planu.
type Krok struct {
	ID           string          `json:"id"`
	Position     int             `json:"position"`
	CheckID      string          `json:"check_id"`
	CheckVersion int             `json:"check_version"`
	ActionType   string          `json:"action_type"`
	Payload      json.RawMessage `json:"payload"`
	// LockClass nazywa zasob hosta, ktorego krok uzywa na wylacznosc.
	LockClass      string     `json:"lock_class,omitempty"`
	RequiresReboot bool       `json:"requires_reboot"`
	JobID          string     `json:"job_id,omitempty"`
	State          string     `json:"state"`
	Reason         string     `json:"reason,omitempty"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
}

// Plan to komplet krokow zatwierdzony przez operatora.
type Plan struct {
	ID              string     `json:"id"`
	HostID          string     `json:"host_id"`
	PlanHash        string     `json:"plan_hash"`
	PlanHashVersion int        `json:"plan_hash_version"`
	Reason          string     `json:"reason"`
	CreatedBy       string     `json:"created_by"`
	StopOnFailure   bool       `json:"stop_on_failure"`
	State           string     `json:"state"`
	CreatedAt       time.Time  `json:"created_at"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
	Steps           []Krok     `json:"steps,omitempty"`
	// BootIDBefore pozwala rozpoznac, czy host naprawde wstal na nowo.
	BootIDBefore string `json:"boot_id_before,omitempty"`
}

// Ulozony to plan krokow gotowy do zapisania.
type Ulozony struct {
	Kroki []Krok
	// Pominiete wylicza ustalenia, ktore nie weszly do planu, wraz z powodem.
	Pominiete map[string]string
}

// Ulozenie ustala kolejnosc krokow i pilnuje granicy restartu.
//
// Kolejnosc nie jest dowolna. Najpierw zmiany konfiguracji, potem to, co
// wymaga restartu - i restart jest ostatni, bo po nim stan hosta trzeba ocenic
// na nowo, a kroki zaplanowane wczesniej odnosilyby sie do faktow sprzed
// restartu. Plan z dwoma restartami nie powstaje: to sa dwa plany.
func Ulozenie(ustalenia []compliance.Ustalenie) (Ulozony, error) {
	wynik := Ulozony{Pominiete: map[string]string{}}
	var zwykle, restarty []Krok

	for _, ustalenie := range ustalenia {
		if !ustalenie.Wymaga() {
			wynik.Pominiete[ustalenie.CheckID] = "ustalenie nie wymaga dzialania"
			continue
		}
		if ustalenie.Remediation == nil || ustalenie.Remediation.Action == "" {
			powod := "to ustalenie nie ma operacji naprawczej"
			if ustalenie.Remediation != nil && ustalenie.Remediation.Note != "" {
				powod = ustalenie.Remediation.Note
			}
			wynik.Pominiete[ustalenie.CheckID] = powod
			continue
		}
		akcja := opspec.ActionType(ustalenie.Remediation.Action)
		if !akcja.Known() {
			return Ulozony{}, fmt.Errorf("ustalenie %s wskazuje nieznana operacje %s",
				ustalenie.CheckID, akcja)
		}
		krok := Krok{
			CheckID:        ustalenie.CheckID,
			CheckVersion:   ustalenie.CheckVersion,
			ActionType:     string(akcja),
			Payload:        ustalenie.Remediation.Payload,
			LockClass:      akcja.LockClass(),
			RequiresReboot: ustalenie.Remediation.RequiresReboot,
			State:          KrokOczekuje,
		}
		if krok.RequiresReboot {
			restarty = append(restarty, krok)
			continue
		}
		zwykle = append(zwykle, krok)
	}

	if len(restarty) > 1 {
		return Ulozony{}, fmt.Errorf("plan mialby %d restartow; restart konczy plan, wiec to sa osobne plany",
			len(restarty))
	}
	// Kolejnosc w obrebie zwyklych krokow jest stala, zeby dwa te same plany
	// wygladaly tak samo: najpierw klasa blokady, potem nazwa sprawdzenia.
	sort.SliceStable(zwykle, func(i, j int) bool {
		if zwykle[i].LockClass != zwykle[j].LockClass {
			return zwykle[i].LockClass < zwykle[j].LockClass
		}
		return zwykle[i].CheckID < zwykle[j].CheckID
	})

	kroki := append(zwykle, restarty...)
	for i := range kroki {
		kroki[i].Position = i + 1
	}
	wynik.Kroki = kroki
	if len(kroki) == 0 {
		return wynik, fmt.Errorf("zadne ze wskazanych ustalen nie ma operacji naprawczej")
	}
	return wynik, nil
}

// Biezacy zwraca pierwszy krok, ktory nie jest zamkniety.
func (p Plan) Biezacy() *Krok {
	for i := range p.Steps {
		switch p.Steps[i].State {
		case KrokOczekuje, KrokWToku:
			return &p.Steps[i]
		}
	}
	return nil
}

// Postep streszcza wykonanie planu.
func (p Plan) Postep() map[string]int {
	liczby := map[string]int{}
	for _, krok := range p.Steps {
		liczby[krok.State]++
	}
	return liczby
}
