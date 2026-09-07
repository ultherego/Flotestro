package campaigns

import (
	"encoding/json"
	"testing"
	"time"
)

func TestProgBezwzglednyDzialaOdPierwszegoBledu(t *testing.T) {
	// Prog bezwzgledny jest po to, zeby zatrzymac kampanie zanim uszkodzi
	// wiele hostow, wiec nie czeka na statystyke.
	exceeded, reason := ThresholdExceeded(1, 1, 100, 0, 1)
	if !exceeded {
		t.Fatal("prog bezwzgledny 1 nie zatrzymal kampanii po pierwszym bledzie")
	}
	if reason == "" {
		t.Error("brak opisu powodu zatrzymania")
	}
	if exceeded, _ := ThresholdExceeded(1, 1, 100, 0, 2); exceeded {
		t.Error("prog 2 zatrzymal kampanie po jednym bledzie")
	}
}

func TestProgProcentowyNieDzialaBezDanych(t *testing.T) {
	// Bez zakonczonych hostow nie ma z czego liczyc udzialu; liczenie
	// procentu z zera zatrzymaloby kazda kampanie na starcie.
	if exceeded, _ := ThresholdExceeded(0, 0, 50, 20, 0); exceeded {
		t.Fatal("prog procentowy zadzialal bez zakonczonych hostow")
	}
}

func TestProgProcentowyLiczySieOdZakonczonych(t *testing.T) {
	// 2 bledy na 10 zakonczonych to 20%, czyli prog 20% jest osiagniety,
	// mimo ze kampania ma 100 celow.
	exceeded, _ := ThresholdExceeded(2, 10, 100, 20, 0)
	if !exceeded {
		t.Fatal("prog 20% nie zadzialal przy 2 bledach na 10 zakonczonych")
	}
	// Ten sam wynik liczony od calosci bylby 2%, wiec kampania jechalaby dalej
	// mimo ze co piaty host padl.
	if exceeded, _ := ThresholdExceeded(1, 10, 100, 20, 0); exceeded {
		t.Error("prog 20% zadzialal przy 10% bledow")
	}
}

func TestOknoSerwisoweOgraniczaCzas(t *testing.T) {
	base := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	start := base.Add(time.Hour)
	end := base.Add(2 * time.Hour)

	if WithinMaintenanceWindow(base, &start, &end) {
		t.Error("kampania ruszyla przed oknem serwisowym")
	}
	if !WithinMaintenanceWindow(base.Add(90*time.Minute), &start, &end) {
		t.Error("kampania nie ruszyla w oknie serwisowym")
	}
	if WithinMaintenanceWindow(base.Add(3*time.Hour), &start, &end) {
		t.Error("kampania jechala po zamknieciu okna")
	}
	// Brak okna oznacza brak ograniczenia.
	if !WithinMaintenanceWindow(base, nil, nil) {
		t.Error("brak okna zablokowal kampanie")
	}
}

func TestStanKampaniiRozrozniaAktywnoscIKoniec(t *testing.T) {
	for _, state := range []State{StateCanary, StateRunning} {
		if !state.Active() {
			t.Errorf("%s powinien byc stanem aktywnym", state)
		}
		if state.Terminal() {
			t.Errorf("%s nie jest stanem koncowym", state)
		}
	}
	// Wstrzymana kampania nie jest aktywna, ale tez nie jest zakonczona:
	// czeka na decyzje czlowieka.
	if StatePaused.Active() || StatePaused.Terminal() {
		t.Error("stan paused zle sklasyfikowany")
	}
	for _, state := range []State{StateCompleted, StateFailed, StateCanceled} {
		if !state.Terminal() || state.Active() {
			t.Errorf("%s powinien byc stanem koncowym", state)
		}
	}
}

func TestStanCeluRozrozniaZakonczenie(t *testing.T) {
	for _, state := range []TargetState{TargetSucceeded, TargetFailed, TargetSkipped, TargetCanceled} {
		if !state.Finished() {
			t.Errorf("%s powinien konczyc udzial hosta", state)
		}
	}
	for _, state := range []TargetState{TargetPending, TargetRunning, TargetRebooting, TargetVerifying} {
		if state.Finished() {
			t.Errorf("%s nie konczy udzialu hosta", state)
		}
	}
}

func TestWalidacjaSpecu(t *testing.T) {
	valid := Spec{Name: "test", WaveSize: 10, MaxConcurrent: 5, RebootPolicy: RebootNever}
	if err := valid.Validate(); err != nil {
		t.Fatalf("poprawny opis odrzucony: %v", err)
	}

	cases := map[string]func(*Spec){
		"brak nazwy":          func(s *Spec) { s.Name = "" },
		"zerowa fala":         func(s *Spec) { s.WaveSize = 0 },
		"zerowa rownoleglosc": func(s *Spec) { s.MaxConcurrent = 0 },
		"ujemne canary":       func(s *Spec) { s.CanarySize = -1 },
		"prog ponad 100%":     func(s *Spec) { s.FailureThresholdPercent = 101 },
		"nieznana polityka":   func(s *Spec) { s.RebootPolicy = "sometimes" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			spec := valid
			mutate(&spec)
			if err := spec.Validate(); err == nil {
				t.Fatal("nieprawidlowy opis przeszedl walidacje")
			}
		})
	}

	t.Run("odwrocone okno serwisowe", func(t *testing.T) {
		spec := valid
		start := time.Now().Add(time.Hour)
		end := time.Now()
		spec.MaintenanceStart, spec.MaintenanceEnd = &start, &end
		if err := spec.Validate(); err == nil {
			t.Fatal("okno konczace sie przed startem przeszlo walidacje")
		}
	})
}

// TestOdciskZmieniaSieZKazdaDecyzja pilnuje, po co odcisk istnieje: zgoda ma
// dotyczyc dokladnie tego, co zatwierdzajacy zobaczyl. Kazda zmiana, ktora
// przesuwa ryzyko, musi go uniewaznic.
func TestOdciskZmieniaSieZKazdaDecyzja(t *testing.T) {
	podstawa := Spec{
		Name: "restart", ActionType: "unit.restart",
		Payload:       json.RawMessage(`{"unit":{"unit":"cron.service"}}`),
		CanarySize:    1,
		WaveSize:      5,
		MaxConcurrent: 2, FailureThresholdPercent: 20, RebootPolicy: RebootNever,
	}
	hosty := []TargetHost{{ID: "host-b"}, {ID: "host-a"}}

	odcisk, err := Odcisk(podstawa, hosty)
	if err != nil {
		t.Fatalf("odcisk: %v", err)
	}
	if odcisk == "" {
		t.Fatal("pusty odcisk")
	}

	// Kolejnosc hostow w migawce nie jest decyzja.
	inaczej, err := Odcisk(podstawa, []TargetHost{{ID: "host-a"}, {ID: "host-b"}})
	if err != nil {
		t.Fatal(err)
	}
	if inaczej != odcisk {
		t.Error("kolejnosc hostow zmienila odcisk")
	}

	zmiany := map[string]func(*Spec, *[]TargetHost){
		"inny host": func(_ *Spec, hosty *[]TargetHost) {
			*hosty = append(*hosty, TargetHost{ID: "host-c"})
		},
		"inny payload": func(s *Spec, _ *[]TargetHost) {
			s.Payload = json.RawMessage(`{"unit":{"unit":"ssh.service"}}`)
		},
		"inna operacja":     func(s *Spec, _ *[]TargetHost) { s.ActionType = "unit.stop" },
		"wiecej rownolegle": func(s *Spec, _ *[]TargetHost) { s.MaxConcurrent = 50 },
		"wieksza fala":      func(s *Spec, _ *[]TargetHost) { s.WaveSize = 500 },
		"brak canary":       func(s *Spec, _ *[]TargetHost) { s.CanarySize = 0 },
		"wyzszy prog":       func(s *Spec, _ *[]TargetHost) { s.FailureThresholdPercent = 100 },
		"restart hostow":    func(s *Spec, _ *[]TargetHost) { s.RebootPolicy = RebootAlways },
	}
	for nazwa, zmien := range zmiany {
		t.Run(nazwa, func(t *testing.T) {
			zmieniona := podstawa
			cele := append([]TargetHost(nil), hosty...)
			zmien(&zmieniona, &cele)
			inny, err := Odcisk(zmieniona, cele)
			if err != nil {
				t.Fatal(err)
			}
			if inny == odcisk {
				t.Error("zmiana nie uniewaznila odcisku zatwierdzenia")
			}
		})
	}
}
