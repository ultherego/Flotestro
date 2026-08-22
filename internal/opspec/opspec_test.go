package opspec

import (
	"bytes"
	"testing"
)

func TestPayloadHashJestStabilny(t *testing.T) {
	payload := Payload{Unit: &UnitPayload{Unit: "nginx.service"}}

	first, err := PayloadHash(ActionUnitRestart, ActionVersion, payload)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	second, err := PayloadHash(ActionUnitRestart, ActionVersion, payload)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	// Serwer i agent licza hash niezaleznie; ten sam plan musi dac ten sam hash.
	if !bytes.Equal(first, second) {
		t.Fatal("ten sam plan dal rozne hashe")
	}
}

func TestPayloadHashWykrywaPodmianePlanu(t *testing.T) {
	approved, _ := PayloadHash(ActionUnitRestart, ActionVersion,
		Payload{Unit: &UnitPayload{Unit: "nginx.service"}})

	cases := map[string]struct {
		action  ActionType
		version int
		payload Payload
	}{
		"podmieniona jednostka": {ActionUnitRestart, ActionVersion,
			Payload{Unit: &UnitPayload{Unit: "sshd.service"}}},
		"podmieniona operacja": {ActionUnitStop, ActionVersion,
			Payload{Unit: &UnitPayload{Unit: "nginx.service"}}},
		"podmieniona wersja kontraktu": {ActionUnitRestart, ActionVersion + 1,
			Payload{Unit: &UnitPayload{Unit: "nginx.service"}}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tampered, err := PayloadHash(tc.action, tc.version, tc.payload)
			if err != nil {
				t.Fatalf("hash: %v", err)
			}
			if bytes.Equal(approved, tampered) {
				t.Fatal("podmiana planu nie zmienila hasha")
			}
		})
	}
}

func TestValidateWymagaPayloaduZgodnegoZTypem(t *testing.T) {
	if err := Validate(ActionUnitRestart, Payload{}); err == nil {
		t.Error("operacja na jednostce bez payloadu przeszla walidacje")
	}
	if err := Validate(ActionUnitRestart, Payload{Unit: &UnitPayload{Unit: "  "}}); err == nil {
		t.Error("pusta nazwa jednostki przeszla walidacje")
	}
	if err := Validate(ActionReadJournal, Payload{Unit: &UnitPayload{Unit: "nginx.service"}}); err == nil {
		t.Error("odczyt dziennika z payloadem jednostki przeszedl walidacje")
	}
	if err := Validate("unit.chmod", Payload{Unit: &UnitPayload{Unit: "x.service"}}); err == nil {
		t.Error("nieznany typ operacji przeszedl walidacje")
	}
	if err := Validate(ActionUnitRestart, Payload{Unit: &UnitPayload{Unit: "nginx.service"}}); err != nil {
		t.Errorf("poprawna operacja odrzucona: %v", err)
	}
}

func TestValidateOgraniczaOdczytDziennika(t *testing.T) {
	// Odczyt bez limitu linii pozwolilby sciagnac dowolnie duzy wynik.
	if err := Validate(ActionReadJournal, Payload{Journal: &JournalPayload{Lines: 0}}); err == nil {
		t.Error("odczyt bez limitu linii przeszedl walidacje")
	}
	if err := Validate(ActionReadJournal, Payload{Journal: &JournalPayload{Lines: 100000}}); err == nil {
		t.Error("odczyt ponad limit przeszedl walidacje")
	}
	priority := uint32(9)
	if err := Validate(ActionReadJournal,
		Payload{Journal: &JournalPayload{Lines: 100, MaxPriority: &priority}}); err == nil {
		t.Error("nieprawidlowy priorytet syslog przeszedl walidacje")
	}
	if err := Validate(ActionReadJournal, Payload{Journal: &JournalPayload{Lines: 100}}); err != nil {
		t.Errorf("poprawny odczyt odrzucony: %v", err)
	}
}

func TestOperacjeMutujaceSaOdrozniane(t *testing.T) {
	if ActionReadJournal.Mutating() {
		t.Error("odczyt dziennika nie jest mutacja")
	}
	for _, action := range []ActionType{ActionUnitStart, ActionUnitStop, ActionUnitRestart, ActionUnitReload} {
		if !action.Mutating() {
			t.Errorf("%s musi byc traktowana jak mutacja", action)
		}
		if action.RequiredCapability() != "systemd" {
			t.Errorf("%s wymaga systemd", action)
		}
	}
	// Kazda operacja ma wlasne uprawnienie; nie istnieje jedno szerokie admin.
	seen := map[string]bool{}
	for _, action := range AllActions() {
		permission := action.Permission()
		if permission == "" {
			t.Errorf("%s nie ma uprawnienia", action)
		}
		if seen[permission] {
			t.Errorf("uprawnienie %s jest wspoldzielone przez wiele operacji", permission)
		}
		seen[permission] = true
	}
}
