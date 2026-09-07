package opspec

import (
	"strings"
	"testing"
)

// TestOdswiezenieBezZakresuJestPoprawne pilnuje, ze najczestsza droga - "pokaz
// mi, jak jest teraz" - nie wymaga niczego od operatora.
func TestOdswiezenieBezZakresuJestPoprawne(t *testing.T) {
	if err := Validate(ActionInventoryRefresh, Payload{}); err != nil {
		t.Fatalf("odswiezenie bez zakresu odrzucone: %v", err)
	}
	if err := Validate(ActionInventoryRefresh, Payload{Inventory: &InventoryPayload{}}); err != nil {
		t.Fatalf("odswiezenie z pustym zakresem odrzucone: %v", err)
	}
}

// TestNieznanyModulJestBledem pilnuje zasady, ze literowka nie moze skonczyc
// sie zadaniem, ktore nic nie odswieza, a wyglada na udane.
func TestNieznanyModulJestBledem(t *testing.T) {
	err := Validate(ActionInventoryRefresh, Payload{
		Inventory: &InventoryPayload{Modules: []string{"pakiety"}},
	})
	if err == nil || !strings.Contains(err.Error(), "nieznany modul") {
		t.Fatalf("nieznany modul dal %v", err)
	}
}

func TestPowtorzonyModulJestBledem(t *testing.T) {
	err := Validate(ActionInventoryRefresh, Payload{
		Inventory: &InventoryPayload{Modules: []string{"packages", "packages"}},
	})
	if err == nil {
		t.Fatal("powtorzony modul przyjety")
	}
}

func TestZakresPoprawnychModulowPrzechodzi(t *testing.T) {
	err := Validate(ActionInventoryRefresh, Payload{
		Inventory: &InventoryPayload{Modules: []string{"packages", "network", "containers"}},
	})
	if err != nil {
		t.Fatalf("poprawny zakres odrzucony: %v", err)
	}
}

// TestOdswiezenieNieBierzeBlokady pilnuje wlasciwosci wynikajacej z tego, ze
// operacja niczego nie zmienia: odczyt moze isc rownolegle z operacja, ktora
// wlasnie trwa - najwyzej zobaczy stan w polowie zmiany, a to jest prawda
// o tej chwili.
func TestOdswiezenieNieBierzeBlokady(t *testing.T) {
	spec := ActionInventoryRefresh.Describe()
	if spec.Mutating {
		t.Fatal("odswiezenie inwentarza jest oznaczone jako zmieniajace host")
	}
	if spec.LockClass != LockNone {
		t.Fatalf("klasa blokady = %q", spec.LockClass)
	}
	if spec.Risk != RiskLow {
		t.Fatalf("ryzyko = %v", spec.Risk)
	}
	if spec.Permission != "inventory.refresh" {
		t.Fatalf("uprawnienie = %q", spec.Permission)
	}
}
