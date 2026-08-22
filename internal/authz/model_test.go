package authz

import "testing"

func principalWith(bindings ...Binding) Principal {
	return Principal{ID: "p1", Subject: "test", Bindings: bindings}
}

func TestZakresOgraniczaUprawnienie(t *testing.T) {
	// Operator ma prawa wylacznie na staging w Warszawie.
	operator := principalWith(Binding{
		Role:  RoleOperator,
		Scope: Scope{Site: "warszawa", Environment: "staging"},
	})

	if !operator.Can(PermUnitRestart, Scope{Site: "warszawa", Environment: "staging"}) {
		t.Error("brak uprawnienia we wlasnym zakresie")
	}
	// Ten sam host w innym srodowisku jest juz poza zakresem.
	if operator.Can(PermUnitRestart, Scope{Site: "warszawa", Environment: "prod"}) {
		t.Error("uprawnienie wyciekło do innego srodowiska")
	}
	if operator.Can(PermUnitRestart, Scope{Site: "krakow", Environment: "staging"}) {
		t.Error("uprawnienie wyciekło do innej lokalizacji")
	}
}

func TestGwiazdkaWCeluNieRozszerzaUprawnien(t *testing.T) {
	// Operacja globalna ma cel z gwiazdka. Waskie przypisanie nie moze jej
	// obejmowac, bo inaczej operator jednego srodowiska zarzadzalby calym
	// systemem.
	operator := principalWith(Binding{
		Role:  RolePlatformAdmin,
		Scope: Scope{Site: "warszawa", Environment: "staging"},
	})
	if operator.Can(PermEnrollmentToken, GlobalScope) {
		t.Fatal("waskie przypisanie objelo operacje globalna")
	}

	global := principalWith(Binding{Role: RolePlatformAdmin, Scope: GlobalScope})
	if !global.Can(PermEnrollmentToken, GlobalScope) {
		t.Fatal("przypisanie z gwiazdka nie objelo operacji globalnej")
	}
}

func TestRozdzialZlecaniaOdZatwierdzania(t *testing.T) {
	// Kto zleca zmiane, nie powinien jej zatwierdzac. Operator i approver maja
	// rozlaczne uprawnienia do tych dwoch krokow.
	if RoleOperator.Has(PermJobApprove) {
		t.Error("operator moze zatwierdzac wlasne zmiany")
	}
	if RoleApprover.Has(PermJobCreate) {
		t.Error("approver moze zlecac zmiany")
	}
	if !RoleOperator.Has(PermJobCreate) || !RoleApprover.Has(PermJobApprove) {
		t.Error("role nie maja swoich podstawowych uprawnien")
	}
}

func TestRolaOdczytuNieZmieniaStanu(t *testing.T) {
	mutating := []Permission{
		PermJobCreate, PermJobApprove, PermJobCancel,
		PermUnitStart, PermUnitStop, PermUnitRestart, PermUnitReload,
		PermEnrollmentToken, PermPrincipalManage,
	}
	for _, role := range []Role{RoleViewer, RoleAuditor} {
		for _, permission := range mutating {
			if role.Has(permission) {
				t.Errorf("rola %s ma uprawnienie zmieniajace stan: %s", role, permission)
			}
		}
	}
}

func TestAudytorWidziAudytAViewerNie(t *testing.T) {
	if !RoleAuditor.Has(PermAuditRead) {
		t.Error("auditor nie widzi audytu")
	}
	if RoleViewer.Has(PermAuditRead) {
		t.Error("viewer widzi audyt")
	}
}

func TestOperacjeMajaOsobneUprawnienia(t *testing.T) {
	// Nie istnieje jedno szerokie uprawnienie obejmujace wszystkie operacje
	// na jednostkach; kazda ma wlasne.
	unitPermissions := []Permission{PermUnitStart, PermUnitStop, PermUnitRestart, PermUnitReload}
	seen := map[Permission]bool{}
	for _, permission := range unitPermissions {
		if seen[permission] {
			t.Errorf("uprawnienie %s powtarza sie", permission)
		}
		seen[permission] = true
		if !RoleOperator.Has(permission) {
			t.Errorf("operator nie ma uprawnienia %s", permission)
		}
	}
}

func TestTozsamoscBezRolNicNieMoze(t *testing.T) {
	for _, permission := range []Permission{PermHostRead, PermJobRead, PermUnitRestart, PermAuditRead} {
		if (Anonymous).Can(permission, Scope{Site: "warszawa", Environment: "staging"}) {
			t.Errorf("tozsamosc anonimowa ma uprawnienie %s", permission)
		}
	}
}

func TestPustyZakresPrzypisaniaNiePasuje(t *testing.T) {
	// Przypisanie bez zakresu nie moze dzialac jak gwiazdka.
	broken := principalWith(Binding{Role: RolePlatformAdmin, Scope: Scope{}})
	if broken.Can(PermHostRead, Scope{Site: "warszawa", Environment: "staging"}) {
		t.Fatal("puste przypisanie objelo konkretny zakres")
	}
}

// TestScopeSQLMaTaSamaSemantykeCoMatches pilnuje zgodnosci zawezania list
// z autoryzacja. Rozjazd tych dwoch regul dal panel, w ktorym administrator
// z zakresem globalnym widzial pusta flote, a operator ograniczony do jednego
// srodowiska widzial swoje hosty poprawnie: gwiazdka trafiala do zapytania
// jako zwykla wartosc i nie pasowala do niczego.
func TestScopeSQLMaTaSamaSemantykeCoMatches(t *testing.T) {
	globalny := []Scope{{Site: Wildcard, Environment: Wildcard}}
	if warunek, args := ScopeSQL(globalny, "site", "environment", 0); warunek != "" || args != nil {
		t.Errorf("zakres globalny nie moze zawezac: %q %v", warunek, args)
	}

	waski := []Scope{{Site: "lab", Environment: "test"}}
	warunek, args := ScopeSQL(waski, "site", "environment", 0)
	if warunek != "((site = $1 and environment = $2))" {
		t.Errorf("warunek waskiego zakresu = %q", warunek)
	}
	if len(args) != 2 || args[0] != "lab" || args[1] != "test" {
		t.Errorf("argumenty = %v", args)
	}

	// Gwiazdka w jednym wymiarze znosi warunek tylko w nim.
	czesciowy := []Scope{{Site: Wildcard, Environment: "prod"}}
	warunek, args = ScopeSQL(czesciowy, "site", "environment", 0)
	if warunek != "((environment = $1))" || len(args) != 1 || args[0] != "prod" {
		t.Errorf("zakres czesciowy: %q %v", warunek, args)
	}

	// Numeracja parametrow uwzglednia te juz uzyte w zapytaniu.
	warunek, _ = ScopeSQL(waski, "h.site", "h.environment", 3)
	if warunek != "((h.site = $4 and h.environment = $5))" {
		t.Errorf("przesuniecie parametrow: %q", warunek)
	}

	// Wartosc pusta nie pasuje do niczego - tak samo jak w Matches.
	if (Scope{Site: "", Environment: "test"}).Matches(Scope{Site: "lab", Environment: "test"}) {
		t.Fatal("pusty wymiar nie moze pasowac")
	}
	warunek, _ = ScopeSQL([]Scope{{Site: "", Environment: "test"}}, "site", "environment", 0)
	if warunek != "((false and environment = $1))" {
		t.Errorf("pusty wymiar w SQL = %q", warunek)
	}

	// Brak zakresow nie moze oznaczac dostepu do wszystkiego.
	if warunek, _ := ScopeSQL(nil, "site", "environment", 0); warunek != "false" {
		t.Errorf("brak zakresow = %q, oczekiwano warunku falszywego", warunek)
	}
}
