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
