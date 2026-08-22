package adminapi

import (
	"testing"

	"github.com/ultherego/flotestro/internal/authz"
)

func TestLocalPathOdrzucaPrzekierowaniaNaZewnatrz(t *testing.T) {
	// Cel przekierowania po zalogowaniu pochodzi z parametru zapytania. Bez
	// walidacji logowanie stalo by sie otwartym przekierowaniem uzywanym
	// w phishingu: uzytkownik widzi zaufany adres panelu i laduje gdzie indziej.
	rejected := []string{
		"https://zly.example.com/",
		"//zly.example.com/",
		"http://zly.example.com",
		"javascript:alert(1)",
		"zly.example.com/sciezka",
	}
	for _, value := range rejected {
		if got := localPath(value); got != "" {
			t.Errorf("przyjeto zewnetrzny cel %q jako %q", value, got)
		}
	}
}

func TestLocalPathPrzyjmujeSciezkiLokalne(t *testing.T) {
	accepted := map[string]string{
		"/":               "/",
		"/hosts":          "/hosts",
		"/campaigns/123":  "/campaigns/123",
		"/hosts?site=lab": "/hosts",
	}
	for value, want := range accepted {
		if got := localPath(value); got != want {
			t.Errorf("localPath(%q) = %q, oczekiwano %q", value, got, want)
		}
	}
	if got := localPath(""); got != "" {
		t.Errorf("pusty cel dal %q", got)
	}
}

// TestKolekcjeNieWymagajaZakresuGlobalnego pilnuje regresji, przez ktora
// operator ograniczony do jednego srodowiska dostawal odmowe na polowie
// panelu: pulpit, kampanie i zadania sprawdzaly uprawnienie w zakresie
// globalnym, ktorego waskie przypisanie nigdy nie spelnia.
func TestKolekcjeNieWymagajaZakresuGlobalnego(t *testing.T) {
	operator := authz.Principal{
		Subject: "jkowalski", Kind: "user",
		Bindings: []authz.Binding{{
			Role:  authz.RoleOperator,
			Scope: authz.Scope{Site: "lab", Environment: "test"},
		}},
	}

	// Zakres globalny nie jest spelniony - i wlasnie dlatego kolekcje nie
	// moga o niego pytac.
	if operator.Can(authz.PermCampaignRead, authz.GlobalScope) {
		t.Fatal("waskie przypisanie nie powinno spelniac celu globalnego")
	}
	for _, permission := range []authz.Permission{
		authz.PermHostRead, authz.PermJobRead, authz.PermCampaignRead,
	} {
		if !operator.CanAnywhere(permission) {
			t.Errorf("operator musi miec %s w swoim zakresie", permission)
		}
		if len(operator.ScopesFor(permission)) != 1 {
			t.Errorf("%s: oczekiwano jednego zakresu", permission)
		}
	}
	// Uprawnienia, ktorych rola nie ma, nadal nie moga sie pojawic.
	if operator.CanAnywhere(authz.PermAuditRead) {
		t.Error("operator nie ma prawa odczytu audytu")
	}
}

// TestUprawnieniaTozsamosciSaKompletne sprawdza liste, na podstawie ktorej
// interfejs ukrywa sekcje. Zgadywanie po nazwach rol w przegladarce rozjezdza
// sie z polityka przy kazdej jej zmianie.
func TestUprawnieniaTozsamosciSaKompletne(t *testing.T) {
	principal := authz.Principal{
		Bindings: []authz.Binding{
			{Role: authz.RoleViewer, Scope: authz.Scope{Site: "lab"}},
			{Role: authz.RoleApprover, Scope: authz.GlobalScope},
		},
	}
	uprawnienia := map[string]bool{}
	for _, permission := range principal.Permissions() {
		uprawnienia[permission] = true
	}

	for _, oczekiwane := range []string{"host.read", "campaign.read", "job.approve", "audit.read"} {
		if !uprawnienia[oczekiwane] {
			t.Errorf("brak uprawnienia %s w podsumowaniu tozsamosci", oczekiwane)
		}
	}
	// Suma nie moze dodawac niczego, czego zadna z rol nie ma.
	if uprawnienia["pki.rotate"] {
		t.Error("podsumowanie zawiera uprawnienie spoza przypisanych rol")
	}
}
